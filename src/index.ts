import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { b64url, sign, unb64url, verify } from "./jwt";
import { esc, left, openForm, page, size } from "./html";

interface Env {
  DB: D1Database;
  BUCKET: R2Bucket;
  LOOKUP_LIMIT: RateLimit;
  AUTH_LIMIT: RateLimit;
  EMAIL?: { send(msg: { to: string; from: string; subject: string; text: string; html?: string }): Promise<unknown> };
  JWT_SECRET: string;
  APP_NAME: string;
  EMAIL_FROM: string;
}

type User = { id: string; email: string; is_admin: number };
type Share = {
  code: string;
  blob: string;
  user_id: string;
  kind: string;
  name: string;
  type: string;
  size: number;
  encrypted: number;
  created_at: number;
  expires_at: number | null;
};

const MAX_BYTES = 100 * 1024 * 1024; // Workers request body limit on Free/Pro.
const DAY = 86400;
const SESSION_COOKIE = "s";
const CHALLENGE_COOKIE = "c";
// Browsers cap cookie lifetime at 400 days; we refresh it on every visit, so sessions never end.
const SESSION_MAX_AGE = 400 * DAY;

const now = () => Math.floor(Date.now() / 1000);
const rand = (n: number) => b64url(crypto.getRandomValues(new Uint8Array(n)));

class HttpError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

const json = (data: unknown, init: ResponseInit = {}) => {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json");
  headers.set("cache-control", "no-store");
  return new Response(JSON.stringify(data), { ...init, headers });
};

function cookie(name: string, value: string, maxAge: number) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function getCookie(req: Request, name: string) {
  const header = req.headers.get("cookie") || "";
  for (const part of header.split(/;\s*/)) {
    const i = part.indexOf("=");
    if (part.slice(0, i) === name) return part.slice(i + 1);
  }
}

async function currentUser(req: Request, env: Env): Promise<{ user: User; token: string } | null> {
  const token = getCookie(req, SESSION_COOKIE);
  const claims = await verify<{ sub: string; typ: string }>(token, env.JWT_SECRET);
  if (!claims || claims.typ !== "session") return null;
  // Revoking an account deletes the row, which invalidates every JWT for it.
  const user = await env.DB.prepare("SELECT id, email, is_admin FROM users WHERE id = ?").bind(claims.sub).first<User>();
  return user ? { user, token: token! } : null;
}

async function requireUser(req: Request, env: Env) {
  const s = await currentUser(req, env);
  if (!s) throw new HttpError(401, "sign in first");
  return s.user;
}

// CSRF guard for every state-changing request.
function checkOrigin(req: Request, url: URL) {
  if (req.headers.get("origin") !== url.origin) throw new HttpError(403, "bad origin");
}

async function limited(limiter: RateLimit, req: Request) {
  const { success } = await limiter.limit({ key: req.headers.get("cf-connecting-ip") || "?" });
  if (!success) throw new HttpError(429, "slow down");
}

async function userCount(env: Env) {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
  return r?.n ?? 0;
}

const isEmail = (s: unknown): s is string => typeof s === "string" && s.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);

/* ---------------- passkeys ---------------- */

async function regOptions(req: Request, env: Env, url: URL) {
  const body = (await req.json().catch(() => ({}))) as { email?: string; invite?: string };
  let email: string;
  let invite: string | null = null;
  if (body.invite) {
    const inv = await env.DB.prepare("SELECT email FROM invites WHERE token = ? AND used_at IS NULL").bind(body.invite).first<{ email: string }>();
    if (!inv) throw new HttpError(400, "invite is invalid or already used");
    email = inv.email;
    invite = body.invite;
  } else {
    if ((await userCount(env)) > 0) throw new HttpError(403, "invite required");
    if (!isEmail(body.email)) throw new HttpError(400, "enter a valid email");
    email = body.email.toLowerCase();
  }
  const uid = rand(16);
  const options = await generateRegistrationOptions({
    rpName: env.APP_NAME,
    rpID: url.hostname,
    userName: email,
    userID: unb64url(uid) as Uint8Array<ArrayBuffer>,
    attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
  });
  const chal = await sign({ typ: "reg", c: options.challenge, uid, email, invite, exp: now() + 300 }, env.JWT_SECRET);
  return json(options, { headers: { "set-cookie": cookie(CHALLENGE_COOKIE, chal, 300) } });
}

async function regVerify(req: Request, env: Env, url: URL) {
  const chal = await verify<{ typ: string; c: string; uid: string; email: string; invite: string | null }>(getCookie(req, CHALLENGE_COOKIE), env.JWT_SECRET);
  if (!chal || chal.typ !== "reg") throw new HttpError(400, "challenge expired, try again");
  const response = await req.json<any>();
  const result = await verifyRegistrationResponse({
    response,
    expectedChallenge: chal.c,
    expectedOrigin: url.origin,
    expectedRPID: url.hostname,
    requireUserVerification: false,
  }).catch((e) => {
    throw new HttpError(400, `passkey rejected: ${e.message}`);
  });
  if (!result.verified || !result.registrationInfo) throw new HttpError(400, "passkey rejected");
  const cred = result.registrationInfo.credential;
  const t = now();

  if (chal.invite) {
    const used = await env.DB.prepare("UPDATE invites SET used_at = ? WHERE token = ? AND used_at IS NULL").bind(t, chal.invite).run();
    if (!used.meta.changes) throw new HttpError(400, "invite already used");
    const existing = await env.DB.prepare("SELECT 1 FROM users WHERE email = ?").bind(chal.email).first();
    if (existing) throw new HttpError(400, "an account with this email already exists");
    await env.DB.prepare("INSERT INTO users (id, email, is_admin, created_at) VALUES (?, ?, 0, ?)").bind(chal.uid, chal.email, t).run();
  } else {
    // First account becomes admin; atomic so only one can ever win.
    const ins = await env.DB.prepare(
      "INSERT INTO users (id, email, is_admin, created_at) SELECT ?, ?, 1, ? WHERE NOT EXISTS (SELECT 1 FROM users)",
    ).bind(chal.uid, chal.email, t).run();
    if (!ins.meta.changes) throw new HttpError(403, "invite required");
  }
  await env.DB.prepare("INSERT INTO credentials (id, user_id, public_key, counter, transports, created_at) VALUES (?, ?, ?, ?, ?, ?)")
    .bind(cred.id, chal.uid, b64url(cred.publicKey), cred.counter, JSON.stringify(cred.transports ?? []), t)
    .run();
  return session(env, chal.uid);
}

async function loginOptions(env: Env, url: URL) {
  const options = await generateAuthenticationOptions({ rpID: url.hostname, userVerification: "preferred" });
  const chal = await sign({ typ: "auth", c: options.challenge, exp: now() + 300 }, env.JWT_SECRET);
  return json(options, { headers: { "set-cookie": cookie(CHALLENGE_COOKIE, chal, 300) } });
}

async function loginVerify(req: Request, env: Env, url: URL) {
  const chal = await verify<{ typ: string; c: string }>(getCookie(req, CHALLENGE_COOKIE), env.JWT_SECRET);
  if (!chal || chal.typ !== "auth") throw new HttpError(400, "challenge expired, try again");
  const response = await req.json<any>();
  const row = await env.DB.prepare("SELECT id, user_id, public_key, counter, transports FROM credentials WHERE id = ?")
    .bind(String(response?.id))
    .first<{ id: string; user_id: string; public_key: string; counter: number; transports: string }>();
  if (!row) throw new HttpError(400, "unknown passkey (account may have been revoked)");
  const result = await verifyAuthenticationResponse({
    response,
    expectedChallenge: chal.c,
    expectedOrigin: url.origin,
    expectedRPID: url.hostname,
    requireUserVerification: false,
    credential: {
      id: row.id,
      publicKey: unb64url(row.public_key) as Uint8Array<ArrayBuffer>,
      counter: row.counter,
      transports: JSON.parse(row.transports || "[]"),
    },
  }).catch((e) => {
    throw new HttpError(400, `passkey rejected: ${e.message}`);
  });
  if (!result.verified) throw new HttpError(400, "passkey rejected");
  await env.DB.prepare("UPDATE credentials SET counter = ? WHERE id = ?").bind(result.authenticationInfo.newCounter, row.id).run();
  return session(env, row.user_id);
}

async function session(env: Env, uid: string) {
  const token = await sign({ typ: "session", sub: uid, iat: now() }, env.JWT_SECRET);
  const headers = new Headers();
  headers.append("set-cookie", cookie(SESSION_COOKIE, token, SESSION_MAX_AGE));
  headers.append("set-cookie", cookie(CHALLENGE_COOKIE, "", 0));
  return json({ ok: true }, { headers });
}

/* ---------------- shares ---------------- */

async function upload(req: Request, env: Env, url: URL) {
  const user = await requireUser(req, env);
  const len = Number(req.headers.get("content-length"));
  if (!len || !req.body) throw new HttpError(400, "empty upload");
  if (len > MAX_BYTES) throw new HttpError(413, "max 100 MB");

  const encrypted = req.headers.get("x-encrypted") === "1";
  // Encrypted shares don't reveal whether they're a paste or a file.
  const kind = !encrypted && req.headers.get("x-kind") === "paste" ? "paste" : "file";
  const forever = req.headers.get("x-forever") === "1";
  let name = "encrypted";
  if (!encrypted) {
    try {
      name = decodeURIComponent(req.headers.get("x-name") || "") || (kind === "paste" ? "paste.txt" : "file");
    } catch {
      name = "file";
    }
    name = name.replace(/[\/\\\x00-\x1f]/g, "_").slice(0, 200);
  }
  const type = encrypted ? "application/octet-stream" : (req.headers.get("content-type") || "application/octet-stream").slice(0, 100);
  const t = now();
  const expires = forever ? null : t + DAY;

  const blob = rand(16);
  const obj = await env.BUCKET.put(blob, req.body, {
    httpMetadata: { contentType: type },
    customMetadata: { exp: expires == null ? "" : String(expires) },
  });

  for (let i = 0; i < 20; i++) {
    const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 100000).padStart(5, "0");
    // Reclaim the code if its previous share has expired but not been swept yet.
    const stale = await env.DB.prepare("DELETE FROM shares WHERE code = ? AND expires_at IS NOT NULL AND expires_at <= ? RETURNING blob")
      .bind(code, t)
      .first<{ blob: string }>();
    if (stale) await env.BUCKET.delete(stale.blob);
    const ins = await env.DB.prepare(
      "INSERT OR IGNORE INTO shares (code, blob, user_id, kind, name, type, size, encrypted, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(code, blob, user.id, kind, name, type, obj.size, encrypted ? 1 : 0, t, expires).run();
    if (ins.meta.changes) return json({ code, url: `${url.origin}/s/${code}` });
  }
  await env.BUCKET.delete(blob);
  throw new HttpError(503, "no free codes, try again");
}

async function getShare(env: Env, code: string) {
  const s = await env.DB.prepare("SELECT * FROM shares WHERE code = ?").bind(code).first<Share>();
  if (!s || (s.expires_at != null && s.expires_at <= now())) return null;
  return s;
}

const rawPath = (s: Share) => `/f/${s.blob}/${encodeURIComponent(s.name)}`;

async function viewPage(req: Request, env: Env, code: string) {
  await limited(env.LOOKUP_LIMIT, req);
  const s = await getShare(env, code);
  if (!s) return page("not found", `<h1>${esc(code)}</h1><p>nothing here (it may have expired)</p><p><a href="/">home</a></p>`, null, { status: 404 });
  const data = { code: s.code, kind: s.kind, name: s.name, type: s.type, size: s.size, encrypted: !!s.encrypted, raw: rawPath(s) };
  const meta = s.encrypted ? `encrypted · ${size(s.size)} · ${left(s.expires_at)}` : `${esc(s.name)} · ${size(s.size)} · ${left(s.expires_at)}`;
  return page(
    s.encrypted ? s.code : `${s.name} · ${s.code}`,
    `<h1>${esc(s.code)}</h1>
<p id="meta">${meta}</p>
<section id="content"><p id="msg">loading…</p></section>
<section id="actions"></section>
<p><a href="/">home</a></p>`,
    data,
  );
}

// Content-addressed by random blob id, so it is safe to cache at the edge for as long as it lives.
async function serveBlob(req: Request, env: Env, ctx: ExecutionContext, blob: string) {
  const cache = caches.default;
  const ranged = req.headers.has("range");
  const cacheable = req.method === "GET" && !ranged;
  if (cacheable) {
    const hit = await cache.match(req);
    if (hit) return hit;
  }
  const obj = await env.BUCKET.get(blob, { range: req.headers, onlyIf: req.headers });
  if (!obj) return new Response("not found", { status: 404 });
  const exp = Number(obj.customMetadata?.exp || 0);
  if (exp && exp <= now()) return new Response("expired", { status: 410 });

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  headers.set("accept-ranges", "bytes");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  const type = headers.get("content-type") || "application/octet-stream";
  const inline = /^(image\/(png|jpeg|gif|webp|avif)|video\/|audio\/|text\/|application\/pdf$)/.test(type);
  if (type.startsWith("text/")) headers.set("content-type", "text/plain; charset=utf-8");
  headers.set("content-disposition", inline ? "inline" : "attachment");
  // Sandbox anything the browser renders on our origin (pdf viewers break under sandbox).
  if (type !== "application/pdf") headers.set("content-security-policy", "sandbox; default-src 'none'; img-src 'self'; media-src 'self'; style-src 'unsafe-inline'");
  const ttl = exp ? Math.max(1, exp - now()) : 365 * DAY;
  headers.set("cache-control", `public, max-age=${ttl}${exp ? "" : ", immutable"}`);

  if (!("body" in obj) || !obj.body) return new Response(null, { status: 304, headers });
  if (ranged && obj.range && "offset" in obj.range) {
    const { offset = 0, length = obj.size - offset } = obj.range as { offset?: number; length?: number };
    headers.set("content-range", `bytes ${offset}-${offset + length - 1}/${obj.size}`);
    headers.set("content-length", String(length));
    return new Response(obj.body, { status: 206, headers });
  }
  headers.set("content-length", String(obj.size));
  const res = new Response(obj.body, { headers });
  if (cacheable) ctx.waitUntil(cache.put(req, res.clone()));
  return res;
}

async function deleteShare(req: Request, env: Env, url: URL) {
  const user = await requireUser(req, env);
  const { code } = await req.json<{ code: string }>();
  const s = await env.DB.prepare("SELECT * FROM shares WHERE code = ?").bind(String(code)).first<Share>();
  if (!s || (s.user_id !== user.id && !user.is_admin)) throw new HttpError(404, "not found");
  await env.DB.prepare("DELETE FROM shares WHERE code = ?").bind(s.code).run();
  await env.BUCKET.delete(s.blob);
  await caches.default.delete(new Request(url.origin + rawPath(s)));
  return json({ ok: true });
}

/* ---------------- pages ---------------- */

async function homePage(req: Request, env: Env) {
  const s = await currentUser(req, env);
  if (!s) {
    const setup = (await userCount(env)) === 0;
    const auth = setup
      ? `<section id="setup">
<h2>create admin account</h2>
<input id="email" type="email" placeholder="email" autocomplete="email" aria-label="email">
<button id="register">create passkey</button>
</section>`
      : `<section><button id="login">sign in with passkey</button></section>`;
    return page(env.APP_NAME, `<h1>${esc(env.APP_NAME)}</h1>${openForm}${auth}<p id="msg"></p>`);
  }
  const { user, token } = s;
  const rows = await env.DB.prepare(
    "SELECT code, name, size, encrypted, expires_at FROM shares WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC LIMIT 100",
  ).bind(user.id, now()).all<Share>();
  const list = rows.results.length
    ? `<ul id="mine">${rows.results
        .map(
          (r) =>
            `<li><a href="/s/${r.code}">${r.code}</a> ${r.encrypted ? "encrypted" : esc(r.name)} · ${size(r.size)} · ${left(r.expires_at)} <button data-del="${r.code}">delete</button></li>`,
        )
        .join("")}</ul>`
    : `<p>nothing yet</p>`;
  return page(
    env.APP_NAME,
    `<h1>${esc(env.APP_NAME)}</h1>
${openForm}
<section id="upload">
<h2>share</h2>
<textarea id="text" rows="8" placeholder="paste text, or drop a file anywhere" aria-label="text"></textarea>
<input id="file" type="file" aria-label="file">
<label><input id="forever" type="checkbox"> keep forever</label>
<label><input id="encrypt" type="checkbox"> encrypt</label>
<button id="send">upload</button>
<progress id="progress" max="1" value="0" hidden></progress>
<p id="msg"></p>
<div id="result" hidden>
<input id="link" readonly aria-label="share link">
<button id="copy">copy</button>
</div>
</section>
<section>
<h2>your uploads</h2>
${list}
</section>
<section>
<p>${esc(user.email)}</p>
${user.is_admin ? `<a href="/admin">admin</a>` : ""}
<button id="logout">sign out</button>
</section>`,
    null,
    // Re-issue the session cookie so the 400-day browser cap never lapses.
    { headers: { "set-cookie": cookie(SESSION_COOKIE, token, SESSION_MAX_AGE) } },
  );
}

async function invitePage(env: Env, token: string) {
  const inv = await env.DB.prepare("SELECT email FROM invites WHERE token = ? AND used_at IS NULL").bind(token).first<{ email: string }>();
  if (!inv) return page("invite", `<h1>invite</h1><p>this invite is invalid or already used</p><p><a href="/">home</a></p>`, null, { status: 404 });
  return page(
    "invite",
    `<h1>${esc(env.APP_NAME)}</h1>
<section>
<p>you were invited as ${esc(inv.email)}</p>
<button id="register">create passkey</button>
<p id="msg"></p>
</section>`,
    { invite: token },
  );
}

async function adminPage(req: Request, env: Env) {
  const s = await currentUser(req, env);
  if (!s?.user.is_admin) return Response.redirect(new URL("/", req.url).toString(), 302);
  const origin = new URL(req.url).origin;
  const users = await env.DB.prepare(
    "SELECT u.id, u.email, u.is_admin, u.created_at, (SELECT COUNT(*) FROM shares WHERE user_id = u.id) AS n FROM users u ORDER BY u.created_at",
  ).all<User & { created_at: number; n: number }>();
  const invites = await env.DB.prepare("SELECT token, email, created_at FROM invites WHERE used_at IS NULL ORDER BY created_at DESC").all<{
    token: string;
    email: string;
  }>();
  return page(
    "admin",
    `<h1>admin</h1>
<section>
<h2>invite</h2>
<input id="email" type="email" placeholder="email" aria-label="email">
<button id="invite">send invite</button>
<p id="msg"></p>
<div id="result" hidden>
<input id="link" readonly aria-label="invite link">
<button id="copy">copy</button>
</div>
</section>
<section>
<h2>pending invites</h2>
${
  invites.results.length
    ? `<ul>${invites.results.map((i) => `<li>${esc(i.email)} <button data-copy="${esc(`${origin}/i/${i.token}`)}">copy link</button> <button data-uninvite="${esc(i.token)}">cancel</button></li>`).join("")}</ul>`
    : "<p>none</p>"
}
</section>
<section>
<h2>accounts</h2>
<ul>${users.results
      .map(
        (u) =>
          `<li>${esc(u.email)} · ${u.n} uploads ${u.is_admin ? "· admin" : `<button data-revoke="${esc(u.id)}" data-email="${esc(u.email)}">revoke</button>`}</li>`,
      )
      .join("")}</ul>
</section>
<p><a href="/">home</a></p>`,
  );
}

async function createInvite(req: Request, env: Env, url: URL) {
  const user = await requireUser(req, env);
  if (!user.is_admin) throw new HttpError(403, "admin only");
  const { email } = await req.json<{ email: string }>();
  if (!isEmail(email)) throw new HttpError(400, "enter a valid email");
  const addr = email.toLowerCase();
  if (await env.DB.prepare("SELECT 1 FROM users WHERE email = ?").bind(addr).first()) throw new HttpError(400, "already has an account");
  const token = rand(18);
  await env.DB.prepare("INSERT INTO invites (token, email, created_at) VALUES (?, ?, ?)").bind(token, addr, now()).run();
  const link = `${url.origin}/i/${token}`;
  let emailed = false;
  let error: string | undefined;
  if (env.EMAIL && env.EMAIL_FROM) {
    try {
      await env.EMAIL.send({
        to: addr,
        from: env.EMAIL_FROM,
        subject: `You're invited to ${env.APP_NAME}`,
        text: `You've been invited to ${url.host}.\n\nCreate your passkey here:\n${link}\n`,
      });
      emailed = true;
    } catch (e: any) {
      error = e?.message || String(e);
    }
  }
  return json({ link, emailed, error });
}

async function adminAction(req: Request, env: Env, action: "uninvite" | "revoke") {
  const user = await requireUser(req, env);
  if (!user.is_admin) throw new HttpError(403, "admin only");
  const body = await req.json<{ token?: string; id?: string }>();
  if (action === "uninvite") {
    await env.DB.prepare("DELETE FROM invites WHERE token = ?").bind(String(body.token)).run();
    return json({ ok: true });
  }
  if (body.id === user.id) throw new HttpError(400, "can't revoke yourself");
  const blobs = await env.DB.prepare("SELECT blob FROM shares WHERE user_id = ?").bind(String(body.id)).all<{ blob: string }>();
  for (let i = 0; i < blobs.results.length; i += 1000) await env.BUCKET.delete(blobs.results.slice(i, i + 1000).map((r) => r.blob));
  await env.DB.batch([
    env.DB.prepare("DELETE FROM shares WHERE user_id = ?").bind(String(body.id)),
    env.DB.prepare("DELETE FROM credentials WHERE user_id = ?").bind(String(body.id)),
    env.DB.prepare("DELETE FROM users WHERE id = ? AND is_admin = 0").bind(String(body.id)),
  ]);
  return json({ ok: true });
}

/* ---------------- router ---------------- */

async function route(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(req.url);
  const p = url.pathname;
  let m: RegExpMatchArray | null;

  if (req.method === "GET" || req.method === "HEAD") {
    if (p === "/") return homePage(req, env);
    if (p === "/go") {
      const c = (url.searchParams.get("c") || "").trim();
      return Response.redirect(`${url.origin}${/^\d{5}$/.test(c) ? `/s/${c}` : "/"}`, 302);
    }
    if ((m = p.match(/^\/s\/(\d{5})\/?$/))) return viewPage(req, env, m[1]);
    if ((m = p.match(/^\/s\/(\d{5})\/raw$/))) {
      await limited(env.LOOKUP_LIMIT, req);
      const s = await getShare(env, m[1]);
      if (!s) return new Response("not found", { status: 404 });
      return Response.redirect(url.origin + rawPath(s), 302);
    }
    if ((m = p.match(/^\/f\/([\w-]{22})(\/|$)/))) return serveBlob(req, env, ctx, m[1]);
    if ((m = p.match(/^\/i\/([\w-]{24})$/))) return invitePage(env, m[1]);
    if (p === "/admin") return adminPage(req, env);
    return page("not found", `<h1>404</h1><p><a href="/">home</a></p>`, null, { status: 404 });
  }

  if (req.method === "POST" && p.startsWith("/api/")) {
    checkOrigin(req, url);
    switch (p) {
      case "/api/reg/options":
        await limited(env.AUTH_LIMIT, req);
        return regOptions(req, env, url);
      case "/api/reg/verify":
        await limited(env.AUTH_LIMIT, req);
        return regVerify(req, env, url);
      case "/api/login/options":
        await limited(env.AUTH_LIMIT, req);
        return loginOptions(env, url);
      case "/api/login/verify":
        await limited(env.AUTH_LIMIT, req);
        return loginVerify(req, env, url);
      case "/api/logout":
        return json({ ok: true }, { headers: { "set-cookie": cookie(SESSION_COOKIE, "", 0) } });
      case "/api/upload":
        return upload(req, env, url);
      case "/api/delete":
        return deleteShare(req, env, url);
      case "/api/admin/invite":
        return createInvite(req, env, url);
      case "/api/admin/uninvite":
        return adminAction(req, env, "uninvite");
      case "/api/admin/revoke":
        return adminAction(req, env, "revoke");
    }
  }
  return json({ error: "not found" }, { status: 404 });
}

export default {
  async fetch(req, env, ctx) {
    try {
      return await route(req, env, ctx);
    } catch (e) {
      if (e instanceof HttpError) return json({ error: e.message }, { status: e.status });
      console.error(e);
      return json({ error: "server error" }, { status: 500 });
    }
  },

  // Sweep expired shares from R2 + D1.
  async scheduled(_event, env) {
    for (;;) {
      const rows = await env.DB.prepare("SELECT code, blob FROM shares WHERE expires_at IS NOT NULL AND expires_at <= ? LIMIT 500")
        .bind(now())
        .all<{ code: string; blob: string }>();
      if (!rows.results.length) break;
      await env.BUCKET.delete(rows.results.map((r) => r.blob));
      await env.DB.batch(rows.results.map((r) => env.DB.prepare("DELETE FROM shares WHERE code = ? AND blob = ?").bind(r.code, r.blob)));
      if (rows.results.length < 500) break;
    }
    // Drop invites older than 30 days that were never used.
    await env.DB.prepare("DELETE FROM invites WHERE used_at IS NULL AND created_at < ?").bind(now() - 30 * DAY).run();
  },
} satisfies ExportedHandler<Env>;
