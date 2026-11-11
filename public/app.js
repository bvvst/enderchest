"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const data = JSON.parse($("data").textContent);
  const msg = (t) => { if ($("msg")) $("msg").textContent = t || ""; };

  const b2u = (buf) => {
    const b = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const u2b = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

  async function api(path, body) {
    const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(d.error || `error ${r.status}`);
    return d;
  }

  const copy = async (text, btn) => {
    try {
      await navigator.clipboard.writeText(text);
      if (btn) { const t = btn.textContent; btn.textContent = "copied"; setTimeout(() => (btn.textContent = t), 1200); }
    } catch { prompt("copy:", text); }
  };

  /* ---------- passkeys ---------- */

  async function register(body) {
    const o = await api("/api/reg/options", body);
    o.challenge = u2b(o.challenge);
    o.user.id = u2b(o.user.id);
    (o.excludeCredentials || []).forEach((c) => (c.id = u2b(c.id)));
    const c = await navigator.credentials.create({ publicKey: o });
    await api("/api/reg/verify", {
      id: c.id,
      rawId: b2u(c.rawId),
      type: c.type,
      response: {
        clientDataJSON: b2u(c.response.clientDataJSON),
        attestationObject: b2u(c.response.attestationObject),
        transports: c.response.getTransports ? c.response.getTransports() : [],
      },
      clientExtensionResults: c.getClientExtensionResults(),
      authenticatorAttachment: c.authenticatorAttachment || undefined,
    });
  }

  async function login() {
    const o = await api("/api/login/options");
    o.challenge = u2b(o.challenge);
    (o.allowCredentials || []).forEach((c) => (c.id = u2b(c.id)));
    const c = await navigator.credentials.get({ publicKey: o });
    await api("/api/login/verify", {
      id: c.id,
      rawId: b2u(c.rawId),
      type: c.type,
      response: {
        clientDataJSON: b2u(c.response.clientDataJSON),
        authenticatorData: b2u(c.response.authenticatorData),
        signature: b2u(c.response.signature),
        userHandle: c.response.userHandle ? b2u(c.response.userHandle) : undefined,
      },
      clientExtensionResults: c.getClientExtensionResults(),
      authenticatorAttachment: c.authenticatorAttachment || undefined,
    });
  }

  const run = (fn) => async (e) => {
    const btn = e && e.currentTarget;
    if (btn) btn.disabled = true;
    msg("");
    try { await fn(e); } catch (err) { msg(err.name === "NotAllowedError" ? "cancelled" : err.message); }
    if (btn) btn.disabled = false;
  };

  if ($("login")) $("login").onclick = run(async () => { await login(); location.reload(); });
  if ($("register")) $("register").onclick = run(async () => {
    if (data && data.invite) await register({ invite: data.invite });
    else await register({ email: $("email").value.trim() });
    location.href = "/";
  });
  if ($("logout")) $("logout").onclick = run(async () => { await api("/api/logout"); location.href = "/"; });

  /* ---------- encryption ---------- */
  // Blob layout: iv(12) || AES-256-GCM( u32be(len) || header JSON {name,type} || bytes ).
  // The key lives only in the URL fragment, which browsers never send to the server.

  async function encrypt(bytes, name, type) {
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const head = new TextEncoder().encode(JSON.stringify({ name, type }));
    const plain = new Uint8Array(4 + head.length + bytes.byteLength);
    new DataView(plain.buffer).setUint32(0, head.length);
    plain.set(head, 4);
    plain.set(new Uint8Array(bytes), 4 + head.length);
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plain);
    const out = new Uint8Array(12 + ct.byteLength);
    out.set(iv);
    out.set(new Uint8Array(ct), 12);
    return { body: out, frag: b2u(await crypto.subtle.exportKey("raw", key)) };
  }

  async function decrypt(buf, frag) {
    const key = await crypto.subtle.importKey("raw", u2b(frag), "AES-GCM", false, ["decrypt"]);
    const plain = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(buf, 0, 12) }, key, new Uint8Array(buf, 12)));
    const len = new DataView(plain.buffer).getUint32(0);
    const head = JSON.parse(new TextDecoder().decode(plain.subarray(4, 4 + len)));
    return { ...head, bytes: plain.subarray(4 + len) };
  }

  /* ---------- upload ---------- */

  function send(body, headers) {
    return new Promise((resolve, reject) => {
      const x = new XMLHttpRequest();
      x.open("POST", "/api/upload");
      for (const k in headers) x.setRequestHeader(k, headers[k]);
      const p = $("progress");
      p.hidden = false;
      p.value = 0;
      x.upload.onprogress = (e) => { if (e.lengthComputable) p.value = e.loaded / e.total; };
      x.onload = () => {
        p.hidden = true;
        let d = {};
        try { d = JSON.parse(x.responseText); } catch {}
        x.status < 300 ? resolve(d) : reject(new Error(d.error || `error ${x.status}`));
      };
      x.onerror = () => { p.hidden = true; reject(new Error("network error")); };
      x.send(body);
    });
  }

  if ($("upload")) {
    const file = $("file");
    const text = $("text");
    const setFile = (files) => { if (files && files.length) { file.files = files; text.value = ""; } };

    document.addEventListener("dragover", (e) => e.preventDefault());
    document.addEventListener("drop", (e) => { e.preventDefault(); setFile(e.dataTransfer.files); });
    text.addEventListener("paste", (e) => {
      if (e.clipboardData.files.length) { e.preventDefault(); setFile(e.clipboardData.files); }
    });

    $("send").onclick = run(async () => {
      const f = file.files[0];
      const paste = !f;
      if (paste && !text.value) throw new Error("paste something or pick a file");
      const name = paste ? "paste.txt" : f.name;
      const type = paste ? "text/plain" : f.type || "application/octet-stream";
      let body = paste ? new TextEncoder().encode(text.value) : f;
      if (body.size > 100 * 1024 * 1024 || body.byteLength > 100 * 1024 * 1024) throw new Error("max 100 MB");
      const enc = $("encrypt").checked;
      let frag = "";
      if (enc) {
        msg("encrypting…");
        const r = await encrypt(paste ? body : await f.arrayBuffer(), name, type);
        body = r.body;
        frag = "#" + r.frag;
        msg("");
      }
      const d = await send(body, {
        "content-type": enc ? "application/octet-stream" : type,
        "x-name": encodeURIComponent(name),
        "x-kind": paste ? "paste" : "file",
        "x-forever": $("forever").checked ? "1" : "0",
        "x-encrypted": enc ? "1" : "0",
      });
      const link = d.url + frag;
      $("result").hidden = false;
      $("link").value = link;
      $("link").select();
      text.value = "";
      file.value = "";
      copy(link).catch(() => {});
      msg("uploaded · link copied");
    });
    $("copy").onclick = (e) => copy($("link").value, e.currentTarget);
  }

  document.querySelectorAll("[data-del]").forEach((b) => {
    b.onclick = run(async () => {
      if (!confirm(`delete ${b.dataset.del}?`)) return;
      await api("/api/delete", { code: b.dataset.del });
      b.closest("li").remove();
    });
  });

  /* ---------- admin ---------- */

  if ($("invite")) {
    $("invite").onclick = run(async () => {
      const d = await api("/api/admin/invite", { email: $("email").value.trim() });
      $("result").hidden = false;
      $("link").value = d.link;
      $("link").select();
      msg(d.emailed ? "invite emailed" : `email not sent${d.error ? ` (${d.error})` : ""}. send them this link:`);
    });
    $("copy").onclick = (e) => copy($("link").value, e.currentTarget);
  }
  document.querySelectorAll("[data-copy]").forEach((b) => (b.onclick = () => copy(b.dataset.copy, b)));
  document.querySelectorAll("[data-uninvite]").forEach((b) => {
    b.onclick = run(async () => { await api("/api/admin/uninvite", { token: b.dataset.uninvite }); b.closest("li").remove(); });
  });
  document.querySelectorAll("[data-revoke]").forEach((b) => {
    b.onclick = run(async () => {
      if (!confirm(`revoke ${b.dataset.email}? this deletes the account and all of its uploads.`)) return;
      await api("/api/admin/revoke", { id: b.dataset.revoke });
      b.closest("li").remove();
    });
  });

  /* ---------- view ---------- */

  if ($("content") && data && data.code) {
    const box = $("content");
    const actions = $("actions");
    const add = (el) => { box.append(el); return el; };

    const show = async ({ name, type, url, getText, size }) => {
      msg("");
      const isText = data.kind === "paste" || /^text\/|json|xml|javascript/.test(type);
      if (isText && size < 5 * 1024 * 1024) {
        const t = await getText();
        add(document.createElement("pre")).textContent = t;
        const c = document.createElement("button");
        c.textContent = "copy text";
        c.onclick = () => copy(t, c);
        actions.append(c);
      } else if (/^image\/(png|jpeg|gif|webp|avif)$/.test(type)) {
        const i = add(document.createElement("img"));
        i.src = url;
        i.alt = name;
      } else if (/^video\//.test(type)) {
        const v = add(document.createElement("video"));
        v.controls = true;
        v.src = url;
      } else if (/^audio\//.test(type)) {
        const a = add(document.createElement("audio"));
        a.controls = true;
        a.src = url;
      } else if (type === "application/pdf" && !data.encrypted) {
        add(document.createElement("iframe")).src = url;
      }
      const a = document.createElement("a");
      a.href = url;
      a.download = name;
      a.textContent = `download ${name}`;
      actions.append(a);
    };

    (async () => {
      try {
        if (!data.encrypted) {
          await show({ name: data.name, type: data.type, url: data.raw, size: data.size, getText: () => fetch(data.raw).then((r) => r.text()) });
          return;
        }
        const frag = location.hash.slice(1);
        if (!frag) throw new Error("this share is encrypted and the link is missing its key (the part after #)");
        msg("decrypting…");
        const r = await fetch(data.raw);
        if (!r.ok) throw new Error(`error ${r.status}`);
        let d;
        try { d = await decrypt(await r.arrayBuffer(), frag); } catch { throw new Error("wrong key, could not decrypt"); }
        const blob = new Blob([d.bytes], { type: d.type });
        $("meta").textContent = `${d.name} · ${$("meta").textContent}`;
        document.title = `${d.name} · ${data.code}`;
        await show({ name: d.name, type: d.type, url: URL.createObjectURL(blob), size: blob.size, getText: () => blob.text() });
      } catch (e) {
        msg(e.message);
      }
    })();
  }
})();
