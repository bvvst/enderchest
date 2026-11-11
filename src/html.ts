// Server-rendered HTML. Unstyled elements; layout-only CSS lives in /app.css.

export const esc = (s: unknown) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

const CSP = [
  "default-src 'self'",
  "script-src 'self' https://challenges.cloudflare.com",
  "style-src 'self'",
  "img-src 'self' blob: data:",
  "media-src 'self' blob:",
  "frame-src 'self' blob: https://challenges.cloudflare.com",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

export function page(title: string, body: string, data: unknown = null, init: ResponseInit = {}, head = ""): Response {
  const json = JSON.stringify(data).replace(/</g, "\\u003c");
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${esc(title)}</title>
<link rel="stylesheet" href="/app.css">
<script type="application/json" id="data">${json}</script>
<script src="/app.js" defer></script>
${head}
</head>
<body>
<main>
${body}
</main>
</body>
</html>`;
  const headers = new Headers(init.headers);
  headers.set("content-type", "text/html; charset=utf-8");
  headers.set("content-security-policy", CSP);
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("cache-control", "no-store");
  // Share pages stay out of search engines (kills the incentive for SEO spam); home opts back in.
  if (!headers.has("x-robots-tag")) headers.set("x-robots-tag", "noindex, nofollow");
  return new Response(html, { ...init, headers });
}

export function size(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB"];
  let i = -1;
  do {
    n /= 1024;
    i++;
  } while (n >= 1024 && i < u.length - 1);
  return `${n.toFixed(n < 10 ? 1 : 0)} ${u[i]}`;
}

export function left(expires: number | null): string {
  if (expires == null) return "forever";
  const s = Math.max(0, expires - Math.floor(Date.now() / 1000));
  if (s >= 3600) return `${Math.floor(s / 3600)}h left`;
  return `${Math.max(1, Math.floor(s / 60))}m left`;
}

export const openForm = `<section>
<form action="/go" method="get" id="open">
<input name="c" id="code" inputmode="numeric" pattern="[0-9]{5}" maxlength="5" placeholder="12345" autocomplete="off" required aria-label="code">
<button>open</button>
</form>
</section>`;
