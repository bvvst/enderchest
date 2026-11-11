<img src="assets/icon.svg" width="64" height="64" alt="">

# enderchest

[enderchest.sh](https://enderchest.sh): tiny paste + file share on Cloudflare only: one Worker, D1 (accounts, passkeys, share index), R2 (file bytes), the edge Cache API, rate-limit bindings, and a cron to sweep expired uploads.

- `/` enter a 5-digit code, or (signed in) paste text / pick or drop a file
- `/s/12345` view a share · `/s/12345/raw` raw bytes (unencrypted only)
- `/admin` invite by email, cancel invites, revoke accounts (deletes their uploads)
- uploads last 24h unless "keep forever" is checked; max 100 MB
- "encrypt" does AES-256-GCM in the browser; the key is only in the `#fragment` of the link and never reaches the server
- passkey-only accounts; the first account becomes admin, everyone else needs an invite
- sessions are HS256 JWT cookies with no expiry (re-set on each visit to beat the browser's 400-day cookie cap); revoking deletes the user row, which kills every session

## Deploy

```sh
npm i
npx wrangler d1 create luke-cdn && npx wrangler r2 bucket create luke-cdn   # put the ids in wrangler.jsonc
npm run db:init
openssl rand -base64 48 | npx wrangler secret put JWT_SECRET
npm run deploy
```

## Custom domain

Passkeys are bound to the hostname. After adding a custom domain (Workers → luke-cdn → Settings → Domains & Routes), accounts made on another hostname can't sign in there. To start fresh on the new domain:

```sh
npx wrangler d1 execute luke-cdn --remote --command "DELETE FROM credentials; DELETE FROM users; DELETE FROM invites;"
```

The next signup becomes admin again. Optionally set `"workers_dev": false` in `wrangler.jsonc` so only the custom domain serves the app.

## Emailing invites (optional)

Without this, the admin page shows the invite link to copy and send yourself.

1. The domain must use Cloudflare DNS. Dashboard → Compute → Email Service → Email Sending → Onboard Domain.
2. Sending to arbitrary addresses requires Workers Paid ($5/mo).
3. In `wrangler.jsonc`, uncomment `"send_email": [{ "name": "EMAIL" }]`, set `EMAIL_FROM` (e.g. `invites@yourdomain`), and `npm run deploy`.
