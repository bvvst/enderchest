<img src="assets/icon.svg" width="64" height="64" alt="">

# enderchest

Tiny paste and file share with 5-digit links (`/s/12345`), built only on Cloudflare: one Worker, D1, R2, the Cache API, rate limiting and Turnstile. Live at [enderchest.sh](https://enderchest.sh).

- Passkey-only accounts. The first signup becomes admin; everyone else needs an invite.
- Signed in: uploads up to 100 MB that last 24h or forever.
- Signed out: uploads up to 10 MB (512 KB pastes) that last 10 minutes, behind Turnstile and per-IP and global limits.
- Optional end-to-end encryption: AES-256-GCM in the browser, with the key only in the link's `#fragment`.
- `/admin` invites by email, revokes accounts and lists reported shares.

## Setup

Requires Node and a Cloudflare account.

```sh
git clone https://github.com/bvvst/enderchest && cd enderchest
npm i
npx wrangler login
```

1. **Create storage.**

   ```sh
   npx wrangler d1 create enderchest
   npx wrangler r2 bucket create enderchest
   ```

   In `wrangler.jsonc`, set `name`, `database_name` and `database_id` (from the output above), and `bucket_name`.

2. **Create the tables.**

   ```sh
   npm run db:init
   ```

3. **Create a Turnstile widget.** In the dashboard, go to Turnstile → Add widget and add your domain. Put the site key in `wrangler.jsonc` under `vars.TURNSTILE_SITEKEY`, then store the secret key:

   ```sh
   npx wrangler secret put TURNSTILE_SECRET
   ```

4. **Set the session secret.**

   ```sh
   openssl rand -base64 48 | npx wrangler secret put JWT_SECRET
   ```

5. **Deploy.**

   ```sh
   npm run deploy
   ```

6. **Add a custom domain.** Go to Workers & Pages → your worker → Settings → Domains & Routes. Do this *before* signing up, because passkeys are bound to the hostname they're created on. `workers_dev` is `false` in the config, so the app is only served on your custom domain.

7. **Sign up.** Open your domain and create the admin account.

### Optional

- **Emailed invites.** Without this, `/admin` shows the invite link for you to send yourself.
  1. Onboard your domain under Email Service → Email Sending. Sending to arbitrary addresses requires Workers Paid.
  2. In `wrangler.jsonc`, uncomment `send_email` and set `EMAIL_FROM` (for example `invites@yourdomain`).
  3. Redeploy.
- **CSAM scanning.** Go to your zone → Caching → Configuration → CSAM Scanning Tool.
- **Limits.** Edit the constants at the top of `src/index.ts`.

### Local development

Put the following in `.dev.vars`. The two Turnstile values are Cloudflare's always-pass test keys.

```sh
JWT_SECRET=dev
TURNSTILE_SITEKEY=1x00000000000000000000AA
TURNSTILE_SECRET=1x0000000000000000000000000000000AA
```

Then run:

```sh
npx wrangler d1 execute DB --local --file=schema.sql
npm run dev
```

## License

MIT
