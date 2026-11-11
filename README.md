<img width="360" height="360" alt="image" src="https://github.com/user-attachments/assets/4079b92b-69d7-48ce-a49b-a75a8ff4e313" />

# enderchest

self host your own pastebin/privnote/fileshare/cdn on Cloudflare. 
or just use it here [enderchest.sh](https://enderchest.sh). uploads last 10 minutes, unless you have an account (accounts are invite only).

i often need to quickly paste stuff from computer to computer. i think its just easiest to go to a website and enter a short pin.

it's secure: optional end-to-end encryption with AES-256-GCM in the browser, with the key in the link's `#fragment`. similar to privnote, 1password sharing, doppler secret sharing, and [vanish.so](https://vanish.so)
it's got basic protection: rate limiting and Turnstile, guest users are capped at 10 MB uploads that last 10 min.
it's tiny: one Worker, D1, R2, the Cache API.

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
