# Skybound

Skybound is a play-money airplane crash game with email-verified accounts. The game is served only to signed-in, verified users. Passwords are stored as salted scrypt hashes, sessions and account data are stored in SQLite, and password resets invalidate existing sessions.

## Legal and launch status

The Terms of Use, Privacy Notice, and Responsible Play page in `public/policies/` are **draft templates** for a Kenya-oriented play-money demo, not legal advice or protection from claims. They contain operator, support, privacy-contact, processor, and transfer placeholders. Replace them with accurate information and have a Kenyan lawyer review the actual product, data flows, hosting, email provider, age controls, and applicable laws. The applicable legal and licensing position depends on the final service; no disclaimer guarantees that the operator cannot be sued.

Sign-up requires users to declare that they are 18 or older and accept the published Terms and Privacy Notice. This is a self-declaration, not independent age verification. The backend stores the accepted policy versions and confirmation time. Production startup is blocked while policy placeholders remain or until the operator explicitly sets `LEGAL_REVIEW_APPROVED=true` after completing appropriate local review. That flag is an operator acknowledgement, not a certification.

The current game is browser-side demo logic: balances and results can be changed by the user, are not saved as a server ledger, and are not independently audited. The project does not currently process deposits, money stakes, withdrawals, or prizes. Do not offer real-money gambling or rewards without a separate product, security, licensing, privacy, consumer-protection, and legal review.

## Requirements

- Node.js 20 or newer
- SMTP is optional for local development; configure it to deliver verification and password-reset emails

## Run locally on Windows

1. Install Node.js 20 or newer.
2. From this folder, install the app packages:

   ```powershell
   npm install
   ```

3. Start the server and open the local URL:

   ```powershell
   npm start
   ```

   Browse to `http://localhost:3000`. Do not open `index.html` as a `file:` URL; authentication is enforced by the server.

4. Open **Create account**, use a password of at least 12 characters, confirm you are 18 or older, and accept the Terms and Privacy Notice. Without SMTP configured, local development displays a verification link on the page; open it, then sign in. This local verification-link fallback is disabled in production.

The app creates `data/skybound.sqlite` automatically; account data and expiring sessions are stored in that database. Keep the `data` folder private and back it up securely. `.env`, databases, and installed packages are excluded from Git.

### Optional local email setup

To test email delivery instead of local verification links, create `.env` from `.env.example` and configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, and `EMAIL_FROM`. For port 587, use `SMTP_SECURE=false`; for port 465, use `SMTP_SECURE=true`. Set a random `SESSION_SECRET` of at least 32 characters. `PUBLIC_BASE_URL` must match the URL used to open the game, such as `http://localhost:3000`. Restart the server after changing `.env`.

When running locally without a configured `SESSION_SECRET`, the server creates a temporary random secret. Sessions are invalidated when the server restarts. Production never uses this fallback.

## Production notes

- Use HTTPS and set `NODE_ENV=production`, `PUBLIC_BASE_URL` to the HTTPS origin, and a unique, randomly generated `SESSION_SECRET`.
- If TLS terminates at a trusted reverse proxy, set `TRUST_PROXY=true` so secure session cookies work. Do not enable this behind an untrusted proxy.
- Keep SMTP credentials and the session secret out of source control and logs.
- Passwords must be 12–128 characters. Verification and reset links expire after 24 hours; auth endpoints are rate limited.
- Balances and rounds remain demo-only client state. These accounts do not enable deposits, withdrawals, or real-money wagering.
- Do not set `LEGAL_REVIEW_APPROVED=true` in production until the policies have been completed and reviewed by qualified local counsel. Production also refuses to start while the visible draft markers or `{{...}}` placeholders remain in the policy pages.
