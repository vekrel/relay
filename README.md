<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/brand/logo-horizontal-on-dark.png">
    <img src=".github/brand/logo-horizontal-on-light.png" alt="Vekrel" width="360">
  </picture>
</p>

# Vekrel-Relay

The hosted Vekrel relay, in Rust (axum). It links machines to accounts, provisions their Cloudflare tunnels, mints one-time connect credentials, forwards webhooks, delivers push, and runs Vekrel accounts (GitHub, Google, magic link, device code). It is a broker, not a byte pipe: once a machine is linked, clients talk to its tunnel directly. Highly inspired by [T3 Code](https://github.com/pingdotgg/t3code) (MIT, see NOTICE); its relay is the behavioural reference.

## Config

Environment variables only:

| Variable | Default | Meaning |
|---|---|---|
| `PORT` | `8080` | Listen port (all interfaces) |
| `RELAY_ORIGIN` | `http://localhost:$PORT` | Public origin of the relay, no trailing slash. Account tokens use it as `iss` |
| `AUTH_SIGNING_KEYS` | unset | Required by `serve`. JSON list `[{kid, private_jwk, status: next\|active\|retired}]`, exactly one `active`. Rotation: add a `next` key, wait 24 h, make it `active` and the old one `retired`, drop the retired one after 24 h. `/.well-known/jwks.json` publishes all listed keys |
| `SIGNUP_MODE` | `allowlist` | `allowlist`: only emails added with `admin allow` can create an account; `open`: anyone can. Existing accounts sign in either way |
| `WEB_ORIGINS` | unset | Comma-separated web app origins (`https://app.<domain>`, `http://localhost:5733` in dev). Each one gets the `vekrel-web` redirect `<origin>/auth/callback` and is the only CORS origin for `/oauth/token` and `/oauth/revoke` |
| `MAGIC_LINK_TRANSPORT` | `log` | `resend` sends sign-in emails through Resend; `log` sends nothing and shows the link and code on the page (dev and staging only; refused when `RAILWAY_ENVIRONMENT_NAME=production`) |
| `RESEND_API_KEY` | unset | Required with `resend`. Never logged |
| `MAGIC_LINK_FROM` | unset | Required with `resend`: sender on a Resend-verified domain, e.g. `Vekrel <signin@<domain>>` |
| `RESEND_BASE_URL` | `https://api.resend.com` | Override for tests |
| `DATABASE_URL` | unset | Postgres URL, required by `serve`. Migrations in `migrations/` apply at boot |
| `RUST_LOG` | `info` | Log filter; logs are JSON on stdout |

## Run locally

```bash
cargo run -- serve                       # PORT=8080 by default
scripts/smoke.sh http://127.0.0.1:8080   # GET /health -> {"ok":true,"service":"relay"}
cargo run -- keygen                      # fresh Ed25519 key: PKCS#8 PEM, then the public JWK
cargo run -- keygen --auth-kid 2026-10   # one AUTH_SIGNING_KEYS entry (status next; set active for the first key)
```

## Accounts

`GET /oauth/authorize` (PKCE S256 only, exact redirect URIs per client in `src/accounts/clients.rs`) shows the sign-in page; `POST /oauth/token` handles `authorization_code` and `refresh_token` (rotated on every use; a reused token revokes its whole family); `POST /oauth/revoke` signs out. The web client gets its refresh token only as an `HttpOnly; Secure; SameSite=Lax; Path=/oauth` cookie. Email sign-in: `POST /auth/email` sends a link and a 6-character code (15 min, single use, stored hashed; 3 sends per email per 15 min, 20 per IP per hour (IP from `X-Real-IP`, else the socket peer), 200 per hour in total). The reply is the same for every address; the sign-up rules apply after the link is opened. The link signs in only the browser that asked; elsewhere it shows the code to type into the waiting page (`POST /auth/email/code`, 5 tries). GitHub, Google and device code arrive in later tasks.

Device code (RFC 8628, `vekrel-engine connect --headless`, client `vekrel-cli` only): `POST /oauth/device_authorization` returns a device code (stored hashed) and an 8-letter user code (`BCDF-GHJK`, consonants only), valid 10 min, poll every 5 s. The person opens `/device`, enters the code, signs in on the normal page (same sign-up rules), then approves or denies explicitly. The CLI polls `/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` and gets `authorization_pending`, `slow_down` (interval +5 s), `expired_token`, `access_denied`, or tokens once. One account can look up 10 codes per 15 min.

Admin (production: `railway run vekrel-relay admin ...`; needs `DATABASE_URL`):

```bash
vekrel-relay admin allow someone@example.com [--note "why"]
vekrel-relay admin disallow someone@example.com
vekrel-relay admin list-allowed
vekrel-relay admin disable-user someone@example.com   # refuses sign-in, revokes refresh tokens, machine links and credentials
vekrel-relay admin enable-user someone@example.com
```

Checks: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo sqlx prepare --check` (CI runs the same). Tests need a Postgres in `DATABASE_URL` (e.g. `postgres://localhost/postgres`); each test creates and drops its own database.

Protocol vectors: `tests/fixtures/relay/{jws,dpop}.json` hold TEST-ONLY tokens and keys with the verdicts Vekrel-Shared's `relayJwt.ts` and `dpop.ts` give them. Regenerate from a Vekrel-Engine checkout with `node apps/server/test/relay-conformance/gen-vectors.ts <out-dir>` (DPoP keys are fresh each run).

## Deploy

Railway builds the `Dockerfile` (distroless runtime) and health-checks `/health` (`railway.json`). Staging deploys from `main`. Set `RELAY_ORIGIN` and `DATABASE_URL` (a reference to the Railway Postgres service) as Railway variables; Railway sets `PORT`. Then run `scripts/smoke.sh https://<relay host>`.

## License

AGPL-3.0, see LICENSE.
