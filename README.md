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
| `MAGIC_LINK_TRANSPORT` | `resend` | `resend` sends sign-in emails through Resend. `log` sends nothing and shows the link and code on the page; it is accepted only when `RELAY_ORIGIN` is loopback (`localhost`, `127.0.0.1`, `[::1]`), so staging and production always use Resend |
| `RESEND_API_KEY` | unset | Required with `resend` (so `serve` fails at boot without it, unless local `log`). Never logged |
| `MAGIC_LINK_FROM` | unset | Required with `resend`: sender on a Resend-verified domain, e.g. `Vekrel <signin@<domain>>` |
| `RESEND_BASE_URL` | `https://api.resend.com` | Override for tests |
| `TRUST_PROXY_IP_HEADER` | `false` | `true`: rate limits key on `X-Real-IP` (falling back to the socket peer). Set it on Railway only after the staging check (plan 6A Task 2) shows the edge overwrites a client-sent `X-Real-IP`; until then the peer address is used |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | unset | GitHub OAuth app (callback `<RELAY_ORIGIN>/auth/github/callback`). Both or neither; unset turns "Continue with GitHub" into a "not set up" page. Tests override `GITHUB_AUTHORIZE_URL`, `GITHUB_TOKEN_URL`, `GITHUB_API_URL` |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | unset | Google OAuth client, Web application (redirect `<RELAY_ORIGIN>/auth/google/callback`, scopes `openid email profile`). Both or neither. Tests override `GOOGLE_AUTHORIZE_URL`, `GOOGLE_TOKEN_URL`, `GOOGLE_JWKS_URL` |
| `DATABASE_URL` | unset | Postgres URL, required by `serve`. Migrations in `migrations/` apply at boot |
| `RELAY_MINT_PRIVATE_KEY` | unset | Required by `serve`. Ed25519 PKCS#8 PEM (`keygen`, first block; literal `\n` allowed). Signs link challenges, relay DPoP tokens and requests to machines; machines pin its public key at link time, so rotating it means relinking every machine |
| `RELAY_TUNNEL_ZONE_NAME` | unset | Zone holding managed tunnel hosts (T3 `managedEndpointBaseDomain`). Unset: connect and status refuse managed endpoints (`managed_endpoint_base_domain_not_configured`) |
| `APNS_TEAM_ID`, `APNS_KEY_ID`, `APNS_BUNDLE_ID`, `APNS_PRIVATE_KEY`, `APNS_ENVIRONMENT` | unset | APNs (iOS alerts and Live Activities): Team ID, the auth key's Key ID, the app's bundle id, the `.p8` (PKCS#8 PEM, literal `\n` allowed, never logged) and `sandbox` or `production`. All or none; none means no iOS push is queued (T3 with APNs off). A device's registered bundle id and APS environment win per device |
| `APNS_BUNDLE_IDS` | `APNS_BUNDLE_ID` | Comma list of bundle ids a device may register as its APNs topic (dev/preview/prod builds); others get 400 and stored ones are never used (Vekrel; T3 takes any) |
| `FCM_PACKAGE_NAMES` | unset | Required with `FCM_SERVICE_ACCOUNT`: comma list of Android packages a device may register (Vekrel; T3 takes any) |
| `FCM_SERVICE_ACCOUNT` | unset | Firebase service-account JSON (FCM v1). Unset: Android pushes answer `ok: false` (T3) |
| `APNS_ENABLED`, `FCM_ENABLED` | `true` | `false` pauses delivery: jobs keep queueing in `relay_push_jobs` and go out when switched back on (APNs jobs expire 10 min after queueing, FCM 5 min, as in T3) |
| `APNS_API_BASE`, `FCM_API_BASE`, `FCM_TOKEN_URL` | Apple's hosts, `https://fcm.googleapis.com`, `https://oauth2.googleapis.com/token` | Overrides for tests |
| `RELAY_STAGE` | unset | Namespace of tunnel hosts and names (`<stage>-<digest>.<zone>`, `vekrelrelay-managedendpoint-<stage>-<digest>`), e.g. `prod`, `staging`. Managed tunnels need it and the zone; the reaper only sees its own stage |
| `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_TUNNEL_ZONE_ID`, `CLOUDFLARE_API_TOKEN` | unset | All or none. Token needs *Account: Cloudflare Tunnel: Edit* and *Zone: DNS: Edit* on the tunnel zone; never logged. Unset: managed links answer 503 `managed_endpoint_not_configured`. Tests set `CLOUDFLARE_API_BASE` (default `https://api.cloudflare.com/client/v4`) to a fake |
| `RELAY_TUNNEL_CLEANUP_MODE`, `RELAY_LEGACY_TUNNEL_CLEANUP_MODE` | `off` | `off`, `dry-run` (logs what it would delete) or `enabled`. Every 5 min one replica (advisory lock) prunes expired relay state and, with Cloudflare set, deletes this stage's tunnels idle past T3's grace (5 min down, 60 min never connected; legacy: machines without recovery, 7 days or `RELAY_LEGACY_TUNNEL_GRACE_MINUTES` off `prod`). Run `dry-run` first |
| `RUST_LOG` | `info` | Log filter; logs are JSON on stdout |

## Run locally

```bash
MAGIC_LINK_TRANSPORT=log cargo run -- serve   # PORT=8080; log transport: sign-in links on the page
scripts/smoke.sh http://127.0.0.1:8080   # GET /health -> {"ok":true,"service":"relay"}
cargo run -- keygen                      # fresh Ed25519 key: PKCS#8 PEM, then the public JWK
cargo run -- keygen --auth-kid 2026-10   # one AUTH_SIGNING_KEYS entry (status next; set active for the first key)
```

## Accounts

`GET /oauth/authorize` (PKCE S256 only, exact redirect URIs per client in `src/accounts/clients.rs`) shows the sign-in page; `POST /oauth/token` handles `authorization_code` and `refresh_token` (rotated on every use; a reused token revokes its whole family); `POST /oauth/revoke` signs out. The web client gets its refresh token only as an `HttpOnly; Secure; SameSite=Lax; Path=/oauth` cookie. Email sign-in: `POST /auth/email` sends a link and a 6-character code (15 min, single use, stored hashed; 3 sends per email per 15 min, 20 per IP per hour (IP: the socket peer, or `X-Real-IP` with `TRUST_PROXY_IP_HEADER=true`), 200 per hour in total). The reply is the same for every address; the sign-up rules apply after the link is opened. The link signs in only the browser that asked; elsewhere it shows the code to type into the waiting page (`POST /auth/email/code`, 5 tries). GitHub signs in with the account's primary verified email; Google with a verified ID token (`email_verified`, nonce, audience, JWKS signature). An email links a new sign-in method to an existing account only when the provider is authoritative for it (GitHub; Google for Gmail or a matching Workspace `hd`); otherwise the page says to use the usual sign-in.

Device code (RFC 8628, `vekrel-engine connect --headless`, client `vekrel-cli` only): `POST /oauth/device_authorization` returns a device code (stored hashed) and an 8-letter user code (`BCDF-GHJK`, consonants only), valid 10 min, poll every 5 s. The person opens `/device`, enters the code, signs in on the normal page (same sign-up rules), then approves or denies explicitly. The CLI polls `/oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code` and gets `authorization_pending`, `slow_down` (interval +5 s), `expired_token`, `access_denied`, or tokens once. One account can look up 10 codes per 15 min.

Admin (production: `railway run vekrel-relay admin ...`; needs `DATABASE_URL`). `admin tunnel-test` creates one throwaway tunnel and CNAME with the configured Cloudflare token, checks both, and deletes them:

```bash
vekrel-relay admin allow someone@example.com [--note "why"]
vekrel-relay admin disallow someone@example.com
vekrel-relay admin list-allowed
vekrel-relay admin disable-user someone@example.com   # refuses sign-in, revokes refresh tokens, machine links and credentials
vekrel-relay admin enable-user someone@example.com
```

Checks: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo sqlx prepare --check` (CI runs the same). Tests need a Postgres in `DATABASE_URL` (e.g. `postgres://localhost/postgres`); each test creates and drops its own database.

Protocol vectors: `tests/fixtures/relay/{jws,dpop}.json` hold TEST-ONLY tokens and keys with the verdicts Vekrel-Shared's `relayJwt.ts` and `dpop.ts` give them. Regenerate from a Vekrel-Engine checkout with `node apps/server/test/relay-conformance/gen-vectors.ts <out-dir>` (DPoP keys are fresh each run).

## Machines

Routes follow Vekrel-Shared `contracts/src/relay.ts` and T3's `infra/relay/src/http/Api.ts`. Client (account access token as `Bearer`): `GET /v1/machines`, `GET /v1/client/devices`, `GET /v2/client/devices`, `POST /v1/client/machine-link-challenges`, `POST /v1/client/machine-links`, `DELETE /v1/client/machine-links/:machineId[/tunnel]`. Token exchange: `POST /v1/client/dpop-token` (form, account token as `subject_token`, DPoP proof) returns a 30-minute relay DPoP token. DPoP client: `POST /v1/machines/:machineId/connect` and `/status` (the relay signs a request, POSTs it to the machine's `/api/vekrel-connect/*` over its tunnel, and checks the signed answer). Machine (machine credential as `Bearer`): `POST /v1/machines/:machineId/tunnel/recovery`, `/tunnel`, `/link-preferences`. A machine credential works only while an active link proven by the same machine key exists and that link's user is not disabled. Managed tunnels need the Cloudflare provider (Task 10); until then a managed link answers 503 `managed_endpoint_not_configured` and publish-only links work. DPoP `htu` is checked against `RELAY_ORIGIN` plus the request path.

## Push

`POST /v1/machines/:id/threads/:tid/agent-activity` (machine credential + machine-signed proof) stores the thread's state and queues one `relay_push_jobs` row per delivery in the same transaction; `/v1/mobile/devices`, `/v1/mobile/live-activities` and `/v1/mobile/agent-activity` (relay DPoP token with `mobile:registration`) register phones. A worker in each `serve` process claims due jobs with `FOR UPDATE SKIP LOCKED` for 2 minutes; a job whose worker died is claimed again after that and re-sent with the same `apns-id`. Failures retry 30 s apart, six deliveries in all, then the job is `dead` (T3's queue settings). APNs 410 / bad-token and FCM `UNREGISTERED` clear the device's token. Payloads are T3's: ids, phases, statuses and the project, thread and model titles the machine publishes; never message content. `vekrel-relay admin push-test <email>` sends one alert to each registered phone and prints APNs/FCM's answers.

## Deploy

Railway builds the `Dockerfile` (distroless runtime) and health-checks `/health` (`railway.json`). Staging deploys from `main`. Set `RELAY_ORIGIN`, `DATABASE_URL` (a reference to the Railway Postgres service), `AUTH_SIGNING_KEYS`, `RELAY_MINT_PRIVATE_KEY`, `RESEND_API_KEY` and `MAGIC_LINK_FROM` as Railway variables (staging too: the log transport is local only); Railway sets `PORT`. Then run `scripts/smoke.sh https://<relay host>`.

## License

AGPL-3.0, see LICENSE.
