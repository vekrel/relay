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
| `DATABASE_URL` | unset | Postgres URL, required by `serve`. Migrations in `migrations/` apply at boot |
| `RUST_LOG` | `info` | Log filter; logs are JSON on stdout |

## Run locally

```bash
cargo run -- serve                       # PORT=8080 by default
scripts/smoke.sh http://127.0.0.1:8080   # GET /health -> {"ok":true,"service":"relay"}
cargo run -- keygen                      # fresh Ed25519 key: PKCS#8 PEM, then the public JWK
cargo run -- keygen --auth-kid 2026-10   # one AUTH_SIGNING_KEYS entry (status next; set active for the first key)
```

Checks: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo sqlx prepare --check` (CI runs the same). Tests need a Postgres in `DATABASE_URL` (e.g. `postgres://localhost/postgres`); each test creates and drops its own database.

Protocol vectors: `tests/fixtures/relay/{jws,dpop}.json` hold TEST-ONLY tokens and keys with the verdicts Vekrel-Shared's `relayJwt.ts` and `dpop.ts` give them. Regenerate from a Vekrel-Engine checkout with `node apps/server/test/relay-conformance/gen-vectors.ts <out-dir>` (DPoP keys are fresh each run).

## Deploy

Railway builds the `Dockerfile` (distroless runtime) and health-checks `/health` (`railway.json`). Staging deploys from `main`. Set `RELAY_ORIGIN` and `DATABASE_URL` (a reference to the Railway Postgres service) as Railway variables; Railway sets `PORT`. Then run `scripts/smoke.sh https://<relay host>`.

## License

AGPL-3.0, see LICENSE.
