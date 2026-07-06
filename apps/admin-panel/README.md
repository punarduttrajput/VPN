# Ferrum Admin Panel

Angular 19 frontend for `ferrum-coordinator`'s `admin-api` feature: device
list/revoke and live ACL-policy view/edit. See
[PRD/admin-panel-angular.md](../../PRD/admin-panel-angular.md) for the design
and [crates/coordinator/src/admin.rs](../../crates/coordinator/src/admin.rs)
for the backend it talks to.

No new API surface — this is a drop-in replacement for the old vanilla
HTML/CSS/JS panel (`crates/coordinator/admin-ui/`, since removed), talking to
the same four endpoints:

- `GET /api/devices`
- `POST /api/devices/revoke`
- `GET /api/policy`
- `PUT /api/policy`

All gated on `Authorization: Bearer <OIDC JWT>` with a verified `admin` tag —
this app never runs an OAuth redirect flow itself; an operator pastes a token
obtained elsewhere.

## Local development

The dev server needs a real coordinator running with `--admin-listen` (and
the OIDC flags it requires — see the crate-level docs). Point the proxy at
it and run:

```bash
npm ci
npm start   # ng serve --proxy-config proxy.conf.json
```

`proxy.conf.json` forwards `/api/*` to `http://127.0.0.1:8080` by default —
edit it if your coordinator's `--admin-listen` address differs. This avoids
needing any CORS configuration on the Rust side; the shipped app is always
served same-origin (see below).

## Unit tests

```bash
npm test -- --watch=false --browsers=ChromeHeadless
```

## Building and embedding into the coordinator

The coordinator embeds this app's build output at Rust compile time via
`rust-embed` (see `admin.rs`'s `AdminUi` struct) — there's no runtime file
path to configure and no separate web server to run in production.

```bash
# 1. Build the Angular app.
cd apps/admin-panel
npm ci
ng build   # -> apps/admin-panel/dist/admin-panel/browser/

# 2. Build the coordinator with the panel embedded.
cd ../..
cargo build -p ferrum-coordinator --features admin-api
```

Step 1 must run before step 2 — `rust-embed`'s `#[folder = "..."]` attribute
resolves at compile time, so `cargo build --features admin-api` fails if
`dist/admin-panel/browser/` doesn't exist yet.

Run the result with `--admin-listen <ip:port>` plus the three `--oidc-*`
flags (the admin API has no other auth mode) and open `http://<ip:port>/` —
the coordinator serves the built app directly, including a SPA fallback to
`index.html` for a hard refresh on `/devices` or `/policy`.
