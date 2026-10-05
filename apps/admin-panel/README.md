# Ferrum Admin Panel

Angular 19 frontend for `ferrum-coordinator`'s `admin-api` feature. See
[PRD/admin-panel-angular.md](../../PRD/admin-panel-angular.md) for the design
(§12 covers the two additions below, which landed after that PRD's
acceptance criteria were already met) and
[crates/coordinator/src/admin.rs](../../crates/coordinator/src/admin.rs) for
the backend it talks to.

## Routes

- **`/dashboard`** (default landing page) — stat cards (device count,
  devices awaiting an endpoint, distinct policy tags in use, ACL policy
  mode) and a recent-devices preview. Computed client-side from the same
  two endpoints below; no dedicated dashboard endpoint exists.
- **`/devices`** — device list/revoke.
- **`/policy`** — live ACL-policy view/edit.
- **`/login`** — paste-a-token screen (see Auth below).

A light/dark theme toggle (sun/moon button in the nav, `ThemeService`) is
available on every authenticated route — persisted to `localStorage`,
defaulting to the OS/browser's `prefers-color-scheme`.

## Backend contract

No new API surface beyond the original vanilla panel it replaced
(`crates/coordinator/admin-ui/`, since removed) — the Dashboard is client-side
aggregation over the same two read endpoints, not a new one:

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

CI runs them in the Admin panel workflow
(`.github/workflows/admin-panel.yml`) with the `ChromeHeadlessCI` launcher from
`karma.conf.js` (`--no-sandbox`, which Ubuntu 24.04 runners need), then builds
the panel and runs the coordinator's `admin-api` tests and clippy against the
embedded build. It runs when anything under `apps/admin-panel/` or
`crates/coordinator/src/admin.rs` changes.

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
flags (the admin API has no other auth mode) and open `http://<ip:port>/`.
The pasted token must be for the admin API's own audience (`--admin-audience`,
default `<--oidc-audience>-admin`) and carry `admin` in its `tags` claim, so a
device token never works here (SEC-014). The coordinator serves the built app
directly —
the coordinator serves the built app directly, including a SPA fallback to
`index.html` for a hard refresh on `/dashboard`, `/devices`, or `/policy`.
