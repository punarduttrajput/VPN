# PRD — Coordinator Admin Panel (Angular Rewrite)

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | Cross-cutting ops tooling (not numbered in the 6-phase roadmap) |
| **Status** | Draft |
| **Owner** | punarduttrajput |
| **Last updated** | 2026-07-06 |
| **Depends on** | `ferrum-coordinator`'s `admin-api` feature (PR #57): `GET/POST /api/devices*`, `GET/PUT /api/policy`, OIDC-bearer auth gated on an `"admin"` tag |

---

## 1. Summary

PR #57 added an `admin-api` Cargo feature to `ferrum-coordinator`: an Axum
HTTP server (`--admin-listen`) exposing device list/revoke and ACL-policy
view/edit behind OIDC bearer auth, plus a small hand-rolled vanilla
HTML/CSS/JS panel (`crates/coordinator/admin-ui/`) embedded into the binary
via `include_str!`. It works, but it's a single flat `main.js` with manual
DOM manipulation, string-built HTML, and no structure to grow from. This PRD
replaces that panel with an Angular application — same backend, same three
JSON endpoints, no new API surface — served from the same coordinator
binary, on the same origin, behind the same auth model.

---

## 2. Goals & Non-Goals

### Goals
- G1. Full feature parity with the existing panel: paste-a-token login,
  device list + revoke, ACL policy view/edit (allow-all toggle + rule
  list), refresh, sign-out.
- G2. Replace ad-hoc DOM string-building with Angular components, typed
  models, reactive forms, and a router — so adding the next admin feature
  (e.g. a metrics view) is additive, not a rewrite.
- G3. Ship as a single artifact: `ng build` output embeds into the
  `ferrum-coordinator` binary at compile time, same deployment model as
  today (no separate web server, no runtime file path to manage).
- G4. A real local dev loop (`ng serve` with live reload) that talks to a
  real running coordinator without needing CORS changes in production.
- G5. Preserve the existing security posture: token lives only in
  `sessionStorage`, is never persisted to disk, and a 401/403 from any API
  call bounces the user back to the login screen.

### Non-Goals
- ❌ New coordinator API endpoints or a browser-based OIDC redirect/login
  flow. The coordinator is a JWT *resource server*, not an identity
  provider (see [phase-3-control-plane.md](phase-3-control-plane.md)); an
  operator still obtains a bearer token out-of-band and pastes it in.
- ❌ CORS support for cross-origin production deployment. Dev-time
  cross-origin is solved with the Angular CLI's proxy config (FR6); the
  shipped app is always same-origin with the API.
- ❌ Angular Material or any component library. Port the existing dark
  palette (`admin-ui/styles.css`) as global styles/tokens instead of
  pulling in a UI kit, matching the project's lean-dependency convention
  (see NFR1).
- ❌ Real-time push updates (e.g. wiring into the gRPC `WatchNetworkMap`
  stream). The existing panel is poll-on-demand (load + manual refresh);
  this rewrite keeps that model — a live-streaming admin view is a
  possible future follow-up, not in scope here.
- ❌ Multi-user/role management beyond the existing single `"admin"` tag
  check.

---

## 3. Background & Rationale

The `admin-api` feature (STATUS.md, PR #57) is functionally complete but
was intentionally minimal — a few hundred lines of hand-rolled JS to prove
the Axum endpoints out. As the admin surface grows (metrics, audit log,
per-device candidate/path detail from Phase 4's mesh state), a flat
`main.js` doesn't scale as an engineering surface the way the rest of this
project (typed Rust throughout) does. Angular's component model + typed
HTTP client + reactive forms give the admin panel the same "typed,
structured, testable" property the Rust side already has, without changing
anything about the backend contract this PRD depends on.

---

## 4. Users & Use Case

- **Primary users:** the operator(s) running a Ferrum coordinator — the
  same people who today run `ferrum-coordinator --admin-listen ... ` and
  paste a token into the existing panel. Not end users of the VPN client.
- **Use case:** an operator opens the panel, pastes an OIDC bearer token
  obtained from their IdP, sees the current device roster and can revoke a
  compromised/decommissioned device's key, and can view/edit the tag-based
  ACL policy live (taking effect immediately, reverting on coordinator
  restart per the existing runtime-only semantics) — all without SSHing in
  or hand-editing a policy TOML file.

---

## 5. Functional Requirements

### FR1 — Project Scaffold
- A standalone-components Angular 19 app (no NgModules) at
  `apps/admin-panel/`, alongside the existing `apps/desktop/` convention.
- Strict TypeScript, `HttpClient` (functional interceptors, not the
  deprecated class-based `HttpInterceptor` pattern), the `Router`.
- No Angular Material / no CSS framework — global styles ported from
  `admin-ui/styles.css`.

### FR2 — Auth (Token Login)
- A `/login` route: a form with a single password-type input for the
  bearer token. On submit, store it in `sessionStorage` and navigate to
  `/devices`.
- A functional `HttpInterceptor` attaches `Authorization: Bearer <token>`
  to every `/api/*` request.
- A functional `CanActivate` guard redirects to `/login` when no token is
  present; the interceptor also catches a `401`/`403` response, clears the
  stored token, and redirects to `/login` (matching the existing panel's
  "sign out on auth failure" behavior).
- An explicit "Sign out" action (clears `sessionStorage`, returns to
  `/login`) — same as today.

### FR3 — Device List & Revoke
- `/devices` route: a table of registered devices — name, tunnel IP,
  public key, endpoint, tags — fetched from `GET /api/devices` on load and
  on a manual "Refresh" action.
- A "Revoke" action per row, behind a confirmation prompt, calling
  `POST /api/devices/revoke` with `{ public_key }`; on success, remove the
  row optimistically and re-confirm via a follow-up refresh.
- Typed `Device` model matching the existing JSON shape (`public_key`,
  `name`, `endpoint`, `tunnel_ip`, `tags: string[]`, `candidates: string[]`).

### FR4 — ACL Policy Editor
- `/policy` route: fetches `GET /api/policy` on load.
- A reactive form: an "Allow all" checkbox and a `FormArray` of rules
  (each rule: comma-separated `src` tags, comma-separated `dst` tags, `*`
  wildcard supported as today), with add-rule / remove-rule controls.
- "Save policy" calls `PUT /api/policy` with the edited `Policy` object;
  surfaces a persistent inline note that edits are runtime-only (revert on
  coordinator restart), matching the existing panel's disclosure.

### FR5 — Shell, Navigation & Status Feedback
- A top-level shell (nav between Devices/Policy, Sign-out) shown once
  authenticated; hidden on `/login`.
- A single status-banner mechanism (success/error) shared across
  routes for API responses, replacing the existing panel's ad-hoc banner
  DOM code with one Angular service.

### FR6 — Dev-Time API Access (No Production CORS)
- `apps/admin-panel/proxy.conf.json` proxies `/api/*` (and `/`, for the
  SPA index during dev-server smoke checks) from `ng serve`'s port to a
  locally running coordinator's `--admin-listen` address, so local
  development never needs the coordinator to send CORS headers.
- The production build is always served same-origin by the coordinator
  itself (FR7) — CORS remains explicitly out of scope (Non-Goals).

### FR7 — Embedding Into the Coordinator Binary
- `ng build` output (`apps/admin-panel/dist/admin-panel/browser/`) is
  embedded at Rust compile time via `rust-embed`, gated behind the
  existing `admin-api` Cargo feature (replacing the three `include_str!`
  handlers for `index.html`/`main.js`/`styles.css`).
- Any embedded asset path is served with its correct `Content-Type`
  (via `rust_embed`'s mime-type metadata); any unmatched `GET` that isn't
  under `/api/*` falls back to `index.html` (SPA deep-link/refresh support
  for Angular's `Router`, e.g. a hard refresh on `/policy`).
- `crates/coordinator/admin-ui/` (the old vanilla panel) is deleted once
  parity is verified.

### FR8 — Tests
- Unit tests (Angular's default Jasmine/Karma harness, matching what
  `ng generate` scaffolds) for: the auth interceptor (attaches header,
  clears token + redirects on 401/403), the auth guard, the devices
  service (list/revoke), and the policy form's rule add/remove logic.
- The existing Rust `admin.rs` integration tests (device list/revoke,
  policy round-trip, static-panel-loads-without-a-token) are updated only
  to the extent the static-serving handler changes (FR7); the auth/API
  behavior they cover is unchanged by this PRD.

---

## 6. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR1 | Lean dependencies | Angular + `@angular/*` + the build toolchain only; no Material/UI-kit, no state-management library (the API surface is small enough for services + signals/RxJS) |
| NFR2 | Single-artifact deployment | `cargo build --features admin-api` produces one binary with the panel embedded; no separate static file server or file path to configure at runtime |
| NFR3 | Token security | Bearer token lives only in `sessionStorage` (cleared on tab close), never written to disk, never logged, matching the existing panel |
| NFR4 | Build reproducibility | A documented two-step build (`npm ci && ng build` in `apps/admin-panel/`, then `cargo build -p ferrum-coordinator --features admin-api`) that a maintainer or CI can run without hidden manual steps |
| NFR5 | Accessibility | WCAG AA contrast for status banners and form validation states, carried over from the existing dark palette |
| NFR6 | No regression in auth semantics | Every existing `admin.rs` auth test (missing token → 401, non-admin tag → 403, admin token → 200) continues to pass unmodified |

---

## 7. Architecture

```
   ┌───────────────────────────────────────────────────────────┐
   │  apps/admin-panel/  (Angular 19, standalone components)   │
   │  routes: /login  /devices  /policy                        │
   │  services: AuthService (sessionStorage) · DevicesService · │
   │            PolicyService · StatusService (banner)          │
   │  guards/interceptors: authGuard · authInterceptor          │
   │  dev: proxy.conf.json → coordinator --admin-listen          │
   └───────────────────────────┬─────────────────────────────────┘
                                │ ng build
                                ▼
              apps/admin-panel/dist/admin-panel/browser/
                                │ rust-embed (compile time)
                                ▼
   ┌───────────────────────────────────────────────────────────┐
   │  crates/coordinator/src/admin.rs                           │
   │  GET/POST /api/devices*, GET/PUT /api/policy (unchanged)   │
   │  GET /* → embedded asset or index.html fallback (new)      │
   │  OidcVerifier bearer-token auth, "admin" tag (unchanged)   │
   └───────────────────────────────────────────────────────────┘
```

### Files
- `apps/admin-panel/` (new) — Angular workspace: `src/app/{login,devices,
  policy}/`, `src/app/core/{auth.interceptor.ts,auth.guard.ts,
  devices.service.ts,policy.service.ts,status.service.ts}`,
  `proxy.conf.json`, `angular.json`, `package.json`.
- `crates/coordinator/src/admin.rs` — static-serving handlers rewritten
  around `rust-embed`'s `RustEmbed` derive + SPA-fallback routing; the four
  `/api/*` handlers and the auth-check middleware are unchanged.
- `crates/coordinator/Cargo.toml` — `admin-api` feature gains
  `dep:rust-embed` alongside the existing `dep:axum`.
- `crates/coordinator/admin-ui/` — deleted after parity is verified.
- `apps/admin-panel/README.md` (new) — dev-server + build + embed steps.

### Key dependencies
`@angular/{core,common,router,forms}` 19.x, Angular CLI 19.x (Node 20.20 on
this host caps out below the current `@angular/cli@latest`, which needs
Node ≥22 — 19.x is the newest line that supports Node 20; re-check on an
updated Node per the environment note in [CLAUDE.md](../CLAUDE.md)),
`rust-embed` (new Rust dep, `admin-api`-gated only).

---

## 8. Milestones

1. **M1** — Angular scaffold + auth: `/login`, `authInterceptor`,
   `authGuard`, `proxy.conf.json` wired to a local coordinator.
2. **M2** — Devices feature: list + revoke, parity with the existing panel.
3. **M3** — Policy feature: allow-all + rule `FormArray`, get/put parity.
4. **M4** — Shell/nav + shared status banner (FR5); unit tests (FR8).
5. **M5** — `rust-embed` integration in `admin.rs` (FR7), SPA fallback,
   delete the old vanilla panel, update `admin.rs` integration tests and
   docs (this repo's `STATUS.md`/`CLAUDE.md` admin-api mention).

---

## 9. Acceptance Criteria

- ✅ Every existing panel action (login, list devices, revoke a device,
  view policy, edit + save policy, sign out) works identically against a
  real running coordinator.
- ✅ `ng build` in `apps/admin-panel/` followed by
  `cargo build -p ferrum-coordinator --features admin-api` produces a
  single binary serving the Angular app with no separate file server.
  step.
- ✅ A hard refresh on `/devices` or `/policy` (not just `/`) loads the app
  correctly (SPA fallback works).
- ✅ All pre-existing `admin.rs` auth tests still pass unmodified.
- ✅ `ng serve` against a local coordinator works with zero CORS
  configuration on the Rust side (proxy-based dev loop).

---

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Node 20.20 on this host can't run the current `@angular/cli@latest` (needs Node ≥22) | Scaffold/build fails with the newest CLI | Pin to Angular CLI/framework **19.x**, the newest major that supports Node 20; re-check the newest CLI once Node is upgraded (environment note in CLAUDE.md) |
| `rust-embed` is a new dependency and this host's cargo is offline-pinned globally | `cargo build` fails to resolve it | Use `CARGO_NET_OFFLINE=false cargo build ...` (or rely on the project-level `.cargo/config.toml` override already added for Android, per STATUS.md) to fetch it once |
| SPA fallback routing could accidentally shadow a future `/api/*` path if route ordering is wrong | A new API route silently 200s with `index.html` instead of reaching its handler | Register the fallback as the last route in the Axum router, after all `/api/*` routes, and cover it with a regression test asserting `/api/devices` never falls through to the SPA handler |
| Feature-parity gap discovered late (e.g. a policy-editor edge case in the existing `main.js` not noticed during the rewrite) | Regression for operators relying on the old panel | Keep the old panel's source available in git history for diffing; M2/M3 acceptance is explicitly "identical behavior," not "equivalent-ish" |

---

## 11. Feeds Into

Replaces the panel shipped in PR #57 (`crates/coordinator/admin-ui/`) with
no change to the `admin-api` feature's HTTP contract, so it's a drop-in
upgrade for anyone already running `ferrum-coordinator --admin-listen`.
Sets up a structured base for later admin-surface growth (Phase 6
metrics/observability data, Phase 4 per-peer path/candidate detail) without
another rewrite.

---

## 12. Post-Acceptance Extensions (not a scope change — logged in STATUS.md)

Two follow-on additions landed the same day, after every milestone/acceptance
criterion above was already met, on top of this same structured base rather
than requiring any revision to it:

- **Dashboard overview page** — a new default landing route (`dashboard/`)
  with stat cards (device count, devices awaiting an endpoint, distinct
  policy tags, ACL policy mode) and a recent-devices preview, computed
  client-side from the same `DevicesService`/`PolicyService` calls the
  Devices/Policy routes already make. No new backend endpoint, no HTTP
  contract change — exactly the kind of admin-surface growth §11 anticipated.
- **Light/dark theme toggle** — a new `ThemeService` (`localStorage`-backed,
  defaults to `prefers-color-scheme`) and a toggle button in the shell nav,
  with a light-theme CSS variable override added alongside the existing dark
  palette in `styles.scss`.

Neither changes this PRD's Goals, Functional Requirements, or Acceptance
Criteria (§5/§9 above describe login+devices+policy parity, which is still
exactly what M1–M5 delivered) — they're additive UI features layered on top.
See the 2026-07-06 STATUS.md entries ("Dashboard overview page + light/dark
theme toggle" and the follow-up login-page theme fix) for what shipped and
how it was verified.
