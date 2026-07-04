# PRD — Phase 5 Addendum: Desktop GUI / UX

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | 5 of 6 — Client Applications (desktop GUI drill-down) |
| **Status** | Draft |
| **Owner** | punarduttrajput |
| **Last updated** | 2026-07-04 |
| **Depends on** | [phase-5-clients.md](phase-5-clients.md) FR4 (desktop shell), the privileged-helper daemons (Linux/Windows) |

---

## 1. Summary

[phase-5-clients.md](phase-5-clients.md) shipped the *engineering* half of the
desktop app: a Tauri backend that drives `client-core`, real TUN/kill-switch
data planes on Linux and Windows, and privileged helpers so the GUI runs
unprivileged. It has not shipped the *product* half. Today's frontend
(`apps/desktop/dist/`) is a single raw form — every low-level protocol field
(coordinator URL, base64 private key, listen port, transport mode, STUN
server, relay override) is typed in by hand on every connect, there is no
persisted identity, no system tray, no settings screen, and no installer has
ever been built. This PRD defines the actual end-user GUI on top of the
already-working backend, and the packaging needed to hand someone a working
app instead of a dev harness.

---

## 2. Goals & Non-Goals

### Goals
- G1. A user generates or imports a key **once**; it's stored securely and
  never re-typed.
- G2. A default "just connect" experience — one visible action — with every
  protocol-level field (transport, STUN, relay override, listen port) moved
  behind an opt-in **Advanced** section.
- G3. Connection status and per-peer detail (direct vs. relay, endpoint) that
  reads at a glance, not from a raw activity log.
- G4. Kill-switch state and privileged-helper reachability are **visible**,
  not silent fallbacks a user has to infer from an error string.
- G5. System tray presence: connect/disconnect/quit without restoring the
  window; a tray icon that reflects live connection state.
- G6. A settings surface for app-level preferences (start on login, minimize
  to tray, theme) separate from per-connection protocol settings.
- G7. A real, buildable installer (`cargo tauri build`) on at least Linux,
  with Windows/macOS documented as the same pipeline.

### Non-Goals
- ❌ Mobile UI — Android already has its own Compose shell; iOS is deferred
  project-wide (needs an Apple host). Not this doc's concern.
- ❌ Changing the Tauri command surface's underlying protocol logic
  (`connect`/`disconnect`/`dataplane::bring_up`, etc.) — this is a UI/UX and
  packaging layer on top of what already works.
- ❌ SSO / hosted-account login. This project has no auth server; "identity"
  here is a locally generated WireGuard keypair, not a login session.
- ❌ Full silent auto-update (FR9 below is a version-*check* only; a signed
  auto-update channel needs a release/signing pipeline this project doesn't
  have yet — tracked as a explicit follow-up, not blocking this PRD).

---

## 3. Background & Rationale

STATUS.md and CLAUDE.md both track the *backend* as functionally complete for
Phase 5's current scope (Linux + Windows privileged helpers, reliability,
transport selection, NAT-traversal fields). But nobody has ever run the
compiled GUI, and the existing frontend was written as a developer test
harness for exercising the Tauri commands directly — not as something to hand
a non-developer end user. Shipping the backend without this layer means the
project has a working VPN engine and no actual product. This PRD closes that
gap: it is scoped to the presentation layer and the handful of new Tauri
commands (identity persistence, tray) needed to support it, explicitly
*not* touching the data-plane/control-plane logic that's already tested.

---

## 4. Users & Use Case

- **Primary users:** the same end users [phase-5-clients.md](phase-5-clients.md)
  targets — privacy-conscious users who are comfortable installing a VPN app
  but are not developers and should never need to know what a "MASQUE proxy"
  or a "listen port" is unless they go looking for it.
- **Use case:** a user installs Ferrum, generates a key on first launch,
  enters the coordinator address once, and from then on just clicks Connect.
  They can see at a glance whether they're connected, whether their traffic
  is routed directly or through a relay, and whether the kill-switch is
  actually enforced. Power users can still reach every protocol knob behind
  an explicit "Advanced" disclosure.

---

## 5. Functional Requirements

### FR1 — Identity & Profile Management
- Generate a new WireGuard keypair, or import an existing private key, on
  first run.
- Persist the private key + profile metadata (name, coordinator, advertised
  endpoint) via OS-backed secure storage (Keychain / Credential Manager /
  Secret Service — the `keyring` crate), not a plaintext file.
- Subsequent launches load the saved profile automatically; `Connect` no
  longer requires re-entering the private key.
- A visible "reset identity" action for regenerating/replacing the key.

### FR2 — Streamlined Connect Screen
- Default view: coordinator address (pre-filled after first setup), a single
  **Connect/Disconnect** control, and the live status indicator.
- Transport mode, server name, MASQUE proxy, STUN server, relay override, and
  listen port move behind a collapsed **Advanced** section, off by default.
- Form validation errors surface inline, not only in the activity log.

### FR3 — Connection Status & Peer Detail
- A single, unambiguous state indicator (Disconnected / Connecting /
  Connected / Reconnecting / Failed) — already exists, carried over.
- Peer list shows path (direct vs. relay) and endpoint per peer — already
  exists in `PeerDto`/`get_peers`, carried over and made visually clearer
  (e.g. a colored dot for direct vs. relay rather than a text label only).
- Activity log retained underneath as a collapsible troubleshooting aid, not
  the primary surface.

### FR4 — Kill-Switch & Privileged-Helper Visibility
- Keep the existing arm/disarm toggle and the `armed`/`blocking`/`off` states.
- Additionally surface *how* privilege was obtained: "via ferrum-helper" vs.
  "running elevated" vs. "unavailable — install ferrum-helper or run
  elevated" — sourced from the existing `open_tun`/`ask_helper` error paths,
  which today only reach a hidden activity-log line.

### FR5 — System Tray
- A tray icon present whenever the app is running, showing connection state
  (e.g. distinct icon glyphs/colors for disconnected/connected/blocked).
- Tray menu: Connect/Disconnect (context-sensitive), Show window, Quit.
- Closing the window minimizes to tray rather than quitting (configurable in
  Settings, FR6) so an always-on tunnel survives an accidental window close.

### FR6 — Settings Screen
- App-level preferences, persisted separately from the connection profile:
  start on login, minimize-to-tray-on-close, and a theme preference
  (light/dark/system).
- Distinct from the per-connection Advanced section in FR2 — these are
  app behavior, not protocol parameters.

### FR7 — Packaging & Distribution
- `cargo tauri build` produces a real installable artifact (`.deb`/AppImage
  on Linux to start; `.msi` on Windows and `.dmg` on macOS use the same
  `tauri.conf.json` bundle config, already present with icons).
- Document the build/release steps (this doesn't require a hosted release
  pipeline yet — just a reproducible local build a maintainer can run).

### FR8 — Visual Design System
- A small set of consistent design tokens (color, spacing, type scale)
  applied across Connect/Settings/tray so the app doesn't read as a
  collection of separately-styled forms.
- Reuse and extend the existing dark palette in `dist/styles.css` rather than
  introducing a competing visual language.

### FR9 — Update Check (not full auto-update)
- A lightweight "check for updates" action (compares the running version
  against a static, hand-published version endpoint/file) surfaced in
  Settings. Explicitly **not** silent/automatic — see Non-Goals.

---

## 6. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR1 | No new heavy frontend dependency | Stay on vanilla HTML/CSS/JS — no bundler/framework, matching the project's existing minimalism (hand-rolled STUN/OIDC, lean deps elsewhere) |
| NFR2 | Cold window-to-usable time | < 1 s (static assets, no bundler step) |
| NFR3 | Key security | Private key stored only via OS-backed secure storage (`keyring`), never written in plaintext, never re-displayed after entry |
| NFR4 | Visual consistency | Same HTML/CSS renders identically on Windows/Linux/macOS (native window chrome is the only per-OS difference) |
| NFR5 | Accessibility | WCAG AA contrast for all status indicators (disconnected/connected/blocked/etc.) |
| NFR6 | Privacy | No telemetry of any kind beyond the explicit, opt-in update-version check in FR9 |

---

## 7. Architecture

```
   ┌────────────────────────────────────────────────────────────┐
   │  apps/desktop/src-tauri (existing: connect/disconnect/      │
   │  get_status/get_peers/set_kill_switch/kill_switch_enabled)  │
   │                                                              │
   │  + new commands: generate_identity / save_identity /         │
   │    load_identity (keyring-backed) · tray setup · settings    │
   │    get/set (Tauri app-data-dir JSON)                         │
   └───────────────────────────┬──────────────────────────────────┘
                                │ invoke / "client-event"
   ┌───────────────────────────▼──────────────────────────────────┐
   │  apps/desktop/dist (vanilla HTML/CSS/JS, no bundler)          │
   │  screens: Connect (default) · Advanced (collapsed) ·          │
   │  Settings · tray-driven quick actions                        │
   └────────────────────────────────────────────────────────────────┘
```

### Files
- `apps/desktop/src-tauri/src/identity.rs` (new) — `keyring`-backed profile
  persistence + keypair generation, called from new Tauri commands.
- `apps/desktop/src-tauri/src/lib.rs` — tray setup (`run()`), new commands
  wired into `invoke_handler`; existing `connect`/`disconnect`/etc. unchanged.
- `apps/desktop/dist/` — restructured `index.html`/`main.js`/`styles.css`
  into the screens above; still static, still no build step.

### Key dependencies
`keyring` (OS-backed secret storage — Keychain/Credential Manager/Secret
Service), Tauri's tray API (already available in Tauri v2, no new crate).

---

## 8. Milestones

1. **M1** — Identity/profile persistence (`keyring`-backed generate/import)
   + restructured Connect screen with Advanced collapsed by default.
2. **M2** — System tray (state-aware icon, quick actions, minimize-to-tray).
3. **M3** — Settings screen (start on login, minimize-to-tray toggle, theme).
4. **M4** — Packaging: a real `cargo tauri build` installer artifact + a
   documented release process.
5. **M5** — Update-check (FR9) + an accessibility/visual-consistency pass.

---

## 9. Acceptance Criteria

- ✅ A user generates/imports a key once and never re-enters it to connect.
- ✅ The default Connect screen shows no raw protocol fields; every one of
  them is reachable only via the opt-in Advanced section.
- ✅ Kill-switch state and *how* privilege was obtained (helper vs. elevated
  vs. unavailable) are both visible without opening the activity log.
- ✅ The app is fully controllable from the tray (connect/disconnect/quit)
  without restoring the window.
- ✅ `cargo tauri build` produces an installable artifact on Linux.

---

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| No real display in the dev sandbox this was authored in | Can't visually confirm the native window | Verify the static frontend via a headless-browser screenshot during development; a maintainer confirms the real Tauri window on a desktop with a display before release |
| `keyring`'s Linux backend needs a Secret Service provider (gnome-keyring/kwallet) | Fails on minimal/headless Linux | Detect and surface a clear error with a documented fallback rather than silently failing |
| Tray behavior is inconsistent across Linux desktop environments (X11 vs. Wayland, DE-specific tray support) | Tray may not appear on some Linux setups | Treat the tray as progressive enhancement — the window-based Connect/Disconnect flow must work with no tray at all |
| Scope creep into a full design-system rewrite | Delays, over-engineering | NFR1 explicitly caps this at vanilla HTML/CSS extending the existing palette, not a framework migration |

---

## 11. Feeds Into

Closes the "is the desktop app ready?" gap identified against
[phase-5-clients.md](phase-5-clients.md): that PRD's FR4/FR5 (desktop shell,
UX & reliability) are backend-complete; this document is what makes them a
shippable product rather than a developer harness.
