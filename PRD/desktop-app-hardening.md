# PRD — Desktop App Hardening & UX Completion

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) — desktop shell (`apps/desktop/`, Tauri v2) |
| **Phase** | Phase 5 FR4/FR5 (desktop), builds on the desktop-GUI PRD |
| **Status** | Proposed |
| **Owner** | punarduttrajput |
| **Last updated** | 2026-07-19 |
| **Depends on** | `ferrum-client-core` (`data-plane`), `ferrum-helper` (Linux daemon / Windows service), the desktop-GUI PRD ([phase-5-desktop-gui.md](phase-5-desktop-gui.md)) M1 (identity) |

## 1. Summary

The Tauri desktop shell drives the real data plane on both desktop OSes,
enforces the kill-switch (nftables/WFP) and leak protection, runs unprivileged
via `ferrum-helper`, and persists identity in OS secure storage. A
desktop-developer review (2026-07-19) found the **backend is strong but the app
shell around it is incomplete**: there's no system tray (so closing the window
kills the always-on tunnel), no secure auto-update, a `null` Content-Security-
Policy combined with `innerHTML` interpolation of network-supplied peer data
(a DOM-XSS surface), no single-instance guard, and no launch-on-boot. These are
the desktop-GUI PRD's still-open M2–M5 items plus one genuine security gap.

## 2. Goals & Non-Goals

### Goals
- **G1. Background-resident app** — a system tray with status, connect/disconnect,
  and close-to-tray, so the always-on tunnel survives window close.
- **G2. Harden the webview** — a strict CSP and no unescaped injection of
  network-supplied data into the DOM.
- **G3. Secure updates** — signed auto-update so shipped clients can be patched.
- **G4. Single-instance + optional launch-on-boot** for a real always-on
  experience.
- **G5. Feature parity across privilege models** — Windows peer-list forwarding;
  a plan for macOS enforcement (pf + helper).
- **G6. Maintainable, testable frontend.**

### Non-Goals
- ❌ Re-doing the connect/data-plane/kill-switch backend — it's complete; this is
  shell/UX/security-of-the-shell work.
- ❌ macOS `pf` kill-switch **implementation** this cycle — tracked as a scoped
  ticket (needs an Apple host); the PRD only requires a committed plan.
- ❌ A frontend framework migration as a gate — the frontend cleanup (DSK-007)
  is bounded, not a rewrite.

## 3. Background & Rationale

- `tauri.conf.json` sets `"security": { "csp": null }` and `withGlobalTauri:
  true`, and `dist/main.js` builds list items with `innerHTML` from
  `p.public_key`, `p.endpoint`, `p.allowed_ips`, and error `message` strings —
  all of which originate from the coordinator/peers/network, i.e. outside the
  app's trust boundary. Unescaped interpolation into `innerHTML` with no CSP is a
  classic DOM-XSS path; in a Tauri app with global API access the blast radius
  includes the command surface.
- No `TrayIcon` is created and no window-close handler exists, so closing the
  window terminates the process and the tunnel — the opposite of what an
  always-on VPN user expects. `tray-icon` is already compiled into the Tauri
  feature set; only the wiring is missing.
- No `tauri-plugin-updater` — there is no secure update path for a security
  product, so a shipped vulnerability can't be remediated in the field.
- No `tauri-plugin-single-instance` — a second launch spawns a second GUI that
  races the first over the session `Mutex`.
- `get_peers` returns empty under the Windows service model (documented
  follow-up) — a real feature gap on Windows.

## 4. Functional Requirements

### FR1 — System tray & window lifecycle (M1) — [DSK-002]
- A tray icon reflecting connection state (connected/connecting/disconnected).
- Tray menu: Show/Hide, Connect/Disconnect, Quit.
- Window close hides to tray (configurable) instead of quitting; Quit tears the
  tunnel + firewall down (the existing `RunEvent::Exit` path).

### FR2 — Webview hardening (M1) — [DSK-001]
- Set a strict CSP in `tauri.conf.json` (no `unsafe-inline` beyond what's
  required; lock script/style/connect sources).
- Replace `innerHTML` interpolation of peer/error data with `textContent` or an
  escaping helper; audit every `innerHTML` sink in `dist/main.js`.
- Re-evaluate `withGlobalTauri` (scope down if the frontend doesn't need it).

### FR3 — Secure auto-update (M2) — [DSK-003]
- Integrate `tauri-plugin-updater` with signature verification; a manual
  "check for updates" plus a periodic check.
- Document the signing key management and the update-server/manifest setup.

### FR4 — Single instance & launch-on-boot (M2) — [DSK-004, DSK-005]
- `tauri-plugin-single-instance`: a second launch focuses the existing window.
- Optional `tauri-plugin-autostart` toggle for launch-on-boot (off by default).

### FR5 — Windows peer-list parity (M2) — [DSK-006]
- Forward the live peer list over the named pipe so `get_peers` is populated
  under the Windows service model (today only the count is forwarded).

### FR6 — macOS enforcement plan (M3) — [DSK-008]
- A committed design for the macOS `pf` kill-switch + leak guard and the macOS
  privileged helper, reusing the transport-agnostic helper protocol. Design +
  ticket breakdown this cycle; implementation when an Apple host is available.

### FR7 — Frontend maintainability & tests (M3) — [DSK-007]
- Bounded cleanup of `dist/` (shared escaping/DOM helpers, remove duplication);
  add the screenshot-harness checks to CI where possible and a lightweight
  lint/type check.

### FR8 — Window UX polish (M3) — [DSK-009]
- Minimum window size, resize behavior, and an accessibility pass (focus order,
  contrast, labels) — the desktop-GUI PRD's M5 items.

## 5. Milestones

| Milestone | Scope | Tickets |
|---|---|---|
| **M1 — Resident & safe shell** | tray + window lifecycle; CSP + XSS fix | DSK-002, DSK-001 |
| **M2 — Update & multi-instance** | signed auto-update; single-instance + autostart; Windows peer parity | DSK-003, DSK-004, DSK-005, DSK-006 |
| **M3 — Parity & polish** | macOS enforcement plan; frontend cleanup/tests; window UX/a11y | DSK-008, DSK-007, DSK-009 |

## 6. Acceptance Criteria

- **AC1:** Closing the window keeps the tunnel up and leaves a functional tray;
  Quit tears everything down (firewall + DNS restored).
- **AC2:** A peer advertising a crafted public key/endpoint string cannot inject
  markup/script into the peer list or activity log; a CSP is present and
  enforced.
- **AC3:** The app can check for and apply a signature-verified update.
- **AC4:** A second launch focuses the first instance rather than starting a
  competing session.
- **AC5:** On Windows, the peer list is populated in the GUI under the service
  model.
- **AC6:** A committed macOS enforcement design doc + tickets exist.

## 7. Risks & Open Questions

- **Headless dev host:** the Tauri GUI needs a display; verification uses the
  existing headless-Chromium screenshot harness for the frontend and a
  display-equipped machine for the tray/window behaviors.
- **Update infra:** auto-update needs a hosting/signing decision (where manifests
  and signed artifacts live) — a small ops dependency for DSK-003.
- **macOS:** no Apple host in-project; DSK-008 is design-only this cycle.
