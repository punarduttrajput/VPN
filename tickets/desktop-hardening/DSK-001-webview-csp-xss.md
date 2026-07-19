# DSK-001 — `csp: null` + `innerHTML` of network data → DOM-XSS

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M1 |
| **PRD** | [desktop-app-hardening.md](../../PRD/desktop-app-hardening.md) FR2 |
| **Area** | `src-tauri/tauri.conf.json`, `dist/main.js` |

## Problem

`tauri.conf.json` sets `"security": { "csp": null }` (no Content-Security-Policy)
and `withGlobalTauri: true`. `dist/main.js` then builds DOM with `innerHTML`
from network-supplied, cross-trust-boundary data:

- `refreshPeers` (`main.js:194–198`): `p.public_key`, `p.endpoint`,
  `p.allowed_ips`, and `p.path` interpolated straight into `innerHTML`.
- `log` (`main.js:175–181`): the error/event `message` interpolated into
  `innerHTML`.

Peer fields and error strings come from the coordinator / other peers / the
network — outside the app's control. Unescaped interpolation into `innerHTML`
with **no CSP** is a DOM-XSS path; in a Tauri app exposing the global API to the
webview, script execution in the webview can reach the command surface.

## Acceptance criteria

- [ ] A strict CSP is set in `tauri.conf.json` and enforced (script/style/connect
      sources locked; no blanket `unsafe-inline` for scripts).
- [ ] No network-supplied value is injected via `innerHTML`; use `textContent`
      or a vetted escaping helper. Every `innerHTML` sink in `dist/` is audited.
- [ ] `withGlobalTauri` is re-evaluated and scoped down if not required.
- [ ] AC2: a crafted peer public key/endpoint cannot inject markup/script into
      the peer list or activity log.

## Implementation notes

- Static markers (the `path-dot direct/relay` class, timestamps) can stay in
  markup; only the **data** must be set via `textContent` on created nodes.
- Test with a peer whose `public_key`/`endpoint` contains
  `<img src=x onerror=…>` and an error message containing markup — confirm it
  renders as inert text.
- A CSP may require moving any inline handlers; `main.js` is already external, so
  this should be low-friction.
