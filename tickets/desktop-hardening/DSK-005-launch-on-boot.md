# DSK-005 — No launch-on-boot for always-on

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M2 |
| **PRD** | [desktop-app-hardening.md](../../PRD/desktop-app-hardening.md) FR4 |
| **Area** | `src-tauri/src/lib.rs`, Settings UI |

## Problem

There's no launch-on-boot option, so an "always-on" desktop VPN doesn't come back
after a reboot until the user manually reopens the app and connects. Mainstream
desktop VPNs offer start-on-login (+ optional auto-connect).

## Acceptance criteria

- [ ] `tauri-plugin-autostart` integrated with a Settings toggle (off by
      default).
- [ ] Optional "auto-connect on launch" using the saved identity/profile.
- [ ] Works on Linux + Windows; macOS deferred with DSK-008.

## Implementation notes

- Pair with the tray (DSK-002) so a boot launch can start hidden-to-tray and
  auto-connect without stealing focus.
- Respect the kill-switch/leak-guard ordering — auto-connect must go through the
  same supervised bring-up, not a shortcut.
