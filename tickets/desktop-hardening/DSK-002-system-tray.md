# DSK-002 — No system tray; closing the window kills the always-on tunnel

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M1 |
| **PRD** | [desktop-app-hardening.md](../../PRD/desktop-app-hardening.md) FR1 |
| **Area** | `src-tauri/src/lib.rs`, `tauri.conf.json` |

## Problem

The app creates no `TrayIcon` and has no window-close handler. Closing the
window terminates the process — and with it the always-on data plane and the
kill-switch/leak-guard teardown fires (`RunEvent::Exit`). For an always-on VPN
this is the opposite of expected behavior: users close the window expecting the
tunnel to keep running in the background. `tray-icon` is already in the compiled
Tauri feature set; only the wiring is missing. This is the desktop-GUI PRD's open
M2 item.

## Acceptance criteria

- [ ] A tray icon that reflects connection state
      (connected/connecting/disconnected).
- [ ] Tray menu: Show/Hide window, Connect/Disconnect, Quit.
- [ ] Closing the window hides to tray (keeps the tunnel up) instead of quitting.
- [ ] Quit performs the full teardown (firewall + DNS restored) via the existing
      `RunEvent::Exit` path.
- [ ] AC1: window-close keeps the tunnel up; Quit tears everything down.

## Implementation notes

- Use Tauri v2 `TrayIconBuilder` + a `Menu`; update the icon/tooltip from the
  same event stream that drives `client-event`.
- Handle `WindowEvent::CloseRequested` to hide instead of close (respect a
  future "quit on close" preference).
- Keep the Exit teardown authoritative so a real quit never strands the firewall.
