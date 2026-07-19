# DSK-004 — No single-instance guard; second launch races the session

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M2 |
| **PRD** | [desktop-app-hardening.md](../../PRD/desktop-app-hardening.md) FR4 |
| **Area** | `src-tauri/src/lib.rs`, `Cargo.toml` |

## Problem

Nothing prevents a second instance of the app. A second launch spawns another GUI
with its own `AppState`/`FerrumClient`, racing the first over the session
`Mutex`, the helper socket/pipe, and the OS firewall rules — leading to
confusing state and possible double-engage/teardown of the kill-switch.

## Acceptance criteria

- [ ] `tauri-plugin-single-instance` integrated: a second launch focuses/raises
      the existing window and exits.
- [ ] No second `AppState`/session is created.
- [ ] AC4: launching twice focuses the first instance.

## Implementation notes

- Register the plugin early in the builder; on the second-instance callback,
  unhide/focus the main window (coordinate with DSK-002's hide-to-tray).
- Verify on each OS (Linux single-instance uses a socket; Windows a named mutex).
