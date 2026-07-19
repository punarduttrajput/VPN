# DSK-006 — Windows peer list not forwarded (get_peers empty)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M2 |
| **PRD** | [desktop-app-hardening.md](../../PRD/desktop-app-hardening.md) FR5 |
| **Area** | `src-tauri/src/{service.rs,ipc.rs,helper_client.rs,lib.rs}` |

## Problem

Under the Windows service privilege model the live connection (and its peer
detail) lives in the helper service. The GUI's `get_peers`
(`lib.rs:481–494`) returns the in-process facade's list, which is **empty** on
Windows — only the peer *count* is forwarded over the pipe (a `peers` UI event).
So the Windows Peers view shows a count but no peer rows, unlike Linux/macOS.
This is called out as a follow-up in the code.

## Acceptance criteria

- [ ] The live peer list (public key, endpoint, allowed IPs, path) is forwarded
      from the service to the GUI over the named pipe.
- [ ] `get_peers` (or an event-fed cache) returns the real list on Windows.
- [ ] AC5: the Windows GUI shows populated peer rows.

## Implementation notes

- Extend `ipc::Event` with a peers-detail variant (or a periodic snapshot), and
  cache it in `AppState` the way `status` is cached from events.
- Mind DSK-001: peer fields rendered in the webview must be escaped there too.
- Keep the pipe message aggregate/detail split reasonable — don't flood on every
  minor change.
