# SEC-005 — Helper socket: group-only gate + world-writable fallback

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M2 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR5 |
| **Area** | `ferrum-helper` (`crates/helper/src/unix.rs`) |

## Problem

`secure_socket` (`crates/helper/src/unix.rs` ~L222–266) gates the root daemon's
Unix socket by **group membership** (mode 0660) and **falls back to a
world-accessible 0666 socket with only a warning** if the group doesn't exist.
Any process in the `ferrum` group — and *any* local process at all under the
0666 fallback — can ask the root daemon to open TUN devices and rewrite firewall
rules. There is no per-request caller credential check (`SO_PEERCRED`) beyond
the message type.

This is a local privilege-escalation footgun: the 0666 fallback silently
removes the trust boundary the daemon exists to enforce.

## Acceptance criteria

- [x] The daemon verifies the connecting peer via `SO_PEERCRED`
      (uid/gid/pid) and rejects callers outside an allow-list.
      *(root, `--group` members, `--allow-uid`; see `AccessPolicy`.)*
- [x] **Fail closed:** if the configured group does not exist, the daemon
      refuses to start (or binds owner-only 0600) — the 0666 fallback is
      removed. *(Refuses to start; `chown`/`chmod` failure is fatal too.)*
- [x] Per-connection request quota to bound abuse of a compromised allowed
      caller. *(One request per connection + per-uid token bucket, in-flight
      cap, I/O timeouts, 64 KiB request cap.)*
- [x] Test: a disallowed uid/gid connection is refused; the missing-group case
      does not produce a 0666 socket.

**Follow-up (not in this ticket's Linux scope):** the Windows named-pipe
service still uses the default pipe security descriptor with no client
identity check — see STATUS.md 2026-09-28.

## Implementation notes

- `getsockopt(SO_PEERCRED)` on the accepted `UnixStream` fd (libc), mirroring
  the project's hand-rolled `fdpass` style.
- Applies to the Linux daemon; document the Windows named-pipe service's
  equivalent (pipe ACL + client PID check) as a follow-up if not already
  covered.
- Update `packaging/systemd/ferrum-helper.service` + `apps/desktop/README.md`
  setup notes (the group is now mandatory).
