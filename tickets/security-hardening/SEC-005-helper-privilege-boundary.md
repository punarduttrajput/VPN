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

**Windows counterpart (follow-up, done 2026-09-29):** the named-pipe service
(`apps/desktop/src-tauri/src/service.rs`) used the default pipe security
descriptor with no client identity check. Now:

- [x] The pipe is created with an explicit DACL (SDDL → `create_with_security_attributes_raw`):
      SYSTEM / Administrators / owner full control, interactive users read/write
      **without** `FILE_CREATE_PIPE_INSTANCE`, network logons denied, medium
      mandatory label. *(`pipe_security::PIPE_SDDL`.)*
- [x] Remote clients rejected (`reject_remote_clients(true)`).
- [x] Every connected client is verified before it's served: impersonate →
      open its token → `CheckTokenMembership` against an allow/deny SID policy
      (SYSTEM / Administrators / INTERACTIVE; not NETWORK). Refused clients get
      "not authorized" + a log line with their pid. *(`pipe_security::verify_client`.)*
- [x] Squatting protection kept *and* extended: `first_pipe_instance` on the
      first instance, and the next instance is created before the current
      connection is handled, so the name is never released between sessions
      (previously it was, after every session).
- [x] 10 s timeout for a client's opening request (connections are served one
      at a time).
- [x] Tests over real pipes: DACL denies an ungranted caller
      (`ERROR_ACCESS_DENIED`), a DACL-admitted but policy-refused caller gets
      "not authorized" (and the loop keeps serving), deny beats allow, the
      production DACL + policy admit a non-elevated interactive user using the
      GUI's own `ClientOptions`, the pipe name stays claimed after a session,
      and SDDL parse/mask checks.

## Implementation notes

- `getsockopt(SO_PEERCRED)` on the accepted `UnixStream` fd (libc), mirroring
  the project's hand-rolled `fdpass` style.
- Applies to the Linux daemon; document the Windows named-pipe service's
  equivalent (pipe ACL + client PID check) as a follow-up if not already
  covered.
- Update `packaging/systemd/ferrum-helper.service` + `apps/desktop/README.md`
  setup notes (the group is now mandatory).
