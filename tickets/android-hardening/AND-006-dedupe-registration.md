# AND-006 — Double coordinator registration (connect + run)

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M2 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR6 |
| **Area** | `FerrumVpnService.kt` |

## Problem

`startTunnel` calls `c.connect(...)` to learn the assigned address for the TUN,
then calls `c.run(...)`, which **re-registers** with the coordinator
(`FerrumVpnService.kt:99–165`, and the comment at 154–155 admits it). That's two
control-plane registrations per connect — extra coordinator load, an extra
round-trip on the connect critical path, and a brief window of two registrations
for the same key.

## Acceptance criteria

- [ ] A single coordinator registration per connect (AC6).
- [ ] The TUN is still built with the correct assigned address before the data
      plane starts.

## Implementation notes

- Either expose the assigned address off the `run()` path (so the TUN can be
  established once `run` reports `Connected`/address) or have `run` accept a
  pre-established connection.
- This likely needs a small `FfiFerrumClient`/`data_plane` surface tweak in
  `ferrum-client-core`; coordinate with the core owner. The Android change is to
  stop calling `connect()` purely to read the address.
- Cross-check the desktop path (`dataplane::bring_up`) — it may already avoid the
  double register and can serve as the reference shape.
