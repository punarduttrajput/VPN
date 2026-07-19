# DSK-008 — macOS kill-switch (pf) + helper missing

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M3 (design only this cycle) |
| **PRD** | [desktop-app-hardening.md](../../PRD/desktop-app-hardening.md) FR6 |
| **Area** | `apps/desktop` (macOS), `crates/helper` (design) |

## Problem

On macOS the GUI brings the data plane up in-process (elevated-GUI model), but
the **kill-switch (`pf`)** and a **macOS privileged helper** are not implemented
(`lib.rs` module docs call `pf` a follow-up). So on macOS the leak-protection /
kill-switch guarantees the product advertises on Linux/Windows don't hold, and
the app must run elevated. There is no Apple host in-project, so this cycle
delivers a **committed design**, not an implementation.

## Acceptance criteria

- [ ] A design doc for: the macOS `pf` kill-switch + leak-guard rule generation
      (mirroring the nftables/WFP rule-gen split), and a macOS privileged helper
      (launchd daemon) speaking the existing transport-agnostic
      `helper_proto`/pipe protocol.
- [ ] A ticket breakdown for the eventual implementation (rule-gen unit-testable
      cross-platform like the others; the privileged parts behind the helper).
- [ ] AC6: the design doc + tickets are committed.

## Implementation notes

- Reuse the pattern: pure, unit-tested rule generation on every platform + a
  privileged helper for the effectful parts. The Linux `firewall`/`leakguard`
  and Windows `wfp` modules are the templates.
- Implementation is gated on an Apple toolchain/host the project doesn't target
  yet (same constraint as iOS).
