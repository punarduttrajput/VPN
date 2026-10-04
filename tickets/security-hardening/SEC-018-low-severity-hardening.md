# SEC-018 — Low-severity hardening batch (from the audit-readiness inventory)

| Field | Value |
|---|---|
| **Severity** | Low |
| **Milestone** | M4 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR9 · [audit plan](../../docs/security/audit-plan.md) P14–P17 |
| **Area** | `ferrum-transport`, `relay-ebpf`, coordinator/relay binaries |

## Problem

Small issues found while building the audit inventory. None is exploitable on
its own for more than degraded service or a weaker obfuscation guarantee, but
each is cheaper to fix than to explain to an auditor:

- **STUN**: the transaction ID is time + counter, i.e. predictable, which
  helps an off-path attacker spoof the reflexive-address response.
- **Metrics / health HTTP servers** (`coordinator/src/main.rs`, relay in
  `cli/src/main.rs`): a single 1 KiB read, **prefix** path matching
  (`/metricsX` matches), no read timeout (slowloris), one task per connection.
- **Jitter**: a clock-seeded LCG decides the delays, so they're predictable.
- **Padding**: `pad::send_batch` skips the `> u16::MAX` length check that
  `send` performs.
- **XDP fast path**: doesn't check the IPv4 version nibble, fragments
  (a first fragment is forwarded alone), that the destination is the relay's
  own address, or the IP/UDP length fields; `GatewayInfo` has implicit padding
  contrary to its `unsafe impl Pod` safety comment; `checksum_update` has no
  unit test.

## Acceptance criteria

- [ ] STUN transaction IDs from `getrandom`.
- [ ] Metrics/health endpoints served by hyper/axum (already dependencies)
      with exact routes and a request timeout; existing probe tests pass.
- [ ] Jitter delays from a CSPRNG (`getrandom`-seeded).
- [ ] `send_batch` enforces the same length limit as `send`, with a test.
- [ ] XDP parser rejects non-IPv4-version, fragmented, and not-for-us packets
      (falls back to `XDP_PASS`) and validates lengths; `GatewayInfo` gets
      explicit padding; `checksum_update` gets unit tests against a reference
      full checksum. Re-run the `relay_traffic` netns check.
