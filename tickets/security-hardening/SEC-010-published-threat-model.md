# SEC-010 — No published metadata/privacy threat model

| Field | Value |
|---|---|
| **Severity** | Market / Process |
| **Milestone** | M4 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR9 |
| **Area** | docs (`SECURITY.md`) |

## Problem

The coordinator sees the whole network map; relays see traffic patterns. The
observability work is admirably NFR5-scoped (no per-user labels), but there is
no **published** statement of what the control plane and relays *can* observe.
Privacy-conscious buyers — the exact audience a WireGuard-based product courts —
will ask, and "trust us" doesn't close enterprise or prosumer deals in 2026.

## Acceptance criteria

- [x] A `SECURITY.md` / threat-model doc covering: *([docs/security/threat-model.md](../../docs/security/threat-model.md), indexed from the root `SECURITY.md`.)*
      - what the coordinator can observe (identities, keys, endpoints, network
        map, tags) and for how long;
      - what a relay can observe (traffic patterns, endpoints; not payload);
      - what the transports leak on-path (pre- and post-SEC-004);
      - the trust boundaries and each component's failure mode;
      - residual risks and explicit non-goals (e.g. DoH bypass).
- [x] A concise, user-facing privacy summary suitable for a product page. *([docs/security/privacy-summary.md](../../docs/security/privacy-summary.md).)*
- [x] Linked from the README and the deployment docs. *(README, `deploy/oracle-vm/README.md`, `deploy/observability/README.md`, and the audit plan.)*

## Implementation notes

- Reconcile with the leak-protection PRD's non-goals and the observability
  NFR5 guarantees so the story is consistent across docs.
- Reference SEC-004's residual on-path threat model rather than duplicating it.
- Pure documentation; no code.
