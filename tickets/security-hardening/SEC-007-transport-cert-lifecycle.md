# SEC-007 — Static self-signed transport certs: no rotation/revocation

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M3 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR7 |
| **Area** | `ferrum-transport`, `ferrum-coordinator` |

## Problem

The QUIC/MASQUE transports use static self-signed certs with (today) permissive
verification. Once SEC-004 pins them, there is no rotation or revocation story:
rolling a cert would break every pinned client. Fine for a research build; a gap
for production trust.

## Acceptance criteria

- [ ] The coordinator can advertise a **set** of accepted transport cert
      fingerprints (current + next) so pinning survives a roll.
- [ ] Clients accept any advertised fingerprint, enabling zero-downtime
      rotation.
- [ ] (Optional/stretch) Short-lived transport certs minted per coordinator
      config.
- [ ] Test: a client mid-rotation (server presents the "next" cert) still
      connects; a fully-unlisted cert is rejected.

## Implementation notes

- Extends the SEC-004 network-map advertisement from a single fingerprint to a
  small list.
- Document the operational rotation runbook (advertise next → roll servers →
  drop old) in the deployment README.

## Dependencies

Depends on SEC-004 (pinning must exist before rotation is meaningful).
