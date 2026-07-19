# SEC-009 — No independent audit; hand-rolled security primitives

| Field | Value |
|---|---|
| **Severity** | Market / Process |
| **Milestone** | M4 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR9 |
| **Area** | whole product |

## Problem

Every serious VPN competitor leads with a third-party audit. Ferrum has none,
and it ships several **hand-rolled** security primitives that are reasonable
engineering but individually un-audited attack surface:

- STUN client (`ferrum-transport`)
- OIDC JWT verification on `ring` instead of a vetted `jsonwebtoken`
  (`ferrum-coordinator::auth`)
- `fdpass` SCM_RIGHTS fd-passing (`ferrum-tunnel::fdpass`)
- WFP + nftables rule generation (desktop killswitch/leakguard, `firewall`)
- the tiny relay wire protocol

This is the single biggest *trust* gap versus the market — independent of any
specific code bug.

## Acceptance criteria

- [ ] An inventory of every hand-rolled security primitive with its risk and a
      disposition: (a) replace with a vetted crate, (b) schedule for external
      review, or (c) accept-with-rationale.
- [ ] A written plan (owners + target dates + budget ask) to commission a
      third-party audit of the crypto/transport/control-plane core.
- [ ] Where a vetted replacement exists and cargo is online (see CLAUDE.md env
      note), a follow-up ticket to adopt it (e.g. `jsonwebtoken` for OIDC).

## Implementation notes

- This is a planning/coordination ticket; it produces a document and follow-up
  tickets, not code.
- The OIDC-on-`ring` and no-`uniffi` workarounds were forced by the old
  offline-Windows environment; CLAUDE.md notes those constraints are now lifted
  on the Linux/online host — re-evaluate the hand-rolled JWT verify first.
- Budget/vendor selection is a business decision (PRD §7 open question).
