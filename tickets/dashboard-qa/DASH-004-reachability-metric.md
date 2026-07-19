# DASH-004 — "Awaiting endpoint / not yet reachable" conflates no-endpoint with unreachable

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Type** | Correctness (metric semantics) |
| **Milestone** | M2 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR4 |
| **Area** | `dashboard/dashboard.component.ts`, `.html` |

## Problem

The "Awaiting endpoint" card is `devices.filter(d => !d.endpoint).length`
(`dashboard.component.ts:26`) with the detail text "not yet reachable"
(`dashboard.component.html:15`). Two issues a QA operator will hit:

1. **False signal.** A device reachable **via relay/NAT** or mid-registration
   can have no `endpoint` yet still be perfectly connected. Counting it as "not
   yet reachable" misrepresents fleet health.
2. **No liveness at all.** There is no online/last-seen concept anywhere on the
   Dashboard, so a long-dead device that once had an endpoint counts as fine,
   while a healthy relay-only device counts as a problem — backwards.

## Acceptance criteria

- [ ] The card measures exactly what its label claims, with a meaning defined and
      asserted in a unit test (AC4).
- [ ] Chosen resolution (pick one, document why):
      - **Relabel** to the honest "No endpoint yet" (drop the reachability
        claim); **or**
      - back it with a real reachability/last-seen signal (add a coordinator
        `last_seen` field and derive online/offline).

## Implementation notes

- If a `last_seen` field is added, this becomes a real "Online / Offline"
  metric — the more useful operational number; coordinate with the coordinator
  owner (PRD §7).
- Minimum viable this cycle: relabel to remove the incorrect reachability claim,
  and open a follow-up for the liveness field.
