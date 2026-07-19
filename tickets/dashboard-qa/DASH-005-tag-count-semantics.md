# DASH-005 — "Tags in use / distinct policy tags" counts device tags only

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Type** | Correctness (metric semantics) |
| **Milestone** | M2 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR4 |
| **Area** | `dashboard/dashboard.component.ts`, `.html` |

## Problem

The "Tags in use" card is `new Set(devices.flatMap(d => d.tags)).size`
(`dashboard.component.ts:27`), detail text "distinct policy tags"
(`dashboard.component.html:20`). But it counts tags present on **devices** only —
a tag referenced by an ACL policy rule (`src`/`dst`) but not yet assigned to any
device is **not** counted, even though it's very much a "policy tag." Sitting
directly beside the ACL-policy card, the label reads as if it reflects policy.

QA impact: an admin auditing tag coverage gets a number that silently omits
policy-only tags, which can hide a misconfigured rule referencing a tag no device
has.

## Acceptance criteria

- [ ] The card measures what its label says (AC4), asserted in a unit test.
- [ ] Chosen resolution (pick one):
      - **Relabel** to "device tags" and keep the device-only count; **or**
      - reconcile device tags ∪ policy-rule tags and label it "distinct tags";
        optionally surface policy-only tags (referenced but unassigned) as a
        warning.

## Implementation notes

- Policy tags are already available (`policy().rules[].src/.dst`) — the component
  loads policy anyway, so unioning is cheap.
- Highlighting "policy tags with zero devices" would be a genuinely useful
  operational signal; consider it a small stretch within this ticket.
