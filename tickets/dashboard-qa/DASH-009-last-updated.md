# DASH-009 — No "last updated" freshness indicator

| Field | Value |
|---|---|
| **Severity** | Low |
| **Type** | UX |
| **Milestone** | M1 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR1 |
| **Area** | `dashboard/dashboard.component.*` |

## Problem

The Dashboard shows no indication of when its data was last loaded. Combined with
the no-auto-refresh defect (DASH-001), an operator cannot tell whether the
numbers are current or minutes old — a trust problem for an operational overview.

## Acceptance criteria

- [x] A visible "Updated N s/min ago" (or an absolute timestamp) that updates on
      each successful refresh.
- [x] Present alongside the Refresh control (AC1).

## Implementation notes

- Record `Date.now()` in a signal on each successful load; render a relative-time
  string (recomputed on the same interval as DASH-001, or via a small ticker).
- Trivial; pairs naturally with DASH-001.
