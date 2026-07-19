# DASH-002 — One failed API call blanks the whole dashboard

| Field | Value |
|---|---|
| **Severity** | High |
| **Type** | Resilience |
| **Milestone** | M1 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR2 |
| **Area** | `dashboard/dashboard.component.ts` |

## Repro

1. Make `/api/policy` fail (e.g. transient coordinator error) while
   `/api/devices` succeeds.
2. Load the Dashboard.

**Expected:** device cards + recent devices render; only the ACL-policy card
shows an error/unknown state.
**Actual:** `forkJoin({ devices, policy })` (`dashboard.component.ts:44`) errors
as a whole when *either* observable errors, so the `next` handler never runs —
`devices` and `policy` signals stay empty and **every** card blanks, plus a
single generic error banner. One flaky endpoint takes down data that loaded
fine.

## Acceptance criteria

- [ ] Devices and policy load independently; one failing does not discard the
      other's data.
- [ ] The failed source renders an error/unknown card state; the succeeded
      source renders normally (AC2).
- [ ] The error is still surfaced (banner/card) without hiding partial data.

## Implementation notes

- Replace the single `forkJoin` with two independent subscriptions, or give each
  inner observable a `catchError` that yields a sentinel so `forkJoin` still
  completes and the component can mark that card as errored.
- Track per-source load/error state (not one shared `loading`).
- Add to DASH-008's test matrix (one-fails-one-succeeds).
