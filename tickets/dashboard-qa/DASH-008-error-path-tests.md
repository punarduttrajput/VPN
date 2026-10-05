# DASH-008 — Error/loading/empty/threshold paths untested

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Type** | Test gap |
| **Milestone** | M1 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR6 |
| **Area** | `dashboard/dashboard.component.spec.ts` |

## Problem

`dashboard.component.spec.ts` covers only happy-path computed signals
(counts, policy label, recent-devices slice). Untested:

- the **error branch** (`refresh()` error → `status.show(...)` at
  `dashboard.component.ts:50–53`) — no test injects a failing service;
- the **loading** state (the `loading` signal transitions);
- the **empty** state ("No devices registered.");
- the **"view all N devices"** threshold (`deviceCount() > recentDevices().length`).

These are exactly the paths the other tickets change (DASH-002/003), so they need
coverage to lock the fixes in.

## Acceptance criteria

- [x] Test: a failing `DevicesService.list` (and/or policy) triggers the error
      path and, per DASH-002, still renders the succeeded half.
- [x] Test: `loading` is true during the in-flight window and false after.
- [x] Test: empty devices → empty state only after load (per DASH-003).
- [x] Test: >5 devices shows the "view all" hint; ≤5 does not.
- [x] `ng test` green (AC6).

## Implementation notes

- Use `throwError(() => ...)` from the service spy and a `StatusService` spy to
  assert the message.
- For loading, use a deferred subject the test controls, or fakeAsync.
- Sequence with DASH-002/003 so the tests describe the fixed behavior.
