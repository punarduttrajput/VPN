# AND-013 — No unit/instrumentation tests

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M2 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR10 |
| **Area** | `clients/android/app/src/test`, `.../androidTest` (new) |

## Problem

The Android module has **no tests** (only `src/main`). Non-trivial logic is
untested: DNS/IPv6 resolution order (`local override → advertised → sink`),
intent building in `VpnViewModel.connect`, the CIDR parse in `buildVpnInterface`,
and the teardown path. Every change is verified only by manual APK runs.

## Acceptance criteria

- [ ] JVM unit tests (`src/test`) for: view-model intent construction, DNS
      override parsing/order, IPv6 policy → route decision, and CIDR parsing.
- [ ] At least one instrumentation smoke test (`src/androidTest`) where feasible
      (service start/stop, permission-needed path).
- [ ] Tests run in the documented gradle flow (CI box has no SDK — note it).

## Implementation notes

- The AND-007 repository refactor makes the view-model logic unit-testable
  without a live service; sequence AND-007 first if convenient.
- Pure helpers (CIDR parse, DNS list parse) can be extracted and tested without
  Robolectric.
