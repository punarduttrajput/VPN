# AND-007 — Global companion-object state; not lifecycle-bound

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M3 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR8 |
| **Area** | `FerrumVpnService.kt`, `VpnViewModel.kt` |

## Problem

Connection state, peers, and address are held in **static** `MutableStateFlow`s
on `FerrumVpnService.companion object` (`FerrumVpnService.kt:36–42`), and
`VpnViewModel` collects those globals directly. Process-global mutable state:

- survives process restart with stale values (no reset tied to a fresh service
  instance);
- couples the ViewModel to the service class rather than a bound interface;
- would clash if more than one service instance ever existed.

It works today but is fragile and hard to test.

## Acceptance criteria

- [ ] State ownership moves to a lifecycle-appropriate holder (a bound-service
      binder, or a single repository/singleton the service updates and the
      view-model observes) with a defined reset on new session.
- [ ] The view-model no longer reaches into service statics.
- [ ] Behavior unchanged from the user's perspective; covered by AND-013 tests.

## Implementation notes

- A small `VpnRepository` (single source of truth for state/peers/address) that
  both the service writes and the view-model reads is the least-invasive
  refactor and makes AND-013 unit tests straightforward.
- Keep it minimal — this is a maintainability/testability cleanup, not a
  re-architecture.
