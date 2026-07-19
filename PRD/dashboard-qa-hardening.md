# PRD — Admin Dashboard QA Hardening

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) — admin panel Dashboard (`apps/admin-panel/`, Angular 19) |
| **Phase** | Admin-panel follow-on (post-acceptance; see [admin-panel-angular.md](admin-panel-angular.md)) |
| **Status** | Proposed |
| **Owner** | punarduttrajput |
| **Last updated** | 2026-07-19 |
| **Depends on** | Coordinator `--admin-listen` API (`/api/devices`, `/api/policy`), the shared `StatusService` banner |

---

## 1. Summary

The Dashboard is the admin panel's default landing page: four stat cards
(Devices, Awaiting endpoint, Tags in use, ACL policy) plus a recent-devices
preview. A senior-QA review (2026-07-19) found the happy path is clean and
unit-tested, but the screen behaves poorly under the conditions QA exercises
first: it never refreshes itself, a single failed API call blanks the whole
page, a genuine "no devices" state is indistinguishable from "still loading,"
and two of the four headline metrics have semantics that will mislead an
operator. The error path, loading state, and empty state are also untested.

This PRD treats those as **defects and test-coverage gaps** and defines the
behavior and coverage the Dashboard must meet to be trustworthy for operations.

## 2. Goals & Non-Goals

### Goals
- **G1. Fresh data.** The Dashboard reflects current coordinator state without a
  manual reload, and shows how fresh the data is.
- **G2. Resilient rendering.** A failure in one data source degrades gracefully
  instead of blanking the page.
- **G3. Unambiguous states.** Loading, empty, error, and populated are visually
  distinct.
- **G4. Honest metrics.** Every stat card measures exactly what its label claims,
  with a defined and tested meaning.
- **G5. Accessible status.** Success/error banners are announced to assistive
  tech and don't persist as stale context across navigation.
- **G6. Coverage for the unhappy paths** — error, loading, empty, and threshold
  cases, plus a DOM-level render check.

### Non-Goals
- ❌ New coordinator API surface beyond what a real "reachability / last-seen"
  metric strictly needs (DASH-004 may need one small field; scoped there).
- ❌ Redesigning the other admin screens (Devices, Policy) — only shared pieces
  they inherit (the status banner) are in scope.
- ❌ A charting/timeseries dashboard — this is the operational overview, not an
  analytics product.

## 3. Background & Rationale

The Dashboard loads once in the component constructor via `forkJoin({ devices,
policy })` and then never updates. Specific QA-visible consequences:

- **Staleness.** Counts drift from reality the moment a device registers/leaves;
  the operator has no cue and must remember to click Refresh
  (`dashboard.component.ts:38–55`).
- **All-or-nothing load.** `forkJoin` errors if *either* call fails, so a policy
  endpoint hiccup blanks the device cards too — and routes the user to a single
  error banner with no partial data.
- **Loading≡empty.** `loading` only disables the Refresh button; the template has
  no spinner/skeleton, so during every load `deviceCount()` is `0` and
  "No devices registered." renders — identical to a truly empty coordinator
  (`dashboard.component.html:33–34`).
- **Misleading metrics.**
  - *Awaiting endpoint* = devices with no `endpoint`, labelled "not yet
    reachable" (`dashboard.component.ts:26`). A device on a relay/NAT path or
    mid-registration has no endpoint but may be perfectly reachable; there is no
    online/last-seen concept at all, so this conflates "no endpoint" with
    "unreachable."
  - *Tags in use* = distinct tags across **devices** only
    (`dashboard.component.ts:27`), but the card sits next to ACL policy and reads
    "distinct policy tags." A tag referenced by a policy rule but not yet on any
    device isn't counted.
- **Status banner.** Rendered as `<div id="status-banner" [class]="msg.kind">`
  with no `role`/`aria-live` (`shell.component.html:7–9`), so screen readers
  never announce load failures. It's only cleared on sign-out, so an error from
  the Dashboard follows the user to Devices/Policy as stale context.

None of these are backend bugs; they're front-end correctness, resilience, and
coverage gaps in the operator's primary screen.

## 4. Functional Requirements

### FR1 — Auto-refresh + freshness (M1) — [DASH-001, DASH-009]
- The Dashboard refreshes on a sensible interval (and/or subscribes to a live
  update signal) while visible; it pauses when the tab/route is not active.
- A visible "updated N s ago" / last-refresh timestamp.

### FR2 — Resilient load (M1) — [DASH-002]
- Devices and policy load independently; a failure in one renders its card in an
  error/unknown state while the other still shows data.
- The error is surfaced without discarding the successful half.

### FR3 — Distinct loading/empty/error states (M1) — [DASH-003]
- A loading indicator (skeleton or spinner) while data is in flight, distinct
  from the empty state.
- "No devices registered." shows only after a successful load returns zero
  devices — never during loading.

### FR4 — Honest metrics (M2) — [DASH-004, DASH-005]
- *Awaiting endpoint*: either relabel to exactly what it measures
  ("no endpoint yet") **or** back it with a real reachability/last-seen signal;
  define and test the meaning. Add an online/last-seen concept if the coordinator
  can supply it (one small field).
- *Tags in use*: count what the label says — reconcile device tags with policy
  tags, or relabel to "device tags" and add a separate policy-tag count.

### FR5 — Accessible, self-clearing status banner (M2) — [DASH-006, DASH-007]
- The banner uses `role="alert"` / `aria-live="assertive"` (errors) and
  `aria-live="polite"` (success) so assistive tech announces it.
- The banner auto-dismisses (timeout) and/or clears on route change; a manual
  dismiss control.

### FR6 — Coverage for the unhappy paths (M1/M2) — [DASH-008, DASH-010]
- Unit tests for the error branch (`status.show`), the loading state, the empty
  state, and the "view all N devices" threshold.
- A DOM-level render test: the four counts appear in the rendered cards and the
  policy/devices links navigate.

## 5. Milestones

| Milestone | Scope | Tickets |
|---|---|---|
| **M1 — Trustworthy states** | auto-refresh + freshness, resilient load, loading/empty/error distinction, error-path tests | DASH-001, DASH-002, DASH-003, DASH-008, DASH-009 |
| **M2 — Honest & accessible** | metric semantics, accessible/self-clearing banner, DOM render test | DASH-004, DASH-005, DASH-006, DASH-007, DASH-010 |

## 6. Acceptance Criteria

- **AC1:** With the Dashboard open, registering/removing a device is reflected
  within the refresh interval without a manual reload; a last-updated time is
  shown.
- **AC2:** With the policy endpoint failing and devices succeeding, the device
  cards still render and only the policy card shows an error/unknown state.
- **AC3:** During load, a loading indicator shows and "No devices registered."
  does **not** appear; it appears only after a successful empty load.
- **AC4:** Each stat card's value matches its label under a defined, tested
  meaning (reachability and tag-source semantics documented in tests).
- **AC5:** A screen reader announces load failure/success; navigating away clears
  or the banner auto-dismisses; a dismiss control exists.
- **AC6:** Unit tests cover error/loading/empty/threshold; a DOM test asserts the
  rendered counts and link targets. `ng test` green.

## 7. Risks & Open Questions

- **Reachability signal (DASH-004):** a real online/last-seen metric may need a
  coordinator field (`last_seen`) — decide whether to add it or relabel the card
  to the honest "no endpoint yet" this cycle.
- **Auto-refresh cost:** polling `/api/devices` + `/api/policy` on an interval is
  cheap at admin scale, but pause-when-hidden avoids needless load; confirm the
  interval with the coordinator owner.
- **Headless test host:** `ng test` uses ChromeHeadless — confirm it runs in CI
  (the admin panel already ships specs, so the runner exists).
