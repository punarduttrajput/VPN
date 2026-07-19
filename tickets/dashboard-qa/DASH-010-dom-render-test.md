# DASH-010 — No DOM-level render/navigation test

| Field | Value |
|---|---|
| **Severity** | Low |
| **Type** | Test gap |
| **Milestone** | M2 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR6 |
| **Area** | `dashboard/dashboard.component.spec.ts` |

## Problem

The existing spec asserts only component **signals**, never the rendered DOM. A
template regression — a card bound to the wrong signal, a broken `routerLink`, a
mislabelled stat — would pass the current tests. For the operator's primary
screen, the rendered output and navigation targets should be covered.

## Acceptance criteria

- [ ] A test renders the fixture and asserts the four stat-card **values** appear
      in the DOM with their expected labels.
- [ ] A test asserts the "edit policy" and "view all devices" links point at
      `/policy` and `/devices`.
- [ ] A test asserts a recent-device row renders name, tunnel IP, endpoint
      fallback, and tag badges.
- [ ] `ng test` green (AC6).

## Implementation notes

- Query via `fixture.nativeElement.querySelectorAll('.stat-card .stat-value')`
  and assert text; check `routerLink` via the `RouterLinkWithHref` debug
  elements or the rendered `href`.
- Builds on DASH-008's fixtures; land together.
