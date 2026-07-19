# DASH-006 — Status banner not announced to screen readers

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Type** | Accessibility |
| **Milestone** | M2 |
| **PRD** | [dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md) FR5 |
| **Area** | `shell/shell.component.html`, `core/status.service.ts` |

## Repro

1. Run a screen reader (NVDA/VoiceOver).
2. Trigger a Dashboard load failure (or a policy save success).

**Expected:** the status message is announced.
**Actual:** the banner is `<div id="status-banner" [class]="msg.kind">{{ msg.text }}</div>`
(`shell.component.html:7–9`) with no `role` or `aria-live`, so it's rendered
silently — assistive-tech users get no feedback that an action succeeded or
failed. This is the single feedback channel for every screen (Dashboard,
Devices, Policy), so the gap affects the whole app.

## Acceptance criteria

- [ ] Error banners use `role="alert"` / `aria-live="assertive"`; success uses
      `aria-live="polite"` (AC5).
- [ ] A screen reader announces both success and failure without stealing focus.
- [ ] Verified with an a11y check (axe or manual SR pass).

## Implementation notes

- Bind `role`/`aria-live` off `msg.kind`, or wrap in a live region container that
  always exists in the DOM (live regions must be present before the text changes
  to announce reliably — consider a persistent container with dynamic content).
- Low-risk, shared win across all admin screens.
