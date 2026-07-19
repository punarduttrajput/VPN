# DSK-007 — Unbundled frontend, no tests/lint

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M3 |
| **PRD** | [desktop-app-hardening.md](../../PRD/desktop-app-hardening.md) FR7 |
| **Area** | `apps/desktop/dist/` |

## Problem

The frontend is a single hand-written `dist/main.js` (~300 lines) + static
`index.html`, with no bundler, no type checking, no lint, and no automated test
beyond the ad-hoc headless-Chromium screenshot harness. As the UI grows (tray
status, update prompts, peer detail, leak-protection chips) this gets fragile —
the kind of place the earlier CSS-cascade bug and the XSS sinks (DSK-001) hide.

## Acceptance criteria

- [ ] Shared DOM/escaping helpers so rendering logic isn't duplicated and
      injection sinks are centralized (supports DSK-001).
- [ ] A lightweight lint (and optional type check via JSDoc/TS) wired into the
      dev flow.
- [ ] The screenshot-harness checks are runnable in CI where feasible
      (documented if the display constraint blocks it).

## Implementation notes

- Bounded cleanup, **not** a framework migration (explicit PRD non-goal as a
  gate). Keep the no-bundler simplicity if it still serves; the priority is
  centralizing the DOM/escaping helpers and adding a lint.
- Sequence after or with DSK-001 so the escaping helper lands once.
