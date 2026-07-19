# DSK-009 — No min window size; accessibility pass

| Field | Value |
|---|---|
| **Severity** | Low |
| **Milestone** | M3 |
| **PRD** | [desktop-app-hardening.md](../../PRD/desktop-app-hardening.md) FR8 |
| **Area** | `src-tauri/tauri.conf.json`, `dist/` |

## Problem

The window is a fixed 440×680 with `resizable: true` but **no minimum size**, so
it can be shrunk until the layout breaks. There has been no accessibility pass
(focus order, contrast in light/dark, control labels, keyboard operability) — the
desktop-GUI PRD's open M5 polish items.

## Acceptance criteria

- [ ] A sensible `minWidth`/`minHeight` prevents layout collapse.
- [ ] Accessibility pass: logical focus order, labelled controls, sufficient
      contrast, keyboard-operable connect/disconnect and Advanced disclosure.
- [ ] Verified via the screenshot harness (light + dark) and a manual keyboard
      pass.

## Implementation notes

- Low-risk polish; batch with DSK-007's frontend cleanup.
- Reuse the existing headless-Chromium harness for the visual checks.
