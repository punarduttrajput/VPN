# Desktop App Hardening — Tickets

Derived from the 2026-07-19 desktop-developer review and
[PRD/desktop-app-hardening.md](../../PRD/desktop-app-hardening.md). All paths are
under `apps/desktop/`. GUI behaviors verify on a display-equipped host; the
frontend uses the repo's headless-Chromium screenshot harness.

| ID | Title | Severity | Milestone |
|----|-------|----------|-----------|
| [DSK-001](DSK-001-webview-csp-xss.md) | `csp: null` + `innerHTML` of network data → DOM-XSS | High | M1 |
| [DSK-002](DSK-002-system-tray.md) | No system tray; closing window kills the always-on tunnel | High | M1 |
| [DSK-003](DSK-003-secure-updates.md) | No secure auto-update mechanism | High | M2 |
| [DSK-004](DSK-004-single-instance.md) | No single-instance guard; second launch races the session | Medium | M2 |
| [DSK-005](DSK-005-launch-on-boot.md) | No launch-on-boot for always-on | Medium | M2 |
| [DSK-006](DSK-006-windows-peer-parity.md) | Windows peer list not forwarded (get_peers empty) | Medium | M2 |
| [DSK-007](DSK-007-frontend-maintainability.md) | Unbundled frontend, no tests/lint | Medium | M3 |
| [DSK-008](DSK-008-macos-enforcement-plan.md) | macOS kill-switch (pf) + helper missing | Medium | M3 |
| [DSK-009](DSK-009-window-ux-a11y.md) | No min window size; accessibility pass | Low | M3 |
