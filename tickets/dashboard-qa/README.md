# Admin Dashboard QA — Tickets

Defects and test-coverage gaps from the 2026-07-19 senior-QA review of the
admin-panel Dashboard, per
[PRD/dashboard-qa-hardening.md](../../PRD/dashboard-qa-hardening.md). All paths
under `apps/admin-panel/`. Verify with `ng test` (ChromeHeadless) and manual
runs against a coordinator on `--admin-listen`.

| ID | Title | Severity | Type | Milestone |
|----|-------|----------|------|-----------|
| [DASH-001](DASH-001-auto-refresh.md) | Dashboard never auto-refreshes; data goes stale | High | Functional | M1 |
| [DASH-002](DASH-002-resilient-load.md) | One failed API call blanks the whole dashboard | High | Resilience | M1 |
| [DASH-003](DASH-003-loading-empty-ambiguity.md) | Loading and empty states are indistinguishable | High | UX/Correctness | M1 |
| [DASH-004](DASH-004-reachability-metric.md) | "Awaiting endpoint / not yet reachable" conflates no-endpoint with unreachable | Medium | Correctness | M2 |
| [DASH-005](DASH-005-tag-count-semantics.md) | "Tags in use / distinct policy tags" counts device tags only | Medium | Correctness | M2 |
| [DASH-006](DASH-006-banner-a11y.md) | Status banner not announced to screen readers | Medium | Accessibility | M2 |
| [DASH-007](DASH-007-banner-persistence.md) | Status banner persists across navigation; no dismiss | Medium | UX | M2 |
| [DASH-008](DASH-008-error-path-tests.md) | Error/loading/empty/threshold paths untested | Medium | Test gap | M1 |
| [DASH-009](DASH-009-last-updated.md) | No "last updated" freshness indicator | Low | UX | M1 |
| [DASH-010](DASH-010-dom-render-test.md) | No DOM-level render/navigation test | Low | Test gap | M2 |
