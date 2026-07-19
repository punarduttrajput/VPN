# Android Client Hardening — Tickets

Derived from the 2026-07-19 Android-developer review and
[PRD/android-client-hardening.md](../../PRD/android-client-hardening.md).
All paths are under `clients/android/`. Verification runs on a provisioned
Android SDK/NDK host (the dev/CI box has none — see CLAUDE.md).

| ID | Title | Severity | Milestone |
|----|-------|----------|-----------|
| [AND-001](AND-001-alwayson-reconnect.md) | Config lost on process death; always-on VPN never reconnects | Critical | M1 |
| [AND-002](AND-002-onrevoke-lifecycle.md) | `onRevoke()` not handled — zombie tunnel on revoke | High | M1 |
| [AND-003](AND-003-honest-killswitch.md) | Kill-switch toggle is a silent no-op | High | M1 |
| [AND-004](AND-004-backup-safety.md) | `allowBackup=true` + EncryptedSharedPreferences → crash after restore | High | M1 |
| [AND-005](AND-005-notification-compliance.md) | POST_NOTIFICATIONS not requested; no Disconnect action | Medium | M2 |
| [AND-006](AND-006-dedupe-registration.md) | Double coordinator registration (connect + run) | Medium | M2 |
| [AND-007](AND-007-state-ownership.md) | Global companion-object state; not lifecycle-bound | Medium | M3 |
| [AND-009](AND-009-split-tunneling.md) | No per-app split tunneling / own-app exclusion | Medium (stretch) | M3 |
| [AND-011](AND-011-network-resilience.md) | No underlying-network handling / MTU; poor Wi-Fi↔cellular handoff | Medium | M2 |
| [AND-012](AND-012-biometric-gate.md) | Private key usable with no device-auth gate | Medium (stretch) | M3 |
| [AND-013](AND-013-test-coverage.md) | No unit/instrumentation tests | Medium | M2 |
| [AND-014](AND-014-stale-keygen-comment.md) | Stale/misleading keygen comment | Low | M3 |
