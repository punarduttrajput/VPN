# PRD — Android Client Hardening & Reliability

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) — Android client (`clients/android/`) |
| **Phase** | Phase 5 (cross-platform clients), post-acceptance follow-on |
| **Status** | Proposed |
| **Owner** | punarduttrajput |
| **Last updated** | 2026-07-19 |
| **Depends on** | `ferrum-client-core` `uniffi` bindings (`FfiFerrumClient`), the leak-protection PRD (DNS/IPv6 already wired M4) |

---

## 1. Summary

The Android shell (`FerrumVpnService` + Compose UI, signed release APK) works
end-to-end: control-plane connect, TUN bring-up via `VpnService.Builder`, the
uniffi data plane, Keystore-backed credentials, and leak-protection DNS/IPv6
policy. An Android-developer review (2026-07-19) found the app is **functionally
complete but not yet production-robust**: it drops its config on process death,
ignores VPN revocation, ships a kill-switch toggle that does nothing, and has a
backup configuration that will crash the app after a cloud restore. None of
these are core-crypto issues — they are the platform-integration and
lifecycle-correctness gaps that separate a demo VPN from a shippable one, and
they are exactly what users and Play reviewers exercise first.

## 2. Goals & Non-Goals

### Goals
- **G1. Survive process death and system-initiated restarts** — an always-on
  VPN that the OS restarts must reconnect with the same config.
- **G2. Correct VPN lifecycle** — handle `onRevoke`, clean teardown, no zombie
  tunnels.
- **G3. Honest security UX** — the kill-switch control does what it says (or is
  replaced with Android's always-on/lockdown guidance); no dead toggles.
- **G4. Safe backups** — a cloud backup/restore never crashes the app or leaks
  or corrupts Keystore-backed secrets.
- **G5. Foreground-service compliance** — the ongoing notification always shows
  on modern Android, with a working Disconnect action.
- **G6. Network resilience** — seamless Wi-Fi↔cellular handoff.
- **G7. Baseline test coverage** for the service and view-model logic.

### Non-Goals
- ❌ iOS (deferred with the Apple targets).
- ❌ Per-app split tunneling as a *shipping* feature this cycle — scoped as a
  stretch ticket (AND-009), not a milestone gate.
- ❌ Re-designing the data-plane/FFI surface — this PRD is client-side only.

## 3. Background & Rationale

Android's `VpnService` contract has sharp edges the current shell doesn't yet
handle:

- `onStartCommand` returns `START_STICKY`, but on a redelivered **null** intent
  it falls through the `when(intent?.action)` and does nothing — so when the OS
  kills and restarts the service (memory pressure, or the user's **always-on
  VPN** setting), the tunnel never comes back. Always-on VPN is *the* headline
  reliability feature Android VPN users rely on.
- `onRevoke()` is never overridden. When the system revokes the VPN (another VPN
  app starts, or the user flips it off in Settings), the service keeps its
  coroutine/TUN state — a leak.
- The Settings screen has a **Kill switch** toggle, but the service treats
  `ClientEvent.TrafficBlocked` as a no-op (`/* no OS-level enforcement */`). A
  security control that silently does nothing is worse than none. Android's real
  mechanism is system **always-on + "Block connections without VPN" (lockdown)**;
  the app should route users there, not fake it.
- `AndroidManifest.xml` sets `android:allowBackup="true"` with no
  `dataExtractionRules`. `EncryptedSharedPreferences` is bound to a Keystore
  master key that is **not** included in backups — so after a device-transfer /
  cloud restore the encrypted prefs can't be decrypted, commonly crashing on
  first read.

## 4. Functional Requirements

### FR1 — Config persistence & always-on reconnect (M1) — [AND-001]
- Persist the last-good start config (coordinator, device name, STUN, relay,
  DNS, IPv6 policy) so a redelivered/empty start intent can reconnect.
- Use `START_REDELIVER_INTENT` (or equivalent persisted-config path) and handle
  the null-intent restart by reconnecting from persisted config.
- Handle the system always-on VPN start path (service started without the app's
  custom action/extras).

### FR2 — VPN lifecycle correctness (M1) — [AND-002]
- Override `onRevoke()` to stop the data plane, close the TUN, and update state.
- Ensure a single, idempotent teardown path shared by `onRevoke`/`onDestroy`/
  `stopTunnel`.

### FR3 — Honest kill-switch UX (M1) — [AND-003]
- Replace the dead toggle with guidance to Android's always-on + lockdown, or
  wire a real enforcement path. At minimum the UI must not present a security
  guarantee the app doesn't deliver.

### FR4 — Backup safety (M1) — [AND-004]
- Set `allowBackup="false"` **or** add `dataExtractionRules`/`fullBackupContent`
  excluding the encrypted prefs and any Keystore-bound material, so a restore
  never yields undecryptable state.

### FR5 — Foreground-service notification (M2) — [AND-005]
- Request `POST_NOTIFICATIONS` at runtime on API 33+.
- Add a **Disconnect** action to the ongoing notification.

### FR6 — Data-plane efficiency (M2) — [AND-006]
- Remove the redundant registration: today `connect()` and then `run()` each
  register with the coordinator. Resolve the assigned address without a
  throwaway control-plane connect (or reuse the one connection).

### FR7 — Network resilience (M2) — [AND-011]
- Call `setUnderlyingNetworks(...)` and react to connectivity changes for
  Wi-Fi↔cellular handoff; set `setMtu(...)` to match the tunnel MTU
  (1100 for QUIC/MASQUE).

### FR8 — State ownership refactor (M3) — [AND-007]
- Move the global `companion object` StateFlows to a lifecycle-appropriate owner
  (bound service or a repository) so state survives correctly and doesn't leak
  across service instances.

### FR9 — Optional biometric gate (M3, stretch) — [AND-012]
- Offer an opt-in "require device authentication to connect" backed by
  `setUserAuthenticationRequired(true)` on the key.

### FR10 — Test coverage (M2) — [AND-013]
- Unit tests for the view-model (intent building, DNS/IPv6 resolution order) and
  the service's config parsing/teardown; a smoke instrumentation test where
  feasible.

## 5. Milestones

| Milestone | Scope | Tickets |
|---|---|---|
| **M1 — Lifecycle & safety** | always-on reconnect, `onRevoke`, honest kill-switch, backup safety | AND-001, AND-002, AND-003, AND-004 |
| **M2 — Compliance & resilience** | runtime notifications + disconnect action, dedupe registration, network handoff/MTU, tests | AND-005, AND-006, AND-011, AND-013 |
| **M3 — Polish** | state-ownership refactor, biometric gate, split tunneling (stretch), doc cleanup | AND-007, AND-012, AND-009, AND-014 |

## 6. Acceptance Criteria

- **AC1:** With system always-on VPN enabled, killing the app process
  reconnects the tunnel from persisted config.
- **AC2:** Toggling the OS VPN off (revoke) tears the tunnel down cleanly (no
  leaked TUN fd / coroutine); logcat shows the revoke path.
- **AC3:** The kill-switch control either enforces or accurately describes
  Android lockdown — no silent no-op.
- **AC4:** A backup→restore cycle launches without crashing and prompts for
  re-setup rather than reading undecryptable prefs.
- **AC5:** On Android 13+, the ongoing notification appears and its Disconnect
  action stops the tunnel.
- **AC6:** Connecting performs a single coordinator registration.
- **AC7:** View-model/service unit tests pass in CI (or the documented local
  gradle run — no SDK on the CI box today).

## 7. Risks & Open Questions

- **No Android SDK/NDK on the dev/CI host** (per CLAUDE.md) — builds/tests run
  via `build-android.ps1`/gradle on a provisioned machine; this PRD's ACs are
  verified there. Flag each ticket's verification accordingly.
- **Always-on start path** varies by OEM; test on stock Android first.
- **Split tunneling** interacts with the mesh routing model — treat as stretch,
  not a gate.
