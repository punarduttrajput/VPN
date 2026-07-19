# AND-001 — Config lost on process death; always-on VPN never reconnects

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Milestone** | M1 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR1 |
| **Area** | `FerrumVpnService.kt`, `VpnViewModel.kt` |

## Problem

`onStartCommand` returns `START_STICKY` but only acts on `intent?.action`
(`FerrumVpnService.kt:56–62`). When the OS restarts the service it redelivers a
**null** intent, so the `when` matches nothing and the tunnel never reconnects.
The same gap breaks Android's **always-on VPN**: the system starts the service
without the app's custom `ACTION_START` + extras, so it no-ops.

Always-on reconnect is the single most-relied-on reliability feature for Android
VPN users; today it silently fails.

## Acceptance criteria

- [ ] The last-good start config (coordinator, device name, STUN, relay, DNS,
      IPv6 policy) is persisted on a successful start.
- [ ] A null/redelivered start intent reconnects from persisted config.
- [ ] The system always-on start path (no custom action/extras) reconnects.
- [ ] With OS always-on VPN enabled, killing the app process reconnects (AC1).

## Implementation notes

- Switch to `START_REDELIVER_INTENT`, or persist the config and reconnect on the
  null-intent branch — persisted config is also needed for the always-on path,
  so prefer that.
- Config already lives in `ferrum_prefs`; centralize read/write so the service
  and view-model share one source.
- Guard against reconnect storms (don't restart faster than the backoff the core
  supervisor already applies).

## Verification

Provisioned SDK host: enable Settings → Network → VPN → always-on, force-stop the
app, confirm reconnect. (No SDK on the dev/CI box.)
