# AND-005 — POST_NOTIFICATIONS not requested; no Disconnect action

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M2 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR5 |
| **Area** | `MainActivity.kt`, `FerrumVpnService.kt` |

## Problem

Two foreground-service notification gaps:

1. `POST_NOTIFICATIONS` is declared in the manifest but never **requested at
   runtime**. On Android 13+ (API 33) the permission defaults to denied, so the
   ongoing VPN notification is suppressed — poor UX and a foreground-service
   compliance risk.
2. The notification (`buildNotification`) has no **Disconnect** action; the only
   affordance is tapping through to `MainActivity`. Every mainstream VPN offers a
   one-tap disconnect from the notification.

## Acceptance criteria

- [ ] The app requests `POST_NOTIFICATIONS` at runtime on API 33+ (rationale UI
      if denied).
- [ ] The ongoing notification shows on Android 13+ (AC5).
- [ ] The notification has a Disconnect action that stops the tunnel
      (`ACTION_STOP`).

## Implementation notes

- Request the runtime permission from `MainActivity` (Compose
  `rememberLauncherForActivityResult` with `RequestPermission`), ideally before
  the first connect.
- Add a `PendingIntent` for `ACTION_STOP` as a `Notification.Action`.
