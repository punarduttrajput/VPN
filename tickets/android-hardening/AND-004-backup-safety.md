# AND-004 — `allowBackup=true` + EncryptedSharedPreferences → crash after restore

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M1 |
| **PRD** | [android-client-hardening.md](../../PRD/android-client-hardening.md) FR4 |
| **Area** | `AndroidManifest.xml`, `KeystoreHelper.kt` |

## Problem

`AndroidManifest.xml:14` sets `android:allowBackup="true"` with no
`dataExtractionRules`/`fullBackupContent`. `KeystoreHelper` stores the WireGuard
private key and OIDC token in `EncryptedSharedPreferences` whose master key lives
in the **Android Keystore** — which is **not** backed up. After a device-transfer
or cloud restore, the encrypted prefs come back but the key to decrypt them does
not, so the first `getString(...)` throws (a well-known
`InvalidProtocolBufferException`/`AEADBadTagException` crash class), bricking the
app on launch on the new device.

## Acceptance criteria

- [ ] A backup→restore cycle launches without crashing and cleanly prompts for
      re-setup (regenerate key / re-enter token) rather than reading
      undecryptable prefs (AC4).
- [ ] No secret material is exfiltrated via cloud backup.

## Implementation notes

- Simplest correct fix: `allowBackup="false"`. If backup is desired for
  non-secret settings, instead add `dataExtractionRules` (API 31+) +
  `fullBackupContent` (older) that **exclude** the `ferrum_secure_prefs` file
  and the Keystore-backed data, and keep only the plain `ferrum_prefs`
  UI settings.
- Add a defensive try/catch around the first secure-prefs read that, on decrypt
  failure, wipes the corrupt store and routes to first-run setup.
