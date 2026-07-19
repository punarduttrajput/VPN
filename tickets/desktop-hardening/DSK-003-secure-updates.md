# DSK-003 — No secure auto-update mechanism

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M2 |
| **PRD** | [desktop-app-hardening.md](../../PRD/desktop-app-hardening.md) FR3 |
| **Area** | `src-tauri/Cargo.toml`, `tauri.conf.json`, ops |

## Problem

There is no `tauri-plugin-updater` (or any update path) in the desktop app. For a
security product this means a shipped vulnerability — in the client, the bundled
`wintun.dll`, or a dependency — cannot be remediated in the field; users are
stuck on whatever they installed. This is the desktop-GUI PRD's open M5
update-check item, elevated because it's a security-relevant gap.

## Acceptance criteria

- [ ] `tauri-plugin-updater` integrated with **signature verification** (the
      updater's public key pinned in config; artifacts signed with the private
      key).
- [ ] A manual "Check for updates" action plus a periodic background check.
- [ ] Update signing-key management + the update-manifest/server layout are
      documented.
- [ ] AC3: the app checks for and applies a signature-verified update.

## Implementation notes

- Decide where signed artifacts + the update manifest are hosted (ops
  dependency, PRD §7).
- Keep the signing key out of the repo and CI logs; document rotation.
- Coordinate versioning with `tauri.conf.json` `version` and the release process.
