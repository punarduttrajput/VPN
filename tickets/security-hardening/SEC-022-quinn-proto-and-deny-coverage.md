# SEC-022 — quinn-proto memory exhaustion; supply-chain gate gaps

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M4 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR8 |
| **Area** | workspace dependencies, `deny.toml`, `.github/workflows/supply-chain.yml`, desktop app |
| **Found by** | a `jsonwebtoken` 11 trial (2026-10-04) |

## Problem

- **RUSTSEC-2026-0185** (quinn-proto 0.11.14): unbounded out-of-order stream
  reassembly lets a remote peer exhaust memory. QUIC-mode nodes and MASQUE
  proxies accept QUIC streams from anyone, before WireGuard authentication.
- **The Supply chain CI job had been failing since SEC-017** and nobody acted
  on it. The CI action passes `--all-features`, but `deny.toml` checked only
  default features, so local `cargo deny check` runs were green while CI hit
  licences (`uniffi` MPL-2.0, `foldhash` Zlib) and then this advisory.
- **The desktop app was not gated at all.** It is its own workspace, and its
  lockfile had drifted onto vulnerable releases: h2 (RUSTSEC-2026-0258),
  rustls (RUSTSEC-2026-0285), quick-xml (RUSTSEC-2026-0194/0195) and a yanked
  num-bigint.

## Acceptance criteria

- [x] quinn-proto >= 0.11.15 in every lockfile (root, desktop, fuzz).
      *(0.11.19.)*
- [x] `deny.toml` checks all features, so a local run matches CI.
- [x] Licence policy for the optional features: Zlib allowed; MPL-2.0 allowed
      only for the `uniffi` crates (used unmodified; file-level copyleft puts
      no obligation on Ferrum's own code). Confirmed by the owner.
- [x] Desktop dependencies updated off every vulnerable release, and a CI step
      runs `cargo deny check advisories` on the desktop workspace with its own
      `deny.toml`. The remaining "unmaintained" notices come from Tauri's own
      tree (`unic-*` via urlpattern, `proc-macro-error` via gtk-rs 0.18) and
      are ignored there with reasons.
- [x] `jsonwebtoken` 11 decision recorded at the pin in
      `crates/coordinator/Cargo.toml` (stay on 9.3 / ring for now).

## Follow-ups

- [x] Desktop **licences, bans and sources** (2026-10-05). The desktop
      `deny.toml` had no licence allow-list, so every crate failed. With the
      root's list, the only new licence is MPL-2.0, allowed per crate for
      Servo's CSS engine (`cssparser`, `cssparser-macros`, `dtoa-short`,
      `selectors`, via tauri-utils/dom_query) and `option-ext` (via dirs), on
      the same file-level-copyleft reasoning as `uniffi`. Bans and sources
      match the root; the app is `publish = false` so its version-less path
      dependencies pass the wildcard check. CI runs `cargo deny check all` on
      the desktop.
