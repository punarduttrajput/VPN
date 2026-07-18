# PRD — Phase 5: Cross-Platform Clients

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | 5 of 6 — Client Applications |
| **Status** | Draft |
| **Owner** | punar@ferrum.dev |
| **Last updated** | 2026-06-16 |
| **Depends on** | Phases 1–4 |

---

## 1. Summary

Package the Rust data plane and `client-core` into polished, native applications
for **iOS, Android, Windows, macOS, and Linux**. The strategy is **one shared Rust
core, thin native shells**: all crypto, transport, mesh, and control-plane logic
lives in `client-core`, exposed to each platform via **`uniffi`** (Swift/Kotlin)
and a C ABI / direct linkage (desktop). Each platform contributes only its OS VPN
integration and UI.

---

## 2. Goals & Non-Goals

### Goals
- G1. Single shared `client-core` powering all platforms via `uniffi` FFI.
- G2. iOS (NetworkExtension) and Android (FerrumService) apps with login + connect.
- G3. Desktop apps for Windows (WinTun), macOS, and Linux with system-tray UX.
- G4. Consistent UX: SSO login, one-tap connect, peer/exit selection, connection status.
- G5. Surface mesh state from Phase 4 (direct vs relay, latency) in the UI.
- G6. Auto-start, reconnect, and "always-on/kill-switch" behavior.

### Non-Goals
- ❌ Re-implementing protocol logic per platform (it lives in `client-core`).
- ❌ eBPF/XDP, anycast, server-side scaling (Phase 6).
- ❌ Admin/management console (separate product track).

---

## 3. Background & Rationale

Re-implementing crypto and protocol per platform multiplies bug surface and audit
cost. A shared Rust core compiled to every target gives one audited code path and
guarantees behavioral parity. `uniffi` generates idiomatic Swift/Kotlin bindings,
so native teams write only UI and OS-integration glue. This is the model used by
mature Rust-based products and is the fastest path to consistent, secure clients.

---

## 4. Users & Use Case

- **Primary users:** all end users across desktop and mobile.
- **Use case:** A user downloads the app, taps "Sign in", authenticates via SSO,
  and connects with one tap. They can see whether each peer is a direct or relayed
  connection, switch exit/peer, and rely on a kill-switch that blocks traffic if the
  tunnel drops.

---

## 5. Functional Requirements

### FR1 — Shared Core via `uniffi`
- Expose `client-core` APIs: `login`, `logout`, `connect`, `disconnect`, `status`,
  `peer_list`, `select_exit`, event/callback stream for state changes.
- Generate Swift and Kotlin bindings; provide a stable C ABI for desktop.
- Core owns crypto, transport (Phase 2), mesh (Phase 4), and control sync (Phase 3).

### FR2 — iOS / macOS
- NetworkExtension `PacketTunnelProvider` hosting the Rust tunnel.
- SwiftUI app: SSO login, connect toggle, status, peer list, settings.
- Keychain storage for the device private key.

### FR3 — Android
- `FerrumService`-based tunnel hosting the Rust core (JNI via `uniffi` Kotlin bindings).
- Jetpack Compose UI mirroring iOS feature set.
- Android Keystore for the device private key.

### FR4 — Desktop (Windows / macOS / Linux)
- Tray/menubar app (Tauri preferred for a small, Rust-friendly footprint).
- Windows uses the WinTun driver; macOS/Linux reuse Phase 1 TUN integration.
- Background service/daemon manages the tunnel; UI controls it over a local IPC.

### FR5 — UX & Reliability Features
- One-tap connect/disconnect; auto-reconnect on network change (leverages Phase 2 migration).
- Always-on VPN + kill-switch (block traffic when tunnel is down).
- Connection detail view: per-peer direct/relay status + latency (Phase 4 data).
- Auto-start on boot/login (per-platform).

### FR6 — Updates & Telemetry
- Secure auto-update channel per platform.
- Opt-in, privacy-preserving diagnostics only — never traffic content.

---

## 6. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR1 | Battery impact (mobile) | Within 5% of native WireGuard apps |
| NFR2 | Cold connect time | < 2 s from tap to tunnel up |
| NFR3 | Core parity | 100% protocol logic shared; zero per-platform crypto |
| NFR4 | App size | Mobile app < 30 MB |
| NFR5 | Crash-free sessions | > 99.5% |
| NFR6 | Key security | Private key in platform secure enclave/keystore |

---

## 7. Architecture

```
   ┌───────────────────────────────────────────────────────┐
   │                    client-core (Rust)                  │
   │  control sync (P3) · transport (P2) · mesh/ICE (P4)    │
   │  · crypto (P1) · connection state machine              │
   └───────────────┬───────────────────────┬───────────────┘
        uniffi      │                       │   C ABI / link
   ┌────────────────▼──────┐      ┌─────────▼───────────────┐
   │  Swift (iOS/macOS)    │      │  Tauri desktop shell     │
   │  Kotlin (Android)     │      │  (Win/macOS/Linux)       │
   │  + NetworkExtension / │      │  + WinTun / TUN + tray   │
   │    FerrumService shells  │      │                          │
   └───────────────────────┘      └──────────────────────────┘
```

### Crates / projects
- `crates/client-core` — uniffi-exported shared core (extended from Phase 3/4).
- `clients/ios`, `clients/android` — native shells.
- `clients/desktop` — Tauri app + background service.

### Key dependencies
`uniffi`, Tauri, platform SDKs (NetworkExtension, FerrumService, WinTun), Phase 1–4 crates.

---

## 8. Milestones

1. **M1** — Define & generate `uniffi` interface; consume from a trivial Swift + Kotlin harness.
2. **M2** — Desktop (Tauri + tray + background service) on Linux/macOS, then Windows/WinTun.
3. **M3** — iOS app: NetworkExtension + SwiftUI login/connect.
4. **M4** — Android app: FerrumService + Compose login/connect.
5. **M5** — Reliability features: kill-switch, always-on, auto-reconnect, peer detail UI.
6. **M6** — Auto-update, store packaging, opt-in diagnostics, polish.

---

## 9. Acceptance Criteria

- ✅ All five platforms connect using the **same** `client-core` (no duplicated protocol code).
- ✅ SSO login → one-tap connect works on each platform within NFR2.
- ✅ Kill-switch blocks traffic when the tunnel drops; always-on reconnects automatically.
- ✅ UI correctly shows direct vs relay status and latency per peer (from Phase 4).
- ✅ Private keys are stored in each platform's secure enclave/keystore.
- ✅ Mobile battery + app-size targets met (NFR1/NFR4).

---

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Platform VPN APIs (NE/FerrumService) are restrictive | Feature gaps | Prototype tunnel-provider early; design core around constraints |
| `uniffi` async/callback ergonomics | Integration friction | Define a callback-stream pattern up front; thin shells |
| App store review (VPN entitlements) | Launch delay | Engage store requirements early; prepare privacy disclosures |
| Per-platform background-execution limits | Drops/battery | Use OS-sanctioned VPN lifecycle; tune keepalive per platform |

---

## 11. Feeds Into
- Phase 6 server-side scale work is validated by real client load from these apps.
