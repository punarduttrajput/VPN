# Ferrum — desktop shell (Tauri)

A desktop GUI (Phase 5 FR4) over the shared client core
([`ferrum-client-core`](../../crates/client-core)). The Rust backend
([`src-tauri/src/lib.rs`](src-tauri/src/lib.rs)) drives `FerrumClient` and forwards
its event stream to a static webview frontend ([`dist/`](dist)).

It is a **standalone workspace** (its own `Cargo.lock`/`target`) so the webview
dependency tree stays out of the main library workspace — `apps/desktop/src-tauri`
is in that workspace's `exclude` list.

## What it does today

- **Connect moves packets, and stays up.** `connect` registers with the coordinator
  to learn the assigned tunnel address, then runs
  `ferrum_client_core::data_plane::run_mesh_session_supervised` in a background task —
  so the GUI drives the actual data plane and **auto-reconnects with backoff** on any
  drop (reopening the TUN + rebinding the socket each attempt via factories). A
  one-shot pre-flight `device::open` fails fast with a clean error on an unsupported
  platform / missing privileges. `disconnect` signals the supervisor to wind down.
- **Kill-switch (FR5).** A toggle arms the core's kill-switch; while the tunnel is
  not up, the backend installs an `nftables` leak-block (a dedicated
  `inet ferrum_killswitch` table that drops non-tunnel egress, allow-listing
  loopback, the tunnel interface, and the coordinator so reconnect still works) and
  removes it when the tunnel comes back or on app exit. Enforcement is Linux-only for
  now (macOS `pf` / Windows WFP are follow-ups); the UI still reflects the intent
  everywhere. See [`src-tauri/src/killswitch.rs`](src-tauri/src/killswitch.rs).
- Live connection state and the peer list, driven through the shared facade.
  Core events (`StateChanged` / `PeersUpdated` / `Error` / `TrafficBlocked`) are
  pushed to the UI as `client-event`.

The connect form takes the device's WireGuard **private key** (the public key is
derived from it and advertised to the coordinator; the private key never leaves
the process) and a UDP listen port.

> The real TUN needs **elevated privileges on a Linux/macOS host** (`/dev/net/tun`).
> On Windows — or without privileges — `connect` returns a clean error and the UI
> stays disconnected (the `tun` driver crate is only built on Unix). Per-platform
> elevated-helper packaging and transport selection (QUIC/MASQUE) are follow-ups.

## Run / build

Requires the platform webview (WebView2 on Windows, `webkit2gtk` on Linux) and
a Rust toolchain. The frontend is static (`dist/`) — no Node build step.

```sh
cd apps/desktop/src-tauri
cargo build           # compile the backend + webview
# A full dev run/bundle uses the Tauri CLI:
#   npm i -g @tauri-apps/cli && cargo tauri dev
```

> The GUI needs a display; on a headless box you can still `cargo build` to
> verify the backend + command layer compile.
