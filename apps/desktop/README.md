# Next-Gen VPN — desktop shell (Tauri)

A desktop GUI (Phase 5 FR4) over the shared client core
([`vpn-client-core`](../../crates/client-core)). The Rust backend
([`src-tauri/src/lib.rs`](src-tauri/src/lib.rs)) drives `VpnClient` and forwards
its event stream to a static webview frontend ([`dist/`](dist)).

It is a **standalone workspace** (its own `Cargo.lock`/`target`) so the webview
dependency tree stays out of the main library workspace — `apps/desktop/src-tauri`
is in that workspace's `exclude` list.

## What it does today

- Connect / disconnect, live connection state, and the peer list — the
  platform-independent **control-plane** loop, driven entirely through the
  shared facade. Core events (`StateChanged` / `PeersUpdated` / `Error`) are
  pushed to the UI as `client-event`.

## Not wired yet (next increment)

- The **data plane**: open a TUN and run `vpn_client_core::data_plane::run_mesh_session`
  (or the `FfiVpnClient::run` fd path). It needs elevated privileges and a
  Linux/macOS host, so it is deliberately left out of the GUI scaffold.

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
