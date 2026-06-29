# Ferrum — desktop shell (Tauri)

A desktop GUI (Phase 5 FR4) over the shared client core
([`ferrum-client-core`](../../crates/client-core)). The Rust backend
([`src-tauri/src/lib.rs`](src-tauri/src/lib.rs)) drives `FerrumClient` and forwards
its event stream to a static webview frontend ([`dist/`](dist)).

It is a **standalone workspace** (its own `Cargo.lock`/`target`) so the webview
dependency tree stays out of the main library workspace — `apps/desktop/src-tauri`
is in that workspace's `exclude` list.

## What it does today

- **Connect moves packets, and stays up.** `connect` brings up the data plane via
  the shared `dataplane::bring_up` (register → learn the assigned tunnel address →
  gather/publish STUN candidates → open the TUN → run
  `ferrum_client_core::data_plane::run_mesh_session_supervised`), so the GUI drives
  the actual data plane and **auto-reconnects with backoff** on any drop (reopening
  the TUN + rebinding the socket each attempt via factories). `disconnect` winds the
  supervisor down. UDP / QUIC / MASQUE transports + STUN-server / relay-override
  fields are exposed in the connect form.
- **Privilege model differs by OS (privileged helper):**
  - **Windows** — the data plane (wintun) and kill-switch (WFP) need elevation, so
    they run in a separate **`ferrum-helper` Windows service** (LocalSystem). The GUI
    stays **unprivileged** and is a named-pipe control client: `connect` ships a
    `ConnectConfig` to the service, which brings the tunnel up and streams events
    back. Closing the GUI (pipe EOF) tears the tunnel + kill-switch down. See
    [`src-tauri/src/service.rs`](src-tauri/src/service.rs),
    [`src-tauri/src/ipc.rs`](src-tauri/src/ipc.rs), and
    [`src-tauri/src/bin/ferrum-helper.rs`](src-tauri/src/bin/ferrum-helper.rs).
  - **Unix (Linux/macOS)** — the GUI brings the data plane up **in-process** (the
    existing elevated-GUI model); the real TUN needs privileges (`/dev/net/tun`).
- **Kill-switch (FR5).** A toggle arms the core's kill-switch; while the tunnel is
  not up, a leak-block is installed (dropping non-tunnel egress, allow-listing
  loopback, the tunnel interface, and the coordinator so reconnect still works) and
  removed when the tunnel comes back or on exit. Enforced on **Linux via `nftables`**
  and **Windows via WFP** — on Windows by the helper service (which has the
  elevation). macOS `pf` is a follow-up; the UI reflects the intent everywhere. See
  [`src-tauri/src/killswitch.rs`](src-tauri/src/killswitch.rs).
- Live connection state and the peer list, driven through the shared facade.
  Core events (`StateChanged` / `PeersUpdated` / `Error` / `TrafficBlocked`) are
  pushed to the UI as `client-event` (on Windows, relayed from the service).

The connect form takes the device's WireGuard **private key** (the public key is
derived from it and advertised to the coordinator; the private key never leaves the
local processes — on Windows it travels only over the local pipe) and a UDP listen
port.

### The `ferrum-helper` service (Windows)

A second binary in this crate. Install it once (elevated), then run the GUI
unprivileged:

```powershell
# from an elevated shell, after `cargo build`:
.\target\debug\ferrum-helper.exe install      # register the service (LocalSystem)
sc start ferrum-helper                         # or: start it from services.msc
# ... run the GUI unprivileged; connect/disconnect drive the service over the pipe.
.\target\debug\ferrum-helper.exe uninstall     # stop + remove the service
```

For development you can skip the SCM and run the server in the foreground from an
elevated console with `ferrum-helper.exe run-console` (Ctrl-C to stop). The pipe
protocol and session handling are unit- and integration-tested (incl. a live
named-pipe round-trip) without elevation; bringing up a real wintun adapter + WFP
still needs an elevated run.

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
