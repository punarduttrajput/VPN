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
  (tried through the [privileged helper daemon](#privileged-helper-linux) first, then
  falling back in-process) and **Windows via WFP** — on Windows by the helper service
  (which has the elevation). macOS `pf` is a follow-up; the UI reflects the intent
  everywhere. See [`src-tauri/src/killswitch.rs`](src-tauri/src/killswitch.rs).
- Live connection state and the peer list, driven through the shared facade.
  Core events (`StateChanged` / `PeersUpdated` / `Error` / `TrafficBlocked`) are
  pushed to the UI as `client-event` (on Windows, relayed from the service).

The connect form takes the device's WireGuard **private key** (the public key is
derived from it and advertised to the coordinator; the private key never leaves the
local processes — on Windows it travels only over the local pipe) and a UDP listen
port.

> The real TUN needs **elevated privileges on a Linux/macOS host** (`/dev/net/tun`),
> or **a Windows Administrator** (wintun) — unless a privileged helper is installed.
> On Linux, `connect` and the kill-switch both try the [privileged helper
> daemon](#privileged-helper-linux) first, so the desktop app itself can run
> unprivileged once it's installed; without it (or without privileges at all),
> `connect` falls back to opening the TUN in-process and returns a clean error if
> that also fails. On Windows, the GUI **always** runs unprivileged against the
> [`ferrum-helper` service](#the-ferrum-helper-service-windows) — see below. macOS
> elevated-helper packaging is a follow-up.

## Privileged helper (Linux)

Opening a TUN device and changing firewall rules both need root. Rather than
running the whole GUI as root, a small daemon — [`ferrum-helper`](../../crates/helper)
— does just those two things and hands results back over a Unix domain socket;
the desktop app (`apps/desktop`) tries that socket first and only falls back to
doing the privileged operation in-process (which still needs the app itself to
run elevated) if the helper isn't reachable.

One-time setup:

```sh
sudo groupadd -f ferrum
sudo usermod -aG ferrum "$USER"     # log out/in (or `newgrp ferrum`) to pick it up
cargo build -p ferrum-helper --release
sudo install -m 0755 target/release/ferrum-helper /usr/local/bin/ferrum-helper
sudo install -m 0644 ../../packaging/systemd/ferrum-helper.service \
    /etc/systemd/system/ferrum-helper.service
sudo systemctl daemon-reload
sudo systemctl enable --now ferrum-helper
```

The daemon listens on `/run/ferrum/helper.sock`, `chown`'d to the `ferrum` group
(mode `0660`) — membership in that group is the entire trust boundary (anyone who
can reach the socket can ask it to create a TUN device or change firewall rules),
so only add users who run the Ferrum desktop app. Without this setup the desktop
still works exactly as before: run it elevated, and it falls back to doing both
privileged operations in-process.

A macOS equivalent (a `pf` helper) is a documented follow-up — the wire protocol
([`ferrum_tunnel::helper_proto`](../../crates/tunnel/src/helper_proto.rs)) is
transport-agnostic, though the Windows service below ended up using its own
named-pipe protocol ([`src-tauri/src/ipc.rs`](src-tauri/src/ipc.rs)) since a
Windows service's session model (one long-lived pipe connection = one tunnel
session) fits that platform better than fd-passing over a request/response socket.

### The `ferrum-helper` service (Windows)

A second binary in this crate (unrelated to — but named the same as, and serving
the same role for — the Linux daemon above: each platform builds only its own).
Install it once (elevated), then run the GUI unprivileged:

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
