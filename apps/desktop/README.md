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
  not up, the backend installs a leak-block (Linux: an `nftables`
  `inet ferrum_killswitch` table that drops non-tunnel egress; Windows: Windows
  Filtering Platform filters), allow-listing loopback, the tunnel interface, and
  the coordinator so reconnect still works, and removes it when the tunnel comes
  back or on app exit. macOS (`pf`) is a follow-up; the UI still reflects the
  intent everywhere. See [`src-tauri/src/killswitch.rs`](src-tauri/src/killswitch.rs).
- Live connection state and the peer list, driven through the shared facade.
  Core events (`StateChanged` / `PeersUpdated` / `Error` / `TrafficBlocked`) are
  pushed to the UI as `client-event`.

The connect form takes the device's WireGuard **private key** (the public key is
derived from it and advertised to the coordinator; the private key never leaves
the process) and a UDP listen port.

> The real TUN needs **elevated privileges on a Linux/macOS host** (`/dev/net/tun`).
> On Linux, `connect` and the kill-switch both try the [privileged helper
> daemon](#privileged-helper-linux) first, so the desktop app itself can run
> unprivileged once the helper is installed; without it (or on Windows, or without
> privileges), `connect` falls back to opening the TUN in-process and returns a
> clean error if that also fails. macOS elevated-helper packaging is a follow-up.

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

Windows/macOS equivalents (a service + named-pipe transport on Windows; a `pf`
helper on macOS) are documented follow-ups — the wire protocol
([`ferrum_tunnel::helper_proto`](../../crates/tunnel/src/helper_proto.rs)) is
already transport-agnostic so a Windows service can plug in without a protocol
change.

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
