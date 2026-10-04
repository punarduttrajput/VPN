# Ferrum — desktop shell (Tauri)

A desktop GUI (Phase 5 FR4) over the shared client core
([`ferrum-client-core`](../../crates/client-core)). The Rust backend
([`src-tauri/src/lib.rs`](src-tauri/src/lib.rs)) drives `FerrumClient` and forwards
its event stream to a static webview frontend ([`dist/`](dist)).

It is a **standalone workspace** (its own `Cargo.lock`/`target`) so the webview
dependency tree stays out of the main library workspace — `apps/desktop/src-tauri`
is in that workspace's `exclude` list.

See [PRD/phase-5-desktop-gui.md](../../PRD/phase-5-desktop-gui.md) for the GUI/UX
product spec this section is tracking against.

## What it does today

- **Identity setup, once.** First run shows a setup screen: generate a fresh
  WireGuard keypair or import an existing private key, plus the device name /
  coordinator / advertised endpoint. Saved to OS-backed secure storage
  (Keychain / Credential Manager / Secret Service, via the `keyring` crate —
  see [`src-tauri/src/identity.rs`](src-tauri/src/identity.rs)), so it's never
  re-typed again; the Connect screen loads it automatically on launch. A
  "Change identity" link clears it and returns to setup.
- **Streamlined Connect screen.** The default view is just the coordinator/
  profile summary and a Connect/Disconnect control — every protocol-level
  field (transport mode, STUN server, relay override, listen port,
  MASQUE/server-name) lives behind a collapsed **Advanced** disclosure,
  off by default.
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
- **Leak protection (DNS + IPv6 — [PRD/leak-protection.md](../../PRD/leak-protection.md) M2+M3).**
  Once a session reaches `Connected`, system DNS is pointed at the resolved
  resolvers (a local `dns_servers` override in the config bundle, else whatever
  the coordinator advertises via `--dns`) and a leak-guard firewall locks
  plaintext DNS (53) / DoT (853) to those resolvers or the tunnel, plus
  (policy `auto`/`block`) drops off-tunnel IPv6 (loopback/link-local exempt).
  On **Linux**: `resolvectl` per-link DNS under systemd-resolved (else an
  `/etc/resolv.conf` swap with backup/restore) + a `ferrum_leakguard`
  `nftables` table, both through the
  [privileged helper daemon](#privileged-helper-linux) first with an
  in-process fallback. On **Windows**: inside the already-elevated helper
  service — adapter DNS via `netsh interface ipv4|ipv6 set/add dnsservers`
  (reset to DHCP on teardown) + WFP filters under a dedicated leak-guard
  provider/sublayer (distinct from the kill-switch's, so either tears down
  independently). Everything is restored on disconnect/exit — including pipe
  EOF/service stop on Windows. Unlike the kill-switch this never blocks
  ordinary traffic, and with no resolver configured or advertised the session
  runs (and logs) **DNS-unprotected** rather than breaking resolution.
  DoH-capable browsers bypass system DNS — a documented non-goal. macOS is
  deferred. See [`src-tauri/src/leakguard.rs`](src-tauri/src/leakguard.rs).
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

Opening a TUN device, changing firewall rules (kill-switch + leak guard), and
setting/restoring system DNS all need root. Rather than running the whole GUI
as root, a small daemon — [`ferrum-helper`](../../crates/helper)
— does just those things and hands results back over a Unix domain socket;
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

The `ferrum` group is **mandatory**: the daemon refuses to start if it doesn't
exist (there is no world-accessible fallback). It listens on
`/run/ferrum/helper.sock`, `chown`'d to that group (mode `0660`, inside a
`root:ferrum 0750` runtime directory), and additionally checks every
connection's peer credentials (`SO_PEERCRED`): only root, members of the group,
or a uid passed via `--allow-uid <UID>` (repeatable) are served; anyone else gets
a "not authorized" error and is logged with their uid/gid/pid. Allowed callers
are bounded too — one request per connection, a per-uid rate limit (burst 32,
2 requests/s sustained), at most 16 connections in flight, 5 s I/O timeouts, and
a 64 KiB request cap. Group membership still means "may ask root to create a TUN
device or change firewall/DNS rules", so only add users who run the Ferrum desktop
app. Without this setup the desktop still works exactly as before: run it
elevated, and it falls back to doing the privileged operations in-process.

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

**Who may drive it.** The pipe (`\\.\pipe\ferrum-helper`) is the service's
privilege boundary — anyone who can talk to it can ask LocalSystem to create a
wintun adapter or rewrite WFP filters — so it's guarded twice
([`src-tauri/src/pipe_security.rs`](src-tauri/src/pipe_security.rs)):

1. **An explicit pipe DACL**, not Windows' default pipe descriptor (which lets
   Everyone and Anonymous read):
   `D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;0x12019b;;;IU)S:(ML;;NW;;;ME)`
   — network logons denied; SYSTEM, elevated Administrators and the service
   itself (owner) full control; **interactive users** read/write only. Their
   `0x12019b` mask deliberately omits `FILE_CREATE_PIPE_INSTANCE`, which
   `GENERIC_WRITE` would include, so a user can't create their own instance of
   the pipe name and race the service for the GUI's connection. The medium
   mandatory label keeps low-integrity/sandboxed processes out, and the pipe is
   created with `PIPE_REJECT_REMOTE_CLIENTS`.
2. **A token check on every connection**, before anything is read from it: the
   service briefly impersonates the client (identification level is enough),
   opens its token and requires membership in SYSTEM, Administrators or
   INTERACTIVE, and none in NETWORK. Refused clients get `"not authorized"` and a
   log line with their pid.

The service also keeps the pipe name claimed for its whole life: the first
instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE` (startup fails if
something already squats the name), and the next instance is always created
before the current connection is handled, so the name is never free between
sessions. A connected client has 10 s to send its opening request.

In practice this means **any user logged on to the machine (console or RDP) can
connect/disconnect the tunnel** — the Windows counterpart of the Linux `ferrum`
group, scoped to "people at this machine" rather than a named group. Services,
scheduled tasks running without an interactive logon, network clients and
sandboxed processes can't.

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
