# PRD — Leak Protection: DNS & IPv6

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | Cross-cutting (Phase 3 control plane + Phase 5 clients) |
| **Status** | In progress — M1–M3 implemented (M3 Windows-side needs an elevated-host verification pass); M4 (Android + deployment) next |
| **Owner** | punarduttrajput |
| **Last updated** | 2026-07-09 |
| **Depends on** | Phase 3 coordinator (network map), Phase 5 kill-switch machinery (`ferrum_tunnel::firewall`, desktop WFP engine), `ferrum-helper` daemons |

---

## 1. Summary

While a Ferrum tunnel is up, two classes of traffic still leave the machine
outside it and reveal the user's activity to the local network / ISP:

1. **DNS.** Nothing in the desktop, CLI, or helper touches the OS resolver —
   every DNS query still goes in plaintext to the LAN/ISP resolver, exposing
   every hostname visited. The only client that sets DNS at all is Android,
   which hardcodes `1.1.1.1` in `FerrumVpnService`.
2. **IPv6.** The tunnel *supports* v6 addresses, but a v4-only tunnel on a
   network with working IPv6 leaks all v6 traffic (including AAAA-driven
   connections) via the physical interface. Today only the **opt-in**
   kill-switch stops that, and it's designed for the coordinator-unreachable
   state, not steady-state leak protection.

This PRD adds **DNS hiding** (queries forced through the tunnel to a
designated in-mesh resolver, with a firewall lock against plaintext DNS
escaping) and **IPv6 leak protection** (block-or-tunnel policy) on desktop
(Linux + Windows), the CLI, and Android — reusing the enforcement machinery
that already exists: the nftables table pattern in
`crates/tunnel/src/firewall.rs`, the WFP filter engine in
`apps/desktop/src-tauri/src/killswitch.rs`, the `ferrum-helper` privilege
boundary, and the "local override else coordinator-advertised" pattern
established by relay selection.

## 2. Goals & Non-Goals

### Goals
- G1. While connected, all system DNS resolves through the tunnel to a
  resolver the coordinator advertises (or a local config override) — the
  local network sees no plaintext DNS.
- G2. A firewall **leak guard**, engaged for the lifetime of the connection
  (distinct from the opt-in kill-switch), drops plaintext DNS (53) and DoT
  (853) that isn't going to the configured resolver or out the tunnel.
- G3. IPv6 policy per connection: `auto` (block v6 off-tunnel when the tunnel
  has no v6 address; route it when it does), `block`, `tunnel`, `off`.
- G4. DNS/IPv6 state restored exactly on disconnect — including after a crash
  (the same "namespaced table, atomic teardown" property the kill-switch has).
- G5. The unprivileged desktop GUI keeps working: enforcement goes through
  `ferrum-helper` where installed, with the existing in-process fallback.
- G6. Android stops hardcoding `1.1.1.1`; DNS comes from the same
  resolution chain as everywhere else.
- G7. A deployable in-mesh resolver: the single-VM deployment
  (`deploy/oracle-vm/`) gains a resolver reachable at a mesh address that the
  coordinator advertises.

### Non-Goals
- ❌ **DoH bypass prevention.** Browsers doing their own DNS-over-HTTPS ignore
  system DNS and are indistinguishable from normal TLS-443; blocking it means
  breaking HTTPS. Documented limitation; browser-policy hints are a possible
  follow-up.
- ❌ An exit-node / full-tunnel feature. This PRD makes DNS and v6 policy
  correct for the mesh product that exists; routing *all* traffic through a
  peer is its own future PRD.
- ❌ macOS — deferred with the rest of the Apple targets (no toolchain/host).
- ❌ Running a recursive resolver *inside* Ferrum. The resolver is an external
  component (unbound/dnsmasq) reachable over the mesh; Ferrum points at it and
  guards the path.

## 3. Background & Rationale

"Hiding DNS" only works if the queries have somewhere trustworthy to go
**through the tunnel** — Ferrum is a mesh VPN, so something on the mesh must
answer DNS. The v1 answer is the Oracle-VM deployment: the VM already runs the
coordinator + relay; it additionally runs a resolver container and a `ferrum`
mesh client, so the resolver is reachable at a mesh IP, and the coordinator
advertises that IP (`--dns`) exactly the way it advertises the relay
(`--relay`). Self-hosted users can point `[dns] servers` at any in-mesh
resolver instead.

IPv6 needs a *policy*, not just a block: the tunnel genuinely supports v6
addresses (including the Windows out-of-band `netsh` path), so when the mesh
carries v6 the right behavior is to use it — blocking is the fallback for the
common v4-only-tunnel case. `auto` picks between them from the tunnel address
family so the default is safe without configuration.

## 4. Functional Requirements

### FR1 — Control-plane DNS advertisement (M1)
- `NetworkMapResponse` gains `repeated string dns_servers` (IP addresses, not
  `ip:port` — DNS is port 53/standard).
- Coordinator `--dns <ip>[,<ip>…]` flag → `CoordinatorService::with_dns_servers`,
  mirroring `--relay`/`with_relay`. Empty (default) advertises none.
- `ControlClient::advertised_dns` surfaces it, mirroring `advertised_relay`.

### FR2 — Client config & resolution (M1)
- `[dns] servers = ["<ip>", …]` — local override, validated as IPs.
- `[leak_protection] ipv6 = "auto" | "block" | "tunnel" | "off"` — default `auto`.
- Resolution order everywhere: local `[dns] servers` if non-empty, else the
  coordinator-advertised list, else none (and a visible warning that DNS is
  unprotected). M1 resolves + logs; enforcement lands in M2/M3 (M1 does not
  change the shared `run_mesh_session` signature, so the desktop app and FFI
  are untouched until their enforcement milestones).

### FR3 — Linux DNS enforcement (M2)
- New `ferrum-tunnel` module `dns` (Linux): set the resolved servers on the
  tunnel interface while connected, restore on disconnect. Primary path
  `resolvectl dns <iface> <servers…>` + `resolvectl domain <iface> '~.'`
  (routing-domain so the tunnel resolver wins under systemd-resolved);
  fallback: swap `/etc/resolv.conf` with backup/restore for non-resolved
  distros.
- New `HelperRequest::{SetDns, RestoreDns}` so the unprivileged GUI works;
  in-process fallback as with TUN/kill-switch.

### FR4 — Leak-guard firewall (M2 Linux, M3 Windows)
- A second nftables table (`ferrum_leakguard`), engaged on connect and torn
  down on disconnect, independent of the kill-switch table:
  - drop outbound udp/tcp dport 53 and 853 unless the daddr is a configured
    DNS server or the packet egresses the tunnel interface;
  - when the effective v6 policy is *block*: drop all v6 output except
    loopback, link-local/ICMPv6-ND, and the tunnel interface.
- Pure rule-generation functions + unit tests, same style as `firewall.rs`.
- Windows: reuse the WFP machinery (`FilterSpec`, transactional install,
  teardown by filter-id) in a second provider/sublayer: block remote-port
  53/853 except to configured DNS or via the tunnel interface LUID; v6 *block*
  = default-block at the `ALE_AUTH_CONNECT_V6` layer with a tunnel-LUID +
  loopback permit.
- New `HelperRequest::{LeakGuardEngage, LeakGuardDisengage}` (Linux daemon)
  and the equivalent named-pipe messages (Windows service).

### FR5 — Windows DNS enforcement (M3)
- Static resolvers on the wintun adapter via `netsh interface ip[v6] set dns`
  (the same out-of-band pattern `device.rs` uses for v6 addresses); restore
  to DHCP on disconnect.

### FR6 — Android (M4)
- Replace hardcoded `addDnsServer("1.1.1.1")` with the resolved DNS list.
- Make the existing `addRoute("::", 0)` policy-driven: on Android, routing
  `::/0` into the VPN *is* the v6 block when the mesh doesn't carry v6.

### FR7 — Deployment (M4)
- `deploy/oracle-vm/`: resolver container (unbound or dnsmasq) + a `ferrum`
  mesh client on the VM so the resolver has a mesh address; `--dns` wired
  into the compose env; README section.

### FR8 — UX & visibility (M5)
- Desktop GUI: "DNS protected" / "IPv6 blocked (or tunneled)" status chips;
  `[dns]`/ipv6-policy fields in the Advanced section; warning state when
  connected with no DNS protection.

## 5. Non-Functional Requirements

- NFR1. **Exact restore.** Disconnect (including crash + next-start cleanup)
  restores prior DNS settings and removes the leak-guard table/filters —
  namespaced tables/sublayers so teardown never touches unrelated rules.
- NFR2. **Captive-portal compatibility.** The leak guard engages only once
  the tunnel is up (post-handshake), never at boot; disconnecting always
  clears it. (The kill-switch remains the opt-in stronger mode.)
- NFR3. **NFR5 privacy carries over.** No hostnames, query names, or per-user
  DNS data in logs/metrics/spans — aggregate counters only, if any.
- NFR4. Unit-testable without root: rule/argument generation stays pure, as
  in `firewall.rs`; privileged paths verified via the documented root/elevated
  developer steps.

## 6. Milestones

| # | Scope | PR |
|---|---|---|
| **M1** ✅ | Protocol + config plumbing: proto `dns_servers`, coordinator `--dns`/`with_dns_servers`, `ControlClient::advertised_dns`, `[dns]` + `[leak_protection]` config blocks, resolution helper + logging in `up-mesh`/`run_mesh_session`. No enforcement. | `leak-protection-m1` |
| **M2** ✅ | Linux enforcement: `ferrum-tunnel::dns` (resolvectl + resolv.conf fallback), `ferrum_leakguard` nftables table (DNS lock + v6 block), helper-proto messages + daemon handlers, desktop + CLI wiring. (The shared `run_mesh_session` signature ended up untouched: enforcement rides the existing `Connected`/`Disconnected` events — CLI via `client.subscribe()`, desktop in its event loop — so the FFI surface is unchanged until a platform needs more.) | `leak-protection-m2` |
| **M3** ✅ | Windows enforcement: netsh DNS on the wintun adapter, WFP leak-guard sublayer (own provider/sublayer, `FilterSpec` extensions), engaged from the helper service's event loop on `Connected` (no new pipe messages needed — the service already owns the session). Written/tested on Linux (pure rule/arg builders + WFP names verified against the `windows` crate source); needs a compile + live pass on a Windows host. | `leak-protection-m3` |
| **M4** | Android DNS/v6 policy + oracle-vm resolver + `--dns` deployment wiring. | `leak-protection-m4` |
| **M5** | GUI status/config surface, netns leak tests in `verify-linux.sh`, docs. | `leak-protection-m5` |

## 7. Acceptance Criteria

- AC1 (M1): a coordinator started with `--dns 10.99.0.53` yields
  `advertised_dns == ["10.99.0.53"]` on clients; a client with
  `[dns] servers = ["10.8.0.2"]` resolves to its override instead; configs
  without the new blocks parse unchanged.
- AC2 (M2, root): with the tunnel up on Linux, `resolvectl status` shows the
  tunnel resolver + `~.` on the ferrum interface; `dig @<LAN resolver>`
  times out; `dig` via the default route resolves through the mesh resolver;
  `curl -6` to a v6-only host fails under *block*; disconnect restores both.
- AC3 (M3, elevated): the Windows equivalents via `Get-DnsClientServerAddress`
  and a v6 connectivity check.
- AC4 (M4): Android `VpnService` sessions carry the advertised DNS; the
  oracle-vm compose brings up a resolver reachable at its mesh IP.
- AC5 (M5): `verify-linux.sh` gains an opt-in leak-test (`TEST_LEAKGUARD=1`)
  asserting AC2's observable behavior in netns; CI stays green across the
  feature matrix.

## 8. Risks & Mitigations

- **DoH bypass** — accepted, documented (Non-Goal). Revisit with
  browser-policy guidance later.
- **resolv.conf diversity** (systemd-resolved vs NetworkManager vs static) —
  resolvectl primary + file-swap fallback; restore path tested for both;
  stale-state cleanup on next start mirrors the kill-switch's
  delete-table-first idempotence.
- **Blocking v6 breaks LAN/link-local services** — the block rules always
  exempt loopback + link-local/ICMPv6-ND; `off` remains available.
- **No in-mesh resolver deployed** → DNS "protected" but dead. Resolution
  chain warns loudly when no resolver is configured/advertised, and the GUI
  shows the unprotected state rather than pretending.

## 9. Feeds Into

- A future exit-node/full-tunnel PRD (the leak guard is a prerequisite).
- The desktop GUI PRD's remaining milestones (status chips land there).
