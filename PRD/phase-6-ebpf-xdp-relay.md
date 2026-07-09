# PRD — Phase 6 Addendum: eBPF/XDP Relay Fast Path

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | 6 of 6 — Scale & Acceleration (FR1 drill-down) |
| **Status** | Implemented (M1–M4); M5 partially done — the kernel program builds, passes the verifier, and attaches on a real Linux host (2026-07-09); live-traffic verification + the NFR1 benchmark remain |
| **Owner** | punarduttrajput |
| **Last updated** | 2026-07-09 |
| **Depends on** | [phase-6-scale-acceleration.md](phase-6-scale-acceleration.md) FR1; the Phase 4 relay (`RelayServer` / `RelayMeshTransport`, `crates/transport/src/relay.rs`) |

---

## 1. Summary

[phase-6-scale-acceleration.md](phase-6-scale-acceleration.md) FR1 calls for
"XDP program (via `aya`) on relays/gateways for fast-path encrypted-packet
forwarding" with a ≥10 Gbps/node target (NFR1), naming a `crates/relay`
component that doesn't exist as such — the actual relay is `RelayServer` in
`crates/transport/src/relay.rs` (Phase 4 M3). This addendum reconciles that
with the real implementation and specifies exactly what the fast path does:
a userspace-controlled, in-kernel XDP forwarder for the relay's `Data`
frames, with the existing userspace `RelayServer` staying as the control
plane and the fallback path for everything the XDP program doesn't handle.

**This addendum also documents a hard environment constraint up front**: it
was authored on a Windows host with no LLVM/clang, no `bpf-linker`, no
`bpfel-unknown-none` Rust target, and no WSL — i.e. no way to compile,
link, load, or run an actual eBPF program, or even syntax-check one against
its real target. That's categorically different from every other
Linux-gated piece of this codebase (the GSO/GRO `unsafe` FFI in
`ferrum-transport` at least cross-compile-checks here via the installed
`x86_64-unknown-linux-gnu` GNU target — see the CLAUDE.md environment note).
The design below is scoped so that everything *except* the actual `.o` the
kernel loads can still be written, compiled, and unit-tested on this host;
the kernel program itself is a fully-specified, reviewed sketch pending a
real Linux build+load+verify pass. See §10 Risks.

---

## 2. Goals & Non-Goals

### Goals
- G1. An XDP program that fast-paths the relay's `Data` frames (Phase 4's
  `TAG_DATA = 0x02`) entirely in-kernel — no round trip to userspace — for
  any flow the control plane has already established.
- G2. The existing userspace `RelayServer` remains the **single source of
  truth**: it owns registration, roaming, and eviction exactly as today; the
  XDP path only mirrors a derived, disposable copy of that state into BPF
  maps. Restarting the userspace relay (or the whole box) never leaves the
  kernel path forwarding to a stale destination — see FR3.
- G3. Everything the XDP program can't (or shouldn't) handle safely falls
  through to the existing userspace path unchanged: `Register` frames,
  IPv6 (v1 is v4-only — see Non-Goals), malformed frames, and any Data
  frame for a flow not yet mirrored into the maps.
- G4. Opt-in and additive: `ferrum relay` behaves exactly as it does today
  unless a new flag explicitly requests the XDP path, and the `xdp` Cargo
  feature is off by default so no existing build (including this host's)
  is affected.
- G5. A design precise enough that a maintainer with a real Linux box can
  build, attach, and benchmark it against the existing userspace relay
  without having to make further architectural decisions.

### Non-Goals
- ❌ IPv6 fast-path (v1 is IPv4-only; an IPv6 Data frame always falls
  through to userspace — the relay already supports it there unchanged).
- ❌ On-link neighbor (ARP) resolution per destination. v1 always forwards
  fast-pathed packets to the **default gateway's MAC** and lets it route
  (the same technique DERP-alternative/L4LB XDP forwarders like Katran
  use) — correct but not maximally efficient for same-subnet peers. A
  later increment can add a per-destination ARP-resolved neighbor map.
- ❌ Anycast, autoscaling, or any other Phase 6 FR (this addendum is FR1
  only).
- ❌ Changing the relay wire protocol (§3 in `relay.rs`'s own doc comment)
  or `RelayMeshTransport`'s client-side behavior — the fast path is purely
  a server-side, in-kernel acceleration of the existing protocol.
- ❌ AF_XDP as an alternative design — considered (redirect matched
  packets into an AF_XDP socket and let userspace do the same rewrite with
  zero-copy, rather than rewriting headers in-kernel) and rejected for v1
  because it still round-trips every packet through userspace, which is a
  weaker fit for the ≥10 Gbps line-rate framing in NFR1. Noted as a
  fallback design in §10 if the full in-kernel rewrite proves too fragile
  against the verifier on a real kernel.

---

## 3. Background & Rationale

The Phase 4 relay (`RelayServer::serve`) does one `recv_from` + one
`send_to` per forwarded frame — two syscalls, a socket-buffer copy each way,
and a full traversal of the kernel network stack in both directions. That's
adequate for NAT-traversal fallback traffic but caps out well below the
line rates Phase 6 targets. XDP runs in the NIC driver's receive path,
before the kernel allocates an `sk_buff` or touches the network stack at
all — a program that recognizes a packet as "already-known Data frame,
forward to X" can rewrite it and re-transmit (`XDP_TX`) without ever
reaching userspace, which is how this reaches the ≥10 Gbps/node target
Phase 4's userspace design structurally cannot.

The relay's own doc comment already makes this tractable: it "never sees
plaintext" and payloads are opaque, so the fast path never needs to inspect
or act on anything below the relay's own tiny framing (a 1-byte tag + a
32-byte key) — no crypto, no WireGuard-awareness, needed in-kernel at all.

---

## 4. Users & Use Case

- **Primary users:** operators running `ferrum relay` on Linux boxes that
  see meaningful relayed traffic volume (NAT-traversal fallback for peers
  behind symmetric NATs/hostile firewalls — Phase 4's use case) and want it
  to scale past userspace-socket throughput without operating a different
  piece of software.
- **Use case:** an operator adds `--xdp-iface eth0` to their existing
  `ferrum relay` invocation. Nothing else changes from their side — same
  binary, same config, same wire protocol clients already speak. Once
  enough peers have registered and exchanged a few frames (warming the
  kernel maps), the bulk of relayed traffic never reaches the relay
  process's own userspace loop again.

---

## 5. Functional Requirements

### FR1 — XDP Program: Fast-Path Match & Forward
- Attached to one named interface (`--xdp-iface <name>`), generic (SKB)
  mode by default — driver/native mode is a deployment-time tuning choice,
  not a code difference.
- On each received frame: parse Ethernet → must be IPv4 (else `XDP_PASS`)
  → IPv4 → must be UDP with destination port == the relay's listen port
  (else `XDP_PASS`) → UDP payload → must be at least `1 + 32` bytes with
  tag byte `TAG_DATA (0x02)` (else `XDP_PASS`; this is exactly how
  `Register` frames and anything malformed fall through).
- Two BPF map lookups, mirroring `Clients::register`'s two tables exactly:
  1. `ADDR_TO_KEY[(src_ip, src_port)]` → sender's public key (needed to
     stamp the *source* key into the rewritten outgoing frame, matching
     `RelayServer::serve`'s `by_addr.get(&from)` lookup).
  2. `KEY_TO_ADDR[dst_key]` (the 32 bytes immediately after the tag) →
     current destination `(ip, port)`, matching `by_key.get(&dst_key)`.
  - Either miss → `XDP_PASS` (falls through to userspace, which drops it
    exactly as it does today for an unknown sender/destination — FR3
    keeps this consistent by construction, not by duplicating drop logic
    in the kernel program).
- On a double hit: rewrite in place (no length change, so no need to grow
  or shrink the buffer):
  - Ethernet: destination MAC ← the gateway MAC (`GATEWAY` map, FR2);
    source MAC ← this relay's own MAC.
  - IPv4: source address ← this relay's own IP; destination address ←
    the resolved destination IP; recompute the IPv4 header checksum.
  - UDP: source port ← the relay's own listen port (unchanged — the
    existing relay always sends from the one socket it's bound on);
    destination port ← the resolved destination port; UDP checksum is
    zeroed (valid for IPv4 per RFC 768, and this is the standard XDP
    L4LB shortcut — Katran does the same).
  - Payload: overwrite the 32-byte key field with the *sender's* key
    (from lookup 1) — this is the exact transformation
    `RelayServer::serve` does today (`data_frame(&src_key, payload)`).
  - Return `XDP_TX` (bounce back out the same interface).
- Any bounds check the eBPF verifier requires (packet-length checks before
  every header/field access) is a **correctness requirement of the
  program itself**, not an implementation detail — the verifier will
  reject a program that reads past a self-reported bound. §10 flags this
  as the primary Linux-side review item, since it can't be checked here.

### FR2 — Gateway MAC Resolution (Control Plane)
- The userspace loader resolves the outbound interface's default gateway
  and its MAC (Linux ARP/neighbor table — `ip route`/`ip neigh` equivalent
  via `rtnetlink`) at startup and refreshes it periodically (staleness
  handled by re-resolving on a timer, not by the kernel program).
- Pushed into a 1-entry `GATEWAY` BPF array map: `{relay_mac, relay_ip,
  gateway_mac}`. If this map is empty (not yet resolved), the XDP program
  treats every packet as a fast-path miss (`XDP_PASS`) — the userspace
  relay keeps working exactly as today until resolution succeeds.

### FR3 — Userspace Mirrors State Into the Maps (Not the Reverse)
- `RelayServer` remains the only place that decides who's registered and
  at what address — this requirement exists specifically so the kernel
  and userspace views of the world can never diverge into the kernel
  forwarding to a stale/attacker-controlled destination.
- Every call to `Clients::register` (a `Register` frame handled today —
  unchanged) additionally pushes `(addr → key)` into `ADDR_TO_KEY` and
  `(key → addr)` into `KEY_TO_ADDR`, and — matching `register`'s existing
  "clear any stale mapping" behavior exactly — deletes the old entries
  first when a key roams to a new address or an address is reused by a
  different key.
- No new eviction/expiry policy is introduced: the mirrored maps track
  `RelayServer`'s existing table 1:1, including the keepalive-driven
  freshness the Phase 4 relay already relies on (`KEEPALIVE = 25s`).
- On process start (including a restart), the maps start empty — a cold
  BPF map on a warm interface behaves exactly like a cold `Clients` table:
  every packet is a fast-path miss until the corresponding peer's next
  keepalive re-registers it, which is the *same* recovery behavior the
  Phase 4 relay already has today (a restarted relay "simply re-learns
  clients from their next register/keepalive" — `RelayServer`'s own doc
  comment).

### FR4 — Fast-Path Metrics
- A small `PerCpuArray<u64>` in the eBPF program counts fast-pathed frames
  and bytes (aggregate only — no per-flow/per-key data ever leaves the
  kernel map, matching NFR5's existing privacy bar for relay metrics).
- The userspace loader periodically sums the per-CPU counters and renders
  them as two **new, separate** counters —
  `ferrum_relay_xdp_frames_forwarded_total` /
  `ferrum_relay_xdp_bytes_forwarded_total` — rather than adding a label to
  the existing `ferrum_relay_frames_forwarded_total` /
  `ferrum_relay_bytes_forwarded_total` (deliberately: those two already
  have operators/dashboards potentially depending on their exact
  unlabeled shape, and this repo's own `relay_metrics_render_in_prometheus_format`
  test asserts exact-match lines against them — adding a label would be a
  breaking change for zero benefit over a new metric name).

### FR5 — CLI & Feature Gating
- New flags on `ferrum relay`: `--xdp-iface <name>` (enables the fast
  path, attaching to this interface) and `--xdp-program <path>` (the
  compiled `.o` to load; see §7 for why this is a runtime path rather
  than something baked in at compile time).
- Both are no-ops unless the `xdp` Cargo feature is built (`ferrum-cli
  --features xdp`, which forwards to `ferrum-transport/xdp`), and that
  feature's `aya` dependency is declared `[target.'cfg(target_os =
  "linux")'.dependencies]` — so on any non-Linux host (including this
  one) it's simply never fetched or compiled, matching the existing
  `libc`-for-Linux-GSO/GRO pattern in the same crate.
- Without `--xdp-iface`, `ferrum relay` is byte-for-byte the same as
  before this addendum.

---

## 6. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR1 | Fast-path throughput | Inherits Phase 6's ≥10 Gbps/node target — to be measured on a real Linux host, not claimed here |
| NFR2 | Never diverge from userspace state | The kernel maps are a strict, always-overwritable mirror of `RelayServer`'s tables (FR3) — no independent kernel-side registration/eviction logic |
| NFR3 | Fail open, not closed | Any XDP program error, unresolved gateway, or map miss results in `XDP_PASS` (userspace handles it) — never a silent drop the existing relay wouldn't also produce |
| NFR4 | No protocol change | Wire-compatible with every existing client (`RelayMeshTransport`) with zero changes on that side |
| NFR5 | Privacy | Fast-path metrics stay aggregate-only (FR4) — no key/address ever appears outside the BPF maps themselves |
| NFR6 | Default-off | The `xdp` feature and its `aya` dependency touch zero existing builds when not explicitly enabled |

---

## 7. Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │  ferrum relay --xdp-iface eth0                │
                    │  (crates/cli -> ferrum-transport, `xdp` feature)│
                    └───────────────────┬───────────────────────────┘
                                        │
        ┌───────────────────────────────┼────────────────────────────────┐
        ▼                               ▼                                ▼
 RelayServer::serve()          relay_xdp loader (aya, userspace)   Prometheus /metrics
 (unchanged Phase 4 code:      - loads relay-ebpf's compiled .o     (existing RelayMetrics,
  Register/Data handling,        from --xdp-program, attaches       gains a `path` label —
  Clients table, keepalive,      to --xdp-iface                     FR4)
  drop-unknown logic)          - on every Clients::register/roam,
        │                        mirrors (addr<->key) into the
        │                        ADDR_TO_KEY / KEY_TO_ADDR maps
        │                      - resolves + refreshes the GATEWAY
        │                        map entry (FR2)
        │                      - sums per-CPU fast-path counters
        └──────────────┬────────┘
                        │ every packet the XDP program XDP_PASSes
                        ▼
              (same recv_from/send_to loop as today)

 ── kernel space, on the NIC's rx path ──────────────────────────────────
 relay-ebpf (aya-ebpf, #[xdp] program, standalone workspace — NOT part of
 the main cargo workspace, matching apps/desktop's own-workspace pattern):
   parse Eth/IPv4/UDP/frame-tag → ADDR_TO_KEY + KEY_TO_ADDR lookups →
   rewrite Eth/IPv4/UDP/key-field → XDP_TX,  or XDP_PASS on any miss/mismatch
```

### Files
- `crates/relay-xdp-common` (new workspace member) — `#![no_std]`-compatible
  plain types shared by both sides with **zero** `aya`/`aya-ebpf`
  dependency, so it builds and unit-tests on any host including this one:
  - `AddrKey` (packed `{ ip: u32, port: u16 }`, IPv4-only per Non-Goals)
  - `GatewayInfo` (`{ relay_mac: [u8; 6], relay_ip: u32, gateway_mac: [u8; 6] }`)
  - The frame-tag/key-length constants, re-derived from (and unit-tested
    against) `relay.rs`'s existing `TAG_DATA`/`KEY_LEN` values so the two
    can never silently drift apart.
- `relay-ebpf/` (new, **top-level**, its own standalone `[workspace]` —
  excluded from the root workspace exactly like `apps/desktop/src-tauri`,
  because it needs a `bpfel-unknown-none` target + nightly + `bpf-linker`
  that most hosts building the rest of this repo (including CI as
  configured today) don't have and shouldn't be forced to install) — the
  `#[xdp]` program itself (FR1), depending on `aya-ebpf`, `aya-log-ebpf`,
  and `ferrum-relay-xdp-common` (a normal path dependency — cross-workspace
  path deps don't require shared-workspace membership).
- `crates/transport/src/relay_xdp.rs` (new) — the userspace loader (FR2–4),
  `#[cfg(target_os = "linux")]`, behind the new `xdp` feature.
- `crates/transport/src/relay.rs` — minimal hook points added to
  `RelayServer`/`Clients::register` so the loader can observe
  register/roam events; the existing forwarding, drop, and metrics logic
  is untouched.
- `crates/cli/src/main.rs` — `--xdp-iface`/`--xdp-program` flags (FR5).

### Key dependencies
`aya-ebpf` + `aya-log-ebpf` (relay-ebpf's own workspace only); `aya`
(userspace loader, Linux-target-gated in the main workspace, matching the
existing `libc` pattern).

---

## 8. Milestones

1. **M1** — `ferrum-relay-xdp-common`: shared types + unit tests (buildable
   and testable on any host, including this one).
2. **M2** — `relay-ebpf`: the XDP program source, in its own standalone
   workspace with a README documenting the exact Linux build/attach steps.
   **Update 2026-07-09: built, verifier-accepted, and attached on a real
   Linux host** — compiled clean on the first attempt; the verifier's one
   rejection (the checksum carry-fold `while` loop, "infinite loop
   detected") is fixed as a fixed two-fold. See `relay-ebpf/README.md`.
3. **M3** — `relay_xdp.rs` userspace loader: map population mirroring
   `Clients::register`, gateway MAC resolution, stats merge. Cross-compile-
   checked here via the installed `x86_64-unknown-linux-gnu` target
   (can't run, but syntax/type-checks — matching the GSO/GRO precedent).
4. **M4** — CLI flags + feature wiring (FR5); confirm every existing test
   and build on this host is unaffected with the feature off.
5. **M5 — Linux follow-up (partially done, 2026-07-09):** ✅ built for real
   (rustup nightly + the prebuilt `bpf-linker` v0.10.4 musl binary), ✅
   loaded + verifier-accepted + attached via `--xdp-iface lo
   --xdp-program …` (`relay xdp fast path enabled`; two first-load bugs
   fixed — the loader's `EbpfLogger` drop and the checksum carry-fold
   loop, both logged in STATUS.md). ⏳ Remaining: **live traffic** through
   the fast path (XDP doesn't fire on loopback — needs netns+veth or two
   hosts), the Wireshark checksum capture check, and the NFR1 benchmark
   against the userspace relay.

---

## 9. Acceptance Criteria

- ✅ `ferrum relay` with no `--xdp-*` flags is byte-for-byte unchanged
  behavior, and every existing `relay.rs` test still passes.
- ✅ `cargo build --workspace` / `cargo test --workspace` on this host are
  completely unaffected (the `xdp` feature is off by default; `aya` is
  Linux-target-gated).
- ✅ `ferrum-relay-xdp-common`'s unit tests pass on this host.
- ✅ `relay_xdp.rs` cross-compile-checks clean on
  `--target x86_64-unknown-linux-gnu`.
- ✅ **Done on a real Linux host (2026-07-09):** `relay-ebpf` compiles
  under `bpf-linker` and **passes the kernel verifier** when loaded via
  the production loader (attached to `lo` in SKB mode; clean teardown).
- ⏳ **Still deferred** (tracked, not claimed done): live relay `Data`
  frames actually take the fast path (needs netns+veth or two hosts —
  XDP doesn't fire on loopback), fast-pathed packets carry a valid IPv4
  checksum (Wireshark check), and the NFR1 throughput target holds
  against the existing userspace relay as a baseline.

---

## 10. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| **This host cannot build, load, or run the eBPF program at all** — no LLVM/`bpf-linker`/BPF target/WSL, unlike every prior Linux-only feature in this repo | The kernel program (§FR1) is unverified even at a syntax level until a real Linux host builds it | Scoped explicitly (§1, §9): everything else (common types, loader, CLI, control-plane mirroring) is written, built, and tested here; `relay-ebpf` ships as a complete, carefully-reviewed source tree + a README with exact build steps, not claimed as working |
| eBPF verifier rejection (bounds checks, helper call constraints) is common and can't be checked without a real kernel | The program as written may need iteration once actually built | `relay-ebpf/README.md` calls out exactly which functions need verifier-focused review (the header-rewrite bounds checks in FR1); the fallback is always `XDP_PASS`, so a rejected/buggy program's failure mode during development is "no acceleration," not "broken relay" |
| Gateway-MAC-only forwarding (Non-Goals) means same-subnet peers hairpin through the router instead of direct L2 delivery | Suboptimal but not incorrect — extra latency/hop, not lost packets | Documented explicitly as a v2 follow-up (per-destination ARP-resolved neighbor map), not attempted in v1 to keep the kernel program's blind-implementation risk bounded |
| Full in-kernel header rewrite (chosen design) proves too fragile against a real verifier | Would block the ≥10 Gbps framing this addendum targets | AF_XDP-redirect-to-userspace is documented as the fallback design (Non-Goals) — same map-based flow classification, but the actual header rewrite happens in userspace with zero-copy instead of in the kernel program |
| Kernel/NIC driver variance (generic vs. native XDP mode, older kernels lacking `XDP_TX` semantics needed here) | Feature may not work identically everywhere | v1 defaults to generic (SKB) mode, the most broadly compatible; native/driver mode is a deployment tuning choice documented in the README, not a code branch |

---

## 11. Feeds Into

Closes out [phase-6-scale-acceleration.md](phase-6-scale-acceleration.md)
FR1/M4 to the extent buildable without a Linux host with a working
`bpf-linker` toolchain; NFR1 (≥10 Gbps/node) stays open pending the M5
Linux follow-up in §8. Reconciles that PRD's `crates/relay` naming with the
actual Phase 4 location (`ferrum-transport`'s `RelayServer`).
