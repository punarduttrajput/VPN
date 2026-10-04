# Audit readiness: hand-rolled primitive inventory and third-party audit plan

**Ticket:** [SEC-009](../../tickets/security-hardening/SEC-009-third-party-audit-plan.md) ·
**PRD:** [security-hardening.md](../../PRD/security-hardening.md) FR9 / AC8 ·
**Status:** draft, 2026-09-29 · **Companion:** threat model (SEC-010, pending)

Ferrum has never had an independent audit, and it ships a number of
security-relevant pieces it wrote itself rather than taking from vetted crates.
This document does two things:

1. **Inventory** every hand-rolled security primitive, with its risk and a
   disposition: **(A) replace** with a vetted crate, **(R) schedule for external
   review**, or **(K) keep, with a stated rationale**.
2. **Plan** the third-party audit: scope, pre-audit fixes, owners, dates and the
   budget ask.

Building the inventory also turned up several **real defects** that no existing
ticket covered. Each is confirmed against the code and filed as a follow-up
ticket (SEC-011 to SEC-018, see §3). Fix them *before* the audit, so the audit
budget goes on what we can't find ourselves.

## 1. Method and baseline

The inventory is a code read of the whole tree (`crates/`, `apps/desktop`,
`relay-ebpf/`, `clients/android`), done on 2026-09-29 against `main` at
`9f07da3`. It covers parsers of untrusted input, cryptographic constructions,
authentication and authorization logic, privilege boundaries, firewall rule
generation, and every `unsafe` block. The most severe findings were re-checked
by hand.

Security fixes already in review (branches pushed, not yet merged to `main`)
are credited below as **pending**:

| Ticket | Branch | Closes |
|---|---|---|
| SEC-005 | `sec-005-helper-privilege-boundary`, `sec-005-windows-pipe-acl` | helper 0666 fallback, no `SO_PEERCRED`, 4 GiB request allocation, no helper rate limit/timeouts; Windows pipe DACL + client token check |
| SEC-006 | `sec-006-control-plane-rate-limiting` | no coordinator rate limits or watch-stream caps |
| SEC-007 | `sec-007-transport-cert-lifecycle` | no TLS pin rotation (next-pin sets) |
| SEC-008 | `sec-008-vendored-binary-provenance` | unpinned `wintun.dll`, `bpf-linker`, Gradle wrapper |

**Cross-cutting gaps** (all tracked in SEC-017):

- No fuzzing or property testing anywhere. No `fuzz/` targets and no
  `proptest`/`quickcheck`/`arbitrary` dependency. Every parser test is a
  hand-written example.
- No dependency-vulnerability or licence gate: no `cargo-deny` or
  `cargo-audit` in CI, and no dependabot/renovate.
- Uneven `unsafe` lints:
  - `ferrum-core` and `ferrum-coordinator` `forbid(unsafe_code)`.
  - `ferrum-transport` `deny`s it, with 5 local allows.
  - `ferrum-tunnel`, `ferrum-helper`, the desktop app and `relay-ebpf` carry no
    lint at all.

## 2. Inventory

Risk is Ferrum's own rating: **H**igh, **M**edium or **L**ow. It combines exposure
(network, local or privileged) with consequence. "Untrusted" means bytes an
attacker controls.

### 2.1 Summary

| # | Primitive | Where | Input / privilege | Risk | Disposition | Follow-up |
|---|---|---|---|---|---|---|
| P1 | Mesh inbound crypto-routing | `tunnel/src/mesh.rs` `handle_inbound`, `runner.rs` | untrusted datagrams, post-decrypt | **H** | R, plus fix | **SEC-011** |
| P2 | nftables script generation | `tunnel/src/firewall.rs`, `leakguard.rs` (+ `dns.rs`) | helper requests, runs **as root** | **H** | R, plus fix | **SEC-012** |
| P3 | Privileged helper daemon + wire protocol | `helper/src/unix.rs`, `tunnel/src/helper_proto.rs` | local socket, **root** | **H** | R (SEC-005 pending), plus fix | **SEC-012** |
| P4 | Coordinator authorization (key binding, ACL, revocation) | `coordinator/src/service.rs`, `registry.rs`, `policy.rs` | untrusted RPCs | **H** | R, plus fix | **SEC-013** |
| P5 | OIDC JWT verification on `ring` | `coordinator/src/auth.rs` | untrusted tokens | **H** | **A** (`jsonwebtoken`) | **SEC-014** |
| P6 | Admin API authorization | `coordinator/src/admin.rs` | untrusted HTTP | M | R, plus fix | **SEC-014** |
| P7 | TLS identity, DER/SPKI parser, pinned verifier | `transport/src/tls.rs`, `fingerprint.rs` | untrusted server certs | M | R; A for the SPKI parser | **SEC-016** |
| P8 | Relay wire protocol + register challenge (SEC-003) | `transport/src/relay.rs`, `relay_auth.rs` | untrusted internet UDP | M | **R** (novel construction) | review; `ct_eq` in SEC-016 |
| P9 | MASQUE CONNECT-UDP proxy | `transport/src/masque.rs` | untrusted QUIC/H3 | M | R, plus fix | **SEC-015** |
| P10 | SCM_RIGHTS fd passing | `tunnel/src/fdpass.rs` | local, **root** sender | M | **A** (`rustix`/`nix`) | **SEC-016** |
| P11 | UDP GSO/GRO `unsafe` FFI | `transport/src/udp.rs` | untrusted datagrams | M | **A** (`quinn-udp`) | **SEC-016** |
| P12 | `FdTun::from_fd` (safe fn over a raw fd) | `tunnel/src/device.rs` | FFI callers | M | **A** (make it `unsafe fn`) | **SEC-016** |
| P13 | Windows WFP kill-switch / leak guard | `apps/desktop/src-tauri/src/killswitch.rs`, `leakguard.rs` | **LocalSystem** | M | **R** (no vetted wrapper exists) | review |
| P14 | eBPF/XDP relay fast path | `relay-ebpf/src/main.rs`, `relay-xdp-common` | every NIC packet, **in kernel** | M | R, plus fix | **SEC-018** |
| P15 | STUN client | `transport/src/stun.rs` | untrusted UDP | L | K, plus fuzz | **SEC-017**, SEC-018 |
| P16 | Metrics / health HTTP servers | `coordinator/src/main.rs`, `cli/src/main.rs` | untrusted TCP | L | **A** (hyper/axum, already deps) | **SEC-018** |
| P17 | Padding framing + timing jitter | `transport/src/pad.rs`, `jitter.rs` | untrusted datagrams | L | K | SEC-018 (RNG) |
| P18 | Rate limiters (relay, coordinator, helper) | `relay_auth.rs`; SEC-005/006 pending | untrusted | L | K | none |
| P19 | Hex pin parser | `transport/src/fingerprint.rs` | config + coordinator | L | K | none |
| P20 | Android credential storage | `clients/android/.../KeystoreHelper.kt` | device-local | L | not hand-rolled; K | AND-004, AND-012 |

### 2.2 Details

#### P1 Mesh inbound crypto-routing (**H**, SEC-011)

- **What it does.** `run_mesh` sends each inbound datagram to whichever peer's
  WireGuard session decrypts it, then writes the plaintext to the TUN.
- **Defect (confirmed).** The inner packet's **source address is never checked
  against that peer's `allowed_ips`**. boringtun returns it
  (`Action::WriteToTun(pkt, ip)`) and it is discarded as `_ip`. The
  point-to-point `runner.rs` does the same.
- **Impact.** Standard WireGuard crypto-routing drops such packets. Without the
  check, any authenticated mesh peer can inject packets carrying *another*
  peer's tunnel IP. That defeats source-IP trust and the coordinator's
  per-device ACL intent.
- **Disposition.** Fix now, then have the review confirm it.

#### P2 nftables script generation (**H**, SEC-012)

- **What it does.** `firewall.rs` and `leakguard.rs` build an `nft -f -` script
  by string templating and run it as root.
- **Defect (confirmed).** The tunnel interface name is interpolated **unescaped**
  into `oifname "{iface}"`, and the helper passes the caller's `iface` through
  unvalidated. A caller allowed on the helper socket can therefore inject
  arbitrary nft statements as root, for example a closing quote followed by a
  newline and `flush ruleset`. That can disable the host firewall.
- **What is already safe.** IP addresses are parsed as `IpAddr` first. `dns.rs`
  passes `iface` as an argv element, not through a shell.
- **Disposition.** Validate interface names at the helper boundary and in the
  generators (IFNAMSIZ, `[A-Za-z0-9_.-]`). Consider the JSON (`nft -j`) or
  netlink API later.

#### P3 Privileged helper daemon and wire protocol (**H**, SEC-005 pending + SEC-012)

- **Already fixed in review (SEC-005).** The 0666 fallback, the missing
  peer-credential check, the unbounded 4 GiB request allocation, and the
  absence of rate limits and timeouts.
- **Still open (confirmed).**
  - The TUN fd returned by `device::open_raw` is **never closed** after being
    sent. `fdpass::send_with_fd` only borrows it. Every `OpenTun` leaks a
    descriptor in the root daemon and keeps the interface alive after its client
    is gone.
  - TUN `name`, address and MTU are otherwise unvalidated (see P2).
- **Disposition.** External review of the full privilege boundary once SEC-005
  and SEC-012 land.

#### P4 Coordinator authorization (**H**, SEC-013)

- **What exists.** SEC-002 binds an authenticated identity to its first public
  key, but only on `RegisterDevice` and `RotateKey`.
- **Gaps (confirmed for `PublishCandidates`).**
  - These RPCs take a caller-supplied `public_key` without checking it belongs
    to the caller: `PublishCandidates`, `GetNetworkMap`, `WatchNetworkMap`.
    Any authenticated device can therefore overwrite another device's ICE
    candidates or read another device's ACL-filtered map.
  - `RelayHeartbeat` lets any authenticated caller advertise the relay that is
    pushed to the whole mesh. It needs a relay role.
  - Admin revoke (`Registry::remove`) leaves the identity binding in place, and
    there is no denylist, so a revoked device's token re-registers at once.
- **Disposition.** Fix, then review the ACL engine (`policy.rs`).

#### P5 OIDC JWT verification (**H**, SEC-014, replace)

- **What it does.** Hand-written RS256/ES256 verification on `ring`, against a
  static JWKS. Algorithm and key type are matched together, so there is no
  alg-confusion, `none` or HS256 path. It was built this way only because the
  original host was offline.
- **Findings.**
  - `exp` is **optional**, so a token without it never expires.
  - A missing `sub` defaults to `""`, so all such tokens share one SEC-002
    identity.
  - `exp + LEEWAY` is unchecked arithmetic.
  - No `iat` or maximum-age, `typ` or `crit` handling.
  - JWK `use`/`alg`/`key_ops` are ignored.
  - RS256, `nbf` and `kid` selection are untested.
- **Disposition.** Replace with `jsonwebtoken` (cargo is online on current
  hosts). Keep Ferrum's claim policy as a thin layer on top and fix the claim
  findings in the same ticket.

#### P6 Admin API authorization (**M**, SEC-014)

- **Findings.**
  - Admin tokens use the same issuer and audience as device tokens and are
    distinguished only by an `admin` tag. An IdP *group* named `admin` therefore
    grants the admin API.
  - `authorize()` is called by hand in each handler rather than as middleware.
  - There is no in-process TLS. The deployment fronts it with Caddy.

#### P7 TLS identity, DER/SPKI parser and pinned verifier (**M**, SEC-016)

- **Components.**
  - The HKDF derivation of an Ed25519 TLS key from the WireGuard key uses
    vetted `ring` HKDF.
  - A hand-built PKCS#8 prefix wraps the derived seed.
  - A ~60-line DER walker (`der_tlv`/`spki_of`) extracts the
    SubjectPublicKeyInfo to pin.
  - A custom rustls `ServerCertVerifier` compares it against the pins.
- **Main review question: parser differential.** The pinned SPKI comes from
  Ferrum's parser, but the handshake signature is checked by rustls/webpki's
  parser of the same certificate. If the two can ever disagree about which key
  a certificate carries, the pin could be bypassed. Ferrum's walker also
  accepts non-minimal DER lengths.
- **Disposition.** Take the pinned SPKI from the same parser that verifies the
  signature (or from `x509-cert`/`der`), and have the review target this
  specifically.
- **Kept, with rationale.** With no pins configured the verifier accepts any
  certificate but logs loudly. SEC-004 made that an explicit, warned opt-out,
  and SEC-010 should document it.

#### P8 Relay protocol and register challenge (**M**, review)

- **Construction.** A novel DERP-style protocol:
  - The cookie is a keyed BLAKE2s MAC over (epoch, source address, key),
    truncated to 16 bytes.
  - The proof is a keyed BLAKE2s MAC under `X25519(client WireGuard static
    key, relay ephemeral key)`.
  - Low-order points are rejected.
- **Review questions.**
  - Cross-protocol reuse of the WireGuard static key as an X25519 MAC key.
  - 128-bit truncation.
  - The relay's key is unauthenticated to the client.
  - Data frames are trusted by source address after registration.
  - The hand-rolled `ct_eq` should become `subtle` (SEC-016).
- **Disposition.** External cryptographic review. There is no crate to adopt
  for a bespoke protocol.

#### P9 MASQUE CONNECT-UDP proxy (**M**, SEC-015)

- **Defect.** It is an **open UDP proxy**: no client authentication and no
  target policy, so loopback, RFC 1918 and link-local destinations are
  reachable. Anyone who can reach it can use it as an SSRF / reflection hop
  into the proxy host's network.

#### P10 to P12 Hand-rolled `unsafe` FFI (**M**, SEC-016, replace)

- **P10, `fdpass`.** Raw `sendmsg`/`recvmsg` with `CMSG_*`.
  - The control buffer is a byte vector, so it is not guaranteed to be
    `cmsghdr`-aligned. That is formally undefined behaviour.
  - No `MSG_CMSG_CLOEXEC`, so the received TUN fd leaks into child processes.
  - `MSG_CTRUNC` is unchecked.
  - Replace with `rustix` or `nix`, both already in `Cargo.lock`.
- **P11, UDP GSO/GRO.** The same cmsg alignment issue, on stack buffers.
  Replace with `quinn-udp`, already in the tree via quinn and widely deployed.
- **P12, `FdTun::from_fd(RawFd)`.** A *safe* function that takes ownership of
  any integer. It breaks Rust's I/O-safety contract and should be an
  `unsafe fn` (or take an `OwnedFd`).

#### P13 Windows WFP (**M**, review)

- **What it does.** About 460 lines of direct WFP FFI: its own provider and
  sublayer, default-block plus permit filters at `ALE_AUTH_CONNECT`, installed
  in one transaction.
- **Review questions.**
  - Filters exist only at the connect layers; inbound is not covered.
  - An allowlisted IP is permitted on every port and protocol.
  - The unit tests cover only the filter *spec*, never WFP itself.
- **Disposition.** No safe WFP wrapper crate is known (comparable products call
  WFP directly), so this is an external-review item. Add a Windows integration
  test first.

#### P14 eBPF/XDP fast path (**M**, SEC-018)

- **What it does.** An in-kernel parser and rewriter running on every packet.
- **Checks it does not make.** The IPv4 version nibble, whether the packet is a
  fragment, whether the destination is the relay's own address, and the IP/UDP
  length fields.
- **Also.** `GatewayInfo` has implicit padding despite its `unsafe impl Pod`
  safety comment. `checksum_update` has no unit test (it was verified live
  only).

#### P15 to P20 Low risk

- **P15, STUN.** About 100 lines of length-checked parsing, and its output is
  only a candidate hint: WireGuard authenticates every path. Kept, but:
  - Fuzz it (SEC-017).
  - Make the transaction ID random rather than time plus a counter, which is
    predictable and so helps an off-path spoofer (SEC-018).
- **P16, metrics and health servers.** A single 1 KiB read with prefix matching
  and no read timeout. Move them onto hyper/axum, which are already
  dependencies (SEC-018).
- **P17, padding and jitter.** Obfuscation, not a security boundary, so kept.
  - The jitter PRNG is a clock-seeded LCG; use `getrandom` (SEC-018).
  - `pad::send_batch` skips the length check that `send` makes (SEC-018).
- **P18, rate limiters.** Small, bounded and tested token buckets. Kept.
  `governor` is optional polish.
- **P19, hex pin parser.** Validated, tested and tiny. Kept.
- **P20, Android.** Uses vetted `EncryptedSharedPreferences` and the Keystore.
  Two findings:
  - The `androidx.security:security-crypto` alpha dependency is reportedly
    deprecated upstream (to verify).
  - The code comment claims StrongBox, which is never requested.
  
  Tracked with AND-004 (backups) and AND-012 (biometric gate).

## 3. Follow-up tickets

| Ticket | Title | Severity | Closes |
|---|---|---|---|
| [SEC-011](../../tickets/security-hardening/SEC-011-mesh-source-address-check.md) | Enforce `allowed_ips` on decrypted inbound packets | High | P1 |
| [SEC-012](../../tickets/security-hardening/SEC-012-helper-request-validation.md) | Validate helper requests; stop the nft injection and the TUN fd leak | High | P2, P3 |
| [SEC-013](../../tickets/security-hardening/SEC-013-coordinator-rpc-authorization.md) | Bind every coordinator RPC to the caller's key; relay role; durable revocation | High | P4 |
| [SEC-014](../../tickets/security-hardening/SEC-014-adopt-jsonwebtoken.md) | Adopt `jsonwebtoken`; tighten claim policy; separate admin audience | High | P5, P6 |
| [SEC-015](../../tickets/security-hardening/SEC-015-masque-proxy-access-control.md) | MASQUE proxy client auth + target policy | Medium | P9 |
| [SEC-016](../../tickets/security-hardening/SEC-016-replace-hand-rolled-unsafe.md) | Replace hand-rolled FFI and parsers with vetted crates | Medium | P7, P8 (`ct_eq`), P10, P11, P12 |
| [SEC-017](../../tickets/security-hardening/SEC-017-fuzzing-and-supply-chain.md) | Fuzz targets + `cargo-deny`/`cargo-audit` in CI | Medium | cross-cutting, P15 |
| [SEC-018](../../tickets/security-hardening/SEC-018-low-severity-hardening.md) | Low-severity hardening batch | Low | P14, P15, P16, P17 |

## 4. Third-party audit plan

### 4.1 Scope

**In scope (priority order).**

1. **Data plane.** `ferrum-tunnel` (mesh crypto-routing, session wrapper,
   path/ICE state machines, TUN, fd passing).
2. **Control plane.** `ferrum-coordinator` (authn/authz, key binding, ACL
   policy, admin API, storage) and `ferrum-client-core`'s use of it.
3. **Transport.** `ferrum-transport`:
   - the relay protocol and register challenge (P8), a cryptographic review;
   - the TLS identity and pinning (P7);
   - QUIC/MASQUE, including the proxy (P9);
   - STUN;
   - the UDP FFI (if SEC-016 hasn't replaced it yet).
4. **Privilege boundaries.** `ferrum-helper` + `helper_proto` (Linux), the
   Windows helper service + WFP (P13), and the nft generators.
5. **Kernel.** `relay-ebpf` + `relay-xdp-common`.

**Out of scope for the first audit.**

- boringtun itself: upstream, audited separately.
- The Angular admin panel's front end, beyond its API surface.
- The Android and desktop UI shells, beyond their credential storage and IPC.
- iOS and macOS, which don't exist yet.

**Deliverables expected from the vendor.** A findings report with severities,
a retest of the fixes, and a public summary we can publish. Publishing it is
the market-facing point of the exercise.

### 4.2 Readiness gates (before the audit window opens)

1. Pending PRs merged: SEC-005, SEC-006, SEC-007, SEC-008.
2. High-severity follow-ups fixed: SEC-011, SEC-012, SEC-013, SEC-014.
3. SEC-017 fuzz targets running in CI for the parsers the auditors will read.
4. SEC-010 threat model published, since the auditors need it as input.
5. A tagged audit commit, a reproducible build recipe, and the Linux/Windows
   test beds (`scripts/verify-linux.sh`, the netns relay harness) documented
   for the vendor.

### 4.3 Owners, dates, budget

Owners and dates are **proposals** for the project owner to confirm. Budget and
vendor selection are business decisions (PRD §7 open question).

| Phase | Owner | Target |
|---|---|---|
| Merge pending security PRs (SEC-005 to SEC-008) | project owner (@punarduttrajput), reviewer/merger | 2026-10-15 |
| Fix the High follow-ups (SEC-011 to SEC-014) | engineering | 2026-11-15 |
| SEC-017 fuzzing + supply-chain gate; SEC-010 threat model | engineering | 2026-11-15 |
| RFP to 3–4 vendors; pick one | project owner | RFP out 2026-10-31, decision 2026-11-30 |
| Audit window | vendor | January 2027 (~4–6 person-weeks) |
| Fix findings, vendor retest | engineering + vendor | February 2027 |
| Publish the report / summary | project owner | March 2027 |

**Budget ask (planning estimate, not a quote).** A Rust network-security
review of this size typically runs about **4–6 auditor-weeks plus a retest**.
Plan for roughly **USD 40k–90k**, and firm it up from the RFP responses. The
cryptographic review of P8 is the part most likely to need a specialist and to
push toward the upper end.

**Vendor shortlist to RFP.** Pick firms that publish reports for VPN clients,
Rust network code and cryptographic protocols, so the public summary carries
weight. Candidates include Cure53, X41 D-Sec, Radically Open Security, Trail of
Bits and NCC Group. Check each firm's current published work when sending the
RFP.

### 4.4 Re-evaluate on these triggers

Re-run the inventory (§2) before signing the audit contract, and again whenever
any of these happens:

- a new parser of untrusted input is added;
- a new `unsafe` block is added;
- a new privileged operation is added;
- a new authentication path is added.
