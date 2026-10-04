# Ferrum threat model: what each component can see

**Ticket:** [SEC-010](../../tickets/security-hardening/SEC-010-published-threat-model.md) ·
**PRD:** [security-hardening.md](../../PRD/security-hardening.md) FR9 ·
**Companions:** [audit plan](audit-plan.md) · [privacy summary](privacy-summary.md) ·
**Status:** 2026-10-04

This is the published statement of what Ferrum's coordinator, relays,
transports and clients **can observe**, what they keep and for how long, where
the trust boundaries are, and what Ferrum does *not* try to protect against.
It describes the code, not intentions. Where a property comes from a specific
security fix, the ticket is named next to it (see §8).

## 1. System in one picture

```
             control plane (gRPC, TCP)                 data plane (UDP)
   ┌────────┐  register / map / candidates  ┌─────────────┐
   │ device ├──────────────────────────────►│ coordinator │◄── admin API (HTTPS via proxy)
   └───┬────┘◄── network map, relay, DNS ───┤  + SQLite   │◄── relay heartbeats
       │                                    └─────────────┘
       │  WireGuard, carried over UDP | QUIC | MASQUE (HTTP/3)
       ├──────────────── direct ──────────────────► peer device
       └──► DERP-style relay (public-key keyed) ──► peer device
            or MASQUE CONNECT-UDP proxy
```

- **Every packet between devices is WireGuard-encrypted end to end**
  (boringtun). No coordinator, relay, proxy or network operator holds the keys
  to read it.
- The **coordinator** is a directory: it hands out tunnel addresses and tells
  devices which peers they may talk to and how to reach them. It never carries
  user traffic.
- A **relay** forwards already-encrypted WireGuard datagrams between devices
  that can't reach each other directly.
- The **transport** (plain UDP, QUIC, or MASQUE over HTTP/3) is the outer
  wrapper that a network on the path sees.

## 2. Assets

| Asset | Where it lives | Who must never get it |
|---|---|---|
| Tunnel payload (the user's actual traffic) | inside WireGuard, end to end | everyone but the two endpoints |
| WireGuard private keys | each device only (Android Keystore-backed storage, desktop/CLI config) | everyone, including the coordinator |
| Network graph (who is in the mesh, who may talk to whom) | coordinator | network observers, other tenants |
| Communication graph (who *actually* talks to whom, when, how much) | partly visible to relays and to the network path | the coordinator does not see it |
| Device locations (public IPs, LAN addresses) | coordinator; permitted peers; relays | non-permitted peers, network observers |
| Identity (OIDC `sub`, mTLS cert fingerprint) | coordinator | peers, relays |
| DNS queries | the in-mesh resolver | the local network and ISP |

## 3. The coordinator

### 3.1 What it can observe

| Data | Source | Persisted? |
|---|---|---|
| Device WireGuard **public** key | `RegisterDevice` | yes (`devices` table) |
| Device name (free-text label chosen by the client) | `RegisterDevice` | yes |
| Self-reported endpoint `ip:port` | `RegisterDevice` | yes |
| Assigned tunnel IP | allocated by the coordinator | yes |
| Tags | the verified OIDC token claim, or self-declared without auth | yes |
| ICE candidates: **LAN host addresses** and the public (STUN-reflexive) `ip:port` | `PublishCandidates` | yes |
| TLS public-key pin (and next pin, SEC-007) | `RegisterDevice` / `RotateKey` | yes |
| Identity → key binding: OIDC `sub` or mTLS client-cert fingerprint (SEC-002) | the authenticated request | yes (`identity_bindings`) |
| Revoked keys and identities (SEC-013) | admin revoke | yes (`revocations`) |
| Token claims (issuer, audience, `sub`, tag/role claim, expiry) | each request's bearer token | no; verified per request |
| The source IP of each control-plane connection | TCP | no; used in memory for rate limiting (SEC-006), keyed by IPv4 address or IPv6 /64 |
| Relay advertise addresses | `RelayHeartbeat` | no; in memory with a 45 s TTL |
| When a device registers, rotates, publishes candidates, or holds a watch stream open | RPC timing | no; only aggregate counters (§6) |

### 3.2 What it cannot observe

- **No tunnel payload and no data-plane traffic.** Devices talk to each other
  directly or via a relay. The coordinator is not on that path.
- **No private keys.** Devices generate their keys and only send the public half.
- **Not who actually talks to whom.** It knows who is *allowed* to (the ACL
  policy) and where they are, but not which permitted pairs exchange traffic,
  when, or how much.
- **No DNS queries.** It only advertises the resolver address.

### 3.3 Retention

- **A device record lives until an admin revokes it.** There is no automatic
  expiry of idle devices. With the SQLite store (`--store`) it survives
  restarts. With the in-memory default it is lost on restart.
- Candidates and the endpoint are **replaced** on every publish or register,
  not appended, so there is no history of past locations in the database.
- Identity bindings and revocation entries are kept after revocation, on
  purpose: that is what stops a revoked identity from silently re-registering.
- Operator-side copies are outside Ferrum's control: database backups, container
  log retention, and anything the reverse proxy logs. The single-VM deployment
  (`deploy/oracle-vm`) does not enable Caddy access logs.

### 3.4 Logs and telemetry

- Info-level coordinator logs record **events, not identities**. For example
  "registered device" with only an `authenticated` flag. Keys, tunnel IPs,
  endpoints, candidates and token contents are not logged.
- Every RPC span is `#[tracing::instrument(skip_all)]`, so request fields never
  enter a span, including spans exported over OTLP (`--otlp-endpoint`). The
  `tracing_privacy` integration test guards this (Phase 6 NFR5).
- Startup logs name the operator's own configuration: listen addresses, the
  advertised relay and DNS addresses, and the OIDC issuer/audience.

### 3.5 The admin API

The admin API (`--admin-listen`, served behind a TLS reverse proxy) returns the
**full device list**: keys, names, endpoints, candidates, tunnel IPs and tags.
It can also revoke and unrevoke devices and rewrite the ACL policy. Access
requires an OIDC token for the separate admin audience (SEC-014). Anyone holding
such a token has the coordinator's full view.

### 3.6 Failure mode: the coordinator is the trust anchor

The coordinator cannot read traffic, but it **decides who is in the mesh**.
Devices accept the network map it sends: peer public keys, the IP ranges each
peer may use (`allowed_ips`), TLS pins, the relay and DNS servers. So a
**compromised or malicious coordinator** (or an attacker who can tamper with an
unprotected control channel) can:

- add a peer it controls to any device's map, or claim another device's
  tunnel IP for it, and so **receive traffic sent to that address** from then on;
- swap a peer's TLS pin to MITM the outer QUIC layer (the inner WireGuard
  still protects the payload unless the WireGuard key is swapped too);
- point devices at a relay or DNS resolver it controls (the relay still sees
  only ciphertext; a hostile resolver sees DNS queries);
- learn everything in §3.1.

It **cannot** decrypt traffic between two existing peers whose keys it does not
replace, and it cannot impersonate a device to a peer without that peer's map
being changed.

Mitigations:

- Protect the control channel with mTLS (`--tls-cert/--tls-key/--tls-ca`) or
  a trusted network. Over plain `http://`, an on-path attacker can do all of
  the above.
- Authentication is fail-closed (SEC-001). Keys are bound to identities
  (SEC-002), and every key-bearing RPC is bound to the caller (SEC-013).
- **Not mitigated:** there is no client-side signing of the network map by
  device owners (a "tailnet lock" equivalent). The coordinator operator is
  trusted with mesh membership. See §7.

## 4. Relays and the MASQUE proxy

### 4.1 DERP-style relay (`ferrum relay`)

A relay sees each data frame's header: `0x02 || peer public key || payload`.

| Data | Visible? | Kept? |
|---|---|---|
| Payload contents | **no**: WireGuard ciphertext | n/a |
| Sender's WireGuard **public key** and source `ip:port` | yes (proven by the SEC-003 register challenge) | in memory only (`key ↔ addr` map); replaced on roam, lost on restart, **no idle expiry** |
| Destination's WireGuard **public key** | yes, in every frame | not stored per frame |
| Packet sizes and timing | yes | not stored |
| Device names, tags, identities, tunnel IPs | no | n/a |

**The relay can build a communication graph.** Every frame names the
destination key, and the relay knows the sender's key from its source address.
An operator who chooses to log can therefore record which device talks to which,
when, and how much, keyed by stable public keys. Combined with the
coordinator's database (which maps keys to names and identities), that
identifies people. This is why the relay's operator must be as trusted as the
coordinator's, and why Ferrum ships with neither component logging any of it:

- Relay logs contain no public keys. Client addresses appear at `debug` level,
  which is off by default (`RUST_LOG` defaults to `info`), with one exception:
  a failed forward logs the destination address at `warn`. That is one address
  per send error, not a flow record.
- Relay metrics are aggregate counters only (NFR5).
- The XDP fast path keeps the same forwarding state in kernel BPF maps
  (client address ↔ key handle, plus the relay's own MAC and IP), and aggregate
  counters.

Traffic only goes through a relay when a direct path can't be established.
Once a direct path is punched, the peer upgrades to it and the relay sees
nothing more for that pair except keepalive registers.

**Failure mode.** A malicious relay can drop, delay or replay ciphertext (denial
of service; WireGuard rejects replays) and log the graph above. It cannot read
or forge traffic. The relay's own key is not authenticated to clients (audit
item P8), so a network attacker can impersonate a relay to the same effect.

### 4.2 MASQUE CONNECT-UDP proxy

A MASQUE proxy is a general UDP forwarder. It sees the client's address, the
**target `ip:port`** of each tunnel, packet sizes and timing, but only
WireGuard ciphertext. It does not see public keys (unlike the relay). With
SEC-015 the in-tree proxy requires a bearer token and refuses loopback,
private and link-local targets. A third-party proxy is trusted for availability
and metadata only.

## 5. On the network path

What someone between a device and the internet (Wi-Fi operator, ISP, national
middlebox) can see depends on the transport.

| Transport | Visible to an on-path observer |
|---|---|
| `udp` (default) | Endpoint IPs and ports, sizes, timing. The traffic is **recognisably WireGuard**: fixed message types and handshake sizes. Peer public keys are not sent in the clear (WireGuard encrypts the static key in the handshake). |
| `quic` | Endpoint IPs and ports, sizes, timing, and the TLS ClientHello. Since SEC-020 the ClientHello carries **no SNI** by default (peers are dialed by IP), or the operator's `server_name` if set, in point-to-point and mesh alike. It also offers no ALPN (see residuals below). The certificate is encrypted (TLS 1.3) and names nothing. |
| `masque` | The proxy's address (UDP/443) and the ClientHello: ALPN `h3`, and SNI only if `server_name` is set (none by default since SEC-020; a third-party proxy usually needs its real hostname). The real peer's address is inside the encrypted HTTP/3 session. |
| any + `padding` / `jitter` | Datagram sizes are normalised to `pad_to`, and send timing is randomised (SEC-018: a CSPRNG). Both are **opt-in** and are obfuscation, not a security boundary. |
| relay fallback | The relay's address; to the network the relay's traffic looks like any UDP flow. |
| control plane | The coordinator's address and connection timing. With mTLS the contents are encrypted; with plain `http://` they are **readable and modifiable** (see §3.6). |

**Before and after SEC-004.** Before SEC-004, QUIC and MASQUE clients accepted
any server certificate. An on-path attacker could silently MITM the outer
layer, watch it more closely, actively probe it, or downgrade it, though never
read the WireGuard payload inside. Since SEC-004 the outer layer is pinned to the
server's public key (configured `cert_pins`, or per-peer pins from the
coordinator in the mesh). Since SEC-016, the pinned key is the same one the
handshake signature is verified against, and TLS 1.2 is refused. With no pin
available Ferrum still connects, but logs "outer transport UNAUTHENTICATED"
every time. The user-facing version of this is in the README's "Certificate
pinning" section; it is not repeated here.

**Residual on-path risks** (pinned or not): the observer always learns *that*
you use some VPN-like service, the address you reach, and traffic volume and
timing. They can block it. Default-mode UDP is trivially classified as
WireGuard. Until SEC-020, QUIC and MASQUE sent the SNI `ferrum` in clear
text, so one DPI rule could single them out. They now send none by default,
and the self-signed certificates no longer carry `ferrum` or rcgen's default
`CN=rcgen self signed cert`. What remains distinguishable: point-to-point and
mesh QUIC offer **no ALPN** (web QUIC always offers `h3`), a ClientHello
without SNI is itself less common than one with, and an active prober that
completes a handshake still gets an anonymous self-signed certificate.

## 6. Clients and peers

- **Peers learn less than the coordinator, but not nothing.** A device's network
  map contains, for each peer the ACL policy lets it reach: the peer's public
  key, endpoint, tunnel IP range, ICE candidates (**including LAN addresses**)
  and TLS pin. It does **not** contain peer names, tags or identities. Peers
  the policy forbids are not in the map at all.
- An authenticated mesh peer **can't spoof another peer's tunnel IP**: decrypted
  packets whose source isn't in the sending peer's `allowed_ips` are dropped
  (SEC-011, standard WireGuard crypto-routing).
- **Local logs.** The CLI logs its published candidates and the DNS servers it
  uses at `info`. These logs stay on the device.
- **Privilege.** On Linux and Windows the GUI runs unprivileged. A root
  `ferrum-helper` (Linux, Unix socket restricted to the `ferrum` group with a
  `SO_PEERCRED` check) or a LocalSystem service (Windows, named pipe with a
  restrictive DACL) owns the TUN device and firewall (SEC-005, SEC-012).
  **Failure mode:** a local user in the `ferrum` group can bring tunnels up or
  down and engage or release the kill-switch. They cannot inject firewall rules
  or get a shell (SEC-012 validates every request).
- **Leak protection.** While connected, system DNS points at the in-mesh
  resolver, and a leak guard drops plaintext DNS (53) and DoT (853) leaving
  outside the tunnel. IPv6 is blocked off-tunnel when the tunnel has no v6
  address. The opt-in kill-switch blocks all non-tunnel traffic: nftables on
  Linux, WFP on Windows, and on Android the OS "Always-on VPN / Block
  connections without VPN" setting. Windows WFP filters cover outbound
  connections only (audit item P13).

## 7. Explicit non-goals and residual risks

These are **out of scope by design**. A user who needs them should not rely on
Ferrum for them.

1. **Anonymity.** Ferrum is a mesh VPN, not an anonymity network. Peers learn
   each other's public addresses, and the coordinator and relay operators can
   learn who you are and who you talk to (§3, §4).
2. **A malicious coordinator.** It is trusted with mesh membership (§3.6).
   There is no "tailnet lock" (owner-signed node keys) yet.
3. **Traffic analysis.** Sizes and timing are visible on the path and to
   relays. Padding and jitter are opt-in mitigations, not guarantees.
4. **Censorship resistance against a determined adversary.** QUIC/MASQUE make
   traffic look like web QUIC/HTTP-3, but the missing ALPN on plain QUIC, the
   endpoint addresses and active probing can still reveal it.
5. **DoH bypass.** Browsers doing their own DNS-over-HTTPS skip system DNS. Their
   queries leave through whatever route the browser takes and can't be told
   apart from HTTPS (leak-protection PRD non-goal).
6. **An exit node / full tunnel.** Ferrum routes mesh traffic. Internet-bound
   traffic outside the mesh is not anonymised or protected.
7. **A compromised endpoint.** Malware on a device with that device's
   WireGuard key *is* that device.
8. **The resolver operator.** The in-mesh resolver sees every DNS query from
   connected devices. It is an ordinary DNS server (dnsmasq/unbound), so trust
   whoever runs it like a DNS provider.
9. **Upstream boringtun.** Ferrum relies on it for WireGuard correctness. Its
   own advisories are tracked by the `cargo-deny` gate (SEC-017). Ferrum is on
   boringtun 0.7 (SEC-019), which brought `curve25519-dalek` 4.1.3 and
   `ring` 0.17, with no advisory exceptions left for the WireGuard engine.
10. **Apple platforms.** iOS and macOS clients don't exist yet, so nothing here
    applies to them.

## 8. Trust boundaries summary

| Component | Trusted for | Compromise means | Cannot do |
|---|---|---|---|
| Coordinator | mesh membership, addressing, ACL | traffic redirection, full metadata (§3.6) | read existing peers' traffic |
| Relay | availability | communication graph, DoS | read or forge traffic |
| MASQUE proxy | availability | flow metadata, DoS | read or forge traffic |
| In-mesh DNS resolver | name resolution | sees and forges DNS answers | read other traffic |
| Network path | nothing | sees metadata (§5), can block | read traffic; MITM the outer layer when pinned |
| Mesh peer | its own traffic | anything a WireGuard peer can do with its own IP | spoof other peers' IPs (SEC-011) |
| Local `ferrum` group member | tunnel control | tunnel and kill-switch on/off | root code execution (SEC-005/012) |
| Admin token holder | operations | everything the coordinator knows; revoke; policy | read traffic |

**Status of fixes referenced here.** SEC-001 to SEC-018 are on `main`, except
SEC-018's eBPF/XDP parser checks, which need a Linux host. SEC-019 (the
boringtun upgrade) is on `main`, pending its Linux real-TUN and throughput
runs. SEC-020 (the SNI default) is implemented and in review.

## 9. Keeping this document true

Update this document whenever any of these changes:

- what a component stores;
- what it logs at `info`;
- what goes into the network map;
- the default transport, SNI, or log level.

The [audit plan](audit-plan.md) §4.4 triggers (a new parser, `unsafe` block,
privileged operation or auth path) are also reasons to re-read it.
