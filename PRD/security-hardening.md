# PRD — Security Hardening & Trust Posture

| Field | Value |
|---|---|
| **Product** | Ferrum (Rust) |
| **Phase** | Cross-cutting (Phase 3 control plane, Phase 4 relay, Phase 5 clients/helper, Phase 2 transport) |
| **Status** | Proposed |
| **Owner** | punarduttrajput |
| **Last updated** | 2026-07-19 |
| **Depends on** | Phase 3 coordinator (`ferrum-coordinator`, OIDC verifier), Phase 4 relay (`RelayServer`/`RelayMeshTransport`), Phase 5 privileged helpers (`ferrum-helper`), Phase 2 transports (QUIC/MASQUE) |

---

## 1. Summary

Ferrum's cryptographic core is sound — WireGuard/Noise data plane,
`#![forbid(unsafe_code)]` on `ferrum-core`, crypto-demux mesh routing, an OIDC
resource-server model, mTLS, and a DNS/IPv6 leak-protection story. This PRD
closes the gap between "cryptographically defensible" and "safe to ship,
by default, to non-expert users, and passable by a third-party audit."

A security review (2026-07-19) surfaced ten pain points across four
severity/positioning tiers. They cluster around one theme: **the product is
secure only when an expert configures it correctly, and several of its trust
boundaries fail *open* rather than *closed*.** In the current market
(Tailscale, Twingate, Cloudflare WARP, WireGuard-native offerings), the bar is
secure-by-default, identity-first, and independently audited. This PRD moves
Ferrum to that bar.

## 2. Goals & Non-Goals

### Goals
- **G1. Fail closed, not open.** Authentication is required by default; every
  privilege boundary rejects on ambiguity instead of degrading to a permissive
  fallback.
- **G2. Bind identity to key material.** An auth token authorizes a specific
  device public key; keys cannot be swapped or self-asserted for privilege.
- **G3. Remove the relay hijack / reflection primitives.** Relay registration
  is return-routability-checked and rate-limited.
- **G4. Authenticate the outer transport** (or document precisely why not, in
  user-facing terms) so the anti-censorship claim survives an on-path adversary.
- **G5. Tighten the local privilege boundary** on the `ferrum-helper` daemons.
- **G6. Rate-limit and quota the control plane** against resource abuse.
- **G7. Provenance for every vendored/prebuilt binary.**
- **G8. Audit-readiness:** a documented, published threat model and a plan
  to get the hand-rolled security primitives independently reviewed.

### Non-Goals
- ❌ Re-architecting the WireGuard/Noise data-plane crypto — it is not the
  problem and is out of scope.
- ❌ macOS / iOS enforcement parity — deferred with the rest of the Apple
  targets (no toolchain/host).
- ❌ A full PKI / CA product for the transport layer — G4 is satisfied by cert
  pinning to coordinator-advertised material, not a general CA.
- ❌ DoH-bypass prevention (covered as a non-goal in the leak-protection PRD).

## 3. Background & Rationale

Ferrum grew from a research/MVP posture where "open mode" (no auth) and a
permissive TLS verifier were sensible defaults for iterating on the crypto and
transport. Those defaults are now liabilities:

- The coordinator's `authenticate()` returns `Ok(None)` whenever OIDC is off or
  unconfigured, and `register_device` then trusts **self-declared tags** — and
  tags are the ACL authorization boundary. An open coordinator is a wide-open
  mesh.
- Even with OIDC on, a verified token is not bound to the presented WireGuard
  public key, so a leaked/low-privilege token can register an attacker-chosen
  key with the token's tags.
- The DERP-style relay maps `pubkey -> source addr` from an **unauthenticated**
  `0x01 || pubkey(32)` datagram with no return-routability check — a mapping
  hijack (public keys aren't secret) and a UDP reflection/amplification vector.
- The QUIC/MASQUE transports use `SkipServerVerification` (accept any cert). The
  inner WireGuard handshake protects *confidentiality*, but the outer layer
  offers zero server authentication, so an on-path adversary can MITM the
  camouflage layer for metadata/active-probing/downgrade — undercutting the
  Phase 2 anti-censorship value.
- The `ferrum-helper` Unix socket gates on **group membership** and silently
  falls back to a **world-writable (0666)** socket if the group is missing —
  a local privilege-escalation footgun with no per-caller credential check.

None of these are data-plane crypto breaks. All of them are trust-boundary and
default-posture gaps — exactly the class that produces breach headlines and
fails audits, and exactly what the market now judges VPN products on.

## 4. Functional Requirements

### FR1 — Secure-by-default coordinator (M1) — [SEC-001]
- Authenticated mode is the default. An operator must pass an explicit
  `--insecure-no-auth` (or equivalent) to run open, and doing so logs a loud,
  repeated warning.
- In authenticated mode, tags come **only** from verified claims; self-declared
  request tags are ignored (never `None => &req.tags` for a privilege decision).
- Startup fails fast if neither auth nor the explicit insecure opt-out is set.

### FR2 — Token-to-key binding (M1) — [SEC-002]
- Registration binds the verified token/identity to the presented
  `public_key` on first use; subsequent registrations for that identity must
  present the same key (or an explicitly authorized rotation).
- A key swap for an existing identity is rejected (`FailedPrecondition`) unless
  it goes through an authorized rotation path.
- Applies on the OIDC path and the mTLS path.

### FR3 — Relay registration hardening (M2) — [SEC-003]
- Add a return-routability challenge: a `Register` does not take effect until
  the client echoes a relay-issued nonce from the same source address.
- Rate-limit registrations per source IP and per key; drop/penalize floods.
- A register for a key that already has a live mapping from a *different*
  source is challenge-gated (no silent hijack).
- Metrics: `ferrum_relay_register_challenges_total`,
  `ferrum_relay_registers_rate_limited_total`.

### FR4 — Outer-transport authentication (M2) — [SEC-004]
- Replace `SkipServerVerification` with a pinning verifier: the client verifies
  the server cert against a coordinator-advertised fingerprint (advertised in
  the network map alongside `relay`/`dns_servers`).
- Where pinning material is unavailable, the client warns visibly that the
  outer transport is unauthenticated (never silently accept).
- Document the residual on-path threat model in user-facing terms.

### FR5 — Helper privilege boundary (M2) — [SEC-005]
- Verify the connecting peer with `SO_PEERCRED` (uid/gid/pid); reject callers
  outside an allow-list.
- **Fail closed:** if the configured group does not exist, refuse to start (or
  bind 0600 owner-only) — never fall back to a world-writable 0666 socket.
- Keep the request-type allow-list; add per-connection request quotas.

### FR6 — Control-plane abuse controls (M3) — [SEC-006]
- Per-identity / per-source rate limits and connection quotas on
  `register_device`, `watch_network_map`, and `RelayHeartbeat`.
- Aggregate-only metrics (NFR5-preserving): rejected/throttled counts, no
  per-user labels.

### FR7 — Transport cert lifecycle (M3) — [SEC-007]
- Coordinator-advertised transport cert fingerprint(s) support rotation
  (advertise current + next), so pinning survives a cert roll.
- Optional: short-lived transport certs minted per coordinator config.

### FR8 — Vendored-binary provenance (M2) — [SEC-008]
- Pin `wintun.dll`, the `bpf-linker` prebuilt, and any other vendored/prebuilt
  binary by SHA-256 in-tree; CI verifies the checksum before use.
- Document the provenance (source URL + expected digest) for each.

### FR9 — Threat model & audit readiness (M4) — [SEC-009, SEC-010]
- A published `SECURITY.md` / threat model: what the coordinator, relay, and
  transports can each observe; the trust boundaries; the residual risks.
- An inventory of hand-rolled security primitives (STUN client, OIDC JWT verify
  on `ring`, `fdpass` SCM_RIGHTS, WFP/nftables rule generation) with a plan to
  get them independently reviewed / replaced with vetted crates where feasible.

## 5. Milestones

| Milestone | Scope | Tickets |
|---|---|---|
| **M1 — Fail-closed control plane** | Secure-by-default auth; token↔key binding | SEC-001, SEC-002 |
| **M2 — Perimeter hardening** | Relay register R-R + rate limit; transport pinning; helper `SO_PEERCRED`/fail-closed; vendored-binary checksums | SEC-003, SEC-004, SEC-005, SEC-008 |
| **M3 — Abuse & lifecycle** | Control-plane rate limits/quotas; transport cert rotation | SEC-006, SEC-007 |
| **M4 — Trust & assurance** | Published threat model; hand-rolled-primitive audit plan | SEC-009, SEC-010 |

## 6. Acceptance Criteria

- **AC1 (M1):** A default-config coordinator refuses unauthenticated RPCs; a
  device cannot self-assign privileged tags; running open requires an explicit
  flag and logs the warning. Verified by integration tests in
  `ferrum-coordinator`.
- **AC2 (M1):** A valid token cannot register a public key other than the one
  it was bound to; a key swap is rejected. Test covers OIDC + mTLS paths.
- **AC3 (M2):** A spoofed relay `Register` from a wrong source does not capture
  the mapping without completing the return-routability challenge; a
  registration flood is rate-limited. Verified against `RelayServer`.
- **AC4 (M2):** A QUIC/MASQUE client rejects a server whose cert does not match
  the advertised fingerprint; with no pinning material it connects but emits the
  documented warning. Verified in `ferrum-transport`.
- **AC5 (M2):** The helper refuses a connection from a disallowed uid/gid and
  refuses to start (or binds 0600) when the group is absent — no 0666 path.
- **AC6 (M2):** CI fails if a vendored binary's SHA-256 does not match the
  pinned digest.
- **AC7 (M3):** Registration/watch/heartbeat floods are throttled with
  aggregate-only metrics; `tracing_privacy` still passes (NFR5).
- **AC8 (M4):** `SECURITY.md` merged; the hand-rolled-primitive audit plan is
  recorded with owners and target dates.

## 7. Risks & Open Questions

- **Backward compatibility:** flipping auth on by default breaks existing open
  deployments (e.g. the Oracle-VM bring-up). Mitigation: the explicit
  `--insecure-no-auth` flag + a migration note in the deployment README.
- **Pinning bootstrap:** the transport cert fingerprint is advertised by the
  coordinator, but the *first* coordinator connection itself needs trust. The
  coordinator gRPC channel already supports mTLS; pinning rides on that. Open
  question: behavior when only the open coordinator is available.
- **Audit funding/vendor:** SEC-009 needs a third-party budget decision — an
  engineering PRD can prepare for it but not commission it.
