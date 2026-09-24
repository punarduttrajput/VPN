# SEC-003 — Relay register is unauthenticated/spoofable + amplification vector

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M2 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR3 |
| **Area** | `ferrum-transport` (`relay.rs`, `RelayServer`) |

## Problem

The DERP-style relay maps `pubkey -> source addr` from an unauthenticated
`Register = 0x01 || self_pubkey(32)` datagram (`crates/transport/src/relay.rs`,
~L11–62). Two issues:

1. **Mapping hijack.** Public keys are not secret. Anyone who knows a target's
   public key can send a register frame and redirect that peer's relayed
   traffic to an attacker address — a DoS and metadata/interception attempt.
   (The inner WireGuard layer still protects payload confidentiality.)
2. **Reflection/amplification.** No proof-of-return-routability, so the relay
   is a UDP reflection candidate driven by spoofed source addresses.

## Acceptance criteria

- [x] A `Register` does not take effect until the client echoes a relay-issued
      nonce from the same source address (return-routability challenge).
- [x] A register for a key that already has a live mapping from a *different*
      source is challenge-gated — no silent hijack.
- [x] Registrations are rate-limited per source IP and per key.
- [x] Metrics added: `ferrum_relay_register_challenges_total`,
      `ferrum_relay_registers_rate_limited_total` (aggregate only, NFR5).
- [x] Test against `RelayServer`: spoofed source fails to capture the mapping;
      a flood is throttled.

## Resolution

Implemented in `crates/transport/src/relay_auth.rs` + `relay.rs`. Beyond the
criteria above, the challenge response also carries a **proof of possession**
of the key's private half (keyed BLAKE2s under `X25519(client_priv,
relay_pub)`): return routability alone stops *spoofed* hijacks, but not an
attacker registering someone else's public key from their own real address.
So `RelayMeshTransport::connect` now takes the node's `StaticSecret`. The
cookie is stateless (keyed BLAKE2s over epoch + source + key, 30–60 s
lifetime), the register frame is padded so a challenge is never larger than
the request that triggers it (no reflection amplification), and a
keepalive for the already-live mapping is a silent refresh (no challenge).
Per-IP limit: burst 32, 8/s (challenges + proofs). Per-key limit: burst 4,
1 per 5 s, applied only to *verified* mapping changes so third parties can't
drain a victim's budget. Extra metric:
`ferrum_relay_register_proofs_rejected_total`.

**Wire-incompatible:** relays and clients must be upgraded together — an old
client's unpadded register is dropped as malformed by a new relay, and an old
relay never challenges.

## Implementation notes

- Add a `Challenge`/`ChallengeResponse` frame pair to the tiny wire protocol;
  keep it one datagram each. The nonce is short-lived and bound to the source
  addr + key.
- Reuse the drain/registry metric patterns already in `relay.rs`.
- Keep it compatible with the XDP fast path (the challenge is a control-plane
  handshake; the fast path only forwards `Data` frames for established maps).
