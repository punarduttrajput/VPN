# SEC-019 — boringtun 0.6 pins vulnerable / unmaintained crypto dependencies

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M4 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR8/FR9 · found by SEC-017's `cargo-deny` |
| **Area** | `ferrum-tunnel`, workspace dependencies |

## Problem

`boringtun` 0.6.0, the WireGuard engine, pins `x25519-dalek = "=2.0.0-rc.3"`
and depends on `ring` 0.16. That drags three RustSec advisories into every
build, currently ignored (with reasons) in `deny.toml`:

- **RUSTSEC-2024-0344**: timing variability in `curve25519-dalek`
  4.0.0-rc.3's `Scalar29::sub` / `Scalar52::sub` (fixed in >= 4.1.3).
- **RUSTSEC-2025-0009**: some `ring` 0.16 AES functions may panic when
  overflow checks are enabled.
- **RUSTSEC-2025-0010**: `ring` < 0.17 is unmaintained.

The same pin also blocks `jsonwebtoken` 11 (its `rust_crypto` backend needs
`curve25519-dalek` 4.1; see SEC-014), and it's why a `ring` 0.16 licence
clarification is needed in `deny.toml`.

`boringtun` 0.7.1 depends on `x25519-dalek ^2.0.1` and `ring ^0.17`.

## Acceptance criteria

- [x] `boringtun` 0.7.x (and `x25519-dalek` 2.0.x stable) in the workspace;
      the session wrapper (`ferrum-tunnel::session`) adapted to any API
      changes. *(0.7.1 and `x25519-dalek` 2.0.1, so `curve25519-dalek` 4.1.3
      and `ring` 0.17.14 only, in all three lockfiles: root, desktop, fuzz.
      The only API change hit is that `Tunn::new` became infallible; a diff of
      boringtun's `noise` module shows no protocol changes. One fix rides
      along: the per-session send counter is now an `AtomicU64` rather than
      `usize`, so 32-bit targets (Android armv7/i686) no longer wrap it at
      2^32.)*
- [x] The three `ignore` entries and the `ring@0.16.20` licence clarification
      removed from `deny.toml`; `cargo deny check` passes without them.
- [ ] Full test matrix green, plus a real-TUN run (`verify-linux.sh`,
      including `TEST_MESH=1 MESH_QUIC=1`) and a throughput check
      (`STRICT_THROUGHPUT=1`), since this is the data-plane crypto engine.
      *(Full matrix green on the Windows dev host, including the Linux
      cross-compile clippy. The real-TUN run and the throughput check need a
      Linux host with root and are still to do.)*
      Commands and pass criteria: [Linux verification runbook](../../docs/linux-verification-runbook.md).
- [x] Follow-up noted: `jsonwebtoken` 11 (`rust_crypto`) becomes possible.
      *(Noted in `crates/coordinator/Cargo.toml` next to the `jsonwebtoken`
      pin.)*
