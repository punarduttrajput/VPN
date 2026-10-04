# SEC-017 — No fuzzing, no dependency-vulnerability gate

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M4 (pre-audit gate) |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR8/FR9 · [audit plan](../../docs/security/audit-plan.md) §1 |
| **Area** | CI, all parsers of untrusted input |

## Problem

Every parser of attacker-controlled bytes is tested only with hand-written
examples. There are no `fuzz/` targets and no property tests. CI has no
`cargo-deny`/`cargo-audit` step, so a dependency with a published advisory (or
a disallowed licence) would go unnoticed.

## Acceptance criteria

- [ ] `cargo-fuzz` targets (in a `fuzz/` crate outside the main workspace) for:
      the STUN response parser, relay frame decoding (server and client sides),
      `spki_of`/`fingerprint_of`, the JWT verifier (or its replacement's
      wrapper, SEC-014), `helper_proto::recv_request`, the pad deframer, and
      the MASQUE path parser. *(Eight targets, plus `pin_parse`. **Not yet:**
      the relay *server* side, whose dispatch is inline in its async serve loop
      and needs extracting into a pure function first. Everything else is
      covered, with the client side of the relay as `relay_challenge`.)*
- [x] A CI job runs each target for a short, bounded time on every PR, and
      longer on a schedule; crashes fail the job. Corpus committed.
      *(`.github/workflows/fuzz.yml`: 30 s/target per push/PR, 10 min nightly;
      reproducers uploaded on failure. Seeds in `fuzz/corpus/`.)*
- [x] `cargo-deny` (advisories, licences, bans, sources) in CI with a committed
      `deny.toml`; `cargo audit` equivalent covered.
      *(`.github/workflows/supply-chain.yml`, daily and per push/PR; the
      advisories check is the `cargo audit` equivalent, and also denies
      unmaintained and yanked crates. The action is pinned to a commit SHA.)*
- [x] Any findings from the first runs triaged into tickets. *(The first
      `cargo deny` run found **seven advisories**. Three were fixed here by
      semver-compatible updates: `rustls` 0.23.45 (RUSTSEC-2026-0285, TLS 1.3
      handshake messages across encryption levels), `h2` 0.4.19
      (RUSTSEC-2026-0258, empty-DATA-frame DoS) and `anyhow` 1.0.104
      (RUSTSEC-2026-0190). Three are pinned by boringtun 0.6 and filed as
      **SEC-019**. `rustls-pemfile` (unmaintained, via tonic) is ignored with a
      reason. For fuzzing, `helper_request` should immediately hit the
      unbounded allocation in `recv_request`, which SEC-005 already fixes.)*

## Implementation notes

- Fuzzing needs nightly + Linux; the CI Linux runner is enough (rustup nightly
  is already used for `relay-ebpf`).
- Expose the parsers as `pub` (or `#[doc(hidden)] pub`) functions where they
  are currently private, so the fuzz crate can call them.
