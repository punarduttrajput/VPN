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
      the MASQUE path parser.
- [ ] A CI job runs each target for a short, bounded time on every PR, and
      longer on a schedule; crashes fail the job. Corpus committed.
- [ ] `cargo-deny` (advisories, licences, bans, sources) in CI with a committed
      `deny.toml`; `cargo audit` equivalent covered.
- [ ] Any findings from the first runs triaged into tickets.

## Implementation notes

- Fuzzing needs nightly + Linux; the CI Linux runner is enough (rustup nightly
  is already used for `relay-ebpf`).
- Expose the parsers as `pub` (or `#[doc(hidden)] pub`) functions where they
  are currently private, so the fuzz crate can call them.
