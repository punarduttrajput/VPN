# Security Hardening — Tickets

Derived from the 2026-07-19 security review and
[PRD/security-hardening.md](../../PRD/security-hardening.md). Ordered by
severity, then market/process. Milestones map to the PRD §5 table.

| ID | Title | Severity | Milestone |
|----|-------|----------|-----------|
| [SEC-001](SEC-001-secure-by-default-auth.md) | Coordinator fails open — make auth the default | Critical | M1 |
| [SEC-002](SEC-002-token-key-binding.md) | Bind auth token to WireGuard public key | Critical | M1 |
| [SEC-003](SEC-003-relay-register-hardening.md) | Relay register is unauthenticated/spoofable + amplification vector | High | M2 |
| [SEC-004](SEC-004-transport-cert-pinning.md) | Permissive TLS verifier on QUIC/MASQUE | High | M2 |
| [SEC-005](SEC-005-helper-privilege-boundary.md) | Helper socket group-only + 0666 fallback | Medium | M2 |
| [SEC-006](SEC-006-control-plane-rate-limiting.md) | No rate limiting / quotas on the coordinator | Medium | M3 |
| [SEC-007](SEC-007-transport-cert-lifecycle.md) | Static self-signed transport certs, no rotation/revocation | Medium | M3 |
| [SEC-008](SEC-008-vendored-binary-provenance.md) | Vendored/prebuilt binaries lack checksum provenance | Medium | M2 |
| [SEC-009](SEC-009-third-party-audit-plan.md) | No independent audit; hand-rolled security primitives | Market/Process | M4 |
| [SEC-010](SEC-010-published-threat-model.md) | No published metadata/privacy threat model | Market/Process | M4 |

Follow-ups from the SEC-009 audit-readiness inventory
([docs/security/audit-plan.md](../../docs/security/audit-plan.md)). The four
Highs are gates for the third-party audit.

| ID | Title | Severity | Milestone |
|----|-------|----------|-----------|
| [SEC-011](SEC-011-mesh-source-address-check.md) | Decrypted inbound packets aren't checked against `allowed_ips` | High | M4 |
| [SEC-012](SEC-012-helper-request-validation.md) | Helper requests unvalidated: nft injection as root + TUN fd leak | High | M4 |
| [SEC-013](SEC-013-coordinator-rpc-authorization.md) | Coordinator RPCs act on any caller-supplied key; revocation isn't durable | High | M4 |
| [SEC-014](SEC-014-adopt-jsonwebtoken.md) | Replace hand-rolled JWT verification; tighten claim policy and admin audience | High | M4 |
| [SEC-015](SEC-015-masque-proxy-access-control.md) | MASQUE proxy is an open UDP proxy | Medium | M4 |
| [SEC-016](SEC-016-replace-hand-rolled-unsafe.md) | Replace hand-rolled `unsafe` FFI and parsers with vetted crates | Medium | M4 |
| [SEC-017](SEC-017-fuzzing-and-supply-chain.md) | No fuzzing, no dependency-vulnerability gate | Medium | M4 |
| [SEC-018](SEC-018-low-severity-hardening.md) | Low-severity hardening batch | Low | M4 |
| [SEC-019](SEC-019-upgrade-boringtun.md) | boringtun 0.6 pins vulnerable / unmaintained crypto dependencies | Medium | M4 |

Follow-ups from the SEC-010 threat model
([docs/security/threat-model.md](../../docs/security/threat-model.md)).

| ID | Title | Severity | Milestone |
|----|-------|----------|-----------|
| [SEC-020](SEC-020-default-sni-fingerprint.md) | Default TLS SNI `ferrum` names the product to on-path DPI | Low | M4 |
| [SEC-021](SEC-021-quic-alpn.md) | Plain and mesh QUIC offer no ALPN | Low | M4 |
| [SEC-022](SEC-022-quinn-proto-and-deny-coverage.md) | quinn-proto memory exhaustion; supply-chain gate gaps | Medium | M4 |
