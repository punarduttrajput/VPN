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
