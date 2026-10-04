# Security

## Reporting a vulnerability

Please report security issues **privately**, using a GitHub security advisory on
this repository ("Report a vulnerability" on the Security tab). Don't open a
public issue. Include the affected component, the version or commit, and steps
to reproduce.

## What Ferrum protects, and what it doesn't

- **[Threat model](docs/security/threat-model.md)**: what the coordinator,
  relays, MASQUE proxies, the network path and peers can each observe, what is
  kept and for how long, trust boundaries and failure modes, and explicit
  non-goals.
- **[Privacy summary](docs/security/privacy-summary.md)**: the short,
  user-facing version.
- **[Audit plan](docs/security/audit-plan.md)**: the inventory of
  security-sensitive code and the plan for an independent audit.
- **Hardening work**: [PRD](PRD/security-hardening.md) and
  [tickets](tickets/security-hardening/README.md).

## Operator checklist

The threat model's guarantees assume these. See the threat model's §3.6 and §5
for why each one matters.

- Run the coordinator with OIDC (it refuses to start otherwise unless
  `--insecure-no-auth`, which is for local testing only).
- Protect the control channel with mTLS, or run it only on a trusted network.
- Pin TLS for QUIC/MASQUE (automatic in the coordinator-managed mesh; set
  `cert_pins` for point-to-point and MASQUE), and set a neutral `server_name`
  where it's configurable (SEC-020).
- Keep coordinator and relay logs at the default `info` level in production.
  `debug` logs client addresses.
- Treat the coordinator database, its backups and admin tokens as sensitive.
  Together they map device keys to people and locations.
