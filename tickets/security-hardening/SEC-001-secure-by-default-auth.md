# SEC-001 — Coordinator fails open: make authentication the default

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Milestone** | M1 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR1 |
| **Area** | `ferrum-coordinator` |

## Problem

`CoordinatorService::authenticate()` returns `Ok(None)` whenever the `oidc`
feature is off *or* no verifier is configured (`crates/coordinator/src/service.rs`,
~L295–310). `register_device` then trusts **self-declared tags**
(`None => &req.tags`, ~L356). Because ACL tags are the authorization boundary,
an unauthenticated coordinator lets any client join the mesh and assign itself
any tags — a fail-open default. This is the misconfiguration class the market
(Tailscale/Twingate/WARP are identity-first by default) specifically avoids.

## Acceptance criteria

- [ ] Authenticated mode is the default; running open requires an explicit
      `--insecure-no-auth` flag.
- [ ] Startup fails fast if neither a verifier nor `--insecure-no-auth` is set.
- [ ] When open mode is active, a loud warning is logged at startup and
      periodically thereafter.
- [ ] In authenticated mode, privileged tags come only from verified claims;
      request-supplied tags are never used for an authorization decision.
- [ ] Integration test: default config rejects unauthenticated RPCs; a device
      cannot self-assign a privileged tag; the open-mode flag path is covered.

## Implementation notes

- Add the flag to `ferrum-coordinator`'s CLI; thread an `AuthMode` into
  `CoordinatorService`.
- Keep the `#[cfg(not(feature = "oidc"))]` build compiling, but make even that
  build require the explicit insecure opt-out (open mode is a runtime choice,
  not a silent build-feature side effect).
- Update `deploy/oracle-vm/` + README with a migration note (see PRD §7 risk).

## Blast radius / migration

Existing open deployments break until they either configure OIDC or pass
`--insecure-no-auth`. Document in the deployment README.
