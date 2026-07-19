# SEC-008 — Vendored/prebuilt binaries lack checksum provenance

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M2 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR8 |
| **Area** | build / CI, `vendor/`, `relay-ebpf/` |

## Problem

`wintun.dll` is vendored in-tree (`vendor/wintun/`) and `bpf-linker` is pulled
as a prebuilt musl binary from GitHub releases (per CLAUDE.md). Both are
pragmatic, but for a security product a vendored binary with no
provenance/checksum moves the trust problem *into* the build: a swapped
`wintun.dll` runs in the elevated Windows data path; a swapped `bpf-linker`
produces the kernel XDP object.

## Acceptance criteria

- [ ] Every vendored/prebuilt binary has a pinned SHA-256 recorded in-tree.
- [ ] CI verifies the checksum before the binary is used; a mismatch fails the
      build.
- [ ] Each binary's provenance (source URL + expected digest + version) is
      documented next to it.
- [ ] Where upstream publishes signatures/attestations (sigstore/SLSA), verify
      them too.

## Implementation notes

- A small `scripts/verify-vendored.sh` (or a CI step) that hashes each pinned
  artifact against a manifest.
- For `bpf-linker`, pin the release tag + asset digest; document the aya-rs
  release URL.
- Low code risk, high assurance value; good first ticket for the milestone.
