# Vendored `wintun.dll`

The Windows data plane (PRD Phase 5) uses [Wintun](https://www.wintun.net/) — the
WireGuard project's userspace TUN driver for Windows — via the `tun` crate's
wintun backend (`crates/tunnel/src/device.rs`, `real-tun` feature). The `wintun`
Rust crate loads `wintun.dll` **dynamically at runtime** (`LoadLibrary`), so the
DLL must be discoverable on the standard search path — i.e. next to the running
executable. We vendor the official, signed binaries here so builds are
self-contained and reproducible.

## Provenance

| Field | Value |
|-------|-------|
| Source | <https://www.wintun.net/builds/wintun-0.14.1.zip> |
| Version | 0.14.1 |
| Publisher | `CN=WireGuard LLC, O=WireGuard LLC, L=Boulder, S=Colorado, C=US` |
| Authenticode | **Valid** (verified with `Get-AuthenticodeSignature` at vendor time) |

## SHA-256

```
amd64/wintun.dll  E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE
arm64/wintun.dll  F7BA89005544BE9D85231A9E0D5F23B2D15B3311667E2DAD0DEBD344918A3F80
```

## License

Wintun is distributed by WireGuard LLC; its prebuilt `wintun.dll` may be
redistributed freely. See the upstream license at <https://www.wintun.net/>.

## Updating

1. Download the desired release zip from <https://www.wintun.net/builds/>.
2. **Verify the Authenticode signature** of each `bin/<arch>/wintun.dll`
   (`Get-AuthenticodeSignature` → `Status` must be `Valid`, signer WireGuard LLC).
3. Replace the per-arch DLLs here and update the version + hashes above **and in
   [`../SHA256SUMS`](../SHA256SUMS)**. That manifest is the enforced pin
   (SEC-008): `scripts/verify-vendored.sh` checks it in CI, CI re-verifies the
   Authenticode signature on Windows, and `apps/desktop/src-tauri/build.rs`
   refuses to copy a DLL whose hash doesn't match.
