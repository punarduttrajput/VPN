# Vendored & prebuilt binaries

Every prebuilt binary this project commits or downloads at build time is pinned
by SHA-256 and has its provenance documented next to it (SEC-008). A swapped
`wintun.dll` would run in the elevated Windows data path, and a swapped
`bpf-linker` would produce the kernel XDP object, so none of these is trusted
on sight.

| Binary | Used by | Provenance | Pin | Upstream signature |
|--------|---------|------------|-----|--------------------|
| `vendor/wintun/{amd64,arm64}/wintun.dll` (Wintun 0.14.1) | Windows data plane (`real-tun`), copied next to the desktop exe | [wintun/README.md](wintun/README.md) | [`SHA256SUMS`](SHA256SUMS), also checked by `apps/desktop/src-tauri/build.rs` on every build | Authenticode (WireGuard LLC), checked in CI |
| `clients/android/gradle/wrapper/gradle-wrapper.jar` (Gradle 8.9) | `./gradlew` (Android builds) | [gradle/wrapper/README.md](../clients/android/gradle/wrapper/README.md) | [`SHA256SUMS`](SHA256SUMS); the Gradle distribution it downloads is pinned via `distributionSha256Sum` | none (digest matches Gradle's official published checksum) |
| `bpf-linker` v0.10.4 (downloaded, not committed) | building `relay-ebpf/` | [relay-ebpf/README.md](../relay-ebpf/README.md) | digests in [`scripts/install-bpf-linker.sh`](../scripts/install-bpf-linker.sh), verified before extraction | none published (no signature or attestation upstream) |

**Checks:** [`scripts/verify-vendored.sh`](../scripts/verify-vendored.sh)
runs in CI (`vendored-binaries` job). It checks `SHA256SUMS`, fails if any
committed executable/archive lacks a pin, and requires every Gradle wrapper to
pin its distribution. The same job verifies wintun's Authenticode signature on
Windows and installs `bpf-linker` through the pinned script on Linux.

**Adding or updating a binary:** get it from the upstream source, verify any
upstream signature, record the SHA-256 in `SHA256SUMS` (paths relative to the
repo root, two spaces, LF) and document the source URL, version and digest in a
README next to it.
