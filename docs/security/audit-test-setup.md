# Audit build and test setup

**For:** the third-party auditors ([audit plan](audit-plan.md) §4.2, gate 5) ·
**Tag:** `audit-2026-10` · **Status:** 2026-10-05 · **Companions:**
[threat model](threat-model.md) · [audit plan](audit-plan.md) (scope §4.1,
inventory §2)

This is how to build every part of Ferrum from the audit tag, and how to run
each test bed the project uses. Everything here runs from a clean clone. Where
a step needs special hardware or privileges, it says so.

## 1. The audit tag

```sh
git clone https://github.com/punarduttrajput/VPN.git ferrum
cd ferrum
git checkout audit-2026-10
git verify-tag audit-2026-10   # only if a signed tag was issued
```

`audit-2026-10` is an annotated tag on a `main` commit that contains this
document. It goes only on a commit where the full CI matrix (§4.1), the Fuzz
workflow and the Supply chain gate have all passed; check the commit's status
on GitHub before relying on it.

**State at the tag.** Security tickets SEC-001 to SEC-022 are merged (see
[tickets](../../tickets/security-hardening/README.md)). Open items the
auditors should know about are in §6.

## 2. What is in the repository

| Workspace | Path | Contents | Toolchain |
|---|---|---|---|
| Root | `Cargo.toml` | all `crates/*`: core, transport, tunnel, control-proto, coordinator, client-core, cli, helper, relay-xdp-common | stable |
| Desktop | `apps/desktop/src-tauri` | Tauri app, Windows `ferrum-helper` service, WFP kill-switch | stable |
| Fuzz | `fuzz/` | 8 `cargo-fuzz` targets + corpus | nightly |
| eBPF | `relay-ebpf/` | the relay's in-kernel XDP fast path | `nightly-2026-07-09` (pinned) + `bpf-linker` |
| Android | `clients/android/` | Kotlin app over the `uniffi` bindings | stable + NDK 27.2 |

The audit scope and priority order are in the [audit plan](audit-plan.md) §4.1.
The [threat model](threat-model.md) states what each component is trusted
with.

## 3. Building

### 3.1 Pinned inputs

What makes a build repeatable here:

- **Lockfiles are committed** for every workspace (`Cargo.lock`,
  `apps/desktop/src-tauri/Cargo.lock`, `fuzz/Cargo.lock`, `relay-ebpf/`).
  Build with `--locked` so a stale lockfile fails instead of silently
  resolving newer crates.
- **`protoc` is vendored** (`protoc-bin-vendored`), so the gRPC code generation
  needs no system install.
- **Prebuilt binaries are digest-pinned** (SEC-008): `vendor/SHA256SUMS` covers
  `wintun.dll` (also Authenticode-checked in CI), and
  `scripts/install-bpf-linker.sh` verifies `bpf-linker` before extracting it.
  Check with `bash scripts/verify-vendored.sh`.
- **Rust:** CI uses the current stable release at run time (1.99.0 at the tag)
  with `-D warnings` clippy. There is no `rust-toolchain.toml` at the root; to
  match the tag exactly, use `rustup toolchain install 1.99.0` and
  `cargo +1.99.0 …`.

These pins make builds repeatable from the same inputs. They are **not**
bit-for-bit reproducible builds: nobody has compared release binaries built on
two machines.

### 3.2 Commands

```sh
# Root workspace: CLI (`ferrum`), coordinator, helper, all libraries
cargo build --locked --release --workspace
cargo build --locked --release --workspace --features ferrum-cli/quic,ferrum-cli/masque,ferrum-tunnel/real-tun
cargo build --locked --release -p ferrum-coordinator --features sqlite,oidc,mtls,admin-api
# (admin-api embeds apps/admin-panel's `ng build` output; build that first:
#  cd apps/admin-panel && npm ci && npx ng build)

# Desktop app (Windows: MSVC toolchain; Linux: Tauri's webkit/GTK dev packages,
# see the `desktop` job in .github/workflows/ci.yml for the exact apt list)
cd apps/desktop/src-tauri && cargo build --locked --release

# eBPF/XDP program (Linux; nightly + the pinned bpf-linker)
bash scripts/install-bpf-linker.sh
cd relay-ebpf && cargo build --release   # uses the pinned nightly in rust-toolchain.toml
#   -> relay-ebpf/target/bpfel-unknown-none/release/ferrum-relay-ebpf

# Android (Windows host as used by the project; needs NDK 27.2)
pwsh scripts/build-android.ps1
```

## 4. Test beds

### 4.1 Unit and integration tests (any OS)

CI (`.github/workflows/ci.yml`) runs these on `ubuntu-latest` and
`windows-latest` on every PR and push to `main` (docs-only changes are
skipped). Run them locally the same way:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test  --workspace
cargo test  --workspace --features ferrum-cli/quic
cargo test  --workspace --features ferrum-cli/masque
cargo test  -p ferrum-coordinator --features sqlite
cargo test  -p ferrum-coordinator --features oidc
cargo test  -p ferrum-client-core --features mtls
cargo test  -p ferrum-coordinator -p ferrum-cli --features ferrum-coordinator/otlp,ferrum-cli/otlp
cargo test  -p ferrum-tunnel --features real-tun,helper-ipc
# not in CI, run when reviewing client-core:
cargo test  -p ferrum-client-core --features uniffi
cargo test  -p ferrum-client-core --features data-plane
# desktop (its own workspace; CI's `desktop` job, Windows + Linux):
cd apps/desktop/src-tauri && cargo fmt -- --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Tests that need Unix (fd passing, the helper's socket and peer-credential
checks, GSO/GRO) only run on Linux. Tests that need root (the helper's
real-TUN fd-leak check) are skipped without it.

### 4.2 Linux real-device bed: `scripts/verify-linux.sh`

Brings up **both peers on one host** in two network namespaces joined by a
veth "underlay", over a real TUN, then checks connectivity and benchmarks.
Needs root, `iproute2` and `iperf3`. It builds the workspace itself.

```sh
sudo ./scripts/verify-linux.sh
```

| Variable | Default | Adds |
|---|---|---|
| `TEST_QUIC=1` | off | point-to-point QUIC over a real TUN |
| `TEST_MESH=1` | off | coordinator-driven mesh: register, watch, converge |
| `MESH_QUIC=1` | off | the mesh over QUIC (with `TEST_MESH=1`) |
| `TEST_LEAKGUARD=1` | off | the production nft leak-guard inside the namespace: DNS lock, IPv6 block, restore (needs `nft`, `python3`) |
| `STRICT_THROUGHPUT=1` | off | makes the NFR1 throughput ratio (>= 0.70 of a shaped 1 Gbps link) a hard failure instead of informational |
| `SHAPE=0` | on | disables the 1 Gbps underlay shaping |

Exit code 0 means every check passed. CI runs the default set on every push
(`verify-linux` job) and `TEST_QUIC=1` on demand (`verify-quic`, from the "Run
workflow" button).

### 4.3 Relay and XDP fast path: the netns harness

The DERP-style relay and its eBPF/XDP fast path are exercised with
`crates/transport/examples/relay_traffic.rs`: two fixed-key clients (`a`, `b`)
that register with a relay and exchange `Data` frames, with verify, flood
(`bench-*`) and byte-dump (`rawdump`) modes. XDP doesn't fire on loopback, so
the relay runs in a network namespace behind a veth pair. The full recipe,
expected counters and the measured results are in
[relay-ebpf/README.md](../../relay-ebpf/README.md) "Verify". Needs root, a
Linux kernel with XDP, and the build from §3.2.

### 4.4 Windows bed

- **Unit/integration:** the §4.1 commands (CI's `windows-latest` jobs).
- **Real TUN (wintun):** from an **elevated** shell, `ferrum up --config
  <config>` with a build that enables `ferrum-tunnel/real-tun` (§3.2). `wintun.dll` must sit next to the binary;
  the desktop build copies the pinned copy there.
- **Privileged helper service + WFP kill-switch:** install the LocalSystem
  `ferrum-helper` service and drive it from the unprivileged GUI, as in
  [apps/desktop/README.md](../../apps/desktop/README.md) "The `ferrum-helper`
  service (Windows)". That section also documents the pipe DACL and client
  token check that form this privilege boundary (audit plan P3, P13).

### 4.5 Fuzzing

```sh
cargo +nightly install cargo-fuzz
cd fuzz
cargo test --no-default-features            # smoke: every target over its corpus
cargo +nightly fuzz list
cargo +nightly fuzz run <target> -- -max_total_time=600
```

Targets: `stun_response`, `relay_challenge`, `pad_deframe`, `tls_spki`,
`pin_parse`, `jwt_verify`, `masque_target`, `helper_request`. Seed corpora are
in `fuzz/corpus/`. CI runs every target for 30 s on each PR and push to
`main`, and for 10 minutes weekly, and uploads any crash reproducer as an
artifact.

### 4.6 Supply chain

```sh
cargo deny check                                         # root, all features
(cd apps/desktop/src-tauri && cargo deny check advisories)
```

Policy and every advisory exception, each with its reason, are in `deny.toml`
and `apps/desktop/src-tauri/deny.toml`. CI runs both on every push and daily.

### 4.7 Observability rules

The Prometheus SLO rules and Alertmanager config are checked with
`promtool`/`amtool` in Docker; the exact commands are in the `observability`
job of `.github/workflows/ci.yml`.

## 5. Coordinator and mesh for manual testing

`ferrum-coordinator` refuses to start without OIDC unless given
`--insecure-no-auth` (SEC-001), which is fine for a local bed. For an
authenticated bed, `deploy/oracle-vm/` brings up the coordinator, relay,
in-mesh DNS resolver and admin panel with Docker Compose, and its README shows
how to mint test OIDC tokens (`deploy/oracle-vm/scripts/mint-token.py`).

## 6. Known gaps at the tag

The Linux-only checks below are scripted, with their pass criteria, in
[docs/linux-verification-runbook.md](../linux-verification-runbook.md).

- **NFR1 at line rate.** The ≥ 10 Gbps relay figure needs real hardware with
  native (driver) XDP and a multi-queue sender. Only a ~1 Gbps netns comparison
  exists. The loader also attaches in generic (SKB) mode only, so native mode
  needs a `--xdp-mode` option first.
- **SEC-018 eBPF/XDP parser checks** (IPv4 version nibble, fragments, "not for
  us", length fields; `GatewayInfo` padding; `checksum_update` unit tests) are
  implemented and unit-tested (`ferrum-relay-xdp-common`), and the program
  type-checks for `bpfel-unknown-none`. They have not been loaded through the
  kernel verifier or re-run on live traffic (the §4.3 netns harness), which
  needs a Linux host with the eBPF toolchain.
- **SEC-019 Linux runs.** The default real-TUN run passed in CI on boringtun
  0.7. The QUIC mesh variant (`TEST_MESH=1 MESH_QUIC=1`) and
  `STRICT_THROUGHPUT=1` haven't been run.
- **Desktop licences and bans** aren't gated in CI yet, only advisories.
- **iOS and macOS** clients don't exist.
- **Residual risks by design** are listed in the threat model §7.

## 7. Contacts and reporting

Report findings during the engagement through the channel agreed in the
contract. Outside it, use the private reporting route in
[SECURITY.md](../../SECURITY.md).
