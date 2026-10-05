# Linux verification runbook

**Purpose:** close the checks that can't run on the Windows dev host or in
CI. Each section below gives the commands and the result that ticks the item.
Run them in order: later steps reuse earlier builds.
**Status:** written 2026-10-05; none of these runs have been done yet.

| § | Check | Closes |
|---|---|---|
| 2 | `relay-ebpf` builds and links on the pinned nightly | the toolchain pin (#115) |
| 3 | XDP program loads through the kernel verifier and attaches | SEC-018 XDP item (part 1) |
| 4 | Live relay traffic over the fast path, including the new rejections | SEC-018 XDP item (part 2) |
| 5 | Real-TUN mesh over QUIC, and strict throughput | SEC-019 test-matrix item |
| 6 | ≥ 10 Gbps relay on real hardware | NFR1 (Phase 6 FR1); needs hardware, see §6 |

## 1. Host

- A Linux kernel with XDP (any recent distribution kernel), and root.
- Packages: `iproute2`, `iperf3`, `ethtool`, `tcpdump`, `nftables`,
  `python3`, `bpftool` (usually in `linux-tools`), `build-essential`.
- `rustup`. The root workspace uses stable (CI used 1.99.0); `relay-ebpf/`
  selects its own pinned nightly from `rust-toolchain.toml`.

```sh
git clone https://github.com/punarduttrajput/VPN.git ferrum && cd ferrum
bash scripts/verify-vendored.sh            # pinned binaries match vendor/SHA256SUMS
bash scripts/install-bpf-linker.sh         # bpf-linker v0.10.4, digest-checked
```

## 2. Build `relay-ebpf` on the pinned nightly

```sh
cd relay-ebpf
rustc -vV | grep -E 'release|LLVM'   # expect 1.99.0-nightly (14cae6813), LLVM 22.1.8
cargo build --release                # no +nightly: let rust-toolchain.toml choose
ls -l target/bpfel-unknown-none/release/ferrum-relay-ebpf
cd ..
```

**Pass:** the object file is produced. A link error mentioning bitcode or an
unknown LLVM version means rustc's LLVM and bpf-linker's (22) disagree; fix
the pin, don't float it.

## 3. Verifier load and attach (SEC-018, part 1)

```sh
cargo build --release -p ferrum-cli --features xdp
```

Set up the namespace bed from
[relay-ebpf/README.md](../relay-ebpf/README.md) "Verify", step 2 (the
`ip netns add frxdp` … `ping -c1` block). Then start the relay on it:

```sh
sudo ip netns exec frxdp ./target/release/ferrum relay --listen 0.0.0.0:51821 \
  --metrics-listen 10.99.0.2:9101 \
  --xdp-iface veth-relay \
  --xdp-program relay-ebpf/target/bpfel-unknown-none/release/ferrum-relay-ebpf &
sudo ip netns exec frxdp bpftool prog show | grep -A3 ferrum_relay
```

**Pass:** the relay logs `relay xdp fast path enabled` (not `failed to attach
fast path`) and `bpftool` lists the program. If the verifier rejects it, the
relay logs the verifier output; the new code in `try_fastpath` (the
`Ipv4UdpFields` reads and `fastpath_eligible`) is the first suspect.

## 4. Live traffic (SEC-018, part 2)

Build the harness, then run it from the root namespace (unprivileged):

```sh
cargo build --release -p ferrum-transport --example relay_traffic
R=./target/release/examples/relay_traffic
$R 10.99.0.2:51821 b recv 2000 30 &
$R 10.99.0.2:51821 a send 2000 1400 5000
curl -s 10.99.0.2:9101/metrics | grep -E 'frames_forwarded|xdp_'
```

**Pass**, as on 2026-07-10:

- `relay_traffic … b recv` reports 2000/2000 received;
- `ferrum_relay_frames_forwarded_total` (userspace) stays **0** while
  `ferrum_relay_xdp_frames_forwarded_total` grows by 2000;
- `sudo tcpdump -v -i veth-host udp port 51821` shows no bad IPv4 checksums.

**What this proves about the SEC-018 change.** Every forwarded frame now
passes `fastpath_eligible` first, which reads the version, total length,
flags/fragment offset, destination and UDP length. If any of those were read
at the wrong offset on the kernel side, no frame would be eligible: the XDP
counter would stay at 0 and userspace would forward all 2000. So the
2000/2000 fast-path result is the live check that the new reads are right.

The rejections themselves (fragments, wrong version, options, not addressed
to the relay, length mismatches) are covered by the unit tests in
`ferrum-relay-xdp-common`. A live negative test needs a **registered** sender:
an unregistered one misses the `ADDR_TO_KEY` lookup and falls through anyway,
so its result proves nothing. That would mean adding a fragmented-send mode to
`relay_traffic` (optional, not required to close the item).

**Then:** tick the SEC-018 XDP item in
[the ticket](../tickets/security-hardening/SEC-018-low-severity-hardening.md)
and add a dated STATUS.md entry with the numbers.

## 5. Real-TUN mesh over QUIC, and throughput (SEC-019)

`verify-linux.sh` builds the workspace once, so both peers run the same build
(this matters since SEC-021 made QUIC ALPN a flag day).

```sh
sudo ./scripts/verify-linux.sh                               # baseline (CI runs this)
sudo TEST_QUIC=1 ./scripts/verify-linux.sh                   # point-to-point QUIC
sudo TEST_MESH=1 MESH_QUIC=1 ./scripts/verify-linux.sh       # SEC-019: coordinator mesh over QUIC
sudo STRICT_THROUGHPUT=1 ./scripts/verify-linux.sh           # SEC-019: NFR1 ratio as a hard gate
```

**Pass:** each exits 0. `STRICT_THROUGHPUT=1` is only meaningful on dedicated
or representative hardware (a shared 2-vCPU VM is CPU-bound well below the
0.70 ratio; see STATUS.md's NFR1 note). Record the measured ratio either way.
The QUIC runs also exercise SEC-020 (no SNI) and SEC-021 (ALPN `h3`) over a
real TUN for the first time.

**Then:** tick the SEC-019 test-matrix item in
[its ticket](../tickets/security-hardening/SEC-019-upgrade-boringtun.md),
with the numbers in STATUS.md.

## 6. NFR1 ≥ 10 Gbps relay

Needs real hardware: a multi-queue NIC whose driver supports native XDP, and a
line-rate sender (a single-socket `relay_traffic` saturates around 1 Gbps).
Attach in native mode:

```sh
sudo ./target/release/ferrum relay --listen 0.0.0.0:51821 --metrics-listen 0.0.0.0:9101   --xdp-iface <nic> --xdp-mode native   --xdp-program relay-ebpf/target/bpfel-unknown-none/release/ferrum-relay-ebpf
```

**Check the mode before measuring:** the relay logs `relay xdp fast path
enabled` with `mode=native (driver)`, and `ip link show <nic>` shows `xdp`
(native), not `xdpgeneric`. A native attach the driver can't do fails with a
warning and leaves the relay userspace-only; it never falls back to generic
mode, so a benchmark can't silently measure the wrong path.

**Pass:** ≥ 10 Gbps forwarded with `ferrum_relay_frames_forwarded_total`
(userspace) flat. Record the NIC, driver, kernel, packet size and sender.
