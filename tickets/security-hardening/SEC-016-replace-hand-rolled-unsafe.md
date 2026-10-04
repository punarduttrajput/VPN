# SEC-016 — Replace hand-rolled `unsafe` FFI and parsers with vetted crates

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Milestone** | M4 |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR9 · [audit plan](../../docs/security/audit-plan.md) P7, P8, P10–P12 |
| **Area** | `ferrum-tunnel` (`fdpass.rs`, `device.rs`), `ferrum-transport` (`udp.rs`, `tls.rs`, `relay_auth.rs`) |

## Problem

Several pieces reimplement what vetted, widely used crates already provide
(most of them are already in `Cargo.lock`):

- **`fdpass`** (raw `sendmsg`/`recvmsg` + `CMSG_*`): the control buffer is a
  byte vector, so it isn't guaranteed `cmsghdr`-aligned (formally UB); no
  `MSG_CMSG_CLOEXEC` (the received TUN fd leaks into child processes such as
  `nft`); `MSG_CTRUNC` and `cmsg_len` unchecked.
- **UDP GSO/GRO** (`udp.rs`, ~270 lines of `unsafe`): the same cmsg
  alignment issue on stack buffers; hard-coded option numbers.
- **`FdTun::from_fd(RawFd)`**: a *safe* function that takes ownership of an
  arbitrary integer, violating Rust's I/O-safety contract.
- **SPKI extraction** (`tls.rs` `der_tlv`/`spki_of`): a hand-rolled DER walker
  whose output is pinned while a *different* parser (rustls/webpki) checks the
  handshake signature. A parser differential there is a pin bypass. It also
  accepts non-minimal DER lengths.
- **`ct_eq`** in `relay_auth.rs`: hand-rolled constant-time compare.

## Acceptance criteria

- [x] `fdpass` on `rustix::net` (or `nix::sys::socket`) with
      `MSG_CMSG_CLOEXEC` and truncation checks; existing tests pass. *(Part 1.
      `send_with_fd` takes a `BorrowedFd`; `recv_with_fd` returns an `OwnedFd`,
      refuses `MSG_CTRUNC` and surplus fds (closing them), and sets `FD_CLOEXEC`
      manually on Apple, which lacks the flag. `helper_proto` now carries
      `BorrowedFd`/`OwnedFd` instead of raw integers.)*
- [ ] UDP batch I/O on `quinn-udp` (GSO/GRO/`sendmmsg`), keeping the current
      `UdpTransport` API and the GSO/GRO tests. Or, if a gap blocks that, fix
      the alignment with properly aligned cmsg buffers and record why.
- [x] `FdTun::from_fd` becomes `unsafe fn` (or takes `OwnedFd`); the FFI entry
      point documents the ownership transfer. *(Part 1: both. There's a new safe
      `device::from_owned_fd`, and `from_fd(RawFd)` is `unsafe fn` with a
      `# Safety` contract. The uniffi `run` call site documents Android's
      `detachFd()` hand-over. `FdTun` I/O is now `rustix::io`, not `unsafe`.)*
- [ ] The pinned SPKI comes from the same parser as the signature check
      (webpki's end-entity cert, if it exposes the SPKI; otherwise
      `x509-cert`/`der`), with a test that the two agree on crafted input.
- [x] `ct_eq` replaced with `subtle::ConstantTimeEq`. *(Part 1.)*
- [x] Remaining `unsafe` inventory re-checked; `ferrum-tunnel` gains
      `#![deny(unsafe_code)]` with local allows, like `ferrum-transport`.
      *(Part 1: `ferrum-tunnel` went from 27 `unsafe` mentions to two
      `OwnedFd::from_raw_fd` conversions (the `tun` crate's `IntoRawFd` in
      `open_raw`, and `from_fd`), each allowed locally, and no longer depends
      on `libc`.)*

**Split into parts.** Part 1 (above, branch `sec-016-vetted-fd-passing`,
stacked on SEC-012) covers fd passing, the fd-TUN, `ct_eq` and the tunnel lint.
**Part 2:** the pinned SPKI. `rustls-webpki` 0.103 exposes no SPKI getter, so the
fix is to verify the handshake signature against the *pinned SPKI bytes
themselves* (rustls's raw-public-key verification), which leaves no second
parser to disagree with. **Part 3:** UDP GSO/GRO on `quinn-udp`, the biggest
rework of the data path.
