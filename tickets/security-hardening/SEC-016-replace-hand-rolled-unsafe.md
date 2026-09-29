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

- [ ] `fdpass` on `rustix::net` (or `nix::sys::socket`) with
      `MSG_CMSG_CLOEXEC` and truncation checks; existing tests pass.
- [ ] UDP batch I/O on `quinn-udp` (GSO/GRO/`sendmmsg`), keeping the current
      `UdpTransport` API and the GSO/GRO tests. Or, if a gap blocks that, fix
      the alignment with properly aligned cmsg buffers and record why.
- [ ] `FdTun::from_fd` becomes `unsafe fn` (or takes `OwnedFd`); the FFI entry
      point documents the ownership transfer.
- [ ] The pinned SPKI comes from the same parser as the signature check
      (webpki's end-entity cert, if it exposes the SPKI; otherwise
      `x509-cert`/`der`), with a test that the two agree on crafted input.
- [ ] `ct_eq` replaced with `subtle::ConstantTimeEq`.
- [ ] Remaining `unsafe` inventory re-checked; `ferrum-tunnel` gains
      `#![deny(unsafe_code)]` with local allows, like `ferrum-transport`.
