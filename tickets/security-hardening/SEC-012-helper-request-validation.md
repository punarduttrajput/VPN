# SEC-012 — Helper requests unvalidated: nft injection as root + TUN fd leak

| Field | Value |
|---|---|
| **Severity** | High |
| **Milestone** | M4 (pre-audit gate) |
| **PRD** | [security-hardening.md](../../PRD/security-hardening.md) FR5/FR9 · [audit plan](../../docs/security/audit-plan.md) P2, P3 |
| **Area** | `ferrum-helper` (`unix.rs`), `ferrum-tunnel` (`firewall.rs`, `leakguard.rs`, `dns.rs`, `device.rs`) |

## Problem

1. **nft script injection.** `firewall::engage` and `leakguard::engage` build
   an `nft -f -` script with the interface name interpolated unescaped into
   `oifname "{iface}"`. The root helper passes the caller's `iface` straight
   through (`kill_switch_engage`, `leak_guard_engage`). A caller admitted to
   the helper socket can send an `iface` containing a quote, a newline and
   arbitrary nft statements (e.g. `flush ruleset`) that root then applies. That
   can tear down the host firewall. SEC-005 narrows *who* can connect; it does
   not validate *what* they send.
2. **TUN fd leak.** `open_tun` returns the fd from `device::open_raw`, which is
   sent with `fdpass::send_with_fd`. That only *borrows* the fd, and the daemon
   never closes its copy. Each `OpenTun` leaks a descriptor in the root
   process and keeps the TUN interface alive after its client exits.
3. TUN `name` (length/charset), address and MTU bounds are otherwise
   unchecked.

## Acceptance criteria

- [x] One validator for interface names (1–15 bytes, i.e. IFNAMSIZ − 1, charset
      `[A-Za-z0-9_.-]`), applied in the helper to every request field that
      names an interface, **and** in `firewall`/`leakguard` script generation
      (defence in depth: the generators refuse a bad name even if called
      directly). *(`ferrum_tunnel::ifname::validate`, which also refuses a
      leading `-` (option injection into `resolvectl`) and `.`/`..`. Applied in
      `validate_request` (helper), both `engage_script`s (now `io::Result`),
      the Linux `dns::set_dns`/`restore_dns`, and `device::open_raw`.)*
- [x] MTU range-checked (e.g. 576–9000); address parsed as today.
- [x] The daemon closes its TUN fd after sending it (wrap in `OwnedFd` so every
      path drops it, including send failures). *(`device::open_raw` now returns
      `OwnedFd`; the helper sends only its raw number.)*
- [x] Tests: a hostile name (`x" ; flush ruleset`, newline, over-long) is
      refused by the helper and by both generators; `open_tun` leaves no fd
      open in the daemon (count `/proc/self/fd` before/after on Linux).
      *(The fd test needs root to create a TUN, so it skips in unprivileged CI.
      Run with `sudo -E cargo test -p ferrum-helper`.)*

## Implementation notes

- Depends on / complements SEC-005 (helper boundary). Land after it to avoid
  conflicts in `unix.rs`.
- Longer term, consider the nft JSON API (`nft -j`) or netlink, which removes
  string templating entirely.
