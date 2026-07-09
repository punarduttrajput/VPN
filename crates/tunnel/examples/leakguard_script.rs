//! Print the leak-guard `nft` script (PRD `leak-protection.md`) for a given
//! interface/policy — exactly what the product engages, produced by the same
//! `ferrum_tunnel::leakguard::engage_script` call.
//!
//! Exists for `scripts/verify-linux.sh` (`TEST_LEAKGUARD=1`), which pipes it
//! into `nft -f -` inside a test network namespace to assert the ruleset's
//! observable behavior without touching the host. Not a product surface.
//!
//! ```text
//! leakguard_script <iface> <block_ipv6: 0|1> [dns_ip…]
//! ```

#[cfg(target_os = "linux")]
fn main() {
    let usage = "usage: leakguard_script <iface> <block_ipv6: 0|1> [dns_ip…]";
    let mut args = std::env::args().skip(1);
    let iface = args.next().unwrap_or_else(|| panic!("{usage}"));
    let block_ipv6 = match args.next().as_deref() {
        Some("0") => false,
        Some("1") => true,
        _ => panic!("{usage}"),
    };
    let dns: Vec<std::net::IpAddr> = args
        .map(|a| {
            a.parse()
                .unwrap_or_else(|e| panic!("bad dns_ip '{a}': {e}"))
        })
        .collect();
    print!(
        "{}",
        ferrum_tunnel::leakguard::engage_script(&iface, &dns, block_ipv6)
    );
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("leakguard_script is Linux-only (nftables)");
    std::process::exit(2);
}
