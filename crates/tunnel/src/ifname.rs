//! Network-interface-name validation (SEC-012).
//!
//! Interface names reach privileged code as untrusted input: the root helper
//! receives them in requests from its (unprivileged) clients, and the Linux
//! firewall generators interpolate them into `nft` scripts. An unvalidated name
//! is an injection vector: `x" accept; flush ruleset` would end the quoted
//! string and run arbitrary nft statements as root. So every name is checked
//! against Linux's own rules, tightened to a charset that needs no quoting.

use std::io;

/// Longest interface name Linux accepts (`IFNAMSIZ` is 16, including the NUL).
pub const MAX_IFNAME_LEN: usize = 15;

/// Check that `name` is a safe interface name: 1–[`MAX_IFNAME_LEN`] bytes,
/// only ASCII letters, digits, `_`, `-` and `.`, not starting with `-`, and not
/// `.` or `..`. This is a subset of what the kernel allows (it permits most
/// bytes except `/`, `:` and whitespace), chosen so the name can never break
/// out of a quoted string in an nft script, nor be taken for an option when
/// passed as an argument (`resolvectl dns <iface> …`). Ferrum only ever names
/// its interfaces like `ferrum0`.
pub fn validate(name: &str) -> io::Result<()> {
    let ok = !name.is_empty()
        && name.len() <= MAX_IFNAME_LEN
        && !name.starts_with('-')
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if ok {
        Ok(())
    } else {
        // Debug-format the name: it is attacker-controlled, and `{:?}` escapes
        // control characters so the error can't forge log lines either.
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid interface name {name:?}: expected 1-{MAX_IFNAME_LEN} of [A-Za-z0-9_.-]"
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_names() {
        for ok in [
            "ferrum0",
            "wg-mesh",
            "tun_1",
            "eth0.100",
            "a",
            "abcdefghijklmno",
        ] {
            validate(ok).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
    }

    #[test]
    fn rejects_hostile_and_malformed_names() {
        let too_long = "a".repeat(MAX_IFNAME_LEN + 1);
        for bad in [
            "",
            ".",
            "..",
            too_long.as_str(),
            "x\" accept; flush ruleset",
            "ferrum0\nflush ruleset",
            "fer rum",
            "a/b",
            "a:b",
            "--help",
            "-x",
            "a\"b",
            "a;b",
            "a{b}",
            "fe\u{0}rrum",
            "ферум",
        ] {
            let err = validate(bad).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput, "{bad:?}");
        }
    }
}
