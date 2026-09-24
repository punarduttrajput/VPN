//! Certificate-pin values (SEC-004): the SHA-256 of a TLS certificate's DER.
//!
//! Kept free of any TLS dependency so crates that only *carry* pins — the
//! coordinator protocol, the mesh runner, the client core — can parse and pass
//! them without enabling the `quic` feature. Verification lives in [`crate::tls`].

use crate::TransportError;

/// SHA-256 of a certificate's SubjectPublicKeyInfo DER — what a pin is.
pub type Fingerprint = [u8; 32];

/// Lowercase hex, no separators — the canonical form Ferrum prints and stores.
pub fn fingerprint_hex(fp: &Fingerprint) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse a SHA-256 pin: 64 hex digits, optionally `:`-separated, any case (so
/// `openssl dgst -sha256`-style and colon-separated output both work).
pub fn parse_fingerprint(s: &str) -> Result<Fingerprint, TransportError> {
    let hex: String = s.trim().chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(TransportError::Setup(format!(
            "certificate pin '{s}' is not a SHA-256 fingerprint (64 hex digits)"
        )));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("validated hex");
    }
    Ok(out)
}

/// Parse a list of pins (e.g. a config field), failing on the first bad one.
pub fn parse_fingerprints(list: &[String]) -> Result<Vec<Fingerprint>, TransportError> {
    list.iter().map(|s| parse_fingerprint(s)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_openssl_forms() {
        let fp: Fingerprint = core::array::from_fn(|i| i as u8 * 7);
        let plain = fingerprint_hex(&fp);
        assert_eq!(plain.len(), 64);
        assert_eq!(parse_fingerprint(&plain).unwrap(), fp);
        let openssl: Vec<String> = fp.iter().map(|b| format!("{b:02X}")).collect();
        assert_eq!(parse_fingerprint(&openssl.join(":")).unwrap(), fp);
    }

    #[test]
    fn malformed_fingerprints_are_rejected() {
        assert!(parse_fingerprint("").is_err());
        assert!(parse_fingerprint("abcd").is_err());
        assert!(parse_fingerprint(&"zz".repeat(32)).is_err());
        assert!(parse_fingerprint(&"ab".repeat(33)).is_err());
    }
}
