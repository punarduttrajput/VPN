//! Fuzz target bodies for Ferrum's parsers of untrusted input (SEC-017).
//!
//! Each function takes arbitrary bytes and drives one parser. The only
//! property checked is the one every parser of attacker-controlled input
//! must have: it returns (accepting or rejecting) without panicking, hanging
//! or reading out of bounds. The `fuzz_targets/` binaries hand these to
//! libFuzzer; the tests below smoke-run them over the committed corpus plus
//! deterministic pseudo-random inputs, on any host.

use std::sync::OnceLock;

/// STUN Binding response parsing (the first 12 bytes are the expected
/// transaction id).
pub fn stun_response(data: &[u8]) {
    let _ = ferrum_transport::fuzzing::stun_binding_response(data);
}

/// A relay Challenge frame, as the client side answers it.
pub fn relay_challenge(data: &[u8]) {
    let _ = ferrum_transport::fuzzing::relay_answer_challenge(data);
}

/// `PaddedTransport`'s deframer.
pub fn pad_deframe(data: &[u8]) {
    let _ = ferrum_transport::fuzzing::pad_deframe(data);
}

/// The DER walk that extracts (and hashes) a certificate's SPKI for pinning.
pub fn tls_spki(data: &[u8]) {
    let spki = ferrum_transport::tls::spki_of(data);
    let pin = ferrum_transport::tls::fingerprint_of(data);
    // The two must agree: a pin exists exactly when an SPKI was found.
    assert_eq!(spki.is_some(), pin.is_some());
}

/// Parsing a pin string (from config or the coordinator's network map).
pub fn pin_parse(data: &[u8]) {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = ferrum_transport::fingerprint::parse_fingerprint(s);
    }
}

/// The coordinator's OIDC bearer-token verification.
pub fn jwt_verify(data: &[u8]) {
    static VERIFIER: OnceLock<ferrum_coordinator::OidcVerifier> = OnceLock::new();
    let verifier = VERIFIER.get_or_init(|| {
        // A fixed P-256 key; the fuzzer can't forge its signatures, so this
        // exercises header/payload/JWKS-selection parsing and rejection paths.
        let jwks = ferrum_coordinator::Jwks::from_json(
            r#"{"keys":[{"kty":"EC","crv":"P-256","kid":"fuzz","x":"OMaaHzJdKtdokNB4SVqYhovIgaB44hP-q_X149BhwfE","y":"igNN7artkDj0bw6yAzqv6dOwnWvrVvHoBw_92tzQ7yE"}]}"#,
        )
        .expect("fixed fuzz JWKS parses");
        ferrum_coordinator::OidcVerifier::new("https://idp.fuzz", "ferrum-fuzz", jwks)
    });
    if let Ok(token) = std::str::from_utf8(data) {
        let _ = verifier.verify(token);
    }
}

/// The MASQUE proxy's CONNECT-UDP path template parser.
pub fn masque_target(data: &[u8]) {
    if let Ok(path) = std::str::from_utf8(data) {
        let _ = ferrum_transport::fuzzing::masque_target(path);
    }
}

/// The privileged helper's request framing + decoding, over a real socket
/// (what the root daemon reads from its clients). Unix only.
pub fn helper_request(data: &[u8]) {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::net::UnixStream;

        let Ok((mut writer, mut reader)) = UnixStream::pair() else {
            return;
        };
        // Small inputs fit the socket buffer; the length cap keeps the
        // reader from ever waiting for more bytes than were written.
        if data.len() > 60_000 || writer.write_all(data).is_err() {
            return;
        }
        drop(writer);
        let _ = ferrum_tunnel::helper_proto::recv_request(&mut reader);
    }
    #[cfg(not(unix))]
    let _ = data;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    type Target = fn(&[u8]);

    const TARGETS: [(&str, Target); 8] = [
        ("stun_response", stun_response),
        ("relay_challenge", relay_challenge),
        ("pad_deframe", pad_deframe),
        ("tls_spki", tls_spki),
        ("pin_parse", pin_parse),
        ("jwt_verify", jwt_verify),
        ("masque_target", masque_target),
        ("helper_request", helper_request),
    ];

    /// Deterministic xorshift, so a failure reproduces.
    fn pseudo_random_inputs(seed: u64, count: usize) -> Vec<Vec<u8>> {
        let mut x = seed | 1;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        (0..count)
            .map(|_| {
                let len = (next() % 512) as usize;
                (0..len).map(|_| next() as u8).collect()
            })
            .collect()
    }

    /// Mutate a seed a little (bit flips, truncation), like a fuzzer's first steps.
    fn mutations(seed: &[u8]) -> Vec<Vec<u8>> {
        let mut out = vec![seed.to_vec(), Vec::new()];
        for cut in [1, seed.len() / 2, seed.len().saturating_sub(1)] {
            out.push(seed[..cut.min(seed.len())].to_vec());
        }
        for i in (0..seed.len()).step_by(seed.len().max(8) / 8) {
            let mut m = seed.to_vec();
            m[i] ^= 0xff;
            out.push(m);
        }
        out
    }

    #[test]
    fn every_target_survives_its_corpus_and_random_input() {
        let corpus_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
        for (i, (name, target)) in TARGETS.iter().enumerate() {
            let dir = corpus_root.join(name);
            let seeds: Vec<Vec<u8>> = std::fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("{name}: corpus dir {dir:?}: {e}"))
                .map(|e| std::fs::read(e.unwrap().path()).unwrap())
                .collect();
            assert!(!seeds.is_empty(), "{name}: empty corpus");
            for seed in &seeds {
                for input in mutations(seed) {
                    target(&input);
                }
            }
            for input in pseudo_random_inputs(0x5eed + i as u64, 500) {
                target(&input);
            }
        }
    }
}
