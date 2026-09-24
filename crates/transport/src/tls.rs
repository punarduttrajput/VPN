//! Outer-transport TLS identity and certificate pinning for QUIC / MASQUE
//! (PRD `security-hardening.md` FR4 / SEC-004).
//!
//! The inner WireGuard handshake authenticates peers and protects payloads, so
//! the QUIC/HTTP-3 layer was built with a self-signed cert and a verifier that
//! accepted *anything*. That keeps payloads safe but gives the outer layer zero
//! server authentication: an on-path attacker could terminate the camouflage
//! QUIC connection to observe metadata, actively probe, or downgrade.
//!
//! Two pieces fix that without introducing a CA:
//!
//! * [`TlsIdentity`] — a node's TLS cert. [`TlsIdentity::from_wireguard_key`]
//!   derives an Ed25519 key from the WireGuard private key (HKDF-SHA256, one-way:
//!   the TLS key reveals nothing about the WireGuard key), so a node presents the
//!   **same public key on every start** — something a peer can pin. Rotating the
//!   WireGuard key rotates it with it.
//! * [`PinnedVerifier`] — accepts a server cert only if the SHA-256 of its
//!   **SubjectPublicKeyInfo** is one of the configured pins (a list, so the
//!   current and the next pin can overlap across a rotation — SEC-007). With
//!   **no** pins it still connects but logs a loud "outer transport
//!   unauthenticated" warning (once per destination); it never silently accepts.
//!
//! Pins cover the public key, not the whole certificate (HPKP-style): the key
//! is stable by construction, whereas the certificate's exact bytes depend on
//! the cert generator's encoding choices, so a dependency upgrade could
//! otherwise silently change every pin. For a third-party MASQUE proxy the pin
//! is `openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform
//! der | openssl dgst -sha256`; hex with or without `:` separators, any case.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, OnceLock};

use zeroize::{Zeroize, Zeroizing};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, SignatureScheme};
use tracing::warn;

pub use crate::fingerprint::{fingerprint_hex, parse_fingerprint, parse_fingerprints, Fingerprint};
use crate::TransportError;

/// TLS name every Ferrum QUIC/MASQUE endpoint presents and dials. Identity is
/// the pinned cert (and, underneath, WireGuard), never the name.
pub const SERVER_NAME: &str = "ferrum";

/// HKDF salt/label for deriving the TLS key from the WireGuard key.
const IDENTITY_SALT: &[u8] = b"ferrum-quic-tls-identity-v1";
const IDENTITY_INFO: &[u8] = b"ed25519 seed";

/// PKCS#8 v1 wrapper for a raw Ed25519 seed (RFC 8410): the fixed ASN.1 prefix
/// followed by the 32-byte seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

fn setup(msg: impl std::fmt::Display) -> TransportError {
    TransportError::Setup(msg.to_string())
}

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> Fingerprint {
    let d = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// A parsed DER TLV: `(tag, whole TLV, value, rest of the input)`.
type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

/// One DER TLV at the start of `input`.
/// Definite lengths only (DER never uses indefinite), up to 4 length bytes.
fn der_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    let (&first, after_len0) = after_tag.split_first()?;
    let (len, after_len) = if first < 0x80 {
        (usize::from(first), after_len0)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 || after_len0.len() < n {
            return None;
        }
        let len = after_len0[..n]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, &after_len0[n..])
    };
    if after_len.len() < len {
        return None;
    }
    let header = input.len() - after_len.len();
    Some((
        tag,
        &input[..header + len],
        &after_len[..len],
        &after_len[len..],
    ))
}

/// The DER-encoded SubjectPublicKeyInfo of an X.509 certificate (RFC 5280
/// §4.1): `Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { [0] version
/// OPTIONAL, serialNumber, signature, issuer, validity, subject,
/// subjectPublicKeyInfo, … }, … }`. `None` for anything that doesn't parse
/// that far — the verifier then refuses the cert.
pub fn spki_of(cert_der: &[u8]) -> Option<&[u8]> {
    const SEQUENCE: u8 = 0x30;
    const VERSION: u8 = 0xa0; // [0] EXPLICIT
    let (tag, _, cert, _) = der_tlv(cert_der)?;
    if tag != SEQUENCE {
        return None;
    }
    let (tag, _, tbs, _) = der_tlv(cert)?;
    if tag != SEQUENCE {
        return None;
    }
    let mut rest = tbs;
    let (tag, _, _, after) = der_tlv(rest)?;
    if tag == VERSION {
        rest = after;
    }
    // serialNumber, signature, issuer, validity, subject.
    for _ in 0..5 {
        rest = der_tlv(rest)?.3;
    }
    let (tag, spki, _, _) = der_tlv(rest)?;
    (tag == SEQUENCE).then_some(spki)
}

/// The pin of an X.509 certificate: SHA-256 of its SubjectPublicKeyInfo.
pub fn fingerprint_of(cert_der: &[u8]) -> Option<Fingerprint> {
    spki_of(cert_der).map(sha256)
}

/// A node's outer-transport TLS certificate and key.
pub struct TlsIdentity {
    cert: CertificateDer<'static>,
    key: PrivatePkcs8KeyDer<'static>,
    fingerprint: Fingerprint,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the key.
        f.debug_struct("TlsIdentity")
            .field("fingerprint", &fingerprint_hex(&self.fingerprint))
            .finish()
    }
}

impl Clone for TlsIdentity {
    fn clone(&self) -> Self {
        Self {
            cert: self.cert.clone(),
            key: self.key.clone_key(),
            fingerprint: self.fingerprint,
        }
    }
}

impl Drop for TlsIdentity {
    fn drop(&mut self) {
        // Don't leave the (WireGuard-derived) TLS private key in freed memory.
        self.key.zeroize();
    }
}

struct SeedLen;
impl ring::hkdf::KeyType for SeedLen {
    fn len(&self) -> usize {
        32
    }
}

impl TlsIdentity {
    /// The stable identity for the node whose WireGuard private key is
    /// `wg_private` — the same cert (and so the same pin) on every start.
    pub fn from_wireguard_key(wg_private: &[u8; 32]) -> Result<Self, TransportError> {
        let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, IDENTITY_SALT).extract(wg_private);
        let mut seed = Zeroizing::new([0u8; 32]);
        prk.expand(&[IDENTITY_INFO], SeedLen)
            .and_then(|okm| okm.fill(&mut seed[..]))
            .map_err(|_| setup("deriving TLS identity"))?;

        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
        pkcs8.extend_from_slice(&seed[..]);
        // Moved (not copied) into `key`, which `Drop` zeroizes.
        let key = PrivatePkcs8KeyDer::from(pkcs8);
        let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key, &rcgen::PKCS_ED25519)
            .map_err(|e| setup(format!("TLS identity key: {e}")))?;
        let fingerprint = sha256(&key_pair.public_key_der());
        let cert = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()])
            .and_then(|p| p.self_signed(&key_pair))
            .map_err(|e| setup(format!("TLS identity cert: {e}")))?;
        Ok(Self {
            cert: cert.der().clone(),
            key,
            fingerprint,
        })
    }

    /// A fresh random identity (a different key every call) — for tests and
    /// for servers nobody pins.
    pub fn ephemeral() -> Result<Self, TransportError> {
        let c = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
            .map_err(|e| setup(format!("self-signed cert: {e}")))?;
        let fingerprint = sha256(&c.key_pair.public_key_der());
        Ok(Self {
            cert: CertificateDer::from(c.cert),
            key: PrivatePkcs8KeyDer::from(c.key_pair.serialize_der()),
            fingerprint,
        })
    }

    /// The SHA-256 pin peers use to authenticate this identity.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// A rustls server config presenting this identity, with `alpn` protocols.
    pub(crate) fn server_crypto(
        &self,
        alpn: &[&[u8]],
    ) -> Result<rustls::ServerConfig, TransportError> {
        crate::quic::install_provider();
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![self.cert.clone()], self.key.clone_key().into())
            .map_err(|e| setup(format!("server tls: {e}")))?;
        cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Ok(cfg)
    }
}

/// The user-facing warning for a connection with nothing to pin against:
/// logged at WARN once per destination per process (a mesh re-dials its peers
/// on every reconnect), and at debug after that.
pub(crate) fn unpinned_warning(what: &str) {
    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let first = WARNED
        .get_or_init(Default::default)
        .lock()
        .map(|mut seen| seen.insert(what.to_string()))
        .unwrap_or(true);
    if first {
        warn!(
            "outer transport UNAUTHENTICATED: no certificate pin for {what}. The tunnel \
             payload is still WireGuard-encrypted and peer-authenticated, but an on-path \
             attacker could intercept this QUIC/HTTP-3 layer to observe metadata, probe, \
             or block it. Configure a pin (SHA-256 of the server's public key) to close \
             this. (Logged once per destination.)"
        );
    } else {
        tracing::debug!("outer transport unauthenticated for {what} (no pin)");
    }
}

/// A rustls verifier that accepts only certs whose SHA-256 is pinned.
///
/// The handshake signature is still checked against the presented cert (so the
/// server must hold the pinned cert's private key, not just replay the cert).
/// With no pins it accepts any cert but warns loudly — see the module docs.
#[derive(Debug)]
pub struct PinnedVerifier {
    pins: Vec<Fingerprint>,
    /// What's being connected to, for the warning/error text.
    what: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedVerifier {
    /// Verify servers against `pins` (any match wins); `what` names the server
    /// in log lines (e.g. `"MASQUE proxy 203.0.113.9:443"`).
    pub fn new(pins: Vec<Fingerprint>, what: impl Into<String>) -> Self {
        Self {
            pins,
            what: what.into(),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.pins.is_empty() {
            unpinned_warning(&self.what);
            return Ok(ServerCertVerified::assertion());
        }
        let Some(got) = fingerprint_of(end_entity) else {
            warn!(
                "{}: unparseable server certificate — refusing the connection",
                self.what
            );
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::BadEncoding,
            ));
        };
        if self.pins.contains(&got) {
            Ok(ServerCertVerified::assertion())
        } else {
            warn!(
                "{}: server key {} matches no configured pin — refusing the connection \
                 (possible interception, or the server's key changed)",
                self.what,
                fingerprint_hex(&got)
            );
            Err(rustls::Error::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A rustls client config that pins `pins` (warning when empty), with `alpn`.
pub(crate) fn client_crypto(
    pins: Vec<Fingerprint>,
    what: impl Into<String>,
    alpn: &[&[u8]],
) -> rustls::ClientConfig {
    crate::quic::install_provider();
    let mut cfg = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(pins, what)))
        .with_no_client_auth();
    cfg.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wireguard_derived_identity_is_stable() {
        let a = TlsIdentity::from_wireguard_key(&[7; 32]).unwrap();
        let b = TlsIdentity::from_wireguard_key(&[7; 32]).unwrap();
        assert_eq!(a.cert, b.cert, "same key must yield a byte-identical cert");
        assert_eq!(a.fingerprint(), b.fingerprint());
        let c = TlsIdentity::from_wireguard_key(&[8; 32]).unwrap();
        assert_ne!(
            a.fingerprint(),
            c.fingerprint(),
            "different key, different pin"
        );
    }

    #[test]
    fn ephemeral_identities_differ() {
        let a = TlsIdentity::ephemeral().unwrap();
        let b = TlsIdentity::ephemeral().unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    /// The pin is the SPKI hash, and the verifier's extraction from a presented
    /// cert agrees with what the identity advertises — for both identity kinds.
    #[test]
    fn pin_is_the_spki_hash_and_extraction_agrees() {
        for id in [
            TlsIdentity::from_wireguard_key(&[5; 32]).unwrap(),
            TlsIdentity::ephemeral().unwrap(),
        ] {
            assert_eq!(fingerprint_of(&id.cert), Some(id.fingerprint()));
        }
        // The same key in a *differently encoded* cert (other SAN, other
        // params) keeps its pin — that's the point of pinning the key.
        let seed_key = TlsIdentity::from_wireguard_key(&[5; 32]).unwrap();
        let kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&seed_key.key, &rcgen::PKCS_ED25519)
            .unwrap();
        let other = rcgen::CertificateParams::new(vec!["something-else.example".to_string()])
            .unwrap()
            .self_signed(&kp)
            .unwrap();
        assert_ne!(other.der().as_ref(), seed_key.cert.as_ref());
        assert_eq!(fingerprint_of(other.der()), Some(seed_key.fingerprint()));
    }

    #[test]
    fn spki_extraction_rejects_garbage() {
        assert!(spki_of(&[]).is_none());
        assert!(spki_of(&[0x30, 0x03, 0x02, 0x01]).is_none(), "truncated");
        assert!(spki_of(&[0x04, 0x00]).is_none(), "not a SEQUENCE");
        let id = TlsIdentity::ephemeral().unwrap();
        assert!(
            spki_of(&id.cert[..id.cert.len() / 2]).is_none(),
            "cut in half"
        );
    }

    #[test]
    fn debug_never_prints_the_key() {
        let id = TlsIdentity::from_wireguard_key(&[3; 32]).unwrap();
        let s = format!("{id:?}");
        assert!(s.contains(&fingerprint_hex(&id.fingerprint())));
        assert!(!s.contains("key"), "{s}");
    }
}
