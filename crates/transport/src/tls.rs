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
//!   the TLS key reveals nothing about the WireGuard key), and rcgen's defaults
//!   are deterministic (fixed validity, serial = hash of the public key, and
//!   Ed25519 signatures are deterministic), so a node presents a **byte-identical
//!   cert on every start** — something a peer can pin. Rotating the WireGuard key
//!   rotates the cert with it.
//! * [`PinnedVerifier`] — accepts a server cert only if the SHA-256 of its DER is
//!   one of the configured pins (a list, so a current + next pin can overlap
//!   across a rotation — SEC-007). With **no** pins it still connects but logs a
//!   loud "outer transport unauthenticated" warning on every handshake; it never
//!   silently accepts.
//!
//! Pins are the standard `openssl x509 -fingerprint -sha256` value, so an
//! operator can pin a third-party MASQUE proxy with stock tooling; hex with or
//! without `:` separators, any case.

use std::sync::Arc;

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

/// SHA-256 of `der`.
pub fn fingerprint_of(der: &[u8]) -> Fingerprint {
    let d = ring::digest::digest(&ring::digest::SHA256, der);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
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
        let mut seed = [0u8; 32];
        prk.expand(&[IDENTITY_INFO], SeedLen)
            .and_then(|okm| okm.fill(&mut seed))
            .map_err(|_| setup("deriving TLS identity"))?;

        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&ED25519_PKCS8_PREFIX);
        pkcs8.extend_from_slice(&seed);
        let key = PrivatePkcs8KeyDer::from(pkcs8);
        let key_pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&key, &rcgen::PKCS_ED25519)
            .map_err(|e| setup(format!("TLS identity key: {e}")))?;
        let cert = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()])
            .and_then(|p| p.self_signed(&key_pair))
            .map_err(|e| setup(format!("TLS identity cert: {e}")))?;
        let cert = cert.der().clone();
        let fingerprint = fingerprint_of(&cert);
        Ok(Self {
            cert,
            key,
            fingerprint,
        })
    }

    /// A fresh random identity (a different cert every call) — for tests and
    /// for servers nobody pins.
    pub fn ephemeral() -> Result<Self, TransportError> {
        let c = rcgen::generate_simple_self_signed(vec![SERVER_NAME.to_string()])
            .map_err(|e| setup(format!("self-signed cert: {e}")))?;
        let cert = CertificateDer::from(c.cert);
        let key = PrivatePkcs8KeyDer::from(c.key_pair.serialize_der());
        let fingerprint = fingerprint_of(&cert);
        Ok(Self {
            cert,
            key,
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

/// The user-facing warning for a connection with nothing to pin against.
pub(crate) fn unpinned_warning(what: &str) {
    warn!(
        "outer transport UNAUTHENTICATED: no certificate pin for {what}. The tunnel \
         payload is still WireGuard-encrypted and peer-authenticated, but an on-path \
         attacker could intercept this QUIC/HTTP-3 layer to observe metadata, probe, or \
         block it. Configure a pin (SHA-256 of the server certificate) to close this."
    );
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
        let got = fingerprint_of(end_entity);
        if self.pins.contains(&got) {
            Ok(ServerCertVerified::assertion())
        } else {
            warn!(
                "{}: certificate {} matches no configured pin — refusing the connection \
                 (possible interception, or the server's certificate changed)",
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

    #[test]
    fn debug_never_prints_the_key() {
        let id = TlsIdentity::from_wireguard_key(&[3; 32]).unwrap();
        let s = format!("{id:?}");
        assert!(s.contains(&fingerprint_hex(&id.fingerprint())));
        assert!(!s.contains("key"), "{s}");
    }
}
