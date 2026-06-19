//! Test PKI + TLS config helpers for mutual TLS (PRD Phase 3, FR2/mTLS).
//!
//! Generates a CA plus server and client identities so the coordinator↔client
//! gRPC channel can be secured with mTLS and verified in-process. In production
//! the operator supplies real certificates (see `--tls-*` flags on the binary);
//! [`generate`] is for tests and local development.

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

/// A self-contained PKI: a CA that signs both the server and a client identity.
pub struct TestPki {
    /// CA certificate (PEM) — the trust root for both sides.
    pub ca_pem: String,
    /// Server certificate (PEM), signed by the CA, SAN `localhost`.
    pub server_cert_pem: String,
    /// Server private key (PEM).
    pub server_key_pem: String,
    /// Client certificate (PEM), signed by the CA.
    pub client_cert_pem: String,
    /// Client private key (PEM).
    pub client_key_pem: String,
}

/// Generate a fresh CA + server + client identities for mTLS.
pub fn generate() -> Result<TestPki, rcgen::Error> {
    // CA.
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Server identity (ServerAuth, SAN localhost).
    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::new(vec!["localhost".to_string()])?;
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    // Client identity (ClientAuth).
    let client_key = KeyPair::generate()?;
    let mut client_params = CertificateParams::new(vec!["client".to_string()])?;
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key)?;

    Ok(TestPki {
        ca_pem: ca_cert.pem(),
        server_cert_pem: server_cert.pem(),
        server_key_pem: server_key.serialize_pem(),
        client_cert_pem: client_cert.pem(),
        client_key_pem: client_key.serialize_pem(),
    })
}

/// Ensure a rustls crypto provider is installed (tonic builds rustls configs that
/// require a process-default provider). Idempotent.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Build a [`ServerTlsConfig`] that presents the server identity and requires
/// client certificates signed by the CA (mutual TLS).
pub fn server_tls_config(pki: &TestPki) -> ServerTlsConfig {
    install_crypto_provider();
    let identity = Identity::from_pem(&pki.server_cert_pem, &pki.server_key_pem);
    let ca = Certificate::from_pem(&pki.ca_pem);
    ServerTlsConfig::new().identity(identity).client_ca_root(ca)
}
