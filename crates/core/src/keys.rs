//! Curve25519 key handling for WireGuard-style peers (PRD FR4).
//!
//! Keys are represented as raw 32-byte values and serialized as base64, matching
//! the reference WireGuard config format.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};

/// A Curve25519 keypair (private + derived public).
#[derive(Clone)]
pub struct KeyPair {
    /// The 32-byte private key.
    pub private: StaticSecret,
    /// The derived 32-byte public key.
    pub public: PublicKey,
}

impl KeyPair {
    /// Generate a fresh random keypair using the OS CSPRNG.
    pub fn generate() -> Self {
        let private = StaticSecret::random();
        let public = PublicKey::from(&private);
        Self { private, public }
    }

    /// Base64-encode the private key.
    pub fn private_base64(&self) -> String {
        B64.encode(self.private.to_bytes())
    }

    /// Base64-encode the public key.
    pub fn public_base64(&self) -> String {
        B64.encode(self.public.as_bytes())
    }
}

/// Decode a base64 string into a 32-byte array.
pub fn decode_key(s: &str) -> Result<[u8; 32]> {
    let bytes = B64.decode(s.trim())?;
    let len = bytes.len();
    let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::KeyLength(len))?;
    Ok(arr)
}

/// Parse a base64 private key into a [`StaticSecret`].
pub fn private_from_base64(s: &str) -> Result<StaticSecret> {
    Ok(StaticSecret::from(decode_key(s)?))
}

/// Parse a base64 public key into a [`PublicKey`].
pub fn public_from_base64(s: &str) -> Result<PublicKey> {
    Ok(PublicKey::from(decode_key(s)?))
}

/// Derive the base64 public key corresponding to a base64 private key.
///
/// Used when registering with the coordinator: a config carries only the private
/// key, but the control plane identifies a device by its public key.
pub fn public_base64_from_private(private_b64: &str) -> Result<String> {
    let secret = private_from_base64(private_b64)?;
    Ok(B64.encode(PublicKey::from(&secret).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_roundtrip_through_base64() {
        let kp = KeyPair::generate();
        let priv_b64 = kp.private_base64();
        let pub_b64 = kp.public_base64();

        let parsed_priv = private_from_base64(&priv_b64).unwrap();
        let parsed_pub = public_from_base64(&pub_b64).unwrap();

        assert_eq!(parsed_priv.to_bytes(), kp.private.to_bytes());
        assert_eq!(parsed_pub.as_bytes(), kp.public.as_bytes());
    }

    #[test]
    fn public_key_derives_from_private() {
        let kp = KeyPair::generate();
        let derived = PublicKey::from(&kp.private);
        assert_eq!(derived.as_bytes(), kp.public.as_bytes());
    }

    #[test]
    fn two_generated_keys_differ() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        assert_ne!(a.private.to_bytes(), b.private.to_bytes());
    }

    #[test]
    fn rejects_wrong_length_key() {
        let short = B64.encode([0u8; 16]);
        let err = decode_key(&short).unwrap_err();
        assert!(matches!(err, Error::KeyLength(16)));
    }

    #[test]
    fn rejects_non_base64() {
        assert!(decode_key("not valid base64!!!").is_err());
    }

    #[test]
    fn public_base64_from_private_matches_keypair() {
        let kp = KeyPair::generate();
        let derived = public_base64_from_private(&kp.private_base64()).unwrap();
        assert_eq!(derived, kp.public_base64());
    }
}
