//! OIDC bearer-token authentication for the coordinator (PRD Phase 3, FR2).
//!
//! Clients present an OIDC-issued JWT in the gRPC `authorization: Bearer <jwt>`
//! metadata header. The coordinator acts as a *resource server*: it verifies the
//! token's signature against a JWKS (JSON Web Key Set) and checks the issuer,
//! audience, and expiry — it does not run the interactive OIDC flow itself (that
//! is the client's business with its identity provider).
//!
//! Verification is fully offline (no network call to the IdP): the operator
//! supplies the IdP's JWKS once via `--oidc-jwks <file>`. Signatures are checked
//! with the in-tree `ring` (RS256 and ES256, the two common OIDC algorithms), so
//! the feature is testable with a locally generated key and needs no external
//! service.
//!
//! Why this matters: until now ACL tags were *self-declared* in the registration
//! request. With OIDC on, the device's tags are taken from a verified claim
//! (`tags`, falling back to `groups`) in a signed token — so the policy engine
//! operates on an authenticated identity instead of unauthenticated input.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use serde::Deserialize;
use thiserror::Error;

use crate::service::VerifiedClaims;

/// Clock-skew leeway (seconds) applied to `exp`/`nbf` checks.
const LEEWAY_SECS: u64 = 60;

/// Why a bearer token was rejected.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The token is not a well-formed `header.payload.signature` JWT.
    #[error("malformed token")]
    Malformed,
    /// A base64url or JSON segment failed to decode.
    #[error("token decode error: {0}")]
    Decode(String),
    /// The token's `alg` is not one we verify (RS256 / ES256).
    #[error("unsupported signing algorithm: {0}")]
    UnsupportedAlg(String),
    /// No JWKS key matched the token's `kid` (or the set was ambiguous).
    #[error("no matching verification key")]
    UnknownKey,
    /// The signature did not verify against the selected key.
    #[error("signature verification failed")]
    BadSignature,
    /// The token has expired (or is not yet valid).
    #[error("token expired or not yet valid")]
    Expired,
    /// The `iss` claim did not match the configured issuer.
    #[error("issuer mismatch")]
    WrongIssuer,
    /// The `aud` claim did not include the configured audience.
    #[error("audience mismatch")]
    WrongAudience,
    /// The JWKS document could not be parsed.
    #[error("invalid JWKS: {0}")]
    Jwks(String),
}

/// A single verification key parsed from a JWKS entry.
enum Key {
    /// RSA public key components (`n`, `e`), for RS256.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// EC P-256 public point (`x`, `y`), for ES256.
    EcP256 { x: Vec<u8>, y: Vec<u8> },
}

/// One key plus its optional `kid` selector.
struct KeyEntry {
    kid: Option<String>,
    key: Key,
}

/// A set of verification keys (the IdP's published JWKS).
pub struct Jwks {
    keys: Vec<KeyEntry>,
}

#[derive(Deserialize)]
struct JwkJson {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    crv: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Deserialize)]
struct JwkSetJson {
    keys: Vec<JwkJson>,
}

impl Jwks {
    /// Parse a JWKS JSON document (`{"keys":[...]}`). Unsupported key types are
    /// skipped; an error is returned only if nothing usable remains.
    pub fn from_json(doc: &str) -> Result<Self, AuthError> {
        let set: JwkSetJson =
            serde_json::from_str(doc).map_err(|e| AuthError::Jwks(e.to_string()))?;
        let mut keys = Vec::new();
        for jwk in set.keys {
            let key = match jwk.kty.as_str() {
                "RSA" => match (jwk.n, jwk.e) {
                    (Some(n), Some(e)) => Key::Rsa {
                        n: b64url(&n)?,
                        e: b64url(&e)?,
                    },
                    _ => continue,
                },
                "EC" if jwk.crv.as_deref() == Some("P-256") => match (jwk.x, jwk.y) {
                    (Some(x), Some(y)) => Key::EcP256 {
                        x: b64url(&x)?,
                        y: b64url(&y)?,
                    },
                    _ => continue,
                },
                _ => continue, // unsupported kty/curve
            };
            keys.push(KeyEntry { kid: jwk.kid, key });
        }
        if keys.is_empty() {
            return Err(AuthError::Jwks("no usable RSA/EC-P256 keys".into()));
        }
        Ok(Self { keys })
    }

    /// Select the key matching `kid`; if the token carries no `kid` and the set
    /// has exactly one key, use it.
    fn select(&self, kid: Option<&str>) -> Option<&Key> {
        match kid {
            Some(k) => self
                .keys
                .iter()
                .find(|e| e.kid.as_deref() == Some(k))
                .map(|e| &e.key),
            None if self.keys.len() == 1 => Some(&self.keys[0].key),
            None => self.keys.iter().find(|e| e.kid.is_none()).map(|e| &e.key),
        }
    }
}

/// Verifies OIDC bearer tokens against a fixed issuer, audience, and JWKS.
pub struct OidcVerifier {
    issuer: String,
    audience: String,
    jwks: Jwks,
}

#[derive(Deserialize)]
struct Header {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Aud {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct ClaimsJson {
    #[serde(default)]
    iss: String,
    #[serde(default)]
    sub: String,
    #[serde(default)]
    aud: Option<Aud>,
    #[serde(default)]
    exp: Option<u64>,
    #[serde(default)]
    nbf: Option<u64>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
}

impl OidcVerifier {
    /// Build a verifier for tokens from `issuer` intended for `audience`,
    /// validated against `jwks`.
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>, jwks: Jwks) -> Self {
        Self {
            issuer: issuer.into(),
            audience: audience.into(),
            jwks,
        }
    }

    /// Verify a JWT and return the authenticated identity + authorized tags.
    pub fn verify(&self, token: &str) -> Result<VerifiedClaims, AuthError> {
        let mut parts = token.split('.');
        let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err(AuthError::Malformed),
        };

        let header: Header = json_segment(h)?;
        let key = self
            .jwks
            .select(header.kid.as_deref())
            .ok_or(AuthError::UnknownKey)?;

        let signature = b64url(s)?;
        let signed = format!("{h}.{p}");
        verify_signature(&header.alg, key, signed.as_bytes(), &signature)?;

        let claims: ClaimsJson = json_segment(p)?;
        if claims.iss != self.issuer {
            return Err(AuthError::WrongIssuer);
        }
        if !aud_contains(&claims.aud, &self.audience) {
            return Err(AuthError::WrongAudience);
        }
        let now = unix_now();
        if let Some(exp) = claims.exp {
            if now > exp + LEEWAY_SECS {
                return Err(AuthError::Expired);
            }
        }
        if let Some(nbf) = claims.nbf {
            if nbf > now + LEEWAY_SECS {
                return Err(AuthError::Expired);
            }
        }

        // Prefer an explicit `tags` claim; fall back to `groups`.
        let tags = if !claims.tags.is_empty() {
            claims.tags
        } else {
            claims.groups
        };
        Ok(VerifiedClaims {
            subject: claims.sub,
            tags,
        })
    }
}

/// Verify `signature` over `message` using `key`, dispatching on the JWS `alg`.
fn verify_signature(
    alg: &str,
    key: &Key,
    message: &[u8],
    signature: &[u8],
) -> Result<(), AuthError> {
    use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, RSA_PKCS1_2048_8192_SHA256};
    match (alg, key) {
        ("RS256", Key::Rsa { n, e }) => ring::signature::RsaPublicKeyComponents { n, e }
            .verify(&RSA_PKCS1_2048_8192_SHA256, message, signature)
            .map_err(|_| AuthError::BadSignature),
        ("ES256", Key::EcP256 { x, y }) => {
            // ring wants the uncompressed SEC1 point: 0x04 || x || y.
            let mut point = Vec::with_capacity(1 + x.len() + y.len());
            point.push(0x04);
            point.extend_from_slice(x);
            point.extend_from_slice(y);
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &point)
                .verify(message, signature)
                .map_err(|_| AuthError::BadSignature)
        }
        ("RS256", _) | ("ES256", _) => Err(AuthError::UnknownKey),
        (other, _) => Err(AuthError::UnsupportedAlg(other.to_string())),
    }
}

/// Whether the `aud` claim includes `expected`.
fn aud_contains(aud: &Option<Aud>, expected: &str) -> bool {
    match aud {
        Some(Aud::One(a)) => a == expected,
        Some(Aud::Many(list)) => list.iter().any(|a| a == expected),
        None => false,
    }
}

/// Decode a base64url (no-pad) segment.
fn b64url(s: &str) -> Result<Vec<u8>, AuthError> {
    B64URL
        .decode(s)
        .map_err(|e| AuthError::Decode(e.to_string()))
}

/// Decode a base64url JWT segment and parse it as JSON.
fn json_segment<T: for<'de> Deserialize<'de>>(seg: &str) -> Result<T, AuthError> {
    let bytes = b64url(seg)?;
    serde_json::from_slice(&bytes).map_err(|e| AuthError::Decode(e.to_string()))
}

/// Current UNIX time in seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Test-only ES256 signer, shared by this module's tests and the service tests.
#[cfg(test)]
pub(crate) mod testsign {
    use super::{Jwks, OidcVerifier, B64URL};
    use base64::Engine as _;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    /// A self-contained ES256 signer + matching JWKS, generated offline with ring.
    pub(crate) struct TestSigner {
        kid: String,
        pair: EcdsaKeyPair,
        rng: SystemRandom,
        jwks_json: String,
    }

    impl TestSigner {
        pub(crate) fn new(kid: &str) -> Self {
            let rng = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let pair =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            // public_key() is the uncompressed SEC1 point 0x04 || x || y.
            let pk = pair.public_key().as_ref();
            let (x, y) = (&pk[1..33], &pk[33..65]);
            let jwks_json = format!(
                r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"{}","x":"{}","y":"{}"}}]}}"#,
                kid,
                B64URL.encode(x),
                B64URL.encode(y),
            );
            Self {
                kid: kid.to_string(),
                pair,
                rng,
                jwks_json,
            }
        }

        /// Sign a JWT with the given raw claims JSON body.
        pub(crate) fn sign(&self, claims_json: &str) -> String {
            let header = format!(r#"{{"alg":"ES256","kid":"{}","typ":"JWT"}}"#, self.kid);
            let signing_input = format!("{}.{}", B64URL.encode(header), B64URL.encode(claims_json));
            let sig = self.pair.sign(&self.rng, signing_input.as_bytes()).unwrap();
            format!("{}.{}", signing_input, B64URL.encode(sig.as_ref()))
        }

        pub(crate) fn jwks(&self) -> Jwks {
            Jwks::from_json(&self.jwks_json).unwrap()
        }

        pub(crate) fn verifier(&self, issuer: &str, audience: &str) -> OidcVerifier {
            OidcVerifier::new(issuer, audience, self.jwks())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testsign::TestSigner;
    use super::*;

    fn claims(iss: &str, aud: &str, exp: u64, extra: &str) -> String {
        format!(r#"{{"iss":"{iss}","aud":"{aud}","sub":"alice","exp":{exp}{extra}}}"#)
    }

    fn far_future() -> u64 {
        unix_now() + 3600
    }

    #[test]
    fn accepts_valid_token_and_extracts_tags() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let token = s.sign(&claims(
            "https://idp.example",
            "ferrum-coordinator",
            far_future(),
            r#","tags":["dev","laptop"]"#,
        ));
        let vc = v.verify(&token).unwrap();
        assert_eq!(vc.subject, "alice");
        assert_eq!(vc.tags, vec!["dev".to_string(), "laptop".to_string()]);
    }

    #[test]
    fn falls_back_to_groups_claim_for_tags() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let token = s.sign(&claims(
            "https://idp.example",
            "ferrum-coordinator",
            far_future(),
            r#","groups":["server"]"#,
        ));
        assert_eq!(v.verify(&token).unwrap().tags, vec!["server".to_string()]);
    }

    #[test]
    fn rejects_tampered_payload() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let token = s.sign(&claims(
            "https://idp.example",
            "ferrum-coordinator",
            far_future(),
            r#","tags":["dev"]"#,
        ));
        // Swap the payload segment for a different (unsigned) one.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = B64URL.encode(claims(
            "https://idp.example",
            "ferrum-coordinator",
            far_future(),
            r#","tags":["admin"]"#,
        ));
        parts[1] = &forged;
        let tampered = parts.join(".");
        assert!(matches!(v.verify(&tampered), Err(AuthError::BadSignature)));
    }

    #[test]
    fn rejects_wrong_issuer_and_audience() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let bad_iss = s.sign(&claims(
            "https://evil.example",
            "ferrum-coordinator",
            far_future(),
            "",
        ));
        assert!(matches!(v.verify(&bad_iss), Err(AuthError::WrongIssuer)));
        let bad_aud = s.sign(&claims(
            "https://idp.example",
            "other-service",
            far_future(),
            "",
        ));
        assert!(matches!(v.verify(&bad_aud), Err(AuthError::WrongAudience)));
    }

    #[test]
    fn rejects_expired_token() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let token = s.sign(&claims(
            "https://idp.example",
            "ferrum-coordinator",
            1000,
            "",
        ));
        assert!(matches!(v.verify(&token), Err(AuthError::Expired)));
    }

    #[test]
    fn rejects_token_signed_by_a_different_key() {
        let signer = TestSigner::new("k1");
        // Verifier trusts a *different* signer's JWKS.
        let other = TestSigner::new("k1");
        let v = other.verifier("https://idp.example", "ferrum-coordinator");
        let token = signer.sign(&claims(
            "https://idp.example",
            "ferrum-coordinator",
            far_future(),
            "",
        ));
        assert!(matches!(v.verify(&token), Err(AuthError::BadSignature)));
    }

    #[test]
    fn accepts_audience_array() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let body = format!(
            r#"{{"iss":"https://idp.example","aud":["a","ferrum-coordinator"],"sub":"bob","exp":{}}}"#,
            far_future()
        );
        assert_eq!(v.verify(&s.sign(&body)).unwrap().subject, "bob");
    }

    #[test]
    fn rejects_malformed_token() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        assert!(matches!(v.verify("not-a-jwt"), Err(AuthError::Malformed)));
    }
}
