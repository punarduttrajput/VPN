//! OIDC bearer-token authentication for the coordinator (PRD Phase 3, FR2).
//!
//! Clients present an OIDC-issued JWT in the gRPC `authorization: Bearer <jwt>`
//! metadata header. The coordinator acts as a *resource server*: it verifies the
//! token's signature against a JWKS (JSON Web Key Set) and checks the issuer,
//! audience, expiry and subject. It does not run the interactive OIDC flow
//! itself (that is the client's business with its identity provider).
//!
//! Verification is fully offline (no network call to the IdP): the operator
//! supplies the IdP's JWKS once via `--oidc-jwks <file>`. Signature and
//! standard-claim validation are done by the vetted `jsonwebtoken` crate on its
//! `ring` backend (SEC-014; this module used to hand-roll them on `ring`
//! directly), restricted to the two common OIDC algorithms, RS256 and ES256. Ferrum's own policy is a thin layer
//! on top: `exp`, `iss`, `aud` and a non-empty `sub` are **required**, the
//! algorithm must match the key it selects, and tags come from a verified claim.
//!
//! Why this matters: until now ACL tags were *self-declared* in the registration
//! request. With OIDC on, the device's tags are taken from a verified claim
//! (`tags`, falling back to `groups`) in a signed token — so the policy engine
//! operates on an authenticated identity instead of unauthenticated input.
//! Roles that grant privileges (`admin`, `relay`) are checked against the
//! explicit `tags` claim only, never the IdP's `groups` fallback — see
//! [`OidcVerifier::verify_role`].

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm, PublicKeyUse};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use thiserror::Error;

use crate::service::VerifiedClaims;

/// Clock-skew leeway (seconds) applied to `exp`/`nbf` checks.
const LEEWAY_SECS: u64 = 60;

/// Claims every accepted token must carry (SEC-014). `exp` in particular: a
/// token without one would otherwise never expire.
const REQUIRED_CLAIMS: [&str; 4] = ["exp", "iss", "aud", "sub"];

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
    /// No JWKS key matched the token's `kid` and `alg` (or the set was
    /// ambiguous).
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
    /// A required claim (`exp`, `iss`, `aud`, or a non-empty `sub`) is absent.
    #[error("missing required claim: {0}")]
    MissingClaim(String),
    /// The token is valid but lacks the role (tag) this operation needs.
    #[error("token lacks the '{0}' role")]
    MissingRole(String),
    /// The JWKS document could not be parsed.
    #[error("invalid JWKS: {0}")]
    Jwks(String),
}

/// One usable verification key from the JWKS.
struct KeyEntry {
    kid: Option<String>,
    /// The only algorithm this key verifies (RS256 for RSA, ES256 for P-256).
    alg: Algorithm,
    key: DecodingKey,
}

/// A set of verification keys (the IdP's published JWKS).
pub struct Jwks {
    keys: Vec<KeyEntry>,
}

impl Jwks {
    /// Parse a JWKS JSON document (`{"keys":[...]}`). Only RSA and EC P-256
    /// signing keys are kept: entries of other types, entries marked for
    /// encryption (`use: "enc"`), entries whose declared `alg` isn't the one
    /// Ferrum would verify them with, and entries that fail to parse are
    /// skipped. An error is returned only if nothing usable remains.
    pub fn from_json(doc: &str) -> Result<Self, AuthError> {
        #[derive(Deserialize)]
        struct Set {
            keys: Vec<serde_json::Value>,
        }
        let set: Set = serde_json::from_str(doc).map_err(|e| AuthError::Jwks(e.to_string()))?;
        let mut keys = Vec::new();
        for raw in set.keys {
            // Parse entries one at a time so one unfamiliar key type doesn't
            // reject the IdP's whole set.
            let Ok(jwk) = serde_json::from_value::<Jwk>(raw) else {
                continue;
            };
            let alg = match &jwk.algorithm {
                AlgorithmParameters::RSA(_) => Algorithm::RS256,
                AlgorithmParameters::EllipticCurve(ec) if ec.curve == EllipticCurve::P256 => {
                    Algorithm::ES256
                }
                _ => continue, // unsupported kty/curve
            };
            if matches!(
                jwk.common.public_key_use,
                Some(ref u) if *u != PublicKeyUse::Signature
            ) {
                continue;
            }
            if let Some(declared) = jwk.common.key_algorithm {
                let expected = match alg {
                    Algorithm::RS256 => KeyAlgorithm::RS256,
                    _ => KeyAlgorithm::ES256,
                };
                if declared != expected {
                    continue;
                }
            }
            let Ok(key) = DecodingKey::from_jwk(&jwk) else {
                continue;
            };
            keys.push(KeyEntry {
                kid: jwk.common.key_id.clone(),
                alg,
                key,
            });
        }
        if keys.is_empty() {
            return Err(AuthError::Jwks("no usable RSA/EC-P256 signing keys".into()));
        }
        Ok(Self { keys })
    }

    /// Select the key matching `kid`; if the token carries no `kid` and the set
    /// has exactly one key, use it (else the first key without a `kid`).
    fn select(&self, kid: Option<&str>) -> Option<&KeyEntry> {
        match kid {
            Some(k) => self.keys.iter().find(|e| e.kid.as_deref() == Some(k)),
            None if self.keys.len() == 1 => self.keys.first(),
            None => self.keys.iter().find(|e| e.kid.is_none()),
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
struct Claims {
    // Defaulted so an absent `sub` reaches the explicit (absent-or-empty)
    // check in `decode` and is reported as `MissingClaim("sub")`.
    #[serde(default)]
    sub: String,
    #[serde(default)]
    tags: Option<Vec<String>>,
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

    /// Verify a JWT and return the authenticated identity + authorized tags
    /// (the `tags` claim, falling back to `groups`).
    pub fn verify(&self, token: &str) -> Result<VerifiedClaims, AuthError> {
        let claims = self.decode(token)?;
        let tags = match claims.tags {
            Some(tags) if !tags.is_empty() => tags,
            _ => claims.groups,
        };
        Ok(VerifiedClaims {
            subject: claims.sub,
            tags,
        })
    }

    /// Verify a JWT that must grant `role` (e.g. `admin`): the role has to be
    /// in the token's explicit `tags` claim. The `groups` fallback that
    /// [`verify`](Self::verify) allows for device ACL tags is deliberately not
    /// consulted, so an IdP group that happens to be called `admin` doesn't
    /// grant the admin API (SEC-014).
    pub fn verify_role(&self, token: &str, role: &str) -> Result<VerifiedClaims, AuthError> {
        let claims = self.decode(token)?;
        let tags = claims.tags.unwrap_or_default();
        if !tags.iter().any(|t| t == role) {
            return Err(AuthError::MissingRole(role.to_string()));
        }
        Ok(VerifiedClaims {
            subject: claims.sub,
            tags,
        })
    }

    /// Signature + standard-claim validation, then Ferrum's claim policy.
    fn decode(&self, token: &str) -> Result<Claims, AuthError> {
        let header = jsonwebtoken::decode_header(token).map_err(map_err)?;
        if !matches!(header.alg, Algorithm::RS256 | Algorithm::ES256) {
            return Err(AuthError::UnsupportedAlg(format!("{:?}", header.alg)));
        }
        let entry = self
            .jwks
            .select(header.kid.as_deref())
            .ok_or(AuthError::UnknownKey)?;
        // The algorithm is pinned by the *key*, never taken on the token's
        // word alone: an ES256 key can't be used to accept an RS256 token.
        if entry.alg != header.alg {
            return Err(AuthError::UnknownKey);
        }

        let mut validation = Validation::new(entry.alg);
        validation.leeway = LEEWAY_SECS;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        validation.set_required_spec_claims(&REQUIRED_CLAIMS);

        let data =
            jsonwebtoken::decode::<Claims>(token, &entry.key, &validation).map_err(map_err)?;
        if data.claims.sub.trim().is_empty() {
            // An empty subject would make every such token share one SEC-002
            // identity (`oidc:`).
            return Err(AuthError::MissingClaim("sub".into()));
        }
        Ok(data.claims)
    }
}

/// Map a `jsonwebtoken` error onto Ferrum's (stable, test-asserted) variants.
fn map_err(e: jsonwebtoken::errors::Error) -> AuthError {
    match e.kind() {
        ErrorKind::InvalidToken => AuthError::Malformed,
        ErrorKind::InvalidSignature => AuthError::BadSignature,
        ErrorKind::ExpiredSignature | ErrorKind::ImmatureSignature => AuthError::Expired,
        ErrorKind::InvalidIssuer => AuthError::WrongIssuer,
        ErrorKind::InvalidAudience => AuthError::WrongAudience,
        ErrorKind::MissingRequiredClaim(claim) => AuthError::MissingClaim(claim.clone()),
        ErrorKind::InvalidAlgorithm | ErrorKind::InvalidAlgorithmName => {
            AuthError::UnsupportedAlg(e.to_string())
        }
        ErrorKind::InvalidEcdsaKey | ErrorKind::InvalidRsaKey(_) | ErrorKind::InvalidKeyFormat => {
            AuthError::UnknownKey
        }
        _ => AuthError::Decode(e.to_string()),
    }
}

/// Test-only ES256 signer, shared by this module's tests and the service tests.
#[cfg(test)]
pub(crate) mod testsign {
    use super::{Jwks, OidcVerifier};
    pub(crate) use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

    /// A self-contained ES256 signer + matching JWKS, generated offline with ring.
    pub(crate) struct TestSigner {
        kid: String,
        pair: EcdsaKeyPair,
        rng: SystemRandom,
        jwk_json: String,
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
            let jwk_json = format!(
                r#"{{"kty":"EC","crv":"P-256","kid":"{}","x":"{}","y":"{}"}}"#,
                kid,
                B64URL.encode(x),
                B64URL.encode(y),
            );
            Self {
                kid: kid.to_string(),
                pair,
                rng,
                jwk_json,
            }
        }

        /// Sign a JWT with the given raw claims JSON body.
        pub(crate) fn sign(&self, claims_json: &str) -> String {
            let header = format!(r#"{{"alg":"ES256","kid":"{}","typ":"JWT"}}"#, self.kid);
            let signing_input = format!("{}.{}", B64URL.encode(header), B64URL.encode(claims_json));
            let sig = self.pair.sign(&self.rng, signing_input.as_bytes()).unwrap();
            format!("{}.{}", signing_input, B64URL.encode(sig.as_ref()))
        }

        /// This signer's public key as a single JWK object.
        pub(crate) fn jwk(&self) -> &str {
            &self.jwk_json
        }

        pub(crate) fn jwks(&self) -> Jwks {
            Jwks::from_json(&format!(r#"{{"keys":[{}]}}"#, self.jwk_json)).unwrap()
        }

        pub(crate) fn verifier(&self, issuer: &str, audience: &str) -> OidcVerifier {
            OidcVerifier::new(issuer, audience, self.jwks())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testsign::{TestSigner, B64URL};
    use super::*;
    use base64::Engine as _;

    fn unix_now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

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

    // ---- SEC-014: claim policy, algorithm pinning, key selection, roles ----

    fn verifier_for(jwks: &str) -> OidcVerifier {
        OidcVerifier::new(
            "https://idp.example",
            "ferrum-coordinator",
            Jwks::from_json(jwks).unwrap(),
        )
    }

    #[test]
    fn requires_exp_iss_aud_and_a_non_empty_sub() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let exp = far_future();
        let missing = [
            (
                r#"{"iss":"https://idp.example","aud":"ferrum-coordinator","sub":"alice"}"#
                    .to_string(),
                "exp",
            ),
            (
                format!(r#"{{"aud":"ferrum-coordinator","sub":"alice","exp":{exp}}}"#),
                "iss",
            ),
            (
                format!(r#"{{"iss":"https://idp.example","sub":"alice","exp":{exp}}}"#),
                "aud",
            ),
            (
                format!(
                    r#"{{"iss":"https://idp.example","aud":"ferrum-coordinator","exp":{exp}}}"#
                ),
                "sub",
            ),
        ];
        for (body, claim) in missing {
            match v.verify(&s.sign(&body)) {
                Err(AuthError::MissingClaim(c)) => assert_eq!(c, claim),
                other => panic!("missing {claim}: expected MissingClaim, got {other:?}"),
            }
        }
        // Present but empty `sub` is refused too (it would be a shared identity).
        let empty_sub = format!(
            r#"{{"iss":"https://idp.example","aud":"ferrum-coordinator","sub":" ","exp":{exp}}}"#
        );
        assert!(matches!(
            v.verify(&s.sign(&empty_sub)),
            Err(AuthError::MissingClaim(c)) if c == "sub"
        ));
    }

    #[test]
    fn rejects_a_token_that_is_not_yet_valid() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let nbf = unix_now() + 3600; // well past the 60 s leeway
        let token = s.sign(&claims(
            "https://idp.example",
            "ferrum-coordinator",
            far_future(),
            &format!(r#","nbf":{nbf}"#),
        ));
        assert!(matches!(v.verify(&token), Err(AuthError::Expired)));
    }

    #[test]
    fn selects_the_key_by_kid() {
        let (a, b) = (TestSigner::new("key-a"), TestSigner::new("key-b"));
        let v = verifier_for(&format!(r#"{{"keys":[{},{}]}}"#, a.jwk(), b.jwk()));
        let body = claims(
            "https://idp.example",
            "ferrum-coordinator",
            far_future(),
            "",
        );
        assert_eq!(v.verify(&a.sign(&body)).unwrap().subject, "alice");
        assert_eq!(v.verify(&b.sign(&body)).unwrap().subject, "alice");
        // A kid the set doesn't contain selects nothing.
        let c = TestSigner::new("key-c");
        assert!(matches!(
            v.verify(&c.sign(&body)),
            Err(AuthError::UnknownKey)
        ));
    }

    #[test]
    fn verifies_rs256_and_pins_the_algorithm_to_the_key() {
        use jsonwebtoken::{EncodingKey, Header};

        let rsa_jwk = format!(
            r#"{{"kty":"RSA","kid":"rsa-1","use":"sig","alg":"RS256","n":"{TEST_RSA_N}","e":"AQAB"}}"#
        );
        let ec = TestSigner::new("ec-1");
        let v = verifier_for(&format!(r#"{{"keys":[{rsa_jwk},{}]}}"#, ec.jwk()));

        let der = base64::engine::general_purpose::STANDARD
            .decode(TEST_RSA_PKCS1_DER_B64)
            .unwrap();
        let body: serde_json::Value = serde_json::from_str(&claims(
            "https://idp.example",
            "ferrum-coordinator",
            far_future(),
            r#","tags":["dev"]"#,
        ))
        .unwrap();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("rsa-1".into());
        let token = jsonwebtoken::encode(&header, &body, &EncodingKey::from_rsa_der(&der)).unwrap();
        assert_eq!(v.verify(&token).unwrap().tags, vec!["dev".to_string()]);

        // The same RS256 token pointed at the EC key (kid swap) is refused: the
        // key decides the algorithm, not the token.
        let mut swapped = Header::new(Algorithm::RS256);
        swapped.kid = Some("ec-1".into());
        let token =
            jsonwebtoken::encode(&swapped, &body, &EncodingKey::from_rsa_der(&der)).unwrap();
        assert!(matches!(v.verify(&token), Err(AuthError::UnknownKey)));
    }

    #[test]
    fn rejects_symmetric_and_unsigned_algorithms() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let body = B64URL.encode(claims(
            "https://idp.example",
            "ferrum-coordinator",
            far_future(),
            "",
        ));
        for alg in ["HS256", "none"] {
            let header = B64URL.encode(format!(r#"{{"alg":"{alg}","kid":"k1"}}"#));
            let token = format!("{header}.{body}.c2ln");
            assert!(v.verify(&token).is_err(), "{alg} must be refused");
        }
    }

    #[test]
    fn jwks_skips_encryption_and_mismatched_alg_keys() {
        let s = TestSigner::new("k1");
        let enc = s.jwk().replacen(r#""kty""#, r#""use":"enc","kty""#, 1);
        let wrong_alg = s.jwk().replacen(r#""kty""#, r#""alg":"RS256","kty""#, 1);
        let unknown = r#"{"kty":"OKP","crv":"Ed25519","x":"AAAA"}"#;
        for doc in [
            format!(r#"{{"keys":[{enc}]}}"#),
            format!(r#"{{"keys":[{wrong_alg}]}}"#),
            format!(r#"{{"keys":[{unknown}]}}"#),
        ] {
            assert!(Jwks::from_json(&doc).is_err(), "{doc}");
        }
        // An unfamiliar entry doesn't spoil the rest of the set.
        let mixed = format!(r#"{{"keys":[{unknown},{}]}}"#, s.jwk());
        assert!(Jwks::from_json(&mixed).is_ok());
    }

    #[test]
    fn roles_come_only_from_the_tags_claim() {
        let s = TestSigner::new("k1");
        let v = s.verifier("https://idp.example", "ferrum-coordinator");
        let with = |extra: &str| {
            s.sign(&claims(
                "https://idp.example",
                "ferrum-coordinator",
                far_future(),
                extra,
            ))
        };
        v.verify_role(&with(r#","tags":["admin"]"#), "admin")
            .unwrap();
        // An IdP *group* named admin: fine as an ACL tag, never as the role.
        let group = with(r#","groups":["admin"]"#);
        assert_eq!(v.verify(&group).unwrap().tags, vec!["admin".to_string()]);
        assert!(matches!(
            v.verify_role(&group, "admin"),
            Err(AuthError::MissingRole(r)) if r == "admin"
        ));
        assert!(matches!(
            v.verify_role(&with(r#","tags":["dev"]"#), "admin"),
            Err(AuthError::MissingRole(_))
        ));
    }

    /// TEST-ONLY RSA-2048 key (PKCS#1 DER, base64), generated for these unit
    /// tests. It protects nothing and must never be used anywhere else.
    const TEST_RSA_PKCS1_DER_B64: &str = "MIIEpAIBAAKCAQEAubLmBKoqJvQsrziSXFQqkBecsp3qyPuCdR7hvIyp6RiHrPlAmTF1j8UJulo2l2Llj1PYhuKb7b98JCPR7kdP2ps/Va7Wb3gYrl7xI5gZ5/NSRyWTofy546llUS2jrm7X5Tf9vGlLjmbrd3Blg2VmD7Of37bF7JptaZfqyg4yNUDFSZ3Hqnxx1vaXrDt70JnlaK/wXTYut7PplFFDqXz/MXLk2db0mzkrvfjjiwLPVAXXqfmvb3TbGPPHuU397dPZD/iPKYdGRdMql8jXkKCPz7JJx1NiMEjBKOtohuf0eKp1hQL1aaisZfYuG54N3jxx2jpm8bkaAY7eb4uPS6+gWwIDAQABAoIBAEKnW5e2Cn5D65wTNrmsPkDNMOIN+72bRUbLyGPYq44uz1g/eTfjgFqT83tvsSOijFpnUpOL2EM8lY8VSl94OknxqoiTQoXtOhKwomZPzJCsjk5aRwUARSrZ3TOHqbZNM/IjKFDODKA3AfKzpcRFi548L7jpjl5wSbB6pnxTHyNsmTnesYjrvxJjsoF1NuuG1H/m6FhK0ZDsZ6mA1gfsADG5o25TAX3l6KlcbL7VrsDD7ARa0xTD59ppdWgekAQx5BIQUWtU3zoEL4BftqciUNNkrxOcwPTQTb11os2fh8Tl9kqnnHwsm5RyZN9O2McRf5j+pawQzpTgmGFIVVYBst0CgYEA3T7i+uo80x3lspGV0unyCaW5uHU5m2d5i1ppxtZSCn2kgkHNoKp55HrDGv+b5TVEx1MzPmLDzBR+dBNsoHV9vMIqFGVK68EnFnIgmJM2EO1BSNL2gOq0fHNpF6rE2GtdhrhbXUAYQiumXePuN27Y7bSXiJBushoEmNjRkd0h7acCgYEA1t6KjV/GhFumr5/ow5f+GS/HfZ0GSjHydaAEV8FmwVa+iypGHCawQ9ZEfX/0Q5OnksmL0/CkO2j6jh67wiNTr68RF8wd/BQ/wdiEnwKKx5srmA7em1rc68L2Iet7zha9IFS3lGCkAEilBY02PnE8XR8hkEtKmwj0IX34ryHfli0CgYEAopmGLYwa+bl+R9dxOhoPdQGkValplgndLQpctPJsRyOB1O1Rl2PSw5VpcJ0s0K5uhuNhxNbHOWRSbzKbYe4XY7N7Q5QSFOPWu0tTI28FjDkiAshwu9xCmzgio28wzjFSAiHZm9XwPilgUp6iQ4Em0sQnngkwIZq3iDHJC59uQP8CgYEAgT0rwysXYacq1DnvrC3wtT+K0yAul1QBjQRpeEsoviOpylTsBKS0oqjvWzkqN7dJNL4rb5gvgFh9VBxiPLw46tP3CQRKCMQ5MSRFaMsDpFnN19EhzfnSJbCHkRFtzyDYMukh3opeOpl3QKaWOOqtLym5a2wN/MBe7wIxIU3TiSUCgYBVhe7eCmP40z3rdF3Jucw6oQkr7Vl4GBVM1URhW3ikbaycbuFqwdkbdU/40Josp1JrxaiLBtzLF5XV6xkQrI4uQ0Hwj8RLlYbfI6FAhUZSXrNCM81Oc36S2JNmGqKqwPFfsIDy+wRr7OPu8WJs3V8wIYTIF1i5VlPia7YgaAfi0w==";
    /// Its public modulus, base64url (the JWK `n`).
    const TEST_RSA_N: &str = "ubLmBKoqJvQsrziSXFQqkBecsp3qyPuCdR7hvIyp6RiHrPlAmTF1j8UJulo2l2Llj1PYhuKb7b98JCPR7kdP2ps_Va7Wb3gYrl7xI5gZ5_NSRyWTofy546llUS2jrm7X5Tf9vGlLjmbrd3Blg2VmD7Of37bF7JptaZfqyg4yNUDFSZ3Hqnxx1vaXrDt70JnlaK_wXTYut7PplFFDqXz_MXLk2db0mzkrvfjjiwLPVAXXqfmvb3TbGPPHuU397dPZD_iPKYdGRdMql8jXkKCPz7JJx1NiMEjBKOtohuf0eKp1hQL1aaisZfYuG54N3jxx2jpm8bkaAY7eb4uPS6-gWw";
}
