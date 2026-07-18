//! Persisted user identity (Phase 5 GUI PRD, FR1).
//!
//! A WireGuard keypair + a small bundle of profile metadata (name, advertised
//! endpoint, coordinator), generated or imported **once** and stored in the
//! OS-backed secure storage (Keychain / Credential Manager / Secret Service —
//! the [`keyring`] crate) rather than re-typed into the connect form every
//! time. The public key is derived from the private key at connect time
//! (mirrors the CLI and the existing form flow); only the private key half
//! needs to leave this module's control at all.

use serde::{Deserialize, Serialize};

/// Namespaces the credential in the OS store so it doesn't collide with any
/// other app's entries.
const SERVICE: &str = "ferrum-desktop";
/// A single fixed account name: this app manages exactly one saved identity
/// per OS user account. Multiple named profiles are a documented follow-up
/// (PRD FR1 notes "at least one"; not required for the first pass).
const ACCOUNT: &str = "identity";

/// The persisted profile: a keypair (private key only — the public key is
/// derived on demand) plus the connect-form fields that don't change often.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub private_key: String,
    pub name: String,
    pub endpoint: String,
    pub coordinator: String,
    /// OIDC bearer token, required on every gRPC call when the coordinator is
    /// built with `--oidc-issuer`. `#[serde(default)]` so identities saved
    /// before this field existed still deserialize.
    #[serde(default)]
    pub token: Option<String>,
}

fn entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| format!("opening the OS secure-storage entry: {e}"))
}

/// Save (overwriting any existing) identity to OS-backed secure storage.
pub fn save(identity: &Identity) -> Result<(), String> {
    let json = serde_json::to_string(identity).map_err(|e| e.to_string())?;
    entry()?
        .set_password(&json)
        .map_err(|e| format!("saving identity to secure storage: {e}"))
}

/// Load the saved identity, if one exists. `Ok(None)` means "no identity
/// saved yet" (first run) — not an error.
pub fn load() -> Result<Option<Identity>, String> {
    match entry()?.get_password() {
        Ok(json) => serde_json::from_str(&json)
            .map(Some)
            .map_err(|e| format!("parsing saved identity: {e}")),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(format!("loading identity from secure storage: {e}")),
    }
}

/// Remove the saved identity ("reset identity" in the UI). Idempotent.
pub fn clear() -> Result<(), String> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(format!("clearing saved identity: {e}")),
    }
}

/// Generate a fresh WireGuard keypair, returning `(private_base64, public_base64)`.
pub fn generate_keypair() -> (String, String) {
    let kp = ferrum_core::keys::KeyPair::generate();
    (kp.private_base64(), kp.public_base64())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure logic only — no secure-storage round trip here (that needs a real
    /// OS keychain/Secret Service, exercised manually; see the PRD's risk
    /// note about headless Linux hosts lacking one).
    #[test]
    fn generate_keypair_produces_a_valid_pair() {
        let (private_b64, public_b64) = generate_keypair();
        let derived = ferrum_core::keys::public_base64_from_private(&private_b64).unwrap();
        assert_eq!(derived, public_b64);
    }

    #[test]
    fn identity_json_roundtrips() {
        let id = Identity {
            private_key: "priv".to_string(),
            name: "desktop".to_string(),
            endpoint: "0.0.0.0:51820".to_string(),
            coordinator: "http://127.0.0.1:50051".to_string(),
            token: Some("tok".to_string()),
        };
        let json = serde_json::to_string(&id).unwrap();
        let back: Identity = serde_json::from_str(&json).unwrap();
        assert_eq!(back.private_key, id.private_key);
        assert_eq!(back.coordinator, id.coordinator);
        assert_eq!(back.token, id.token);
    }

    /// Identities saved before `token` existed have no such key in their JSON;
    /// `#[serde(default)]` must still deserialize them rather than error.
    #[test]
    fn identity_without_token_field_deserializes() {
        let json = r#"{"private_key":"priv","name":"desktop","endpoint":"0.0.0.0:51820","coordinator":"http://127.0.0.1:50051"}"#;
        let back: Identity = serde_json::from_str(json).unwrap();
        assert_eq!(back.token, None);
    }
}
