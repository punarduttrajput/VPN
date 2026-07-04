//! Admin HTTP API + static panel (device list/revoke, live ACL policy view/edit).
//!
//! Lives in the same process as the gRPC [`crate::service::CoordinatorService`]
//! (shares its `Arc<Mutex<Registry>>` and change-notification channel) because
//! only the live in-process registry can push a fresh network map to connected
//! `WatchNetworkMap` streams — a separate process touching the SQLite file
//! directly would have no way to notify them.
//!
//! **Auth**: every `/api/*` route requires a bearer JWT verified by the same
//! [`crate::auth::OidcVerifier`] used for device auth, whose claims must
//! additionally include the `"admin"` tag. There is no other auth mode: the
//! caller (`main.rs`) refuses to start the admin listener at all if OIDC isn't
//! configured, rather than serving this surface unauthenticated.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::auth::OidcVerifier;
use crate::policy::Policy;
use crate::registry::{Device, Registry, RegistryError};

#[derive(Clone)]
struct AdminState {
    registry: Arc<Mutex<Registry>>,
    changes: broadcast::Sender<()>,
    verifier: Arc<OidcVerifier>,
}

/// Build the admin router over a registry shared with the gRPC service.
/// `registry` and `changes` should be clones of the handles
/// [`crate::service::CoordinatorService`] holds, so a mutation here (revoke,
/// policy edit) is visible to it and triggers the same watcher push.
pub fn router(
    registry: Arc<Mutex<Registry>>,
    changes: broadcast::Sender<()>,
    verifier: Arc<OidcVerifier>,
) -> Router {
    let state = AdminState {
        registry,
        changes,
        verifier,
    };
    Router::new()
        .route("/api/devices", get(list_devices))
        .route("/api/devices/revoke", axum::routing::post(revoke_device))
        .route("/api/policy", get(get_policy).put(put_policy))
        .route("/", get(index))
        .route("/main.js", get(main_js))
        .route("/styles.css", get(styles_css))
        .with_state(state)
}

/// Bind and serve the admin router until the process exits or the listener
/// errors. The caller (`main.rs`) spawns this on its own task.
pub async fn serve(addr: std::net::SocketAddr, router: Router) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await
}

/// Verify the `Authorization: Bearer <token>` header and require the verified
/// claims to include the `"admin"` tag. The HTTP analog of
/// `service::bearer_token` + `CoordinatorService::authenticate`, reusing the
/// exact same [`OidcVerifier::verify`].
#[allow(clippy::result_large_err)] // Response is the natural error type for an axum handler
fn authorize(headers: &HeaderMap, state: &AdminState) -> Result<(), Response> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| {
            h.strip_prefix("Bearer ")
                .or_else(|| h.strip_prefix("bearer "))
        })
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "missing bearer token").into_response())?;
    let claims = state
        .verifier
        .verify(token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, format!("token rejected: {e}")).into_response())?;
    if !claims.tags.iter().any(|t| t == "admin") {
        return Err((StatusCode::FORBIDDEN, "token lacks the admin tag").into_response());
    }
    Ok(())
}

async fn list_devices(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if let Err(resp) = authorize(&headers, &state) {
        return resp;
    }
    let devices: Vec<Device> = state
        .registry
        .lock()
        .expect("registry mutex poisoned")
        .devices();
    Json(devices).into_response()
}

#[derive(Deserialize)]
struct RevokeRequest {
    public_key: String,
}

async fn revoke_device(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(body): Json<RevokeRequest>,
) -> Response {
    if let Err(resp) = authorize(&headers, &state) {
        return resp;
    }
    let result = state
        .registry
        .lock()
        .expect("registry mutex poisoned")
        .remove(&body.public_key);
    match result {
        Ok(()) => {
            // A revoked device must vanish from every connected peer's map now,
            // not on their next unrelated change (mirrors register/rotate_key).
            let _ = state.changes.send(());
            StatusCode::NO_CONTENT.into_response()
        }
        Err(RegistryError::UnknownDevice) => {
            (StatusCode::NOT_FOUND, "unknown device").into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn get_policy(State(state): State<AdminState>, headers: HeaderMap) -> Response {
    if let Err(resp) = authorize(&headers, &state) {
        return resp;
    }
    let policy: Policy = state
        .registry
        .lock()
        .expect("registry mutex poisoned")
        .policy();
    Json(policy).into_response()
}

async fn put_policy(
    State(state): State<AdminState>,
    headers: HeaderMap,
    Json(policy): Json<Policy>,
) -> Response {
    if let Err(resp) = authorize(&headers, &state) {
        return resp;
    }
    state
        .registry
        .lock()
        .expect("registry mutex poisoned")
        .set_policy(policy);
    // Reachability may have just changed for every device; push fresh maps.
    let _ = state.changes.send(());
    StatusCode::NO_CONTENT.into_response()
}

// Static panel — embedded at compile time (no bundler, matching
// `apps/desktop/dist`'s own no-build-step convention). Deliberately not behind
// `authorize`: the page shell has to load before an operator has a token to
// paste in; only the `/api/*` routes above are gated.

async fn index() -> Response {
    (
        [("content-type", "text/html; charset=utf-8")],
        include_str!("../admin-ui/index.html"),
    )
        .into_response()
}

async fn main_js() -> Response {
    (
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("../admin-ui/main.js"),
    )
        .into_response()
}

async fn styles_css() -> Response {
    (
        [("content-type", "text/css; charset=utf-8")],
        include_str!("../admin-ui/styles.css"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::testsign::TestSigner;
    use axum::body::Body;
    use axum::http::Request;
    use std::net::Ipv4Addr;
    use tower::ServiceExt;

    fn state_and_router(verifier: OidcVerifier) -> (Arc<Mutex<Registry>>, Router) {
        let registry = Arc::new(Mutex::new(Registry::new(Ipv4Addr::new(10, 8, 0, 0), 24)));
        let (changes, _) = broadcast::channel(16);
        let router = router(registry.clone(), changes, Arc::new(verifier));
        (registry, router)
    }

    fn admin_token(signer: &TestSigner, exp_in: u64) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + exp_in;
        signer.sign(&format!(
            r#"{{"iss":"https://idp.example","aud":"ferrum-admin","sub":"alice","exp":{exp},"tags":["admin"]}}"#
        ))
    }

    fn non_admin_token(signer: &TestSigner, exp_in: u64) -> String {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + exp_in;
        signer.sign(&format!(
            r#"{{"iss":"https://idp.example","aud":"ferrum-admin","sub":"bob","exp":{exp},"tags":["dev"]}}"#
        ))
    }

    #[tokio::test]
    async fn devices_requires_a_bearer_token() {
        let signer = TestSigner::new("k1");
        let (_registry, router) =
            state_and_router(signer.verifier("https://idp.example", "ferrum-admin"));

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn devices_rejects_a_valid_token_without_the_admin_tag() {
        let signer = TestSigner::new("k1");
        let (_registry, router) =
            state_and_router(signer.verifier("https://idp.example", "ferrum-admin"));
        let token = non_admin_token(&signer, 3600);

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/devices")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn devices_lists_registered_devices_for_an_admin_token() {
        let signer = TestSigner::new("k1");
        let (registry, router) =
            state_and_router(signer.verifier("https://idp.example", "ferrum-admin"));
        registry
            .lock()
            .unwrap()
            .register("AAA", "laptop", "1.1.1.1:51820", &["dev".to_string()])
            .unwrap();
        let token = admin_token(&signer, 3600);

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/devices")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        // `Device` is Serialize-only (the API never needs to deserialize one
        // back), so assert on the raw JSON shape instead.
        let devices: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(devices.as_array().unwrap().len(), 1);
        assert_eq!(devices[0]["public_key"], "AAA");
    }

    #[tokio::test]
    async fn revoke_removes_the_device_and_a_second_revoke_is_not_found() {
        let signer = TestSigner::new("k1");
        let (registry, router) =
            state_and_router(signer.verifier("https://idp.example", "ferrum-admin"));
        registry
            .lock()
            .unwrap()
            .register("AAA", "laptop", "1.1.1.1:51820", &[])
            .unwrap();
        let token = admin_token(&signer, 3600);

        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/devices/revoke")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"public_key":"AAA"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(registry.lock().unwrap().device_count(), 0);

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/devices/revoke")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"public_key":"AAA"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn policy_round_trips_through_get_and_put() {
        let signer = TestSigner::new("k1");
        let (registry, router) =
            state_and_router(signer.verifier("https://idp.example", "ferrum-admin"));
        let token = admin_token(&signer, 3600);

        let new_policy = serde_json::json!({
            "allow_all": false,
            "rules": [{"src": ["dev"], "dst": ["server"]}]
        });
        let resp = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/policy")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(new_policy.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // The registry's live policy changed (a peer's map now reflects it).
        assert!(!registry.lock().unwrap().policy().allow_all);
        assert_eq!(registry.lock().unwrap().policy().rules.len(), 1);

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/policy")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let policy: Policy = serde_json::from_slice(&body).unwrap();
        assert_eq!(policy.rules.len(), 1);
        assert_eq!(policy.rules[0].src, vec!["dev".to_string()]);
    }

    #[tokio::test]
    async fn static_panel_loads_without_a_token() {
        let signer = TestSigner::new("k1");
        let (_registry, router) =
            state_and_router(signer.verifier("https://idp.example", "ferrum-admin"));

        let resp = router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
