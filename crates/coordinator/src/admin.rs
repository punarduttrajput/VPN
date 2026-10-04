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
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use rust_embed::RustEmbed;
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
        .route(
            "/api/devices/unrevoke",
            axum::routing::post(unrevoke_device),
        )
        .route("/api/policy", get(get_policy).put(put_policy))
        // Anything that isn't an /api/* route falls through to here — the
        // embedded Angular build, with an index.html fallback for its
        // client-side routes (/devices, /policy, a hard refresh on either).
        .fallback(static_asset)
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
        // Durable (SEC-013): the key and its bound identity stay refused until
        // an explicit unrevoke, so the same token can't simply re-register.
        .revoke(&body.public_key);
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

/// Lift a revocation (SEC-013): the key, and any identity revoked with it, may
/// register again. `404` if the key isn't revoked.
async fn unrevoke_device(
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
        .unrevoke(&body.public_key);
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "key is not revoked").into_response(),
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

// Static panel — the Angular app's `ng build` output
// (apps/admin-panel/dist/admin-panel/browser/), embedded at compile time so
// the coordinator ships as a single binary with no separate file server or
// runtime path to configure. Deliberately not behind `authorize`: the page
// shell (and its JS bundle) has to load before an operator has a token to
// paste in; only the `/api/*` routes above are gated.
#[derive(RustEmbed)]
#[folder = "../../apps/admin-panel/dist/admin-panel/browser/"]
struct AdminUi;

async fn static_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    // An /api/* path that no route above matched is a missing endpoint, not a
    // client-side route: answer 404 rather than a 200 app shell, so a typo'd or
    // not-yet-deployed API call fails loudly instead of "succeeding" with HTML
    // (PRD admin-panel-angular.md §10). Unauthenticated on purpose — it reveals
    // nothing beyond "no such route". Case-insensitive, so `/API/...` can't
    // slip past it (the routes above are case-sensitive and wouldn't match).
    let first_segment = path.split('/').next().unwrap_or("");
    if first_segment.eq_ignore_ascii_case("api") {
        return (StatusCode::NOT_FOUND, "no such API route").into_response();
    }
    // A hit is a real asset (index.html, a hashed JS/CSS chunk, favicon).
    if let Some(asset) = serve_embedded(path) {
        return asset;
    }
    // A miss that names a file (`chunk-OLD.js` requested by a tab loaded
    // before an upgrade) is a missing asset: 404, so the browser reports a
    // failed load instead of trying to run index.html as a script. Only
    // extensionless paths are the Angular router's client-side routes
    // (/devices, /policy, or a hard refresh on either) — serve the app shell
    // for those and let its Router take over.
    let last_segment = path.rsplit('/').next().unwrap_or("");
    if last_segment.contains('.') {
        return StatusCode::NOT_FOUND.into_response();
    }
    serve_embedded("index.html").unwrap_or_else(|| StatusCode::NOT_FOUND.into_response())
}

fn serve_embedded(path: &str) -> Option<Response> {
    let file = AdminUi::get(path)?;
    let mime = file.metadata.mimetype();
    Some(([("content-type", mime)], file.data.into_owned()).into_response())
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

    /// SEC-013: an admin revoke is durable (the key can't re-register) until
    /// `/api/devices/unrevoke` lifts it; unrevoking a key that isn't revoked
    /// is a 404.
    #[tokio::test]
    async fn revoke_is_durable_until_unrevoked() {
        let signer = TestSigner::new("k1");
        let (registry, router) =
            state_and_router(signer.verifier("https://idp.example", "ferrum-admin"));
        registry
            .lock()
            .unwrap()
            .register("AAA", "laptop", "1.1.1.1:51820", &[])
            .unwrap();
        let token = admin_token(&signer, 3600);
        let post = |uri: &str| {
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"public_key":"AAA"}"#))
                .unwrap()
        };

        let resp = router
            .clone()
            .oneshot(post("/api/devices/revoke"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            registry.lock().unwrap().register("AAA", "laptop", "", &[]),
            Err(RegistryError::Revoked)
        );

        let resp = router
            .clone()
            .oneshot(post("/api/devices/unrevoke"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        registry
            .lock()
            .unwrap()
            .register("AAA", "laptop", "", &[])
            .unwrap();

        let resp = router.oneshot(post("/api/devices/unrevoke")).await.unwrap();
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

    /// PRD admin-panel-angular.md §10: an unknown /api/* path must never fall
    /// through to the SPA shell (it used to answer 200 + index.html), while the
    /// Angular client-side routes still do.
    #[tokio::test]
    async fn unknown_api_paths_404_instead_of_serving_the_app() {
        let signer = TestSigner::new("k1");
        let (_registry, router) =
            state_and_router(signer.verifier("https://idp.example", "ferrum-admin"));
        let admin = admin_token(&signer, 3600);

        for (uri, token) in [
            ("/api/nonexistent", None),
            ("/api/nonexistent", Some(admin.as_str())),
            ("/api/devices/nope", Some(admin.as_str())),
            ("/api", None),
            // Wrong case can't slip past the guard either.
            ("/API/devices", Some(admin.as_str())),
            ("/Api/policy", None),
            // A missing asset file isn't a client-side route.
            ("/chunk-DOESNOTEXIST.js", None),
            ("/assets/missing.css", None),
        ] {
            let mut req = Request::builder().uri(uri);
            if let Some(t) = token {
                req = req.header("authorization", format!("Bearer {t}"));
            }
            let resp = router
                .clone()
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{uri}");
            let ct = resp
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap().to_string());
            assert_ne!(
                ct.as_deref(),
                Some("text/html"),
                "{uri} served the app shell"
            );
        }

        // Client-side routes (a hard refresh on them) still get the app shell.
        for uri in ["/devices", "/policy", "/dashboard"] {
            let resp = router
                .clone()
                .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
        }
    }
}
