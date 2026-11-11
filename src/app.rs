//! HTTP routes.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{FromRequestParts, Query, State};
use axum::http::request::Parts;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use opslab_auth::AccessClaims;
use serde::Deserialize;
use tower_http::trace::TraceLayer;

use crate::keys::KeyStore;
use crate::terminal::{self, Machines};

/// Shared state of the handlers.
#[derive(Clone)]
pub struct AppState {
    pub keys: KeyStore,
    pub machines: Arc<dyn Machines>,
    /// Terminals without input for this long are closed.
    pub idle_timeout: Duration,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/readyz", get(readyz))
        .route("/v1/whoami", get(whoami))
        .route("/v1/terminal", get(terminal::terminal))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// Ready once the api's keys are loaded: before that every token is rejected.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match state.keys.verifier() {
        Some(_) => (StatusCode::OK, "ok"),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "access token keys not loaded",
        ),
    }
}

/// Echoes the verified access token: lets the UI and tests check the
/// api → gateway token flow end to end.
async fn whoami(Access(claims): Access) -> Json<AccessClaims> {
    Json(claims)
}

/// A verified access token, taken from `Authorization: Bearer <token>` or,
/// for WebSocket connections that cannot set headers, `?token=<token>`.
pub struct Access(pub AccessClaims);

#[derive(Deserialize)]
struct TokenQuery {
    token: Option<String>,
}

impl FromRequestParts<AppState> for Access {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let from_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::to_owned);
        let token = match from_header {
            Some(t) => Some(t),
            None => Query::<TokenQuery>::try_from_uri(&parts.uri)
                .ok()
                .and_then(|q| q.0.token),
        };
        let Some(token) = token else {
            return Err((StatusCode::UNAUTHORIZED, "missing access token").into_response());
        };
        let Some(verifier) = state.keys.verifier() else {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "access token keys not loaded",
            )
                .into_response());
        };
        let mut result = verifier.verify(&token);
        // A key the gateway does not know yet: the api may have rotated it.
        if matches!(result, Err(opslab_auth::Error::UnknownKeyId(_)))
            && state.keys.refresh_now().await
            && let Some(verifier) = state.keys.verifier()
        {
            result = verifier.verify(&token);
        }
        match result {
            Ok(claims) => Ok(Access(claims)),
            Err(e) => {
                tracing::info!(error = %e, "rejected access token");
                Err((StatusCode::UNAUTHORIZED, "invalid access token").into_response())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use opslab_auth::{AccessGrant, AccessKind, Signer};
    use tower::ServiceExt;

    use super::*;

    struct NoMachines;

    #[async_trait::async_trait]
    impl Machines for NoMachines {
        async fn instance(
            &self,
            _: &str,
            _: &str,
        ) -> kube::Result<Option<opslab_types::ChallengeInstance>> {
            Ok(None)
        }
        async fn shell(&self, _: &terminal::Target) -> kube::Result<kube::api::AttachedProcess> {
            unreachable!("no machine")
        }
    }

    fn state(keys: KeyStore) -> AppState {
        AppState {
            keys,
            machines: Arc::new(NoMachines),
            idle_timeout: Duration::from_secs(60),
        }
    }

    fn setup() -> (Signer, Router) {
        let signer = Signer::generate().unwrap();
        let keys = KeyStore::default();
        keys.set(&signer.jwks()).unwrap();
        (signer, router(state(keys)))
    }

    #[tokio::test]
    async fn terminals_of_missing_instances_are_denied() {
        let (signer, app) = setup();
        let req = Request::get(format!("/v1/terminal?token={}", token(&signer)))
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header(header::SEC_WEBSOCKET_VERSION, "13")
            .header(header::SEC_WEBSOCKET_KEY, "dGhlIHNhbXBsZSBub25jZQ==")
            .body(Body::empty())
            .unwrap();
        let (status, body) = send(app, req).await;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::FORBIDDEN, "the instance does not exist")
        );
    }

    fn token(signer: &Signer) -> String {
        let grant = AccessGrant {
            user_id: "42".into(),
            instance: "opslab-instances/hello-alice".into(),
            machine: "box".into(),
            kind: AccessKind::Terminal {
                user: "student".into(),
            },
        };
        signer
            .sign(&grant, SystemTime::now(), Duration::from_secs(60))
            .unwrap()
    }

    async fn send(app: Router, req: Request<Body>) -> (StatusCode, String) {
        let res = app.oneshot(req).await.unwrap();
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn whoami_accepts_bearer_and_query_tokens() {
        let (signer, app) = setup();
        let t = token(&signer);
        let by_header = Request::get("/v1/whoami")
            .header(header::AUTHORIZATION, format!("Bearer {t}"))
            .body(Body::empty())
            .unwrap();
        let (status, body) = send(app.clone(), by_header).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let claims: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(claims["machine"], "box");
        assert_eq!(claims["access"], "terminal");

        let by_query = Request::get(format!("/v1/whoami?token={t}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app, by_query).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn whoami_rejects_missing_and_foreign_tokens() {
        let (_, app) = setup();
        let none = Request::get("/v1/whoami").body(Body::empty()).unwrap();
        assert_eq!(send(app.clone(), none).await.0, StatusCode::UNAUTHORIZED);

        let other = Signer::generate().unwrap();
        let foreign = Request::get(format!("/v1/whoami?token={}", token(&other)))
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app, foreign).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn accepts_tokens_of_a_rotated_key_right_away() {
        // The api now signs with a new key; the gateway still has the old one.
        let rotated = Signer::generate().unwrap();
        let jwks = rotated.jwks();
        let api = Router::new().route("/jwks.json", get(move || async move { axum::Json(jwks) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, api).await.unwrap() });

        let keys =
            KeyStore::with_source(reqwest::Client::new(), format!("http://{addr}/jwks.json"));
        keys.set(&Signer::generate().unwrap().jwks()).unwrap();
        let req = Request::get(format!("/v1/whoami?token={}", token(&rotated)))
            .body(Body::empty())
            .unwrap();
        let (status, body) = send(router(state(keys)), req).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn not_ready_until_keys_are_loaded() {
        let app = router(state(KeyStore::default()));
        let req = || Request::get("/readyz").body(Body::empty()).unwrap();
        assert_eq!(
            send(app.clone(), req()).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        let whoami = Request::get("/v1/whoami?token=x")
            .body(Body::empty())
            .unwrap();
        assert_eq!(send(app, whoami).await.0, StatusCode::SERVICE_UNAVAILABLE);

        let (_, ready) = setup();
        assert_eq!(send(ready, req()).await.0, StatusCode::OK);
    }
}
