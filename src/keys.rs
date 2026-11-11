//! Public keys of the api, used to verify access tokens.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::Context;
use opslab_auth::{JwkSet, Verifier};

/// Minimum time between two on-demand refreshes, so tokens with made-up key
/// IDs cannot make the gateway hammer the api.
const ON_DEMAND_INTERVAL: Duration = Duration::from_secs(10);

/// Holds the current verifier. Empty until the first successful fetch.
#[derive(Clone, Default)]
pub struct KeyStore {
    verifier: Arc<RwLock<Option<Arc<Verifier>>>>,
    source: Option<Arc<Source>>,
}

/// Where keys are fetched from, for on-demand refreshes.
struct Source {
    client: reqwest::Client,
    url: String,
    last: Mutex<Option<Instant>>,
}

impl KeyStore {
    /// A store that can refetch its keys when a token names an unknown key
    /// (the api rotated its key since the last periodic refresh).
    pub fn with_source(client: reqwest::Client, url: String) -> Self {
        Self {
            verifier: Arc::default(),
            source: Some(Arc::new(Source {
                client,
                url,
                last: Mutex::new(None),
            })),
        }
    }

    /// Refetches the keys now, unless it was done less than
    /// ON_DEMAND_INTERVAL ago. Returns whether new keys were loaded.
    pub async fn refresh_now(&self) -> bool {
        let Some(source) = &self.source else {
            return false;
        };
        {
            let mut last = source.last.lock().expect("key source lock poisoned");
            if last.is_some_and(|t| t.elapsed() < ON_DEMAND_INTERVAL) {
                return false;
            }
            *last = Some(Instant::now());
        }
        match fetch(&source.client, &source.url)
            .await
            .and_then(|jwks| self.set(&jwks))
        {
            Ok(()) => {
                tracing::info!("access token keys refreshed on demand");
                true
            }
            Err(e) => {
                tracing::warn!(error = format!("{e:#}"), "cannot refresh access token keys");
                false
            }
        }
    }

    /// Replaces the trusted keys.
    pub fn set(&self, jwks: &JwkSet) -> anyhow::Result<()> {
        let verifier = Verifier::from_jwks(jwks)?;
        *self.verifier.write().expect("key store lock poisoned") = Some(Arc::new(verifier));
        Ok(())
    }

    /// The current verifier, if keys were loaded.
    pub fn verifier(&self) -> Option<Arc<Verifier>> {
        self.verifier
            .read()
            .expect("key store lock poisoned")
            .clone()
    }
}

/// Downloads a JWKS document.
pub async fn fetch(client: &reqwest::Client, url: &str) -> anyhow::Result<JwkSet> {
    client
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(|| format!("fetching {url}"))?
        .json()
        .await
        .with_context(|| format!("decoding {url}"))
}

/// Keeps the store up to date: retries every few seconds until the first
/// success, then refreshes every `interval` (the api may rotate its key).
pub async fn refresh_forever(
    store: KeyStore,
    client: reqwest::Client,
    url: String,
    interval: Duration,
) {
    const RETRY: Duration = Duration::from_secs(5);
    loop {
        let result = match fetch(&client, &url).await {
            Ok(jwks) => store.set(&jwks),
            Err(e) => Err(e),
        };
        let wait = match result {
            Ok(()) => {
                tracing::debug!("access token keys refreshed");
                interval
            }
            Err(e) => {
                tracing::warn!(error = format!("{e:#}"), "cannot load access token keys");
                if store.verifier().is_some() {
                    interval
                } else {
                    RETRY
                }
            }
        };
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::routing::get;
    use opslab_auth::Signer;

    use super::*;

    #[tokio::test]
    async fn fetches_keys_over_http() {
        let signer = Signer::generate().unwrap();
        let jwks = signer.jwks();
        let app = Router::new().route(
            "/.well-known/jwks.json",
            get(move || async move { axum::Json(jwks) }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let url = format!("http://{addr}/.well-known/jwks.json");
        let fetched = fetch(&reqwest::Client::new(), &url).await.unwrap();
        let store = KeyStore::default();
        store.set(&fetched).unwrap();
        assert!(store.verifier().is_some());
    }

    #[tokio::test]
    async fn refreshes_on_demand_at_most_every_interval() {
        let jwks = Arc::new(RwLock::new(Signer::generate().unwrap().jwks()));
        let served = jwks.clone();
        let app = Router::new().route(
            "/jwks.json",
            get(move || {
                let jwks = served.read().unwrap().clone();
                async move { axum::Json(jwks) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let store =
            KeyStore::with_source(reqwest::Client::new(), format!("http://{addr}/jwks.json"));
        assert!(store.refresh_now().await);
        // The api rotates its key: the next refresh is throttled.
        let rotated = Signer::generate().unwrap();
        *jwks.write().unwrap() = rotated.jwks();
        assert!(!store.refresh_now().await);
        assert!(store.verifier().unwrap().verify("x.y.z").is_err());
    }

    #[tokio::test]
    async fn reports_http_errors() {
        let err = fetch(&reqwest::Client::new(), "http://127.0.0.1:1/jwks.json")
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("fetching"));
    }
}
