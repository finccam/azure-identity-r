use async_trait::async_trait;
use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
    http::{HttpClient, Method, Request},
};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

const IMDS_ENDPOINT: &str = "http://169.254.169.254/metadata/identity/oauth2/token";
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

// Match source selection in azure_identity 1.0.0. In particular, a VM doesn't
// need any environment variables. Let the SDK handle configured MI sources,
// including its errors for sources it doesn't support.
pub(crate) fn uses_imds(has_env: impl Fn(&str) -> bool) -> bool {
    if has_env("IDENTITY_ENDPOINT") {
        !has_env("IDENTITY_HEADER") && !has_env("IMDS_ENDPOINT")
    } else {
        !has_env("MSI_ENDPOINT")
    }
}

#[derive(Debug)]
pub(crate) struct ManagedIdentityDiscovery {
    credential: Arc<dyn TokenCredential>,
    probe_client: Option<Arc<dyn HttpClient>>,
    endpoint_available: AtomicBool,
}

impl ManagedIdentityDiscovery {
    pub(crate) fn new(
        credential: Arc<dyn TokenCredential>,
        probe_client: Option<Arc<dyn HttpClient>>,
    ) -> Self {
        Self {
            credential,
            probe_client,
            endpoint_available: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl TokenCredential for ManagedIdentityDiscovery {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        if let Some(client) = &self.probe_client {
            if !self.endpoint_available.load(Ordering::Relaxed) {
                // Follow Azure's cross-language discovery design:
                // https://gist.github.com/ahsonkhan/d6c4d3a9780bb058a729b76844923ef1
                // Use the token endpoint for compatibility with IMDS emulators.
                // Omitting Metadata deliberately elicits an error response without
                // acquiring a token. Any HTTP status establishes reachability.
                let request =
                    Request::new(IMDS_ENDPOINT.parse().expect("valid IMDS URL"), Method::Get);
                // A raw transport request bypasses the SDK retry pipeline. The
                // deadline bounds discovery only, never normal MI authentication.
                match tokio::time::timeout(PROBE_TIMEOUT, client.execute_request(&request)).await {
                    Ok(Ok(_)) => self.endpoint_available.store(true, Ordering::Relaxed),
                    _ => {
                        return Err(Error::with_message(
                            ErrorKind::Credential,
                            "ManagedIdentityCredential is unavailable: IMDS discovery received no response within one second or encountered a transport error",
                        ));
                    }
                }
            }
        }

        self.credential.get_token(scopes, options).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DefaultAzureCredential, NamedCredential};
    use azure_core::{
        http::{headers::Headers, AsyncRawResponse, StatusCode},
        time::OffsetDateTime,
        Bytes,
    };
    use std::sync::atomic::AtomicUsize;

    #[derive(Debug, Clone, Copy)]
    enum ProbeResult {
        Response(StatusCode),
        ConnectionError,
        Stall,
    }

    #[derive(Debug)]
    struct ProbeClient {
        result: ProbeResult,
        calls: AtomicUsize,
    }

    #[async_trait]
    impl HttpClient for ProbeClient {
        async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.url().as_str(), IMDS_ENDPOINT);
            assert_eq!(request.method(), Method::Get);
            assert!(request
                .headers()
                .get_optional_str(&"metadata".into())
                .is_none());
            match self.result {
                ProbeResult::Response(status) => Ok(AsyncRawResponse::from_bytes(
                    status,
                    Headers::default(),
                    Bytes::new(),
                )),
                ProbeResult::ConnectionError => Err(Error::with_message(
                    ErrorKind::Connection,
                    "network unreachable",
                )),
                ProbeResult::Stall => std::future::pending().await,
            }
        }
    }

    #[derive(Debug)]
    struct SlowCredential {
        calls: AtomicUsize,
        fails: bool,
        delay: Duration,
    }

    #[async_trait]
    impl TokenCredential for SlowCredential {
        async fn get_token(
            &self,
            scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            assert_eq!(scopes, &["scope"]);
            self.calls.fetch_add(1, Ordering::SeqCst);
            // Normal authentication (including retries) may exceed probe timeout.
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.fails {
                Err(Error::with_message(
                    ErrorKind::Credential,
                    "authentication failed",
                ))
            } else {
                Ok(AccessToken::new("test-token", OffsetDateTime::now_utc()))
            }
        }
    }

    fn setup(
        result: ProbeResult,
        fails: bool,
    ) -> (
        ManagedIdentityDiscovery,
        Arc<ProbeClient>,
        Arc<SlowCredential>,
    ) {
        let client = Arc::new(ProbeClient {
            result,
            calls: AtomicUsize::new(0),
        });
        let credential = Arc::new(SlowCredential {
            calls: AtomicUsize::new(0),
            fails,
            delay: Duration::from_secs(3),
        });
        (
            ManagedIdentityDiscovery::new(credential.clone(), Some(client.clone())),
            client,
            credential,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn unavailable_imds_falls_through_without_retries() {
        for result in [ProbeResult::ConnectionError, ProbeResult::Stall] {
            let (discovery, client, mi) = setup(result, false);
            let cli = Arc::new(SlowCredential {
                calls: AtomicUsize::new(0),
                fails: false,
                delay: Duration::ZERO,
            });
            let chain = DefaultAzureCredential::with_credentials(vec![
                NamedCredential {
                    name: "ManagedIdentityCredential",
                    credential: Arc::new(discovery),
                },
                NamedCredential {
                    name: "AzureCliCredential",
                    credential: cli.clone(),
                },
            ]);
            let start = tokio::time::Instant::now();
            let token = chain.get_token(&["scope"], None).await.unwrap();
            assert_eq!(token.token.secret(), "test-token");
            assert_eq!(cli.calls.load(Ordering::SeqCst), 1);
            let expected = if matches!(result, ProbeResult::Stall) {
                PROBE_TIMEOUT
            } else {
                Duration::ZERO
            };
            assert_eq!(start.elapsed(), expected);
            assert_eq!(mi.calls.load(Ordering::SeqCst), 0);
            assert_eq!(client.calls.load(Ordering::SeqCst), 1);
            // Selecting CLI prevents another probe on subsequent requests.
            chain.get_token(&["scope"], None).await.unwrap();
            assert_eq!(client.calls.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn http_responses_enable_normal_authentication_and_skip_later_probes() {
        for status in [
            StatusCode::BadRequest,
            StatusCode::TooManyRequests,
            StatusCode::ServiceUnavailable,
        ] {
            let (discovery, client, mi) = setup(ProbeResult::Response(status), false);
            let start = tokio::time::Instant::now();
            for _ in 0..2 {
                discovery.get_token(&["scope"], None).await.unwrap();
            }
            assert_eq!(start.elapsed(), Duration::from_secs(6));
            assert_eq!(client.calls.load(Ordering::SeqCst), 1);
            assert_eq!(mi.calls.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn authentication_errors_are_preserved_after_discovery() {
        let (discovery, client, _) = setup(ProbeResult::Response(StatusCode::BadRequest), true);
        for _ in 0..2 {
            let error = discovery.get_token(&["scope"], None).await.unwrap_err();
            assert_eq!(error.to_string(), "authentication failed");
        }
        assert_eq!(client.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn configured_sources_bypass_discovery() {
        let credential = Arc::new(SlowCredential {
            calls: AtomicUsize::new(0),
            fails: false,
            delay: Duration::from_secs(3),
        });
        let discovery = ManagedIdentityDiscovery::new(credential.clone(), None);
        discovery.get_token(&["scope"], None).await.unwrap();
        assert_eq!(credential.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn source_selection_matches_pinned_sdk() {
        let cases: &[(&[&str], bool)] = &[
            (&[], true),                                        // VM or local machine
            (&["AZURE_CLIENT_ID"], true),                       // user-assigned VM identity
            (&["IDENTITY_ENDPOINT", "IDENTITY_HEADER"], false), // App Service
            (
                &[
                    "IDENTITY_ENDPOINT",
                    "IDENTITY_HEADER",
                    "IDENTITY_SERVER_THUMBPRINT",
                ],
                false,
            ),
            (&["IDENTITY_ENDPOINT", "IMDS_ENDPOINT"], false), // Arc
            (&["MSI_ENDPOINT", "MSI_SECRET"], false),         // Azure ML
            (&["MSI_ENDPOINT"], false),                       // Cloud Shell
            (&["IDENTITY_ENDPOINT"], true), // incomplete configuration falls back to IMDS
            (&["IDENTITY_HEADER"], true),
            (&["IMDS_ENDPOINT"], true),
            (&["IDENTITY_ENDPOINT", "MSI_ENDPOINT"], true), // IDENTITY_ENDPOINT takes precedence
        ];
        for (names, expected) in cases {
            assert_eq!(
                uses_imds(|name| names.contains(&name)),
                *expected,
                "{names:?}"
            );
        }
    }
}
