use async_trait::async_trait;
use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
};
use azure_identity::{
    AzureCliCredential, AzureDeveloperCliCredential, ClientSecretCredential,
    ManagedIdentityCredential, WorkloadIdentityCredential,
};
use extendr_api::prelude::*;
use std::{
    env, fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};
use tokio::runtime::Runtime;

const NO_CREDENTIAL_SELECTED: usize = usize::MAX;

struct NamedCredential {
    name: &'static str,
    credential: Arc<dyn TokenCredential>,
}

struct DefaultAzureCredential {
    credentials: Vec<NamedCredential>,
    successful_index: AtomicUsize,
}

impl fmt::Debug for DefaultAzureCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DefaultAzureCredential")
            .field(
                "credentials",
                &self
                    .credentials
                    .iter()
                    .map(|credential| credential.name)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl DefaultAzureCredential {
    fn new() -> Self {
        let credentials = vec![
            environment_credential(),
            named_credential(
                "WorkloadIdentityCredential",
                WorkloadIdentityCredential::new(None),
            ),
            named_credential(
                "ManagedIdentityCredential",
                ManagedIdentityCredential::new(None),
            ),
            named_credential("AzureCliCredential", AzureCliCredential::new(None)),
            named_credential(
                "AzureDeveloperCliCredential",
                AzureDeveloperCliCredential::new(None),
            ),
        ];

        Self {
            credentials,
            successful_index: AtomicUsize::new(NO_CREDENTIAL_SELECTED),
        }
    }

    #[cfg(test)]
    fn with_credentials(credentials: Vec<NamedCredential>) -> Self {
        Self {
            credentials,
            successful_index: AtomicUsize::new(NO_CREDENTIAL_SELECTED),
        }
    }
}

#[async_trait]
impl TokenCredential for DefaultAzureCredential {
    async fn get_token(
        &self,
        scopes: &[&str],
        options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        let successful_index = self.successful_index.load(Ordering::Relaxed);
        if successful_index != NO_CREDENTIAL_SELECTED {
            return self.credentials[successful_index]
                .credential
                .get_token(scopes, options)
                .await;
        }

        let mut errors = Vec::with_capacity(self.credentials.len());
        for (index, candidate) in self.credentials.iter().enumerate() {
            match candidate
                .credential
                .get_token(scopes, options.clone())
                .await
            {
                Ok(token) => {
                    self.successful_index.store(index, Ordering::Relaxed);
                    return Ok(token);
                }
                Err(error) => errors.push(format!("{}: {}", candidate.name, error)),
            }
        }

        Err(Error::with_message(
            ErrorKind::Credential,
            format!(
                "Multiple errors were encountered while attempting to authenticate:\n{}",
                errors.join("\n")
            ),
        ))
    }
}

#[derive(Debug)]
struct UnavailableCredential {
    message: String,
}

#[async_trait]
impl TokenCredential for UnavailableCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        Err(Error::with_message(
            ErrorKind::Credential,
            self.message.clone(),
        ))
    }
}

fn named_credential<T>(
    name: &'static str,
    credential: azure_core::Result<Arc<T>>,
) -> NamedCredential
where
    T: TokenCredential + 'static,
{
    let credential: Arc<dyn TokenCredential> = match credential {
        Ok(credential) => credential,
        Err(error) => Arc::new(UnavailableCredential {
            message: error.to_string(),
        }),
    };
    NamedCredential { name, credential }
}

fn environment_credential() -> NamedCredential {
    const NAME: &str = "EnvironmentCredential";
    let tenant_id = env::var("AZURE_TENANT_ID");
    let client_id = env::var("AZURE_CLIENT_ID");
    let client_secret = env::var("AZURE_CLIENT_SECRET");

    match (tenant_id, client_id, client_secret) {
        (Ok(tenant_id), Ok(client_id), Ok(client_secret)) => named_credential(
            NAME,
            ClientSecretCredential::new(&tenant_id, client_id, Secret::new(client_secret), None),
        ),
        _ => NamedCredential {
            name: NAME,
            credential: Arc::new(UnavailableCredential {
                message: "EnvironmentCredential is unavailable because AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET are not fully configured".to_string(),
            }),
        },
    }
}

fn runtime() -> std::result::Result<&'static Runtime, String> {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }

    let runtime =
        Runtime::new().map_err(|error| format!("failed to start Tokio runtime: {error}"))?;
    let _ = RUNTIME.set(runtime);
    Ok(RUNTIME.get().expect("Tokio runtime was initialized"))
}

/// An Azure credential that selects and retains the first authentication method that succeeds.
#[extendr]
struct AzureCredential {
    credential: Arc<DefaultAzureCredential>,
}

/// Methods for requesting Azure access tokens.
#[extendr]
impl AzureCredential {
    /// Request an access token for one or more scopes.
    fn get_token(&self, scopes: Vec<String>) -> std::result::Result<String, String> {
        if scopes.is_empty() {
            return Err("at least one scope is required".to_string());
        }

        let scope_refs = scopes.iter().map(String::as_str).collect::<Vec<_>>();
        let token = runtime()?
            .block_on(self.credential.get_token(&scope_refs, None))
            .map_err(|error| error.to_string())?;
        Ok(token.token.secret().to_string())
    }
}

/// Create the default Azure credential chain.
/// @export
#[extendr]
fn default_azure_credential() -> AzureCredential {
    AzureCredential {
        credential: Arc::new(DefaultAzureCredential::new()),
    }
}

// Macro to generate exports.
// This ensures exported functions are registered with R.
// See corresponding C code in `entrypoint.c`.
extendr_module! {
    mod azidentity;
    impl AzureCredential;
    fn default_azure_credential;
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::time::{Duration, OffsetDateTime};
    use std::sync::atomic::AtomicBool;

    #[derive(Debug)]
    struct MockCredential {
        name: &'static str,
        calls: AtomicUsize,
        succeeds: AtomicBool,
    }

    impl MockCredential {
        fn new(name: &'static str, succeeds: bool) -> Arc<Self> {
            Arc::new(Self {
                name,
                calls: AtomicUsize::new(0),
                succeeds: AtomicBool::new(succeeds),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl TokenCredential for MockCredential {
        async fn get_token(
            &self,
            _scopes: &[&str],
            _options: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<AccessToken> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.succeeds.load(Ordering::SeqCst) {
                Ok(AccessToken::new(
                    self.name,
                    OffsetDateTime::now_utc() + Duration::hours(1),
                ))
            } else {
                Err(Error::with_message(
                    ErrorKind::Credential,
                    format!("{} failed", self.name),
                ))
            }
        }
    }

    fn candidate(name: &'static str, credential: Arc<MockCredential>) -> NamedCredential {
        NamedCredential { name, credential }
    }

    #[tokio::test]
    async fn caches_the_first_successful_credential() {
        let first = MockCredential::new("first", false);
        let second = MockCredential::new("second", true);
        let third = MockCredential::new("third", true);
        let chain = DefaultAzureCredential::with_credentials(vec![
            candidate("first", first.clone()),
            candidate("second", second.clone()),
            candidate("third", third.clone()),
        ]);

        for _ in 0..3 {
            let token = chain.get_token(&["scope"], None).await.unwrap();
            assert_eq!(token.token.secret(), "second");
        }

        assert_eq!(first.calls(), 1);
        assert_eq!(second.calls(), 3);
        assert_eq!(third.calls(), 0);
    }

    #[tokio::test]
    async fn does_not_fall_back_after_selecting_a_credential() {
        let first = MockCredential::new("first", true);
        let second = MockCredential::new("second", true);
        let chain = DefaultAzureCredential::with_credentials(vec![
            candidate("first", first.clone()),
            candidate("second", second.clone()),
        ]);

        chain.get_token(&["scope"], None).await.unwrap();
        first.succeeds.store(false, Ordering::SeqCst);
        let error = chain.get_token(&["scope"], None).await.unwrap_err();

        assert_eq!(error.to_string(), "first failed");
        assert_eq!(first.calls(), 2);
        assert_eq!(second.calls(), 0);
    }

    #[tokio::test]
    async fn aggregates_errors_when_every_credential_fails() {
        let first = MockCredential::new("first", false);
        let second = MockCredential::new("second", false);
        let chain = DefaultAzureCredential::with_credentials(vec![
            candidate("first", first),
            candidate("second", second),
        ]);

        let error = chain.get_token(&["scope"], None).await.unwrap_err();
        let message = error.to_string();
        assert!(message.contains("first: first failed"));
        assert!(message.contains("second: second failed"));
    }
}
