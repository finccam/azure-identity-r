use async_trait::async_trait;
use azure_core::{
    credentials::{AccessToken, Secret, TokenCredential, TokenRequestOptions},
    error::{Error, ErrorKind},
};
use azure_identity::{
    AzureCliCredential, AzureDeveloperCliCredential, ClientSecretCredential,
    ManagedIdentityCredential, ManagedIdentityCredentialOptions, UserAssignedId,
    WorkloadIdentityCredential,
};
use extendr_api::prelude::*;
use std::{
    collections::HashMap,
    env, fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};
use tokio::{runtime::Runtime, sync::Mutex};

const NO_CREDENTIAL_SELECTED: usize = usize::MAX;
const REFRESH_OFFSET_SECONDS: i64 = 300;

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
            managed_identity_credential(),
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

struct CachedCredential {
    credential: Arc<dyn TokenCredential>,
    tokens: Mutex<HashMap<Vec<String>, AccessToken>>,
}

impl CachedCredential {
    fn new(credential: Arc<dyn TokenCredential>) -> Self {
        Self {
            credential,
            tokens: Mutex::new(HashMap::new()),
        }
    }

    async fn get_token(&self, scopes: Vec<String>) -> azure_core::Result<AccessToken> {
        let mut scopes = scopes;
        scopes.sort_unstable();
        scopes.dedup();

        let mut tokens = self.tokens.lock().await;
        if let Some(token) = tokens.get(&scopes) {
            if token.expires_on
                > azure_core::time::OffsetDateTime::now_utc()
                    + azure_core::time::Duration::seconds(REFRESH_OFFSET_SECONDS)
            {
                return Ok(token.clone());
            }
        }

        let scope_refs = scopes.iter().map(String::as_str).collect::<Vec<_>>();
        let token = self.credential.get_token(&scope_refs, None).await?;
        tokens.insert(scopes, token.clone());
        Ok(token)
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

fn managed_identity_credential() -> NamedCredential {
    named_credential(
        "ManagedIdentityCredential",
        ManagedIdentityCredential::new(managed_identity_options(env::var("AZURE_CLIENT_ID").ok())),
    )
}

fn managed_identity_options(client_id: Option<String>) -> Option<ManagedIdentityCredentialOptions> {
    client_id
        .filter(|client_id| !client_id.is_empty())
        .map(|client_id| ManagedIdentityCredentialOptions {
            user_assigned_id: Some(UserAssignedId::ClientId(client_id)),
            ..Default::default()
        })
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

fn default_credential() -> &'static CachedCredential {
    static CREDENTIAL: OnceLock<CachedCredential> = OnceLock::new();
    CREDENTIAL.get_or_init(|| CachedCredential::new(Arc::new(DefaultAzureCredential::new())))
}

/// Get an access token using the default Azure credential chain.
/// @param scopes One or more Azure OAuth 2.0 scopes.
/// @return A scalar character access token.
/// @examples
/// \dontrun{
/// default_azure_credential("https://management.azure.com/.default")
/// }
/// @export
#[extendr]
fn default_azure_credential(scopes: Vec<String>) -> std::result::Result<String, String> {
    if scopes.is_empty() {
        return Err("at least one scope is required".to_string());
    }

    let token = runtime()?
        .block_on(default_credential().get_token(scopes))
        .map_err(|error| error.to_string())?;
    Ok(token.token.secret().to_string())
}

// Macro to generate exports.
// This ensures exported functions are registered with R.
// See corresponding C code in `entrypoint.c`.
extendr_module! {
    mod azidentity;
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
        token_lifetime: Duration,
    }

    impl MockCredential {
        fn new(name: &'static str, succeeds: bool) -> Arc<Self> {
            Arc::new(Self {
                name,
                calls: AtomicUsize::new(0),
                succeeds: AtomicBool::new(succeeds),
                token_lifetime: Duration::hours(1),
            })
        }

        fn expiring(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                calls: AtomicUsize::new(0),
                succeeds: AtomicBool::new(true),
                token_lifetime: Duration::seconds(REFRESH_OFFSET_SECONDS),
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
                    OffsetDateTime::now_utc() + self.token_lifetime,
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

    #[tokio::test]
    async fn caches_tokens_across_scope_orderings() {
        let credential = MockCredential::new("token", true);
        let cache = CachedCredential::new(credential.clone());

        let first = cache
            .get_token(vec!["scope-b".to_string(), "scope-a".to_string()])
            .await
            .unwrap();
        let second = cache
            .get_token(vec!["scope-a".to_string(), "scope-b".to_string()])
            .await
            .unwrap();

        assert_eq!(first.token.secret(), second.token.secret());
        assert_eq!(credential.calls(), 1);
    }

    #[tokio::test]
    async fn refreshes_tokens_with_five_minutes_remaining() {
        let credential = MockCredential::expiring("token");
        let cache = CachedCredential::new(credential.clone());

        cache.get_token(vec!["scope".to_string()]).await.unwrap();
        cache.get_token(vec!["scope".to_string()]).await.unwrap();

        assert_eq!(credential.calls(), 2);
    }

    #[test]
    fn configures_user_assigned_managed_identity_from_client_id() {
        assert!(managed_identity_options(None).is_none());
        assert!(managed_identity_options(Some(String::new())).is_none());

        let options = managed_identity_options(Some("client-id".to_string())).unwrap();
        match options.user_assigned_id {
            Some(UserAssignedId::ClientId(client_id)) => assert_eq!(client_id, "client-id"),
            _ => panic!("expected a user-assigned managed identity client ID"),
        }
    }
}
