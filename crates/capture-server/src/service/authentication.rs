//! Authenticates provider requests as organizations.
//!
//! Every provider request carries `Capture-Authorization: Bearer <token>`,
//! because the standard `Authorization` header carries the caller's provider
//! credential. The token resolves to the organization the request is
//! captured for. Token values are never logged, stored, or forwarded: the
//! proxy removes the header before the request reaches the capture engine,
//! and caches and token files hold only SHA-256 digests.

use std::{
    collections::{HashMap, hash_map::Entry},
    io::Read as _,
    path::Path,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail, ensure};
use axum::http::{HeaderMap, HeaderName, StatusCode, header::Entry as HeaderEntry};
use capture_engine::platform::api_origin::ApiOrigin;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::{auth, http_client_builder};
use crate::{config::AuthenticationConfig, organization::OrganizationId};

/// The header that carries the organization credential on provider routes.
pub(crate) const CAPTURE_AUTHORIZATION: HeaderName =
    HeaderName::from_static("capture-authorization");

/// The longest bearer token the proxy accepts.
const MAX_TOKEN_BYTES: usize = 4096;

/// The organization a request is captured for, and which credential proved
/// it. The credential is a non-secret identifier for logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Authenticated {
    pub(crate) organization: OrganizationId,
    pub(crate) credential: String,
}

/// Why a presented token did not authenticate a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthenticationError {
    /// The token is unknown, revoked or expired.
    Invalid,
    /// The token is valid but may not make capture requests.
    Forbidden,
    /// The credential service could not answer.
    Unavailable,
}

/// Resolves a bearer token to the organization it records for.
#[async_trait::async_trait]
pub(crate) trait Authenticator: Send + Sync {
    async fn authenticate(
        &self,
        token: &str,
    ) -> std::result::Result<Authenticated, AuthenticationError>;
}

/// Builds the configured authenticator. A token file is read and checked
/// here, so a bad file stops startup.
pub(crate) fn from_config(config: &AuthenticationConfig) -> Result<Arc<dyn Authenticator>> {
    Ok(match config {
        AuthenticationConfig::Hosted { .. } => {
            Arc::new(HostedAuthenticator::new(auth::configured_api_origin()?)?)
        }
        AuthenticationConfig::TokenFile { path } => Arc::new(TokenFileAuthenticator::load(path)?),
    })
}

/// Why a request's `Capture-Authorization` header could not be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HeaderError {
    Missing,
    Malformed,
}

/// Removes every `Capture-Authorization` header from `headers` and returns
/// its bearer token. The header is removed even when it is malformed, so it
/// can never travel further.
pub(crate) fn take_bearer_token(
    headers: &mut HeaderMap,
) -> std::result::Result<String, HeaderError> {
    let values: Vec<_> = match headers.entry(CAPTURE_AUTHORIZATION) {
        HeaderEntry::Occupied(entry) => entry.remove_entry_mult().1.collect(),
        HeaderEntry::Vacant(_) => return Err(HeaderError::Missing),
    };
    let [value] = values.as_slice() else {
        return Err(HeaderError::Malformed);
    };
    let value = value.to_str().map_err(|_| HeaderError::Malformed)?;
    let (scheme, token) = value.split_once(' ').ok_or(HeaderError::Malformed)?;
    let token = token.trim_start_matches(' ');
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.len() > MAX_TOKEN_BYTES
        || token.bytes().any(|byte| byte == b' ' || byte == b'\t')
    {
        return Err(HeaderError::Malformed);
    }
    Ok(token.to_owned())
}

fn token_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Accepts Exalto credentials (API keys and Device access tokens) with the
/// `capture:request` scope by asking capture-api which organization each
/// one records for.
///
/// Successful answers are cached by the token's SHA-256 digest for
/// [`HOSTED_CACHE_TTL`], so a revoked credential keeps working on a replica
/// for at most that long. Failures are never cached.
pub(crate) struct HostedAuthenticator {
    origin: ApiOrigin,
    client: reqwest::Client,
    cache: AuthenticationCache,
}

/// How long a replica trusts capture-api's answer for a credential.
pub(crate) const HOSTED_CACHE_TTL: Duration = Duration::from_secs(60);
/// The most credentials one replica remembers at once.
const HOSTED_CACHE_CAPACITY: usize = 10_000;
const HOSTED_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HOSTED_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HOSTED_RESPONSE_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
struct CaptureAuthorizationResponse {
    organization_id: String,
    credential: CaptureCredential,
}

#[derive(Deserialize)]
struct CaptureCredential {
    kind: String,
    id: String,
}

impl HostedAuthenticator {
    pub(crate) fn new(origin: ApiOrigin) -> Result<Self> {
        Self::with_cache(origin, HOSTED_CACHE_TTL, HOSTED_CACHE_CAPACITY)
    }

    fn with_cache(origin: ApiOrigin, ttl: Duration, capacity: usize) -> Result<Self> {
        let client = http_client_builder()
            .connect_timeout(HOSTED_CONNECT_TIMEOUT)
            .timeout(HOSTED_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the capture authorization client")?;
        Ok(Self {
            origin,
            client,
            cache: AuthenticationCache::new(ttl, capacity),
        })
    }

    async fn ask(&self, token: &str) -> std::result::Result<Authenticated, AuthenticationError> {
        let mut response = self
            .client
            .get(self.origin.api_url("/api/capture-authorization"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| unavailable("capture-api could not be reached"))?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED => return Err(AuthenticationError::Invalid),
            StatusCode::FORBIDDEN => return Err(AuthenticationError::Forbidden),
            status => {
                tracing::warn!(
                    status = status.as_u16(),
                    "capture-api could not check a capture credential"
                );
                return Err(AuthenticationError::Unavailable);
            }
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| unavailable("capture-api response ended early"))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_HOSTED_RESPONSE_BYTES {
                return Err(unavailable("capture-api response is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let answer = serde_json::from_slice::<CaptureAuthorizationResponse>(&body)
            .map_err(|_| unavailable("capture-api response is malformed"))?;
        let organization = OrganizationId::parse(answer.organization_id)
            .map_err(|_| unavailable("capture-api returned an invalid organization"))?;
        let credential = &answer.credential;
        if !safe_identifier(&credential.kind) || !safe_identifier(&credential.id) {
            return Err(unavailable("capture-api returned an invalid credential"));
        }
        Ok(Authenticated {
            organization,
            credential: format!("{}:{}", credential.kind, credential.id),
        })
    }
}

#[async_trait::async_trait]
impl Authenticator for HostedAuthenticator {
    async fn authenticate(
        &self,
        token: &str,
    ) -> std::result::Result<Authenticated, AuthenticationError> {
        let digest = token_digest(token);
        if let Some(authenticated) = self.cache.get(&digest, Instant::now()) {
            return Ok(authenticated);
        }
        let authenticated = self.ask(token).await?;
        self.cache
            .insert(digest, authenticated.clone(), Instant::now());
        Ok(authenticated)
    }
}

fn unavailable(reason: &'static str) -> AuthenticationError {
    tracing::warn!(reason, "capture authorization is unavailable");
    AuthenticationError::Unavailable
}

fn safe_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Successful authentications by token digest, each kept for a fixed time.
/// When full, expired entries go first, then the entry closest to expiry.
struct AuthenticationCache {
    ttl: Duration,
    capacity: usize,
    entries: Mutex<HashMap<[u8; 32], (Instant, Authenticated)>>,
}

impl AuthenticationCache {
    fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            ttl,
            capacity,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, digest: &[u8; 32], now: Instant) -> Option<Authenticated> {
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        match entries.entry(*digest) {
            Entry::Occupied(entry) if entry.get().0 > now => Some(entry.get().1.clone()),
            Entry::Occupied(entry) => {
                entry.remove();
                None
            }
            Entry::Vacant(_) => None,
        }
    }

    fn insert(&self, digest: [u8; 32], authenticated: Authenticated, now: Instant) {
        if self.ttl.is_zero() || self.capacity == 0 {
            return;
        }
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= self.capacity && !entries.contains_key(&digest) {
            entries.retain(|_, (expires_at, _)| *expires_at > now);
            if entries.len() >= self.capacity
                && let Some(soonest) = entries
                    .iter()
                    .min_by_key(|(_, (expires_at, _))| *expires_at)
                    .map(|(digest, _)| *digest)
            {
                entries.remove(&soonest);
            }
        }
        entries.insert(digest, (now + self.ttl, authenticated));
    }
}

/// Accepts the tokens listed, by SHA-256 digest, in a private TOML file:
///
/// ```toml
/// [[tokens]]
/// sha256 = "<64 hexadecimal characters>"
/// organization = "acme"
/// ```
///
/// The file is read once at startup; restart replicas after changing it.
pub(crate) struct TokenFileAuthenticator {
    tokens: HashMap<[u8; 32], OrganizationId>,
}

const MAX_TOKEN_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenFile {
    tokens: Vec<TokenFileEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenFileEntry {
    sha256: String,
    organization: String,
}

impl TokenFileAuthenticator {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("opening token file {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspecting token file {}", path.display()))?;
        ensure!(
            metadata.is_file(),
            "token file {} is not a regular file",
            path.display()
        );
        let mut bytes = Vec::new();
        file.take(MAX_TOKEN_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading token file {}", path.display()))?;
        ensure!(
            bytes.len() as u64 <= MAX_TOKEN_FILE_BYTES,
            "token file {} is larger than {MAX_TOKEN_FILE_BYTES} bytes",
            path.display()
        );
        Self::parse(&bytes).with_context(|| format!("token file {} is invalid", path.display()))
    }

    fn parse(bytes: &[u8]) -> Result<Self> {
        let source = std::str::from_utf8(bytes).context("the file is not UTF-8")?;
        // Only the parser's message is reported, never the offending line,
        // in case a raw token was written into the file by mistake.
        let file: TokenFile =
            toml::from_str(source).map_err(|error| anyhow::anyhow!("{}", error.message()))?;
        ensure!(!file.tokens.is_empty(), "the file lists no tokens");
        let mut tokens = HashMap::with_capacity(file.tokens.len());
        for (index, entry) in file.tokens.into_iter().enumerate() {
            let number = index + 1;
            let digest: [u8; 32] = match hex::decode(&entry.sha256) {
                Ok(digest) => digest.try_into().map_err(|_| {
                    anyhow::anyhow!("token {number}: sha256 must be 64 hexadecimal characters")
                })?,
                Err(_) => bail!("token {number}: sha256 must be 64 hexadecimal characters"),
            };
            let organization = OrganizationId::parse(entry.organization)
                .map_err(|_| anyhow::anyhow!("token {number}: organization is invalid"))?;
            ensure!(
                tokens.insert(digest, organization).is_none(),
                "token {number}: the same token is listed twice"
            );
        }
        Ok(Self { tokens })
    }
}

#[async_trait::async_trait]
impl Authenticator for TokenFileAuthenticator {
    async fn authenticate(
        &self,
        token: &str,
    ) -> std::result::Result<Authenticated, AuthenticationError> {
        let digest = token_digest(token);
        let organization = self
            .tokens
            .get(&digest)
            .ok_or(AuthenticationError::Invalid)?;
        Ok(Authenticated {
            organization: organization.clone(),
            // A digest prefix names the entry without revealing the token.
            credential: format!("token:{}", hex::encode(&digest[..6])),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::http::HeaderValue;

    use super::*;

    fn headers(values: &[&[u8]]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer provider-secret"),
        );
        headers.insert("x-api-key", HeaderValue::from_static("provider-key"));
        for value in values {
            headers.append(
                CAPTURE_AUTHORIZATION,
                HeaderValue::from_bytes(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn the_capture_header_is_always_removed_and_must_hold_one_bearer_token() {
        let long_token = format!("Bearer {}", "t".repeat(MAX_TOKEN_BYTES + 1));
        type Case<'a> = (&'a [&'a [u8]], std::result::Result<&'a str, HeaderError>);
        let cases: [Case; 11] = [
            (&[b"Bearer capture-token"], Ok("capture-token")),
            (&[b"bearer   capture-token"], Ok("capture-token")),
            (&[], Err(HeaderError::Missing)),
            (&[b"capture-token"], Err(HeaderError::Malformed)),
            (&[b"Basic capture-token"], Err(HeaderError::Malformed)),
            (&[b"Bearer "], Err(HeaderError::Malformed)),
            (&[b"Bearer capture token"], Err(HeaderError::Malformed)),
            (&[b"Bearer capture\ttoken"], Err(HeaderError::Malformed)),
            (&[b"Bearer caf\xc3\xa9"], Err(HeaderError::Malformed)),
            (&[long_token.as_bytes()], Err(HeaderError::Malformed)),
            (
                &[b"Bearer first-token", b"Bearer second-token"],
                Err(HeaderError::Malformed),
            ),
        ];
        for (values, expected) in cases {
            let mut headers = headers(values);
            assert_eq!(
                take_bearer_token(&mut headers)
                    .as_deref()
                    .map_err(|error| *error),
                expected,
                "{values:?}"
            );
            assert!(headers.get(CAPTURE_AUTHORIZATION).is_none(), "{values:?}");
            assert_eq!(
                headers.get(axum::http::header::AUTHORIZATION).unwrap(),
                "Bearer provider-secret"
            );
            assert_eq!(headers.get("x-api-key").unwrap(), "provider-key");
        }
    }

    /// A stand-in capture-api that answers by token and counts every check.
    async fn capture_api() -> (ApiOrigin, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin =
            ApiOrigin::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let app = axum::Router::new().route(
            "/api/capture-authorization",
            axum::routing::get({
                let calls = calls.clone();
                move |headers: HeaderMap| async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    let token = headers
                        .get(axum::http::header::AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.strip_prefix("Bearer "))
                        .unwrap_or_default()
                        .to_owned();
                    let ok = |organization: &str| {
                        (
                            StatusCode::OK,
                            serde_json::json!({
                                "organization_id": organization,
                                "credential": { "kind": "api_key", "id": "key-1" },
                            })
                            .to_string(),
                        )
                    };
                    let error = |status: StatusCode| (status, r#"{"error":"denied"}"#.to_owned());
                    match token.as_str() {
                        "alice-token" => ok("acct-alice"),
                        "bob-token" => ok("acct-bob"),
                        "bad-organization-token" => ok("../acct-alice"),
                        "garbled-token" => (StatusCode::OK, "not json".to_owned()),
                        "huge-token" => (StatusCode::OK, "x".repeat(MAX_HOSTED_RESPONSE_BYTES + 1)),
                        "read-only-token" => error(StatusCode::FORBIDDEN),
                        "broken-token" => error(StatusCode::INTERNAL_SERVER_ERROR),
                        "busy-token" => error(StatusCode::TOO_MANY_REQUESTS),
                        _ => error(StatusCode::UNAUTHORIZED),
                    }
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (origin, calls, server)
    }

    #[tokio::test]
    async fn hosted_answers_are_cached_briefly_and_failures_never() {
        let (origin, calls, server) = capture_api().await;
        let authenticator = HostedAuthenticator::new(origin.clone()).unwrap();

        let alice = authenticator.authenticate("alice-token").await.unwrap();
        assert_eq!(alice.organization.as_str(), "acct-alice");
        assert_eq!(alice.credential, "api_key:key-1");
        assert_eq!(
            authenticator.authenticate("alice-token").await.unwrap(),
            alice
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a cached answer is reused");
        let bob = authenticator.authenticate("bob-token").await.unwrap();
        assert_eq!(bob.organization.as_str(), "acct-bob");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        for (token, expected) in [
            ("revoked-token", AuthenticationError::Invalid),
            ("read-only-token", AuthenticationError::Forbidden),
            ("broken-token", AuthenticationError::Unavailable),
            ("busy-token", AuthenticationError::Unavailable),
            ("garbled-token", AuthenticationError::Unavailable),
            ("huge-token", AuthenticationError::Unavailable),
            ("bad-organization-token", AuthenticationError::Unavailable),
        ] {
            let before = calls.load(Ordering::SeqCst);
            for _ in 0..2 {
                assert_eq!(
                    authenticator.authenticate(token).await.unwrap_err(),
                    expected,
                    "{token}"
                );
            }
            assert_eq!(
                calls.load(Ordering::SeqCst) - before,
                2,
                "{token} must not be cached"
            );
        }

        // Without a cache lifetime every request asks again, which is how a
        // revoked credential stops working once its cached answer expires.
        let uncached =
            HostedAuthenticator::with_cache(origin, Duration::ZERO, HOSTED_CACHE_CAPACITY).unwrap();
        let before = calls.load(Ordering::SeqCst);
        uncached.authenticate("alice-token").await.unwrap();
        uncached.authenticate("alice-token").await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst) - before, 2);

        server.abort();
        let _ = server.await;
        let unreachable = HostedAuthenticator::new(
            ApiOrigin::parse(&format!("http://{}", {
                let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
                listener.local_addr().unwrap()
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            unreachable.authenticate("bob-token").await.unwrap_err(),
            AuthenticationError::Unavailable
        );
    }

    #[test]
    fn cached_answers_expire_and_a_full_cache_evicts_the_soonest_expiry() {
        let organization = |name: &str| Authenticated {
            organization: OrganizationId::parse(name).unwrap(),
            credential: "api_key:key-1".to_owned(),
        };
        let now = Instant::now();
        let cache = AuthenticationCache::new(Duration::from_secs(60), 2);
        cache.insert([1; 32], organization("first"), now);
        cache.insert(
            [2; 32],
            organization("second"),
            now + Duration::from_secs(1),
        );
        assert_eq!(
            cache.get(&[1; 32], now + Duration::from_secs(59)),
            Some(organization("first"))
        );
        assert_eq!(
            cache.get(&[1; 32], now + Duration::from_secs(60)),
            None,
            "expired"
        );

        cache.insert([1; 32], organization("first"), now);
        cache.insert([3; 32], organization("third"), now + Duration::from_secs(2));
        let later = now + Duration::from_secs(10);
        assert_eq!(
            cache.get(&[1; 32], later),
            None,
            "the soonest expiry was evicted"
        );
        assert_eq!(cache.get(&[2; 32], later), Some(organization("second")));
        assert_eq!(cache.get(&[3; 32], later), Some(organization("third")));
        assert!(cache.entries.lock().unwrap().len() <= 2);
    }

    fn sha256_hex(token: &str) -> String {
        hex::encode(token_digest(token))
    }

    fn write_private(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[tokio::test]
    async fn a_token_file_maps_token_digests_to_organizations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture-tokens.toml");
        write_private(
            &path,
            &format!(
                "[[tokens]]\nsha256 = \"{}\"\norganization = \"acme\"\n\n[[tokens]]\nsha256 = \"{}\"\norganization = \"globex\"\n",
                sha256_hex("acme-token"),
                sha256_hex("globex-token").to_uppercase(),
            ),
        );
        let authenticator = from_config(&AuthenticationConfig::TokenFile { path }).unwrap();

        let acme = authenticator.authenticate("acme-token").await.unwrap();
        assert_eq!(acme.organization.as_str(), "acme");
        assert_eq!(
            acme.credential,
            format!("token:{}", &sha256_hex("acme-token")[..12])
        );
        assert!(!acme.credential.contains("acme-token"));
        assert_eq!(
            authenticator
                .authenticate("globex-token")
                .await
                .unwrap()
                .organization
                .as_str(),
            "globex"
        );
        for unknown in ["", "acme-token ", "ACME-TOKEN", &sha256_hex("acme-token")] {
            assert_eq!(
                authenticator.authenticate(unknown).await.unwrap_err(),
                AuthenticationError::Invalid,
                "{unknown}"
            );
        }
    }

    #[test]
    fn token_files_must_be_bounded_and_well_formed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture-tokens.toml");
        let valid = format!(
            "[[tokens]]\nsha256 = \"{}\"\norganization = \"acme\"\n",
            sha256_hex("acme-token")
        );
        write_private(&path, &valid);
        TokenFileAuthenticator::load(&path).unwrap();

        assert!(TokenFileAuthenticator::load(directory.path()).is_err());
        assert!(TokenFileAuthenticator::load(&directory.path().join("missing.toml")).is_err());

        let oversized = format!(
            "{valid}# {}\n",
            "x".repeat(usize::try_from(MAX_TOKEN_FILE_BYTES).unwrap())
        );
        write_private(&path, &oversized);
        assert!(TokenFileAuthenticator::load(&path).is_err());

        let digest = sha256_hex("acme-token");
        for invalid in [
            String::new(),
            "tokens = []\n".to_owned(),
            format!("[[tokens]]\nsha256 = \"{digest}\"\n"),
            format!(
                "[[tokens]]\nsha256 = \"{}\"\norganization = \"acme\"\n",
                &digest[..62]
            ),
            format!(
                "[[tokens]]\nsha256 = \"{}zz\"\norganization = \"acme\"\n",
                &digest[..62]
            ),
            format!("[[tokens]]\nsha256 = \"{digest}\"\norganization = \"../acme\"\n"),
            format!("{valid}\n[[tokens]]\nsha256 = \"{digest}\"\norganization = \"globex\"\n"),
        ] {
            write_private(&path, &invalid);
            assert!(TokenFileAuthenticator::load(&path).is_err(), "{invalid}");
        }

        // A raw token written into the file by mistake is never echoed.
        write_private(
            &path,
            &format!(
                "{valid}\n[[tokens]]\ntoken = \"raw-secret-canary\"\norganization = \"acme\"\n"
            ),
        );
        let error = format!("{:#}", TokenFileAuthenticator::load(&path).err().unwrap());
        assert!(error.contains("unknown field"), "{error}");
        assert!(!error.contains("raw-secret-canary"), "{error}");
        write_private(
            &path,
            "[[tokens]]\nsha256 = \"raw-secret-canary\"\norganization = \"acme\"\n",
        );
        let error = format!("{:#}", TokenFileAuthenticator::load(&path).err().unwrap());
        assert!(!error.contains("raw-secret-canary"), "{error}");
    }
}
