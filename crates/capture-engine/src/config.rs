//! Versioned local configuration for the proxy and capture metadata.

use std::{
    env,
    ffi::OsString,
    fmt, fs,
    io::{ErrorKind, Read as _, Write as _},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher as _, password_hash::SaltString};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use capture_core::{
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES, registry::NotaryEndpoint,
    sha256_hex,
};

use crate::artifact_store::{ArtifactResult, invalid};
pub use crate::providers::{ProviderConfig, ProvidersConfig};

/// The versioned identifier for a captured configuration file.
pub const CONFIG_FORMAT: &str = "ecp/captured-config/v1";

pub const METADATA_DATABASE_URL_ENV: &str = "CAPTURE_SERVER_METADATA_DATABASE_URL";
pub const METADATA_DATABASE_URL_FILE_ENV: &str = "CAPTURE_SERVER_METADATA_DATABASE_URL_FILE";
pub const METADATA_MIGRATION_URL_ENV: &str = "CAPTURE_SERVER_METADATA_MIGRATION_URL";
pub const METADATA_MIGRATION_URL_FILE_ENV: &str = "CAPTURE_SERVER_METADATA_MIGRATION_URL_FILE";
pub const ARTIFACT_S3_ACCESS_KEY_ID_ENV: &str = "CAPTURE_SERVER_ARTIFACT_S3_ACCESS_KEY_ID";
pub const ARTIFACT_S3_ACCESS_KEY_ID_FILE_ENV: &str =
    "CAPTURE_SERVER_ARTIFACT_S3_ACCESS_KEY_ID_FILE";
pub const ARTIFACT_S3_SECRET_ACCESS_KEY_ENV: &str = "CAPTURE_SERVER_ARTIFACT_S3_SECRET_ACCESS_KEY";
pub const ARTIFACT_S3_SECRET_ACCESS_KEY_FILE_ENV: &str =
    "CAPTURE_SERVER_ARTIFACT_S3_SECRET_ACCESS_KEY_FILE";
pub const ARTIFACT_S3_SESSION_TOKEN_ENV: &str = "CAPTURE_SERVER_ARTIFACT_S3_SESSION_TOKEN";
pub const ARTIFACT_S3_SESSION_TOKEN_FILE_ENV: &str =
    "CAPTURE_SERVER_ARTIFACT_S3_SESSION_TOKEN_FILE";
pub const ADMIN_PASSWORD_ENV: &str = "CAPTURE_SERVER_ADMIN_PASSWORD";
pub const ADMIN_PASSWORD_FILE_ENV: &str = "CAPTURE_SERVER_ADMIN_PASSWORD_FILE";
pub const CLUSTER_INSTANCE_ID_ENV: &str = "CAPTURE_SERVER_CLUSTER_INSTANCE_ID";

/// Local proxy configuration. This is intentionally separate from the private
/// vault state, which contains key references and passphrase KDF parameters.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedConfig {
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cluster: Option<ClusterConfig>,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub notary: NotaryConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub metadata: MetadataConfig,
    #[serde(default)]
    pub providers: ProvidersConfig,
}

/// Explicit multi-replica cluster profile. Coordination timings and replica
/// identities are internal so every deployment uses the same safety rules.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfig {
    /// Public HTTPS endpoint applications use for provider requests.
    pub proxy_origin: String,
    /// Public HTTPS endpoint operators use for the dashboard and admin API.
    pub admin_origin: String,
    /// How provider requests are authenticated as organizations. Every
    /// provider request carries `Capture-Authorization: Bearer <token>`;
    /// there is no unauthenticated mode.
    pub authentication: AuthenticationConfig,
    /// The private listener through which capture-api acts for
    /// organizations. Without it no customer listener runs, and operators
    /// use the admin listener's dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub customer_api: Option<CustomerApiConfig>,
}

/// The customer API: the engine's Trace, operation, verification, activity
/// and settings routes for the organization each request names. Its bearer
/// token may act as any organization, so the listener belongs on a private
/// network that only capture-api reaches.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CustomerApiConfig {
    pub listen: SocketAddr,
    /// A private file holding the bearer token capture-api presents.
    pub token_file: PathBuf,
}

/// How a capture server resolves a request's bearer token to an
/// organization.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticationConfig {
    /// Exalto credentials with the `capture:request` scope, checked against
    /// the configured Exalto API origin.
    Hosted {
        /// A private file holding this server's capture service credential,
        /// with which capture-api charges each notary admission to the
        /// request's organization. Required with the hosted notary (no
        /// `notary.endpoint`), which admits every operation with a ticket,
        /// and refused with a self-hosted notary, which needs none.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capture_service_token_file: Option<PathBuf>,
    },
    /// A private TOML file mapping SHA-256 digests of tokens to
    /// organizations, for self-hosted servers.
    TokenFile { path: PathBuf },
}

/// Local administration listener. It is deliberately separate from the
/// provider proxy so proxy callers cannot reach privileged routes.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminConfig {
    #[serde(default = "default_admin_listen")]
    pub listen: SocketAddr,
    /// Optional HTTP Basic authentication for the loopback administration
    /// listener. The listener is open to local processes when omitted.
    pub auth: Option<AdminAuthConfig>,
}

/// Optional password authentication for the local administration listener.
/// The password is stored only as an Argon2id PHC string.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdminAuthConfig {
    pub username: String,
    /// Existing deployments may keep an Argon2id hash in the config. New
    /// cluster deployments leave this unset and provide a password secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    #[serde(default = "default_max_attestable_http_bytes")]
    pub max_attestable_http_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryConfig {
    /// Optional explicit endpoint. Without this the client uses the signed
    /// Registry at the configured public API origin.
    pub endpoint: Option<String>,
    /// Explicit SEC1 secp256k1 trust anchor for `endpoint`. The endpoint and
    /// key are configured together so a self-hosted connection cannot become
    /// an implicit trust decision.
    pub public_key: Option<String>,
    #[serde(default = "default_max_frame_bytes")]
    pub max_frame_bytes: usize,
}

impl Default for NotaryConfig {
    fn default() -> Self {
        Self {
            endpoint: None,
            public_key: None,
            max_frame_bytes: default_max_frame_bytes(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default)]
    pub backend: ArtifactStorageBackend,
    #[serde(default = "default_checkpoint_dir")]
    pub checkpoint_dir: PathBuf,
    #[serde(default = "default_package_dir")]
    pub package_dir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub s3: Option<S3StorageConfig>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStorageBackend {
    #[default]
    Filesystem,
    S3,
}

impl ArtifactStorageBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::S3 => "s3",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct S3StorageConfig {
    pub bucket: String,
    #[serde(default = "default_s3_region")]
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default = "default_s3_prefix")]
    pub prefix: String,
    #[serde(default)]
    pub force_path_style: bool,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default = "default_s3_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_s3_operation_timeout_seconds")]
    pub operation_timeout_seconds: u64,
}

impl S3StorageConfig {
    pub fn artifact_store_config(&self) -> Result<S3ArtifactStoreConfig> {
        let endpoint = self
            .endpoint
            .as_deref()
            .map(url::Url::parse)
            .transpose()
            .context("storage.s3.endpoint must be an absolute URL")?;
        S3ArtifactStoreConfig::new(
            endpoint,
            self.region.clone(),
            self.bucket.clone(),
            self.prefix.clone(),
            self.force_path_style,
            self.allow_insecure_http,
            Duration::from_secs(self.connect_timeout_seconds),
            Duration::from_secs(self.operation_timeout_seconds),
        )
        .map_err(|error| anyhow::Error::new(error).context("storage.s3 configuration is invalid"))
    }
}

/// Non-secret connection and namespace settings for daemon-private objects.
#[derive(Clone, Debug)]
pub struct S3ArtifactStoreConfig {
    endpoint: Option<url::Url>,
    region: String,
    bucket: String,
    prefix: String,
    force_path_style: bool,
    connect_timeout: Duration,
    operation_timeout: Duration,
}

impl S3ArtifactStoreConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: Option<url::Url>,
        region: String,
        bucket: String,
        prefix: String,
        force_path_style: bool,
        allow_insecure_http: bool,
        connect_timeout: Duration,
        operation_timeout: Duration,
    ) -> ArtifactResult<Self> {
        validate_s3_config(
            endpoint.as_ref(),
            &region,
            &bucket,
            allow_insecure_http,
            connect_timeout,
            operation_timeout,
        )?;
        Ok(Self {
            endpoint,
            region,
            bucket,
            prefix: normalize_s3_prefix(&prefix)?,
            force_path_style,
            connect_timeout,
            operation_timeout,
        })
    }

    pub fn endpoint(&self) -> Option<&url::Url> {
        self.endpoint.as_ref()
    }

    pub fn region(&self) -> &str {
        &self.region
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// The validated prefix, without leading or trailing slashes.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn force_path_style(&self) -> bool {
        self.force_path_style
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    pub fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }
}

fn validate_s3_config(
    endpoint: Option<&url::Url>,
    region: &str,
    bucket: &str,
    allow_insecure_http: bool,
    connect_timeout: Duration,
    operation_timeout: Duration,
) -> ArtifactResult<()> {
    if let Some(endpoint) = endpoint {
        if endpoint.cannot_be_a_base()
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.path() != "/"
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(invalid(
                "invalid_s3_endpoint",
                anyhow!(
                    "S3 endpoint must be an origin URL without credentials, path, query, or fragment"
                ),
            ));
        }
        match endpoint.scheme() {
            "https" => {}
            "http" if allow_insecure_http => {}
            "http" => {
                return Err(invalid(
                    "insecure_s3_endpoint",
                    anyhow!("HTTP S3 endpoints require explicit insecure-local opt-in"),
                ));
            }
            _ => {
                return Err(invalid(
                    "invalid_s3_endpoint",
                    anyhow!("S3 endpoint must use HTTPS or explicitly allowed HTTP"),
                ));
            }
        }
    } else if allow_insecure_http {
        return Err(invalid(
            "invalid_s3_endpoint",
            anyhow!("allow_insecure_http requires an explicit S3 endpoint"),
        ));
    }
    if !(1..=128).contains(&region.len())
        || !safe_s3_namespace_component(region)
        || !(1..=255).contains(&bucket.len())
        || !safe_s3_namespace_component(bucket)
    {
        return Err(invalid(
            "invalid_s3_namespace",
            anyhow!("S3 region or bucket is outside its safe length/character bounds"),
        ));
    }
    if connect_timeout.is_zero()
        || connect_timeout > Duration::from_secs(300)
        || operation_timeout.is_zero()
        || operation_timeout > Duration::from_secs(300)
    {
        return Err(invalid(
            "invalid_s3_timeout",
            anyhow!("S3 connect and operation timeouts must be between 1 and 300 seconds"),
        ));
    }
    Ok(())
}

fn normalize_s3_prefix(prefix: &str) -> ArtifactResult<String> {
    if prefix.len() > 512 {
        return Err(invalid(
            "invalid_s3_prefix",
            anyhow!("S3 prefix exceeds 512 bytes"),
        ));
    }
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        return Ok(String::new());
    }
    if prefix.contains("//")
        || prefix.contains('\\')
        || prefix.split('/').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || !part
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(invalid(
            "invalid_s3_prefix",
            anyhow!("S3 prefix must contain only safe, non-empty path segments"),
        ));
    }
    Ok(prefix.to_owned())
}

fn safe_s3_namespace_component(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub struct SecretS3Credentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl SecretS3Credentials {
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    pub fn session_token(&self) -> Option<&str> {
        self.session_token.as_deref()
    }
}

impl fmt::Debug for SecretS3Credentials {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretS3Credentials([REDACTED])")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataConfig {
    #[serde(default)]
    pub backend: MetadataBackend,
    #[serde(default = "default_metadata_path")]
    pub path: PathBuf,
    #[serde(default = "default_preview_chars")]
    pub prompt_preview_chars: usize,
    #[serde(default = "default_preview_chars")]
    pub output_preview_chars: usize,
    #[serde(default = "default_true")]
    pub full_text_search: bool,
    #[serde(default, skip_serializing_if = "PostgresMetadataConfig::is_default")]
    pub postgres: PostgresMetadataConfig,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataBackend {
    #[default]
    Sqlite,
    Postgres,
}

impl MetadataBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PostgresMetadataConfig {
    #[serde(default)]
    pub ssl_mode: PostgresSslMode,
    #[serde(default = "default_postgres_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_postgres_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_postgres_acquire_timeout_seconds")]
    pub acquire_timeout_seconds: u64,
    #[serde(default = "default_postgres_migration_lock_timeout_seconds")]
    pub migration_lock_timeout_seconds: u64,
}

impl Default for PostgresMetadataConfig {
    fn default() -> Self {
        Self {
            ssl_mode: PostgresSslMode::VerifyFull,
            max_connections: default_postgres_max_connections(),
            connect_timeout_seconds: default_postgres_connect_timeout_seconds(),
            acquire_timeout_seconds: default_postgres_acquire_timeout_seconds(),
            migration_lock_timeout_seconds: default_postgres_migration_lock_timeout_seconds(),
        }
    }
}

impl PostgresMetadataConfig {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PostgresSslMode {
    /// Test-only or explicitly trusted local networks. Bytes are plaintext.
    Disable,
    /// Encrypts the connection without validating the server hostname.
    Require,
    /// Encrypts and validates the server certificate and hostname.
    #[default]
    VerifyFull,
}

/// A PostgreSQL connection URL whose debug output never contains credentials.
pub struct SecretDatabaseUrl(String);

impl SecretDatabaseUrl {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretDatabaseUrl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretDatabaseUrl([REDACTED])")
    }
}

impl Default for CapturedConfig {
    fn default() -> Self {
        Self {
            format: CONFIG_FORMAT.to_owned(),
            cluster: None,
            proxy: ProxyConfig::default(),
            admin: AdminConfig::default(),
            notary: NotaryConfig::default(),
            storage: StorageConfig::default(),
            metadata: MetadataConfig::default(),
            providers: ProvidersConfig::default(),
        }
    }
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: default_admin_listen(),
            auth: None,
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            max_attestable_http_bytes: default_max_attestable_http_bytes(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: ArtifactStorageBackend::Filesystem,
            checkpoint_dir: default_checkpoint_dir(),
            package_dir: default_package_dir(),
            s3: None,
        }
    }
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            backend: MetadataBackend::Sqlite,
            path: default_metadata_path(),
            prompt_preview_chars: default_preview_chars(),
            output_preview_chars: default_preview_chars(),
            full_text_search: true,
            postgres: PostgresMetadataConfig::default(),
        }
    }
}

impl CapturedConfig {
    /// Loads and validates one versioned TOML configuration file.
    pub fn load(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .with_context(|| format!("reading captured configuration {}", path.display()))?;
        let config: Self = toml::from_str(&source)
            .with_context(|| format!("parsing captured configuration {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    /// Loads only enough configuration for the one-shot metadata migrator.
    /// Unrelated listener, vault, provider, and notary settings are neither
    /// initialized nor validated by that command.
    pub fn load_for_metadata_migration(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)
            .with_context(|| format!("reading captured configuration {}", path.display()))?;
        let config: Self = toml::from_str(&source)
            .with_context(|| format!("parsing captured configuration {}", path.display()))?;
        ensure!(
            config.format == CONFIG_FORMAT,
            "unsupported captured configuration format: {}",
            config.format
        );
        config.validate_metadata()?;
        Ok(config)
    }

    /// Creates an editable default configuration when the file does not yet
    /// exist. Returns whether this invocation created the file.
    pub fn ensure_default(path: &Path) -> Result<bool> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| anyhow::anyhow!("captured configuration path has no parent"))?;
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        let contents = format!(
            "# Notary local captured configuration.\n# This file is created automatically on first use. Edit it to change local behavior.\n\n{}",
            toml::to_string_pretty(&Self::default())?
        );
        let mut file = match fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("creating captured configuration {}", path.display())
                });
            }
        };
        file.write_all(contents.as_bytes())
            .with_context(|| format!("writing captured configuration {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("syncing captured configuration {}", path.display()))?;
        Ok(true)
    }

    /// Loads a configuration, first materializing the standard defaults when
    /// the requested file does not exist.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool)> {
        let created = Self::ensure_default(path)?;
        Ok((Self::load(path)?, created))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.format == CONFIG_FORMAT,
            "unsupported captured configuration format: {}",
            self.format
        );
        ensure!(
            self.proxy.max_attestable_http_bytes > 0,
            "proxy.max_attestable_http_bytes must be non-zero"
        );
        if let Some(cluster) = &self.cluster {
            self.validate_cluster(cluster)?;
        } else {
            ensure!(
                self.proxy.listen.ip().is_loopback(),
                "proxy.listen must use a loopback address outside cluster mode"
            );
            ensure!(
                self.admin.listen.ip().is_loopback(),
                "admin.listen must use a loopback address outside cluster mode"
            );
        }
        ensure!(
            self.admin.listen != self.proxy.listen,
            "admin.listen and proxy.listen must be different addresses"
        );
        if let Some(auth) = &self.admin.auth {
            ensure!(
                !auth.username.is_empty() && auth.username.len() <= 128,
                "admin.auth.username must contain between 1 and 128 bytes"
            );
            ensure!(
                !auth.username.contains(':'),
                "admin.auth.username must not contain a colon"
            );
            if let Some(value) = auth.password_hash.as_deref() {
                let password_hash = PasswordHash::new(value).map_err(|error| {
                    anyhow::anyhow!("admin.auth.password_hash is invalid: {error}")
                })?;
                ensure!(
                    password_hash.algorithm.as_str() == "argon2id",
                    "admin.auth.password_hash must use Argon2id"
                );
            } else {
                ensure!(
                    self.cluster.is_some(),
                    "admin.auth.password_hash is required outside cluster mode"
                );
            }
        }
        match (&self.notary.endpoint, &self.notary.public_key) {
            (Some(endpoint), Some(_)) => {
                endpoint
                    .parse::<NotaryEndpoint>()
                    .context("notary.endpoint is invalid")?;
                self.notary_public_key()?;
            }
            (None, None) => {}
            _ => bail!("notary.endpoint and notary.public_key must be configured together"),
        }
        ensure!(
            self.notary.max_frame_bytes > 0 && self.notary.max_frame_bytes <= u32::MAX as usize,
            "notary.max_frame_bytes must be between 1 and {}",
            u32::MAX
        );
        self.validate_metadata()?;
        self.validate_storage()?;

        let routes = [
            ("openai", &self.providers.openai),
            ("codex", &self.providers.codex),
            ("anthropic", &self.providers.anthropic),
            ("deepseek", &self.providers.deepseek),
            ("openrouter", &self.providers.openrouter),
        ];
        let mut prefixes: Vec<(&str, &str)> = Vec::new();
        for (name, provider) in routes {
            ensure!(
                provider.route_prefix.starts_with('/'),
                "providers.{name}.route_prefix must start with /"
            );
            ensure!(
                provider.route_prefix.len() > 1,
                "providers.{name}.route_prefix must not be /"
            );
            ensure!(
                !provider.route_prefix.ends_with('/'),
                "providers.{name}.route_prefix must not end with /"
            );
            ensure!(
                provider
                    .route_prefix
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric()
                        || character == '-'
                        || character == '_'
                        || character == '/'),
                "providers.{name}.route_prefix contains an invalid character"
            );
            if provider.enabled {
                for (other_name, other_prefix) in &prefixes {
                    ensure!(
                        !route_prefixes_overlap(&provider.route_prefix, other_prefix),
                        "enabled provider route prefixes overlap: providers.{name}.route_prefix ({}) and providers.{other_name}.route_prefix ({other_prefix})",
                        provider.route_prefix,
                    );
                }
                prefixes.push((name, provider.route_prefix.as_str()));
            }
        }
        Ok(())
    }

    fn validate_cluster(&self, cluster: &ClusterConfig) -> Result<()> {
        ensure!(
            self.metadata.backend == MetadataBackend::Postgres,
            "cluster mode requires metadata.backend = \"postgres\""
        );
        ensure!(
            self.storage.backend == ArtifactStorageBackend::S3,
            "cluster mode requires storage.backend = \"s3\""
        );
        ensure!(
            self.admin.auth.is_some(),
            "cluster mode requires admin authentication"
        );
        let proxy = cluster.proxy_origin.as_str();
        let admin = cluster.admin_origin.as_str();
        validate_public_https_origin(proxy, "cluster.proxy_origin")?;
        validate_public_https_origin(admin, "cluster.admin_origin")?;
        ensure!(
            proxy != admin,
            "cluster proxy and admin origins must be different"
        );
        match &cluster.authentication {
            AuthenticationConfig::TokenFile { path } => ensure!(
                path.is_absolute(),
                "cluster.authentication.path must be an absolute path"
            ),
            // Only the hosted notary (no explicit endpoint) admits operations
            // with tickets, which hosted authentication charges to each
            // request's organization.
            AuthenticationConfig::Hosted {
                capture_service_token_file,
            } => match (self.notary.endpoint.is_none(), capture_service_token_file) {
                (true, Some(path)) => ensure!(
                    path.is_absolute(),
                    "cluster.authentication.capture_service_token_file must be an absolute path"
                ),
                (true, None) => bail!(
                    "cluster.authentication.capture_service_token_file is required for hosted authentication with the hosted notary"
                ),
                (false, Some(_)) => bail!(
                    "cluster.authentication.capture_service_token_file is used only with the hosted notary; remove it when notary.endpoint is configured"
                ),
                (false, None) => {}
            },
        }
        if let Some(customer_api) = &cluster.customer_api {
            ensure!(
                customer_api.token_file.is_absolute(),
                "cluster.customer_api.token_file must be an absolute path"
            );
            for (name, other) in [
                ("proxy.listen", self.proxy.listen),
                ("admin.listen", self.admin.listen),
            ] {
                ensure!(
                    !listeners_collide(customer_api.listen, other),
                    "cluster.customer_api.listen must not share a port with {name}"
                );
            }
        }
        Ok(())
    }

    fn validate_storage(&self) -> Result<()> {
        ensure!(
            !self.storage.checkpoint_dir.as_os_str().is_empty(),
            "storage.checkpoint_dir must not be empty"
        );
        ensure!(
            !self.storage.package_dir.as_os_str().is_empty(),
            "storage.package_dir must not be empty"
        );
        if self.storage.backend == ArtifactStorageBackend::S3 {
            ensure!(
                self.storage.s3.is_some(),
                "storage.s3 is required when storage.backend = \"s3\""
            );
        }
        if let Some(s3) = &self.storage.s3 {
            s3.artifact_store_config()?;
        }
        Ok(())
    }

    fn validate_metadata(&self) -> Result<()> {
        match self.metadata.backend {
            MetadataBackend::Sqlite => {
                ensure!(
                    !self.metadata.path.as_os_str().is_empty(),
                    "metadata.path must not be empty for the SQLite backend"
                );
                ensure!(
                    self.metadata.postgres.is_default(),
                    "non-default metadata.postgres settings require metadata.backend = \"postgres\""
                );
            }
            MetadataBackend::Postgres => {
                let postgres = &self.metadata.postgres;
                ensure!(
                    (1..=64).contains(&postgres.max_connections),
                    "metadata.postgres.max_connections must be between 1 and 64"
                );
                ensure!(
                    (1..=300).contains(&postgres.connect_timeout_seconds),
                    "metadata.postgres.connect_timeout_seconds must be between 1 and 300"
                );
                ensure!(
                    (1..=300).contains(&postgres.acquire_timeout_seconds),
                    "metadata.postgres.acquire_timeout_seconds must be between 1 and 300"
                );
                ensure!(
                    (1..=300).contains(&postgres.migration_lock_timeout_seconds),
                    "metadata.postgres.migration_lock_timeout_seconds must be between 1 and 300"
                );
            }
        }
        Ok(())
    }

    /// Returns a stable identifier for the complete, non-secret configuration
    /// that governed a capture.
    pub fn fingerprint(&self) -> Result<String> {
        let mut normalized = self.clone();
        if let Some(auth) = normalized.admin.auth.as_mut() {
            auth.password_hash = None;
        }
        Ok(format!(
            "sha256:{}",
            sha256_hex(toml::to_string(&normalized)?.as_bytes())
        ))
    }

    pub fn notary_endpoint(&self) -> Result<Option<NotaryEndpoint>> {
        self.notary.endpoint.as_deref().map(str::parse).transpose()
    }

    pub fn notary_public_key(&self) -> Result<Option<Vec<u8>>> {
        self.notary
            .public_key
            .as_deref()
            .map(|value| {
                let key = hex::decode(value).context("notary.public_key must be hexadecimal")?;
                VerifyingKey::from_sec1_bytes(&key)
                    .context("notary.public_key must be a SEC1 secp256k1 key")?;
                Ok(key)
            })
            .transpose()
    }

    pub fn s3_credentials(&self) -> Result<SecretS3Credentials> {
        ensure!(
            self.storage.s3.is_some(),
            "S3 artifact storage is not configured"
        );
        let access_key_id = resolve_secret_value(
            env::var_os(ARTIFACT_S3_ACCESS_KEY_ID_ENV),
            env::var_os(ARTIFACT_S3_ACCESS_KEY_ID_FILE_ENV),
            ARTIFACT_S3_ACCESS_KEY_ID_ENV,
            ARTIFACT_S3_ACCESS_KEY_ID_FILE_ENV,
        )?;
        let secret_access_key = resolve_secret_value(
            env::var_os(ARTIFACT_S3_SECRET_ACCESS_KEY_ENV),
            env::var_os(ARTIFACT_S3_SECRET_ACCESS_KEY_FILE_ENV),
            ARTIFACT_S3_SECRET_ACCESS_KEY_ENV,
            ARTIFACT_S3_SECRET_ACCESS_KEY_FILE_ENV,
        )?;
        let session_token = resolve_optional_secret_value(
            env::var_os(ARTIFACT_S3_SESSION_TOKEN_ENV),
            env::var_os(ARTIFACT_S3_SESSION_TOKEN_FILE_ENV),
            ARTIFACT_S3_SESSION_TOKEN_ENV,
            ARTIFACT_S3_SESSION_TOKEN_FILE_ENV,
        )?;
        Ok(SecretS3Credentials {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }
    pub fn postgres_runtime_url(&self) -> Result<SecretDatabaseUrl> {
        ensure!(
            self.metadata.backend == MetadataBackend::Postgres,
            "PostgreSQL metadata is not selected"
        );
        resolve_database_url(
            env::var_os(METADATA_DATABASE_URL_ENV),
            env::var_os(METADATA_DATABASE_URL_FILE_ENV),
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
    }

    pub fn postgres_migration_url(&self) -> Result<SecretDatabaseUrl> {
        ensure!(
            self.metadata.backend == MetadataBackend::Postgres,
            "PostgreSQL metadata is not selected"
        );
        resolve_migration_database_url(
            env::var_os(METADATA_DATABASE_URL_ENV),
            env::var_os(METADATA_DATABASE_URL_FILE_ENV),
            env::var_os(METADATA_MIGRATION_URL_ENV),
            env::var_os(METADATA_MIGRATION_URL_FILE_ENV),
        )
    }

    /// Resolves the cluster dashboard password once at startup. Plaintext is
    /// never retained in the configuration or written back to disk.
    pub fn resolve_runtime_secrets(&mut self) -> Result<()> {
        if self.cluster.is_none() {
            return Ok(());
        }
        let auth = self
            .admin
            .auth
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("cluster mode requires admin authentication"))?;
        if auth.password_hash.is_some() {
            return Ok(());
        }
        let password = zeroize::Zeroizing::new(resolve_secret_value(
            env::var_os(ADMIN_PASSWORD_ENV),
            env::var_os(ADMIN_PASSWORD_FILE_ENV),
            ADMIN_PASSWORD_ENV,
            ADMIN_PASSWORD_FILE_ENV,
        )?);
        let password_hash = hash_admin_password(password.as_bytes())?;
        auth.password_hash = Some(password_hash);
        Ok(())
    }
}

fn hash_admin_password(password: &[u8]) -> Result<String> {
    let salt = SaltString::encode_b64(uuid::Uuid::new_v4().as_bytes())
        .map_err(|error| anyhow::anyhow!("creating admin password salt failed: {error}"))?;
    Argon2::default()
        .hash_password(password, &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| anyhow::anyhow!("hashing admin password failed: {error}"))
}

fn resolve_migration_database_url(
    runtime_inline: Option<OsString>,
    runtime_file: Option<OsString>,
    migration_inline: Option<OsString>,
    migration_file: Option<OsString>,
) -> Result<SecretDatabaseUrl> {
    if migration_inline.is_none() && migration_file.is_none() {
        return resolve_database_url(
            runtime_inline,
            runtime_file,
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        );
    }
    resolve_database_url(
        migration_inline,
        migration_file,
        METADATA_MIGRATION_URL_ENV,
        METADATA_MIGRATION_URL_FILE_ENV,
    )
}

fn resolve_database_url(
    inline: Option<OsString>,
    file: Option<OsString>,
    inline_name: &'static str,
    file_name: &'static str,
) -> Result<SecretDatabaseUrl> {
    let value = resolve_secret_value(inline, file, inline_name, file_name)?;
    let parsed = url::Url::parse(&value).context("PostgreSQL metadata URL is invalid")?;
    ensure!(
        matches!(parsed.scheme(), "postgres" | "postgresql"),
        "PostgreSQL metadata URL must use postgres:// or postgresql://"
    );
    Ok(SecretDatabaseUrl(value))
}

fn resolve_optional_secret_value(
    inline: Option<OsString>,
    file: Option<OsString>,
    inline_name: &'static str,
    file_name: &'static str,
) -> Result<Option<String>> {
    if inline.is_none() && file.is_none() {
        return Ok(None);
    }
    resolve_secret_value(inline, file, inline_name, file_name).map(Some)
}

fn resolve_secret_value(
    inline: Option<OsString>,
    file: Option<OsString>,
    inline_name: &'static str,
    file_name: &'static str,
) -> Result<String> {
    const MAX_SECRET_BYTES: usize = 16 * 1024;

    // The direct value intentionally wins and prevents the file path from
    // being opened. This also makes mounted-secret rotations deterministic.
    let value = if let Some(value) = inline {
        value
            .into_string()
            .map_err(|_| anyhow::anyhow!("{inline_name} is not valid UTF-8"))?
    } else if let Some(path) = file {
        let path = PathBuf::from(path);
        let file = fs::File::open(&path)
            .with_context(|| format!("reading secret file from {file_name}"))?;
        ensure!(
            file.metadata()
                .with_context(|| format!("inspecting secret file from {file_name}"))?
                .is_file(),
            "secret source from {file_name} must be a regular file"
        );
        let mut bytes = Vec::new();
        file.take(u64::try_from(MAX_SECRET_BYTES + 1).expect("secret limit fits in u64"))
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading secret file from {file_name}"))?;
        ensure!(bytes.len() <= MAX_SECRET_BYTES, "secret file is too large");
        let mut value = String::from_utf8(bytes).context("secret file is not UTF-8")?;
        if value.ends_with("\r\n") {
            value.truncate(value.len() - 2);
        } else if value.ends_with('\n') {
            value.pop();
        }
        value
    } else {
        bail!("set {inline_name} or {file_name}");
    };
    ensure!(!value.is_empty(), "secret value is empty");
    ensure!(value.len() <= MAX_SECRET_BYTES, "secret value is too large");
    ensure!(
        !value
            .chars()
            .any(|character| matches!(character, '\r' | '\n' | '\0')),
        "secret value contains invalid control characters"
    );
    Ok(value)
}

/// Whether two listeners cannot both bind: the same port on the same or an
/// unspecified address. Port 0 asks for a fresh port each time.
fn listeners_collide(left: SocketAddr, right: SocketAddr) -> bool {
    left.port() != 0
        && left.port() == right.port()
        && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

fn route_prefixes_overlap(left: &str, right: &str) -> bool {
    left == right
        || left
            .strip_prefix(right)
            .is_some_and(|suffix| suffix.starts_with('/'))
        || right
            .strip_prefix(left)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub fn valid_instance_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_public_https_origin(value: &str, name: &str) -> Result<()> {
    let parsed = url::Url::parse(value).with_context(|| format!("{name} is invalid"))?;
    ensure!(parsed.scheme() == "https", "{name} must use https://");
    ensure!(parsed.host_str().is_some(), "{name} must include a host");
    ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "{name} must not contain credentials"
    );
    ensure!(
        parsed.path() == "/" && parsed.query().is_none() && parsed.fragment().is_none(),
        "{name} must be an origin without a path, query, or fragment"
    );
    Ok(())
}

pub use capture_updater::default_config_path;

fn config_path(path: Option<&Path>) -> Result<PathBuf> {
    match path {
        Some(path) => Ok(path.to_owned()),
        None => default_config_path(),
    }
}

/// Loads an captured configuration, generating the editable defaults on first
/// use. Every config-driven command shares this behavior so a fresh install
/// can start the proxy without a setup command.
pub fn load_captured_config(path: Option<&Path>) -> Result<(CapturedConfig, PathBuf)> {
    let explicit = path.is_some();
    let path = config_path(path)?;
    if explicit {
        let mut config = CapturedConfig::load(&path)?;
        config.resolve_runtime_secrets()?;
        return Ok((config, path));
    }
    let (mut config, created) = CapturedConfig::load_or_create(&path)?;
    if created {
        eprintln!("created default captured configuration: {}", path.display());
    }
    config.resolve_runtime_secrets()?;
    Ok((config, path))
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:8787"
        .parse()
        .expect("valid default listen address")
}

fn default_admin_listen() -> SocketAddr {
    "127.0.0.1:8788"
        .parse()
        .expect("valid default admin listen address")
}

fn default_max_attestable_http_bytes() -> usize {
    DEFAULT_MAX_ATTESTABLE_HTTP_BYTES
}

fn default_max_frame_bytes() -> usize {
    DEFAULT_NOTARY_MAX_FRAME_BYTES
}

fn default_preview_chars() -> usize {
    1_000
}

fn default_true() -> bool {
    true
}

fn default_postgres_max_connections() -> u32 {
    8
}

fn default_postgres_connect_timeout_seconds() -> u64 {
    10
}

fn default_postgres_acquire_timeout_seconds() -> u64 {
    10
}

fn default_postgres_migration_lock_timeout_seconds() -> u64 {
    60
}

fn default_s3_prefix() -> String {
    "captured".to_owned()
}

fn default_s3_region() -> String {
    "us-east-1".to_owned()
}

fn default_s3_connect_timeout_seconds() -> u64 {
    10
}

fn default_s3_operation_timeout_seconds() -> u64 {
    30
}

fn default_data_dir() -> PathBuf {
    if let Some(path) = env::var_os("XDG_DATA_HOME") {
        PathBuf::from(path).join("ai.exalto.capture")
    } else if let Some(path) = env::var_os("LOCALAPPDATA") {
        PathBuf::from(path).join("ai.exalto.capture")
    } else if let Some(path) = env::var_os("HOME") {
        let home = PathBuf::from(path);
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support/ai.exalto.capture")
        } else {
            home.join(".local/share/ai.exalto.capture")
        }
    } else {
        PathBuf::from("capture-data")
    }
}

fn default_checkpoint_dir() -> PathBuf {
    default_data_dir().join("capture-checkpoints")
}

fn default_package_dir() -> PathBuf {
    default_data_dir().join("trace-packages")
}

fn default_metadata_path() -> PathBuf {
    default_data_dir().join("metadata.db")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_configuration_enables_the_built_in_providers() {
        let config = CapturedConfig::default();
        config.validate().unwrap();
        assert!(config.providers.openai.enabled);
        assert!(config.providers.codex.enabled);
        assert!(config.providers.anthropic.enabled);
        assert!(config.providers.deepseek.enabled);
        assert!(config.providers.openrouter.enabled);
        assert_eq!(config.metadata.prompt_preview_chars, 1_000);
        assert!(config.metadata.full_text_search);
        assert_eq!(config.metadata.backend, MetadataBackend::Sqlite);
        assert_eq!(config.metadata.postgres, PostgresMetadataConfig::default());
        assert_eq!(config.storage.backend, ArtifactStorageBackend::Filesystem);
        assert!(config.storage.s3.is_none());
        assert_eq!(config.proxy.listen.to_string(), "127.0.0.1:8787");
        assert_eq!(config.admin.listen.to_string(), "127.0.0.1:8788");
        assert!(config.admin.auth.is_none());
    }

    #[test]
    fn non_loopback_or_shared_listeners_are_rejected() {
        let mut config = CapturedConfig::default();
        config.admin.listen = "0.0.0.0:8788".parse().unwrap();
        assert!(config.validate().is_err());

        config.admin.listen = config.proxy.listen;
        assert!(config.validate().is_err());
    }

    /// A valid cluster profile with a self-hosted notary.
    fn cluster_profile() -> CapturedConfig {
        let mut config = CapturedConfig {
            cluster: Some(ClusterConfig {
                proxy_origin: "https://proxy.notary.example".into(),
                admin_origin: "https://admin.notary.example".into(),
                authentication: AuthenticationConfig::TokenFile {
                    path: "/run/secrets/capture-tokens.toml".into(),
                },
                customer_api: None,
            }),
            ..CapturedConfig::default()
        };
        config.proxy.listen = "0.0.0.0:8787".parse().unwrap();
        config.admin.listen = "0.0.0.0:8788".parse().unwrap();
        config.admin.auth = Some(AdminAuthConfig {
            username: "admin".into(),
            password_hash: None,
        });
        config.metadata.backend = MetadataBackend::Postgres;
        config.metadata.postgres = PostgresMetadataConfig::default();
        config.storage.backend = ArtifactStorageBackend::S3;
        config.storage.s3 = Some(S3StorageConfig {
            bucket: "private-artifacts".into(),
            region: "us-east-1".into(),
            endpoint: Some("https://s3.example.test".into()),
            prefix: "server".into(),
            force_path_style: false,
            allow_insecure_http: false,
            connect_timeout_seconds: 5,
            operation_timeout_seconds: 10,
        });
        config.notary.endpoint = Some("tcp://notary.internal:7047".into());
        config.notary.public_key =
            Some("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into());
        config
    }

    #[test]
    fn cluster_profile_has_safe_defaults_and_rejects_unsafe_combinations() {
        let mut config = cluster_profile();
        config.validate().unwrap();

        let valid = config.clone();
        let encoded = toml::to_string_pretty(&valid).unwrap();
        assert!(encoded.contains("[cluster]"));
        assert!(
            toml::from_str::<CapturedConfig>(&encoded.replace("[cluster]", "[server]")).is_err()
        );
        config.metadata.backend = MetadataBackend::Sqlite;
        assert!(config.validate().is_err());
        config = valid.clone();
        config.storage.backend = ArtifactStorageBackend::Filesystem;
        assert!(config.validate().is_err());
        config = valid.clone();
        config.admin.auth = None;
        assert!(config.validate().is_err());
        config = valid.clone();
        config.cluster.as_mut().unwrap().admin_origin = String::new();
        assert!(config.validate().is_err());
        config = valid.clone();
        config.cluster.as_mut().unwrap().authentication = AuthenticationConfig::TokenFile {
            path: "capture-tokens.toml".into(),
        };
        assert!(config.validate().is_err());
        config.cluster.as_mut().unwrap().authentication = AuthenticationConfig::Hosted {
            capture_service_token_file: None,
        };
        config.validate().unwrap();
        // A self-hosted notary needs no admission, so nothing is charged and
        // a capture service credential would be unused.
        config.cluster.as_mut().unwrap().authentication = AuthenticationConfig::Hosted {
            capture_service_token_file: Some("/run/secrets/capture_service_token".into()),
        };
        assert!(config.validate().is_err());
        // The hosted notary admits every operation, which hosted
        // authentication charges to each request's organization.
        config.notary.endpoint = None;
        config.notary.public_key = None;
        config.validate().unwrap();
        config.cluster.as_mut().unwrap().authentication = AuthenticationConfig::Hosted {
            capture_service_token_file: Some("capture_service_token".into()),
        };
        assert!(config.validate().is_err());
        config.cluster.as_mut().unwrap().authentication = AuthenticationConfig::Hosted {
            capture_service_token_file: None,
        };
        assert!(config.validate().is_err());
        config = valid.clone();
        config.notary.endpoint = None;
        config.notary.public_key = None;
        config.validate().unwrap();
    }

    #[test]
    fn the_customer_api_is_optional_private_and_on_its_own_port() {
        let section = |customer_api: &str| {
            format!(
                "proxy_origin = \"https://proxy.notary.example\"\nadmin_origin = \"https://admin.notary.example\"\n\n[authentication]\nkind = \"hosted\"\n{customer_api}"
            )
        };
        let parse = |source: String| toml::from_str::<ClusterConfig>(&source);
        assert_eq!(parse(section("")).unwrap().customer_api, None);
        assert_eq!(
            parse(section(
                "\n[customer_api]\nlisten = \"[::]:8789\"\ntoken_file = \"/run/secrets/customer_api_token\"\n"
            ))
            .unwrap()
            .customer_api,
            Some(CustomerApiConfig {
                listen: "[::]:8789".parse().unwrap(),
                token_file: "/run/secrets/customer_api_token".into(),
            })
        );
        for invalid in [
            "\n[customer_api]\nlisten = \"[::]:8789\"\n",
            "\n[customer_api]\ntoken_file = \"/run/secrets/customer_api_token\"\n",
            "\n[customer_api]\nlisten = \"customer-api:8789\"\ntoken_file = \"/run/secrets/customer_api_token\"\n",
            "\n[customer_api]\nlisten = \"[::]:8789\"\ntoken_file = \"/run/secrets/customer_api_token\"\ntoken = \"raw\"\n",
        ] {
            assert!(parse(section(invalid)).is_err(), "{invalid}");
        }

        let without = cluster_profile();
        without.validate().unwrap();
        assert!(
            !toml::to_string_pretty(&without)
                .unwrap()
                .contains("customer_api")
        );
        let mut config = without.clone();
        config.cluster.as_mut().unwrap().customer_api = Some(CustomerApiConfig {
            listen: "0.0.0.0:8789".parse().unwrap(),
            token_file: "/run/secrets/customer_api_token".into(),
        });
        config.validate().unwrap();
        let encoded = toml::to_string_pretty(&config).unwrap();
        assert!(encoded.contains("[cluster.customer_api]"), "{encoded}");
        assert_eq!(
            toml::from_str::<CapturedConfig>(&encoded)
                .unwrap()
                .cluster
                .unwrap()
                .customer_api,
            config.cluster.as_ref().unwrap().customer_api
        );

        let mut invalid = config.clone();
        invalid
            .cluster
            .as_mut()
            .unwrap()
            .customer_api
            .as_mut()
            .unwrap()
            .token_file = "customer_api_token".into();
        let error = invalid.validate().unwrap_err().to_string();
        assert!(
            error.contains("token_file must be an absolute path"),
            "{error}"
        );
        // The listener may not take the proxy's or the admin listener's
        // port on the same or an unspecified address.
        for (listen, collides) in [
            ("0.0.0.0:8787", true),
            ("127.0.0.1:8787", true),
            ("[::]:8788", true),
            ("10.0.0.5:8788", true),
            ("0.0.0.0:8789", false),
            ("[fdaa::3]:8789", false),
        ] {
            let mut candidate = config.clone();
            candidate
                .cluster
                .as_mut()
                .unwrap()
                .customer_api
                .as_mut()
                .unwrap()
                .listen = listen.parse().unwrap();
            match candidate.validate() {
                Ok(()) => assert!(!collides, "{listen}"),
                Err(error) => {
                    assert!(collides, "{listen}: {error}");
                    assert!(
                        error
                            .to_string()
                            .starts_with("cluster.customer_api.listen must not share a port"),
                        "{error}"
                    );
                }
            }
        }
        assert!(listeners_collide(
            "127.0.0.1:8789".parse().unwrap(),
            "127.0.0.1:8789".parse().unwrap()
        ));
        assert!(!listeners_collide(
            "127.0.0.1:8789".parse().unwrap(),
            "127.0.0.2:8789".parse().unwrap()
        ));
        assert!(!listeners_collide(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap()
        ));
    }

    #[test]
    fn cluster_authentication_is_required_and_explicit() {
        let cluster = |authentication: &str| {
            format!(
                "proxy_origin = \"https://proxy.notary.example\"\nadmin_origin = \"https://admin.notary.example\"\n{authentication}"
            )
        };
        let parse = |source: String| toml::from_str::<ClusterConfig>(&source);

        assert!(parse(cluster("")).is_err(), "authentication is required");
        assert_eq!(
            parse(cluster("\n[authentication]\nkind = \"hosted\"\n"))
                .map(|config| config.authentication)
                .unwrap_or_else(|error| panic!("{error}")),
            AuthenticationConfig::Hosted {
                capture_service_token_file: None
            }
        );
        assert_eq!(
            parse(cluster(
                "\n[authentication]\nkind = \"hosted\"\ncapture_service_token_file = \"/run/secrets/capture_service_token\"\n"
            ))
            .unwrap()
            .authentication,
            AuthenticationConfig::Hosted {
                capture_service_token_file: Some("/run/secrets/capture_service_token".into())
            }
        );
        assert_eq!(
            parse(cluster(
                "\n[authentication]\nkind = \"token_file\"\npath = \"/run/secrets/capture-tokens.toml\"\n"
            ))
            .unwrap()
            .authentication,
            AuthenticationConfig::TokenFile {
                path: "/run/secrets/capture-tokens.toml".into()
            }
        );
        for invalid in [
            "\n[authentication]\nkind = \"none\"\n",
            "\n[authentication]\nkind = \"token_file\"\n",
            "\n[authentication]\nkind = \"hosted\"\npath = \"/run/secrets/capture-tokens.toml\"\n",
            "\n[authentication]\nkind = \"token_file\"\npath = \"/run/secrets/capture-tokens.toml\"\ncapture_service_token_file = \"/run/secrets/capture_service_token\"\n",
        ] {
            assert!(parse(cluster(invalid)).is_err(), "{invalid}");
        }
        for authentication in [
            AuthenticationConfig::Hosted {
                capture_service_token_file: None,
            },
            AuthenticationConfig::Hosted {
                capture_service_token_file: Some("/run/secrets/capture_service_token".into()),
            },
        ] {
            let mut profile = parse(cluster("\n[authentication]\nkind = \"hosted\"\n")).unwrap();
            profile.authentication = authentication.clone();
            let config = CapturedConfig {
                cluster: Some(profile),
                ..CapturedConfig::default()
            };
            let encoded = toml::to_string_pretty(&config).unwrap();
            assert!(encoded.contains("[cluster.authentication]\nkind = \"hosted\""));
            assert_eq!(
                toml::from_str::<CapturedConfig>(&encoded)
                    .unwrap()
                    .cluster
                    .unwrap()
                    .authentication,
                authentication
            );
        }
    }

    #[test]
    fn explicit_notary_endpoint_requires_a_valid_trust_anchor() {
        let mut config = CapturedConfig::default();
        config.notary.endpoint = Some("tcp://127.0.0.1:7047".to_owned());
        assert!(config.validate().is_err());

        config.notary.public_key =
            Some("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_owned());
        config.validate().unwrap();
        assert_eq!(config.notary_public_key().unwrap().unwrap().len(), 33);

        config.notary.endpoint = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn configured_admin_auth_requires_an_argon2id_hash() {
        let mut config = CapturedConfig::default();
        config.admin.auth = Some(AdminAuthConfig {
            username: "local-admin".to_owned(),
            password_hash: Some("$2b$12$not-an-argon2id-hash".to_owned()),
        });
        assert!(config.validate().is_err());

        config.admin.auth.as_mut().unwrap().password_hash = Some(
            "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$yJIR0lVleM2KSPdVmBvsQ9uhA06YIR8aPCbRDbNvXXQ".to_owned(),
        );
        config.validate().unwrap();

        let generated = hash_admin_password(b"generated server password").unwrap();
        let parsed = PasswordHash::new(&generated).unwrap();
        use argon2::PasswordVerifier as _;
        Argon2::default()
            .verify_password(b"generated server password", &parsed)
            .unwrap();
    }

    #[test]
    fn duplicate_enabled_routes_are_rejected() {
        let mut config = CapturedConfig::default();
        config.providers.anthropic.route_prefix = "/openai".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn overlapping_enabled_routes_are_rejected() {
        let mut config = CapturedConfig::default();
        config.providers.openai.route_prefix = "/ai".to_owned();
        config.providers.anthropic.route_prefix = "/ai/anthropic".to_owned();
        assert!(config.validate().is_err());
    }

    #[test]
    fn creating_a_default_configuration_is_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        let (config, created) = CapturedConfig::load_or_create(&path).unwrap();
        assert!(created);
        config.validate().unwrap();
        assert!(!CapturedConfig::ensure_default(&path).unwrap());
    }

    #[test]
    fn default_configuration_round_trips_as_toml() {
        let config = CapturedConfig::default();
        let encoded = toml::to_string_pretty(&config).unwrap();
        assert!(!encoded.contains("[metadata.postgres]"));
        assert!(!encoded.contains("[cluster]"));
        let parsed: CapturedConfig = toml::from_str(&encoded).unwrap();
        parsed.validate().unwrap();
    }

    #[test]
    fn retired_configuration_formats_and_sections_are_rejected() {
        let encoded = toml::to_string_pretty(&CapturedConfig::default()).unwrap();

        let old_format = encoded.replace(CONFIG_FORMAT, "llm-notary/agent-config/v1");
        let parsed: CapturedConfig = toml::from_str(&old_format).unwrap();
        assert!(parsed.validate().is_err());

        let old_metadata_section = encoded.replace("[metadata]", "[catalog]");
        assert!(toml::from_str::<CapturedConfig>(&old_metadata_section).is_err());
    }

    #[test]
    fn postgres_configuration_is_explicit_and_bounded() {
        let mut config = CapturedConfig::default();
        config.metadata.backend = MetadataBackend::Postgres;
        config.validate().unwrap();
        assert_eq!(
            config.metadata.postgres.ssl_mode,
            PostgresSslMode::VerifyFull,
            "remote PostgreSQL connections must verify certificates and hostnames by default"
        );
        config.metadata.postgres.max_connections = 0;
        assert!(config.validate().is_err());

        config.metadata.backend = MetadataBackend::Sqlite;
        assert!(config.validate().is_err());
    }

    #[test]
    fn minimal_postgres_configuration_uses_safe_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            format!("format = {CONFIG_FORMAT:?}\n\n[metadata]\nbackend = \"postgres\"\n"),
        )
        .unwrap();

        let config = CapturedConfig::load_for_metadata_migration(&path).unwrap();
        assert_eq!(config.metadata.backend, MetadataBackend::Postgres);
        assert_eq!(config.metadata.postgres, PostgresMetadataConfig::default());
    }

    #[test]
    fn s3_configuration_is_explicit_secure_and_bounded() {
        let mut config = CapturedConfig::default();
        config.storage.backend = ArtifactStorageBackend::S3;
        assert!(config.validate().is_err());

        config.storage.s3 = Some(S3StorageConfig {
            bucket: "notary-artifacts".to_owned(),
            region: "us-east-1".to_owned(),
            endpoint: None,
            prefix: "tenant/daemon".to_owned(),
            force_path_style: false,
            allow_insecure_http: false,
            connect_timeout_seconds: 10,
            operation_timeout_seconds: 30,
        });
        config.validate().unwrap();

        let s3 = config.storage.s3.as_mut().unwrap();
        s3.endpoint = Some("http://object-store:8333".to_owned());
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().allow_insecure_http = true;
        config.validate().unwrap();

        config.storage.s3.as_mut().unwrap().prefix = "../other-tenant".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().prefix = "tenant/daemon/".to_owned();
        config.validate().unwrap();
        config.storage.s3.as_mut().unwrap().prefix = "tenant//daemon".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().prefix = "tenant daemon".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().prefix = String::new();
        config.validate().unwrap();
        config.storage.s3.as_mut().unwrap().prefix = "tenant/daemon".to_owned();
        config.storage.s3.as_mut().unwrap().bucket = "bucket/escape".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().bucket = "notary-artifacts".to_owned();
        config.storage.s3.as_mut().unwrap().region = "region\nother".to_owned();
        assert!(config.validate().is_err());
        config.storage.s3.as_mut().unwrap().region = "us-east-1".to_owned();
        config
            .storage
            .s3
            .as_mut()
            .unwrap()
            .operation_timeout_seconds = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn minimal_s3_configuration_uses_aws_defaults() {
        let encoded = format!(
            "format = {CONFIG_FORMAT:?}\n\n[storage]\nbackend = \"s3\"\n\n[storage.s3]\nbucket = \"private-artifacts\"\n"
        );
        let config: CapturedConfig = toml::from_str(&encoded).unwrap();
        config.validate().unwrap();
        let s3 = config.storage.s3.unwrap();
        assert_eq!(s3.region, "us-east-1");
        assert!(s3.endpoint.is_none());
        assert_eq!(s3.prefix, "captured");
        assert!(!s3.force_path_style);
        assert!(!s3.allow_insecure_http);
    }

    #[test]
    fn filesystem_can_retain_an_s3_read_profile() {
        let mut config = CapturedConfig::default();
        config.storage.s3 = Some(S3StorageConfig {
            bucket: "notary-artifacts".to_owned(),
            region: "us-east-1".to_owned(),
            endpoint: Some("https://s3.example.test".to_owned()),
            prefix: "captured".to_owned(),
            force_path_style: false,
            allow_insecure_http: false,
            connect_timeout_seconds: 10,
            operation_timeout_seconds: 30,
        });
        config.validate().unwrap();
    }

    #[test]
    fn inline_database_url_precedes_the_file_source_and_debug_is_redacted() {
        let secret = resolve_database_url(
            Some("postgres://operator:secret@database/daemon".into()),
            Some("/a/path/that/must/not/be/read".into()),
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
        .unwrap();
        assert_eq!(
            secret.expose(),
            "postgres://operator:secret@database/daemon"
        );
        assert_eq!(format!("{secret:?}"), "SecretDatabaseUrl([REDACTED])");
    }

    #[test]
    fn migration_url_defaults_to_runtime_and_allows_a_privileged_override() {
        let shared = resolve_migration_database_url(
            Some("postgres://runtime/database".into()),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(shared.expose(), "postgres://runtime/database");

        let separate = resolve_migration_database_url(
            Some("postgres://runtime/database".into()),
            None,
            Some("postgres://migrator/database".into()),
            Some("/a/path/that/must/not/be/read".into()),
        )
        .unwrap();
        assert_eq!(separate.expose(), "postgres://migrator/database");
    }

    #[test]
    fn artifact_credentials_are_redacted_and_inline_values_skip_files() {
        let access_key = resolve_secret_value(
            Some("access-canary".into()),
            Some("/a/path/that/must/not/be/read".into()),
            ARTIFACT_S3_ACCESS_KEY_ID_ENV,
            ARTIFACT_S3_ACCESS_KEY_ID_FILE_ENV,
        )
        .unwrap();
        let credentials = SecretS3Credentials {
            access_key_id: access_key,
            secret_access_key: "secret-canary".to_owned(),
            session_token: Some("session-canary".to_owned()),
        };
        assert_eq!(credentials.access_key_id(), "access-canary");
        assert_eq!(credentials.secret_access_key(), "secret-canary");
        assert_eq!(credentials.session_token(), Some("session-canary"));
        let debug = format!("{credentials:?}");
        assert_eq!(debug, "SecretS3Credentials([REDACTED])");
        assert!(!debug.contains("canary"));
        assert!(
            resolve_optional_secret_value(None, None, "DIRECT", "FILE")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn database_url_file_trims_only_one_line_ending() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("database-url");
        fs::write(&path, b"postgres://database/daemon\r\n").unwrap();
        let secret = resolve_database_url(
            None,
            Some(path.into_os_string()),
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
        .unwrap();
        assert_eq!(secret.expose(), "postgres://database/daemon");
    }

    #[test]
    fn database_url_failures_do_not_echo_secrets_or_secret_paths() {
        let inline_canary = "postgres://operator:canary-password@[invalid";
        let inline_error = resolve_database_url(
            Some(inline_canary.into()),
            None,
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
        .unwrap_err();
        assert!(!format!("{inline_error:#}").contains(inline_canary));

        let path_canary = "/does/not/exist/canary-database-secret";
        let file_error = resolve_database_url(
            None,
            Some(path_canary.into()),
            METADATA_DATABASE_URL_ENV,
            METADATA_DATABASE_URL_FILE_ENV,
        )
        .unwrap_err();
        assert!(!format!("{file_error:#}").contains(path_canary));
    }
}
