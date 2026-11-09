//! Versioned notary discovery and signing-key lifecycle.

use std::{collections::BTreeSet, fmt, str::FromStr};

use anyhow::{Context, Result, bail};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::sha256_hex;

pub const REGISTRY_FORMAT: &str = "ecp/registry/v1";

/// The transport used for the public local-proxy-to-notary connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotaryTransport {
    /// A direct raw TCP connection. This remains suitable for loopback and
    /// deployments that protect the path outside the client.
    #[default]
    Tcp,
    /// A public-CA-validated TLS connection carrying the raw notary protocol.
    Tls,
}

impl NotaryTransport {
    pub fn scheme(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }
}

impl FromStr for NotaryTransport {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "tls" => Ok(Self::Tls),
            _ => bail!("notary transport must be tcp or tls"),
        }
    }
}

/// A hostname-preserving notary endpoint.
///
/// TLS endpoints retain `host` for SNI and certificate validation; they must
/// never be reduced to an IP address before the TLS handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotaryEndpoint {
    pub host: String,
    pub port: u16,
    pub transport: NotaryTransport,
}

impl NotaryEndpoint {
    pub fn new(host: String, port: u16, transport: NotaryTransport) -> Result<Self> {
        let endpoint = Self {
            host,
            port,
            transport,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    fn validate(&self) -> Result<()> {
        if self.host.is_empty() || self.host.chars().any(char::is_whitespace) || self.port == 0 {
            bail!("notary endpoint is invalid");
        }
        Ok(())
    }
}

impl fmt::Display for NotaryEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.contains(':') {
            write!(
                formatter,
                "{}://[{}]:{}",
                self.transport.scheme(),
                self.host,
                self.port
            )
        } else {
            write!(
                formatter,
                "{}://{}:{}",
                self.transport.scheme(),
                self.host,
                self.port
            )
        }
    }
}

impl FromStr for NotaryEndpoint {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        if !value.contains("://") {
            bail!("notary endpoint must explicitly use tcp:// or tls://");
        }
        let url = url::Url::parse(value).context("invalid notary endpoint")?;
        let transport = match url.scheme() {
            "tcp" => NotaryTransport::Tcp,
            "tls" => NotaryTransport::Tls,
            scheme => bail!("notary endpoint must use tcp:// or tls://, not {scheme}://"),
        };
        if !url.username().is_empty()
            || url.password().is_some()
            || !matches!(url.path(), "" | "/")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            bail!("notary endpoint must contain only a scheme, host, and port");
        }
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("notary endpoint has no host"))?
            .to_owned();
        let port = url
            .port()
            .ok_or_else(|| anyhow::anyhow!("notary endpoint has no port"))?;
        Self::new(host, port, transport)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NotaryKeyStatus {
    Active,
    Retiring,
    Retired,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryRecord {
    /// Server-supplied signer identity, for example `Seal` or `seal1`.
    pub name: String,
    /// Organization responsible for operating the notary.
    pub operator: String,
    pub host: String,
    pub port: u16,
    /// How clients connect to this endpoint.
    pub transport: NotaryTransport,
    pub key_id: String,
    pub public_key: String,
    pub status: NotaryKeyStatus,
    pub valid_from_unix_ms: u64,
    /// Last authenticated provider-connection timestamp this key may sign.
    pub valid_until_unix_ms: Option<u64>,
    /// Last wall-clock time at which this endpoint may notarize an existing
    /// capture checkpoint. This is separate from the capture cutoff.
    pub notarize_until_unix_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub format: String,
    /// Monotonically increasing operator revision used to reject rollback.
    pub generation: u64,
    pub active_key_id: String,
    pub notaries: Vec<RegistryRecord>,
}

impl RegistryRecord {
    pub fn endpoint(&self) -> Result<NotaryEndpoint> {
        NotaryEndpoint::new(self.host.clone(), self.port, self.transport)
    }

    pub fn public_key_bytes(&self) -> Result<Vec<u8>> {
        let public_key =
            hex::decode(&self.public_key).context("registry key is not hexadecimal")?;
        VerifyingKey::from_sec1_bytes(&public_key)
            .context("registry key is not a SEC1 secp256k1 key")?;
        if self.key_id != key_id(&public_key) {
            bail!("registry key ID does not match its public key");
        }
        Ok(public_key)
    }

    pub fn trusted_at(&self, unix_ms: u64) -> bool {
        self.status != NotaryKeyStatus::Revoked
            && unix_ms >= self.valid_from_unix_ms
            && self
                .valid_until_unix_ms
                .is_none_or(|until| unix_ms <= until)
    }

    pub fn accepts_capture_at(&self, unix_ms: u64) -> bool {
        self.status == NotaryKeyStatus::Active && self.trusted_at(unix_ms)
    }

    pub fn accepts_notarization_at(&self, unix_ms: u64) -> bool {
        matches!(
            self.status,
            NotaryKeyStatus::Active | NotaryKeyStatus::Retiring
        ) && unix_ms >= self.valid_from_unix_ms
            && self
                .notarize_until_unix_ms
                .is_none_or(|until| unix_ms <= until)
    }
}

impl Registry {
    pub fn validate(&self) -> Result<()> {
        if self.format != REGISTRY_FORMAT {
            bail!("unsupported notary registry format: {}", self.format);
        }
        if self.notaries.is_empty() || self.notaries.len() > 32 {
            bail!("notary registry must contain between 1 and 32 records");
        }
        let mut ids = BTreeSet::new();
        for record in &self.notaries {
            validate_record(record)?;
            if !ids.insert(record.key_id.as_str()) {
                bail!("notary registry contains a duplicate key ID");
            }
        }
        let active = self
            .notaries
            .iter()
            .find(|record| record.key_id == self.active_key_id)
            .ok_or_else(|| anyhow::anyhow!("active notary key is missing from the registry"))?;
        if active.status != NotaryKeyStatus::Active {
            bail!("the selected active notary key is not marked active");
        }
        Ok(())
    }

    pub fn active(&self) -> Result<&RegistryRecord> {
        self.validate()?;
        Ok(self
            .notaries
            .iter()
            .find(|record| record.key_id == self.active_key_id)
            .expect("validated registry has its active key"))
    }

    pub fn active_at(&self, unix_ms: u64) -> Result<&RegistryRecord> {
        let active = self.active()?;
        if !active.accepts_capture_at(unix_ms) {
            bail!("the active notary key is outside its validity window");
        }
        Ok(active)
    }
}

pub fn parse_registry(bytes: &[u8]) -> Result<Registry> {
    let registry: Registry =
        serde_json::from_slice(bytes).context("decoding v3 notary registry")?;
    registry.validate()?;
    Ok(registry)
}

/// Parses a Registry as Exalto's API publishes it, which names each notary's
/// key `verification_key`. A record still carrying the retired `public_key`
/// field is refused.
pub fn parse_hosted_registry(bytes: &[u8]) -> Result<Registry> {
    let mut document: serde_json::Value =
        serde_json::from_slice(bytes).context("decoding hosted Notary Registry")?;
    let notaries = document
        .get_mut("notaries")
        .and_then(serde_json::Value::as_array_mut)
        .context("hosted Notary Registry is missing its notaries")?;
    for notary in notaries {
        let notary = notary
            .as_object_mut()
            .context("hosted Notary Registry contains an invalid notary")?;
        if notary.contains_key("public_key") {
            bail!("hosted Notary Registry uses a retired public_key field");
        }
        let verification_key = notary
            .remove("verification_key")
            .context("hosted Notary Registry is missing a verification_key")?;
        notary.insert("public_key".to_owned(), verification_key);
    }
    let internal = serde_json::to_vec(&document).context("adapting hosted Notary Registry")?;
    parse_registry(&internal)
}

/// The key of the first record trusted at `at_unix_ms` for which `signed`
/// succeeds.
pub fn trusted_key_at(
    records: &[RegistryRecord],
    at_unix_ms: u64,
    signed: impl Fn(&[u8]) -> Result<()>,
) -> Result<Vec<u8>> {
    for record in records {
        let key = record.public_key_bytes()?;
        if record.trusted_at(at_unix_ms) && signed(&key).is_ok() {
            return Ok(key);
        }
    }
    bail!("no notary key trusted at that time signed it")
}

/// The Registry key that signed a witness receipt and was trusted when the
/// notary opened the provider connection.
pub fn witness_key(
    records: &[RegistryRecord],
    exchange: &crate::witness::WitnessedExchange,
) -> Result<Vec<u8>> {
    trusted_key_at(records, exchange.receipt().connected_at_unix_ms(), |key| {
        exchange.verify(key)
    })
    .context("no trusted notary key signed this witness receipt")
}

/// The key and record that can seal `checkpoint` at `now_unix_ms`: a record
/// trusted when the provider connection opened, still accepting sealing, whose
/// key signed the capture receipt.
pub fn sealing_record<'a>(
    records: &'a [RegistryRecord],
    checkpoint: &crate::CaptureCheckpoint,
    now_unix_ms: u64,
) -> Result<(Vec<u8>, &'a RegistryRecord)> {
    let connected_at = checkpoint.authenticated_connection_time_unix_ms()?;
    for record in records {
        let key = record.public_key_bytes()?;
        if record.trusted_at(connected_at)
            && record.accepts_notarization_at(now_unix_ms)
            && checkpoint.verify_notary_key(&key).is_ok()
        {
            return Ok((key, record));
        }
    }
    bail!("no active or retiring notary can seal this capture")
}

pub fn key_id(public_key: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(public_key))
}

fn validate_record(record: &RegistryRecord) -> Result<()> {
    for (label, value) in [("name", &record.name), ("operator", &record.operator)] {
        if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
            bail!("registry notary {label} is invalid");
        }
    }
    record
        .endpoint()
        .context("registry key has an invalid endpoint")?;
    if record
        .valid_until_unix_ms
        .is_some_and(|until| until < record.valid_from_unix_ms)
    {
        bail!("registry key validity window is inverted");
    }
    if record
        .notarize_until_unix_ms
        .is_some_and(|until| until < record.valid_from_unix_ms)
    {
        bail!("registry key notarization window is inverted");
    }
    if record.status == NotaryKeyStatus::Retiring {
        let capture_until = record
            .valid_until_unix_ms
            .ok_or_else(|| anyhow::anyhow!("a retiring key requires a capture cutoff"))?;
        let notarize_until = record
            .notarize_until_unix_ms
            .ok_or_else(|| anyhow::anyhow!("a retiring key requires a notarization cutoff"))?;
        if notarize_until < capture_until {
            bail!("a retiring key cannot stop notarization before its capture cutoff");
        }
    }
    record.public_key_bytes()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_registry_uses_the_canonical_verification_key_field() {
        let document = serde_json::json!({
            "format": "ecp/registry/v1",
            "generation": 1,
            "active_key_id": "sha256:0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554",
            "notaries": [{
                "name": "Test Notary",
                "operator": "Exalto",
                "host": "notary.example.com",
                "port": 7047,
                "transport": "tcp",
                "key_id": "sha256:0f715baf5d4c2ed329785cef29e562f73488c8a2bb9dbc5700b361d54b9b0554",
                "verification_key": "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                "status": "active",
                "valid_from_unix_ms": 0,
                "valid_until_unix_ms": null,
                "notarize_until_unix_ms": null
            }]
        });
        let registry = parse_hosted_registry(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(
            registry.notaries[0].public_key,
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );

        let mut retired = document;
        let record = retired["notaries"][0].as_object_mut().unwrap();
        let key = record.remove("verification_key").unwrap();
        record.insert("public_key".to_owned(), key);
        assert!(parse_hosted_registry(&serde_json::to_vec(&retired).unwrap()).is_err());
    }

    fn record(seed: u8, status: NotaryKeyStatus) -> RegistryRecord {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = signing.verifying_key().to_sec1_bytes().to_vec();
        RegistryRecord {
            name: format!("Notary {seed}"),
            operator: "Test operator".to_owned(),
            host: format!("notary-{seed}.example"),
            port: 7047,
            transport: NotaryTransport::Tcp,
            key_id: key_id(&public),
            public_key: hex::encode(public),
            status,
            valid_from_unix_ms: 100,
            valid_until_unix_ms: None,
            notarize_until_unix_ms: None,
        }
    }

    #[test]
    fn validates_rotation_and_time_scoped_historical_trust() {
        let mut old = record(7, NotaryKeyStatus::Retired);
        old.valid_until_unix_ms = Some(199);
        let active = record(8, NotaryKeyStatus::Active);
        let registry = Registry {
            format: REGISTRY_FORMAT.into(),
            generation: 2,
            active_key_id: active.key_id.clone(),
            notaries: vec![old.clone(), active],
        };
        registry.validate().unwrap();
        assert!(registry.active_at(100).is_ok());
        assert!(registry.active_at(99).is_err());
        assert!(old.trusted_at(150));
        assert!(!old.trusted_at(200));
        assert!(!old.accepts_notarization_at(150));
    }

    #[test]
    fn retiring_key_separates_capture_and_notarization_cutoffs() {
        let active = record(8, NotaryKeyStatus::Active);
        let mut retiring = record(7, NotaryKeyStatus::Retiring);
        retiring.valid_until_unix_ms = Some(199);
        retiring.notarize_until_unix_ms = Some(299);
        let registry = Registry {
            format: REGISTRY_FORMAT.into(),
            generation: 3,
            active_key_id: active.key_id.clone(),
            notaries: vec![retiring.clone(), active],
        };
        registry.validate().unwrap();
        assert!(retiring.trusted_at(199));
        assert!(!retiring.trusted_at(200));
        assert!(retiring.accepts_notarization_at(250));
        assert!(!retiring.accepts_notarization_at(300));
    }

    #[test]
    fn rejects_revoked_or_missing_active_selection() {
        let revoked = record(7, NotaryKeyStatus::Revoked);
        let mut registry = Registry {
            format: REGISTRY_FORMAT.into(),
            generation: 2,
            active_key_id: revoked.key_id.clone(),
            notaries: vec![revoked],
        };
        assert!(registry.validate().is_err());
        registry.active_key_id = "sha256:missing".into();
        assert!(registry.validate().is_err());
    }

    #[test]
    fn rejects_retired_registry_formats() {
        let active = record(9, NotaryKeyStatus::Active);
        for format in [
            "llm-notary/notary-registry/v1",
            "llm-notary/notary-registry/v2",
        ] {
            let registry = Registry {
                format: format.to_owned(),
                generation: 2,
                active_key_id: active.key_id.clone(),
                notaries: vec![active.clone()],
            };
            assert!(parse_registry(&serde_json::to_vec(&registry).unwrap()).is_err());
        }
    }

    #[test]
    fn canonical_registry_preserves_a_tls_endpoint() {
        let mut active = record(9, NotaryKeyStatus::Active);
        active.host = "notary.capture.exalto.ai".to_owned();
        active.port = 443;
        active.transport = NotaryTransport::Tls;
        let registry = Registry {
            format: REGISTRY_FORMAT.to_owned(),
            generation: 3,
            active_key_id: active.key_id.clone(),
            notaries: vec![active],
        };
        let parsed = parse_registry(&serde_json::to_vec(&registry).unwrap()).unwrap();
        assert_eq!(
            parsed.notaries[0].endpoint().unwrap().to_string(),
            "tls://notary.capture.exalto.ai:443"
        );
    }

    #[test]
    fn endpoint_overrides_require_an_explicit_supported_transport() {
        let tls = "tls://notary.capture.exalto.ai:443"
            .parse::<NotaryEndpoint>()
            .unwrap();
        assert_eq!(tls.transport, NotaryTransport::Tls);
        assert_eq!(tls.host, "notary.capture.exalto.ai");
        let tcp = "tcp://127.0.0.1:7047".parse::<NotaryEndpoint>().unwrap();
        assert_eq!(tcp.transport, NotaryTransport::Tcp);
        assert!("127.0.0.1:7047".parse::<NotaryEndpoint>().is_err());
        assert!(
            "https://notary.example:443"
                .parse::<NotaryEndpoint>()
                .is_err()
        );
    }
}
