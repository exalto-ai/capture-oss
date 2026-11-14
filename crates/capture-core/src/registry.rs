//! The Registry: where new captures go, and which notary keys to trust.

use std::{fmt, str::FromStr};

use anyhow::{Context, Result, bail};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

use crate::sha256_hex;

/// The transport used for the public local-proxy-to-notary connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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

/// A hostname-preserving notary endpoint, written `tls://host:port` or
/// `tcp://host:port`.
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
        if host.is_empty() || host.chars().any(char::is_whitespace) || port == 0 {
            bail!("notary endpoint is invalid");
        }
        Ok(Self {
            host,
            port,
            transport,
        })
    }
}

impl fmt::Display for NotaryEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = self.transport.scheme();
        if self.host.contains(':') {
            write!(formatter, "{scheme}://[{}]:{}", self.host, self.port)
        } else {
            write!(formatter, "{scheme}://{}:{}", self.host, self.port)
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

impl Serialize for NotaryEndpoint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for NotaryEndpoint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(|error| D::Error::custom(format!("{error:#}")))
    }
}

/// Where new captures go, and every notary whose key is trusted. A key is
/// trusted exactly while it is listed: evidence verifies when a listed key
/// signed it, and removing a key stops everything it signed from verifying.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Registry {
    /// Where new sessions connect.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "tls://notary.capture.exalto.ai:443"))]
    pub capture_endpoint: NotaryEndpoint,
    pub notaries: Vec<RegistryNotary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RegistryNotary {
    /// A label for the notary, shown beside evidence its key signed.
    pub name: String,
    /// The notary's compressed SEC1 secp256k1 public key, in hexadecimal.
    /// Its receipts are signed with the matching private key.
    #[serde(with = "hex_key")]
    #[cfg_attr(feature = "openapi", schema(value_type = String))]
    pub public_key: Vec<u8>,
    /// Where a capture whose receipt this key signed is sealed. A notary
    /// without one can no longer seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>))]
    pub seal_endpoint: Option<NotaryEndpoint>,
}

impl RegistryNotary {
    pub fn key_id(&self) -> String {
        key_id(&self.public_key)
    }
}

impl Registry {
    /// The Registry of a notary you run: it captures and seals at `endpoint`,
    /// and `key` is the only key trusted.
    pub fn single(endpoint: NotaryEndpoint, key: Vec<u8>) -> Self {
        Self {
            capture_endpoint: endpoint.clone(),
            notaries: vec![RegistryNotary {
                name: "Configured notary".to_owned(),
                public_key: key,
                seal_endpoint: Some(endpoint),
            }],
        }
    }

    /// The listed notary whose public key is `key`.
    pub fn notary(&self, key: &[u8]) -> Option<&RegistryNotary> {
        self.notaries.iter().find(|notary| notary.public_key == key)
    }

    /// The listed key for which `signed` succeeds.
    pub fn signing_key(&self, signed: impl Fn(&[u8]) -> Result<()>) -> Result<Vec<u8>> {
        self.notaries
            .iter()
            .find(|notary| signed(&notary.public_key).is_ok())
            .map(|notary| notary.public_key.clone())
            .context("no trusted notary key in the Registry signed it")
    }

    /// The listed key that signed a witness receipt.
    pub fn witness_key(&self, exchange: &crate::witness::WitnessedExchange) -> Result<Vec<u8>> {
        self.signing_key(|key| exchange.verify(key))
            .context("no trusted notary key signed this witness receipt")
    }

    /// The listed key that signed a capture checkpoint's receipt.
    pub fn capture_key(&self, checkpoint: &crate::CaptureCheckpoint) -> Result<Vec<u8>> {
        self.signing_key(|key| checkpoint.verify_notary_key(key))
            .context("no trusted notary key signed this capture receipt")
    }

    /// The key that signed `checkpoint`'s receipt and the endpoint that seals
    /// it.
    pub fn sealing_notary(
        &self,
        checkpoint: &crate::CaptureCheckpoint,
    ) -> Result<(Vec<u8>, NotaryEndpoint)> {
        let key = self.capture_key(checkpoint)?;
        let endpoint = self
            .notary(&key)
            .and_then(|notary| notary.seal_endpoint.clone())
            .context("the notary that captured this no longer seals")?;
        Ok((key, endpoint))
    }
}

/// Parses and checks a Registry document.
pub fn parse_registry(bytes: &[u8]) -> Result<Registry> {
    let registry: Registry = serde_json::from_slice(bytes).context("decoding the Registry")?;
    if registry.notaries.is_empty() {
        bail!("the Registry lists no notaries");
    }
    Ok(registry)
}

/// `sha256:` followed by the SHA-256 of the compressed SEC1 public key.
pub fn key_id(public_key: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(public_key))
}

mod hex_key {
    use super::*;

    pub(super) fn serialize<S: Serializer>(key: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(key))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let key = hex::decode(String::deserialize(deserializer)?)
            .map_err(|_| D::Error::custom("a notary key is not hexadecimal"))?;
        VerifyingKey::from_sec1_bytes(&key)
            .map_err(|_| D::Error::custom("a notary key is not a SEC1 secp256k1 key"))?;
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> String {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        hex::encode(signing.verifying_key().to_sec1_bytes())
    }

    #[test]
    fn parses_a_registry_document() {
        let document = serde_json::json!({
            "capture_endpoint": "tls://notary.capture.exalto.ai:443",
            "notaries": [
                { "name": "seal2", "public_key": key(2), "seal_endpoint": "tls://notary.capture.exalto.ai:443" },
                { "name": "seal1", "public_key": key(1) },
            ],
        });
        let registry = parse_registry(&serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(
            registry.capture_endpoint.to_string(),
            "tls://notary.capture.exalto.ai:443"
        );
        assert_eq!(registry.notaries[1].seal_endpoint, None);
        assert_eq!(serde_json::to_value(&registry).unwrap(), document);
    }

    #[test]
    fn refuses_an_empty_registry_and_malformed_keys() {
        for notaries in [
            serde_json::json!([]),
            serde_json::json!([{ "name": "seal1", "public_key": "zz" }]),
            serde_json::json!([{ "name": "seal1", "public_key": "02ab" }]),
        ] {
            let document = serde_json::json!({
                "capture_endpoint": "tls://notary.capture.exalto.ai:443",
                "notaries": notaries,
            });
            assert!(parse_registry(&serde_json::to_vec(&document).unwrap()).is_err());
        }
    }

    #[test]
    fn endpoints_require_an_explicit_supported_transport() {
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
