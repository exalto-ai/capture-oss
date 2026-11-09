use std::process::Command;

use capture::client::{
    CaptureMode, CapturedClient, NotaryReadiness, NotaryTrust, NotaryTrustRecord, Status,
};
use serde::Serialize;
use url::{Host, Url};

const ADMIN_ADDRESS: &str = "127.0.0.1:8788";
const OFFICIAL_EXALTO_REGISTRY_SOURCES: [&str; 1] = ["https://api.capture.exalto.ai/api/registry"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum SealingServiceKind {
    Exalto,
    Registry,
    Configured,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct SealingServiceIdentity {
    pub(super) name: String,
    pub(super) kind: SealingServiceKind,
}

fn official_exalto_registry(source: Option<&str>) -> bool {
    let Some(source) = source.and_then(|value| Url::parse(value).ok()) else {
        return false;
    };
    OFFICIAL_EXALTO_REGISTRY_SOURCES
        .iter()
        .any(|candidate| Url::parse(candidate).is_ok_and(|official| source == official))
}

fn safe_registry_name(record: &NotaryTrustRecord) -> Option<String> {
    let name = record.name.trim();
    (!name.is_empty() && name.len() <= 96 && !name.chars().any(char::is_control))
        .then(|| name.to_owned())
}

fn resolve_sealing_service(trust: &NotaryTrust) -> Option<SealingServiceIdentity> {
    let active = match trust.active_key_id.as_deref() {
        Some(active_key_id) => trust
            .notaries
            .iter()
            .find(|record| record.key_id == active_key_id)?,
        None => trust.notaries.first()?,
    };

    match trust.source.as_str() {
        "registry" if official_exalto_registry(trust.registry_source.as_deref()) => {
            Some(SealingServiceIdentity {
                name: "Exalto’s notary".into(),
                kind: SealingServiceKind::Exalto,
            })
        }
        "registry" => Some(SealingServiceIdentity {
            name: safe_registry_name(active).unwrap_or_else(|| "Registry sealing service".into()),
            kind: SealingServiceKind::Registry,
        }),
        "explicit_configuration" => Some(SealingServiceIdentity {
            name: "Configured sealing service".into(),
            kind: SealingServiceKind::Configured,
        }),
        _ => None,
    }
}

fn client() -> Result<CapturedClient, String> {
    CapturedClient::connect_loopback(
        ADMIN_ADDRESS
            .parse()
            .expect("the bundled admin address is valid"),
    )
    .map_err(|error| error.to_string())
}

pub(super) async fn read_admin_status() -> Result<Status, String> {
    client()?.status().await.map_err(|error| error.to_string())
}

pub(super) async fn read_sealing_service() -> Result<Option<SealingServiceIdentity>, String> {
    client()?
        .notary_trust()
        .await
        .map(|trust| resolve_sealing_service(&trust))
        .map_err(|error| error.to_string())
}

pub(super) async fn read_sealing_service_readiness(
    refresh: bool,
) -> Result<NotaryReadiness, String> {
    client()?
        .notary_readiness(refresh)
        .await
        .map_err(|error| error.to_string())
}

pub(super) fn validate_account_link(value: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| "The account link is not a valid URL.".to_string())?;
    let secure = url.scheme() == "https";
    let loopback_http = url.scheme() == "http"
        && url.host().is_some_and(|host| match host {
            Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
            Host::Ipv4(address) => address.is_loopback(),
            Host::Ipv6(address) => address.is_loopback(),
        });
    let valid_authorization_query = |query: &str| {
        let mut request_id = false;
        let mut approval_secret = false;
        for pair in query.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                return false;
            };
            if value.is_empty()
                || value
                    .bytes()
                    .any(|byte| byte.is_ascii_control() || byte == b'#')
            {
                return false;
            }
            match key {
                "request_id" if !request_id => request_id = true,
                "approval_secret" if !approval_secret => approval_secret = true,
                _ => return false,
            }
        }
        request_id && approval_secret
    };
    let clean_authorization = url.path() == "/authorize"
        && url.fragment().is_none()
        && url.query().is_some_and(valid_authorization_query);
    let clean_route = url.fragment().is_none()
        && url.query().is_none()
        && matches!(
            url.path(),
            "/app" | "/app/" | "/app/overview" | "/app/traces" | "/app/usage" | "/app/settings"
        );
    let allowed_route = clean_route || clean_authorization;
    if (!secure && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !allowed_route
    {
        return Err(
            "The account link was rejected because it is not a trusted hosted route.".into(),
        );
    }
    Ok(url)
}

#[tauri::command]
pub(super) fn open_account_link(url: String) -> Result<(), String> {
    let url = validate_account_link(&url)?;
    open_external_url(url.as_str(), "account page")
}

pub(super) fn open_external_url(url: &str, label: &str) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    let result = Command::new("open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let result = Command::new("explorer.exe").arg(url).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let result = Command::new("xdg-open").arg(url).spawn();
    result
        .map(|_| ())
        .map_err(|error| format!("Could not open the {label}: {error}"))
}

pub(super) async fn write_capture_mode(mode: CaptureMode) -> Result<CaptureMode, String> {
    client()?
        .set_capture_mode(mode)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub(super) async fn set_capture_mode(
    mode: CaptureMode,
    app: tauri::AppHandle,
) -> Result<CaptureMode, String> {
    let mode = write_capture_mode(mode).await?;
    crate::tray::publish_capture_mode(&app, mode);
    Ok(mode)
}

pub(super) async fn daemon_is_healthy() -> bool {
    let Ok(client) = client() else {
        return false;
    };
    client.verify_version().await.is_ok()
}

#[cfg(test)]
mod tests {
    use capture::client::{NotaryTrust, NotaryTrustRecord};

    use super::{SealingServiceIdentity, SealingServiceKind, resolve_sealing_service};

    fn trust(
        source: &str,
        registry_source: Option<&str>,
        active_key_id: Option<&str>,
        records: &[(&str, &str)],
    ) -> NotaryTrust {
        NotaryTrust {
            source: source.into(),
            registry_source: registry_source.map(str::to_owned),
            active_key_id: active_key_id.map(str::to_owned),
            notaries: records
                .iter()
                .map(|(name, key_id)| NotaryTrustRecord {
                    name: (*name).into(),
                    key_id: (*key_id).into(),
                })
                .collect(),
        }
    }

    #[test]
    fn sealing_service_brand_requires_an_exact_official_registry() {
        let official = trust(
            "registry",
            Some("https://api.capture.exalto.ai/api/registry"),
            Some("key-1"),
            &[("Legacy hosted name", "key-1")],
        );
        assert_eq!(
            resolve_sealing_service(&official),
            Some(SealingServiceIdentity {
                name: "Exalto’s notary".into(),
                kind: SealingServiceKind::Exalto,
            })
        );

        for source in [
            "https://seal.example/api/registry",
            "https://api.capture.exalto.ai.evil.example/api/registry",
            "https://api.capture.exalto.ai/api/registry?mirror=1",
        ] {
            let third_party = trust(
                "registry",
                Some(source),
                Some("key-1"),
                &[("Northstar Seal", "key-1")],
            );
            assert_eq!(
                resolve_sealing_service(&third_party),
                Some(SealingServiceIdentity {
                    name: "Northstar Seal".into(),
                    kind: SealingServiceKind::Registry,
                })
            );
        }
    }

    #[test]
    fn sealing_service_identity_is_neutral_for_explicit_or_unusable_trust() {
        let explicit = trust(
            "explicit_configuration",
            None,
            None,
            &[("Configured notary", "key-1")],
        );
        assert_eq!(
            resolve_sealing_service(&explicit),
            Some(SealingServiceIdentity {
                name: "Configured sealing service".into(),
                kind: SealingServiceKind::Configured,
            })
        );
        assert_eq!(
            resolve_sealing_service(&trust("registry", None, None, &[])),
            None
        );
        assert_eq!(
            resolve_sealing_service(&trust(
                "registry",
                Some("https://seal.example/api/registry"),
                Some("missing"),
                &[("Northstar Seal", "key-1")],
            )),
            None
        );
    }
}
