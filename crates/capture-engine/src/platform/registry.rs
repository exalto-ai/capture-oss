use std::{
    collections::BTreeMap,
    fs,
    fs::OpenOptions,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use k256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use capture_core::{
    CaptureCheckpoint,
    registry::{
        NotaryEndpoint, NotaryKeyStatus, REGISTRY_FORMAT, Registry, RegistryRecord, key_id,
    },
};

use super::{api_origin::ApiOrigin, http_client_builder, storage};
use crate::metadata::RegistrySnapshot;

pub use capture_core::registry::parse_registry;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryStore {
    format: String,
    generation: u64,
    registry_sha256: Option<String>,
    registry_source: Option<String>,
    active_key_id: Option<String>,
    records: Vec<RegistryRecord>,
}

#[derive(Clone, Debug)]
pub struct PinnedRegistryState {
    pub registry_source: Option<String>,
    pub generation: u64,
    pub active_key_id: String,
    pub records: Vec<RegistryRecord>,
}

impl From<RegistrySnapshot> for PinnedRegistryState {
    fn from(value: RegistrySnapshot) -> Self {
        Self {
            registry_source: Some(value.registry_source),
            generation: value.generation,
            active_key_id: value.active_key_id,
            records: value.records,
        }
    }
}

pub fn pin(registry: Registry, registry_source: &str) -> Result<()> {
    let path = registry_store_path()?;
    pin_at_path(&path, registry, registry_source)
}

fn pin_at_path(path: &Path, registry: Registry, registry_source: &str) -> Result<()> {
    registry.validate()?;
    let parent = path.parent().expect("registry store has a parent");
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    let lock_path = path.with_extension("json.lock");
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open {}", lock_path.display()))?;
    lock.lock()
        .with_context(|| format!("lock {}", lock_path.display()))?;
    // The read must happen after acquiring the cross-process lock. Otherwise a
    // slower process could overwrite a newer generation or cached revocation.
    let mut store = merge_store(load_store(path)?, registry)?;
    store.registry_source = Some(registry_source.to_owned());
    validate_registry_store(&store)?;
    write_store(path, &store)
}

fn merge_store(mut store: RegistryStore, registry: Registry) -> Result<RegistryStore> {
    let registry_sha256 = capture_core::sha256_hex(
        &serde_json::to_vec(&registry).context("encode notary registry revision")?,
    );
    if registry.generation < store.generation {
        bail!(
            "notary registry generation {} is older than cached generation {}",
            registry.generation,
            store.generation
        );
    }
    if registry.generation == store.generation
        && store
            .registry_sha256
            .as_ref()
            .is_some_and(|cached| cached != &registry_sha256)
    {
        bail!(
            "notary registry generation {} conflicts with the cached revision",
            registry.generation
        );
    }
    let mut records = store
        .records
        .drain(..)
        .map(|record| (record.key_id.clone(), record))
        .collect::<BTreeMap<_, _>>();

    // A planned removal becomes historical registry entry. Compromise revocation must
    // be explicit in a registry response before the record is removed.
    for record in records.values_mut() {
        if matches!(
            record.status,
            NotaryKeyStatus::Active | NotaryKeyStatus::Retiring
        ) {
            record.status = NotaryKeyStatus::Retired;
        }
    }
    for record in registry.notaries {
        if records
            .get(&record.key_id)
            .is_some_and(|cached| cached.status == NotaryKeyStatus::Revoked)
            && record.status != NotaryKeyStatus::Revoked
        {
            continue;
        }
        records.insert(record.key_id.clone(), record);
    }
    store.format = REGISTRY_FORMAT.to_owned();
    store.generation = registry.generation;
    store.registry_sha256 = Some(registry_sha256);
    store.active_key_id = Some(registry.active_key_id);
    store.records = records.into_values().collect();
    Ok(store)
}

pub fn merge_registry_snapshot(
    current: Option<RegistrySnapshot>,
    registry: Registry,
    registry_source: &str,
) -> Result<RegistrySnapshot> {
    let source_url =
        url::Url::parse(registry_source).context("notary registry source is invalid")?;
    if registry_source.len() > 2048
        || !matches!(source_url.scheme(), "http" | "https")
        || !source_url.username().is_empty()
        || source_url.password().is_some()
        || source_url.path() != "/api/registry"
        || source_url.query().is_some()
        || source_url.fragment().is_some()
    {
        bail!("notary registry source is not a public registry URL");
    }
    if current
        .as_ref()
        .is_some_and(|current| current.registry_source != registry_source)
    {
        bail!("notary registry source differs from the pinned server authority");
    }
    let store = current.map_or_else(RegistryStore::default, |current| RegistryStore {
        format: REGISTRY_FORMAT.to_owned(),
        generation: current.generation,
        registry_sha256: Some(current.registry_sha256),
        registry_source: Some(current.registry_source),
        active_key_id: Some(current.active_key_id),
        records: current.records,
    });
    let mut store = merge_store(store, registry)?;
    store.registry_source = Some(registry_source.to_owned());
    validate_registry_store(&store)?;
    Ok(shared_from_store(store))
}

pub fn validate_registry_snapshot(snapshot: &RegistrySnapshot) -> Result<()> {
    validate_registry_store(&RegistryStore {
        format: REGISTRY_FORMAT.to_owned(),
        generation: snapshot.generation,
        registry_sha256: Some(snapshot.registry_sha256.clone()),
        registry_source: Some(snapshot.registry_source.clone()),
        active_key_id: Some(snapshot.active_key_id.clone()),
        records: snapshot.records.clone(),
    })
}

pub fn registry_key_at(
    snapshot: &RegistrySnapshot,
    public_key: &[u8],
    authenticated_unix_ms: u64,
) -> Result<(String, String)> {
    validate_registry_snapshot(snapshot)?;
    let requested_id = key_id(public_key);
    let record = snapshot
        .records
        .iter()
        .find(|record| {
            record
                .public_key
                .eq_ignore_ascii_case(&hex::encode(public_key))
        })
        .ok_or_else(|| anyhow!("notary key {requested_id} is not present in shared registry"))?;
    if !record.trusted_at(authenticated_unix_ms) {
        bail!(
            "notary key {} was not trusted at the authenticated connection time",
            record.key_id
        );
    }
    Ok((record.key_id.clone(), "registry".to_owned()))
}

pub fn registry_record_for_checkpoint(
    snapshot: &RegistrySnapshot,
    checkpoint: &CaptureCheckpoint,
) -> Result<(Vec<u8>, RegistryRecord)> {
    validate_registry_snapshot(snapshot)?;
    let connection_time = checkpoint.authenticated_connection_time_unix_ms()?;
    let now = unix_time_ms()?;
    for record in &snapshot.records {
        let key = record.public_key_bytes()?;
        if record.trusted_at(connection_time)
            && record.accepts_notarization_at(now)
            && checkpoint.verify_notary_key(&key).is_ok()
        {
            return Ok((key, record.clone()));
        }
    }
    bail!("no shared active or retiring notary can notarize this checkpoint")
}

fn shared_from_store(store: RegistryStore) -> RegistrySnapshot {
    RegistrySnapshot {
        generation: store.generation,
        registry_sha256: store
            .registry_sha256
            .expect("validated registry state has a digest"),
        registry_source: store
            .registry_source
            .expect("validated registry state has a source"),
        active_key_id: store
            .active_key_id
            .expect("validated registry state has an active key"),
        records: store.records,
    }
}

pub fn cached_registry_key_at(
    public_key: &[u8],
    authenticated_unix_ms: u64,
) -> Result<(String, String)> {
    let requested_id = key_id(public_key);
    let store = validated_store()?;
    let record = store
        .records
        .iter()
        .find(|record| {
            record
                .public_key
                .eq_ignore_ascii_case(&hex::encode(public_key))
        })
        .ok_or_else(|| {
            anyhow!(
                "notary key {requested_id} is not present in the local registry store; configure notary.public_key with an explicit endpoint for a self-hosted notary"
            )
        })?;
    if !record.trusted_at(authenticated_unix_ms) {
        bail!(
            "notary key {} was not trusted at the authenticated connection time",
            record.key_id
        );
    }
    Ok((record.key_id.clone(), "registry".to_owned()))
}

pub fn cached_registry_record_for_checkpoint(
    checkpoint: &CaptureCheckpoint,
) -> Result<(Vec<u8>, RegistryRecord)> {
    let connection_time = checkpoint.authenticated_connection_time_unix_ms()?;
    let now = unix_time_ms()?;
    for record in validated_store()?.records {
        let key = record.public_key_bytes()?;
        if record.trusted_at(connection_time)
            && record.accepts_notarization_at(now)
            && checkpoint.verify_notary_key(&key).is_ok()
        {
            return Ok((key, record));
        }
    }
    bail!(
        "no cached active or retiring notary can notarize this checkpoint; refresh the registry or configure notary.endpoint and notary.public_key together"
    )
}

/// Returns the records of the locally pinned Registry.
pub fn cached_registry_records() -> Result<Vec<RegistryRecord>> {
    Ok(validated_store()?.records)
}

/// Finds the Registry key that signed a witness receipt and was trusted when
/// the notary opened the provider connection.
pub fn witness_key_from_records(
    records: &[RegistryRecord],
    exchange: &capture_core::witness::WitnessedExchange,
) -> Result<Vec<u8>> {
    let connected_at = exchange.receipt().connected_at_unix_ms();
    for record in records {
        let key = record.public_key_bytes()?;
        if record.trusted_at(connected_at) && exchange.verify(&key).is_ok() {
            return Ok(key);
        }
    }
    bail!("no trusted notary key signed this witness receipt")
}

pub fn explicit_key(value: &str) -> Result<(Vec<u8>, String)> {
    let key = hex::decode(value).context("trusted notary key must be hexadecimal")?;
    VerifyingKey::from_sec1_bytes(&key)
        .context("trusted notary key must be a SEC1 secp256k1 key")?;
    Ok((key.clone(), key_id(&key)))
}

pub fn pinned_state() -> Result<Option<PinnedRegistryState>> {
    let path = registry_store_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let store = load_store(&path)?;
    validate_registry_store(&store)?;
    Ok(Some(PinnedRegistryState {
        registry_source: store.registry_source,
        generation: store.generation,
        active_key_id: store
            .active_key_id
            .expect("validated registry store has an active key"),
        records: store.records,
    }))
}

fn validated_store() -> Result<RegistryStore> {
    let store = load_store(&registry_store_path()?)?;
    validate_registry_store(&store)?;
    Ok(store)
}

fn validate_registry_store(store: &RegistryStore) -> Result<()> {
    if store.format != REGISTRY_FORMAT {
        bail!("unsupported local notary registry store format");
    }
    if store.records.is_empty() || store.records.len() > 4096 {
        bail!("local notary registry store must contain between 1 and 4096 historical records");
    }
    if let Some(source) = &store.registry_source {
        let source_url =
            url::Url::parse(source).context("cached notary registry source is invalid")?;
        if source.len() > 2048
            || !matches!(source_url.scheme(), "http" | "https")
            || !source_url.username().is_empty()
            || source_url.password().is_some()
            || source_url.path() != "/api/registry"
            || source_url.query().is_some()
            || source_url.fragment().is_some()
        {
            bail!("cached notary registry source is not a public registry URL");
        }
    }
    let active_key_id = store
        .active_key_id
        .as_deref()
        .ok_or_else(|| anyhow!("local notary registry store has no active key"))?;
    let mut ids = std::collections::BTreeSet::new();
    for record in &store.records {
        record.public_key_bytes()?;
        if record
            .valid_until_unix_ms
            .is_some_and(|until| until < record.valid_from_unix_ms)
            || record
                .notarize_until_unix_ms
                .is_some_and(|until| until < record.valid_from_unix_ms)
        {
            bail!("cached notary key has an inverted lifecycle window");
        }
        if !ids.insert(record.key_id.as_str()) {
            bail!("local notary registry store contains a duplicate key ID");
        }
    }
    let active = store
        .records
        .iter()
        .find(|record| record.key_id == active_key_id)
        .ok_or_else(|| anyhow!("local notary registry store is missing its active key"))?;
    if active.status != NotaryKeyStatus::Active {
        bail!("local notary registry store selected a non-active key");
    }
    Ok(())
}

fn registry_store_path() -> Result<PathBuf> {
    storage::config_file("registry.json")
}

fn load_store(path: &Path) -> Result<RegistryStore> {
    if !path.exists() {
        return Ok(RegistryStore::default());
    }
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse local notary registry store")?;
    match value.get("format").and_then(serde_json::Value::as_str) {
        Some(REGISTRY_FORMAT) => {
            serde_json::from_value(value).context("parse v3 local notary registry store")
        }
        Some(format) => bail!(
            "unsupported local notary registry store format: {format}; remove the cache and refresh the notary registry"
        ),
        None => bail!(
            "local notary registry store format is missing; remove the cache and refresh the notary registry"
        ),
    }
}

fn write_store(path: &Path, store: &RegistryStore) -> Result<()> {
    storage::write_private_file_atomically(path, &serde_json::to_vec_pretty(store)?)
}

fn unix_time_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")
}

pub async fn discover_notary() -> Result<NotaryEndpoint> {
    let registry = refresh_registry().await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")?;
    resolve_notary(registry.active_at(now)?).await
}

pub async fn refresh_registry() -> Result<Registry> {
    refresh_registry_from(&super::auth::configured_api_origin()?).await
}

pub async fn refresh_registry_from(api_origin: &ApiOrigin) -> Result<Registry> {
    let (registry, registry_source_url) = fetch_registry_from(api_origin).await?;
    pin(registry.clone(), registry_source_url.as_str())?;
    tracing::info!(
        key_id = %registry.active_key_id,
        key_count = registry.notaries.len(),
        "pinned trusted notary registry"
    );
    Ok(registry)
}

pub async fn fetch_registry_from(api_origin: &ApiOrigin) -> Result<(Registry, url::Url)> {
    let registry_source_url = registry_url(api_origin);
    let bytes = http_client_builder()
        .build()?
        .get(registry_source_url.clone())
        .send()
        .await
        .with_context(|| format!("fetching notary endpoint from {registry_source_url}"))?
        .error_for_status()
        .with_context(|| format!("fetching notary endpoint from {registry_source_url}"))?
        .bytes()
        .await
        .context("reading notary registry from Notary API")?;
    let registry = parse_hosted_registry(&bytes)?;
    Ok((registry, registry_source_url))
}

fn parse_hosted_registry(bytes: &[u8]) -> Result<Registry> {
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

fn registry_url(api_origin: &ApiOrigin) -> url::Url {
    api_origin.api_url("/api/registry")
}

pub async fn resolve_notary(record: &RegistryRecord) -> Result<NotaryEndpoint> {
    record.endpoint()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use capture_core::registry::NotaryTransport;

    use super::*;

    fn record(seed: u8, status: NotaryKeyStatus) -> RegistryRecord {
        let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
        let public = signing.verifying_key().to_sec1_bytes().to_vec();
        RegistryRecord {
            name: format!("Notary {seed}"),
            operator: "Test operator".to_owned(),
            host: "notary.example".into(),
            port: 7047,
            transport: NotaryTransport::Tcp,
            key_id: key_id(&public),
            public_key: hex::encode(public),
            status,
            valid_from_unix_ms: 0,
            valid_until_unix_ms: None,
            notarize_until_unix_ms: None,
        }
    }

    #[test]
    fn merge_preserves_missing_keys_as_retired_and_applies_revocation() {
        let old = record(7, NotaryKeyStatus::Active);
        let new = record(8, NotaryKeyStatus::Active);
        let store = RegistryStore {
            format: REGISTRY_FORMAT.into(),
            generation: 1,
            registry_sha256: None,
            registry_source: None,
            active_key_id: Some(old.key_id.clone()),
            records: vec![old.clone()],
        };
        let updated = merge_store(
            store,
            Registry {
                format: REGISTRY_FORMAT.into(),
                generation: 2,
                active_key_id: new.key_id.clone(),
                notaries: vec![new],
            },
        )
        .unwrap();
        assert_eq!(
            updated
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Retired
        );

        let mut revoked = old;
        revoked.status = NotaryKeyStatus::Revoked;
        let replaced = merge_store(
            updated,
            Registry {
                format: REGISTRY_FORMAT.into(),
                generation: 3,
                active_key_id: record(8, NotaryKeyStatus::Active).key_id,
                notaries: vec![record(8, NotaryKeyStatus::Active), revoked.clone()],
            },
        )
        .unwrap();
        assert!(
            !replaced
                .records
                .iter()
                .find(|record| record.key_id == revoked.key_id)
                .unwrap()
                .trusted_at(1)
        );

        let attempted_restore = merge_store(
            replaced,
            Registry {
                format: REGISTRY_FORMAT.into(),
                generation: 4,
                active_key_id: record(8, NotaryKeyStatus::Active).key_id,
                notaries: vec![
                    record(8, NotaryKeyStatus::Active),
                    record(7, NotaryKeyStatus::Retired),
                ],
            },
        )
        .unwrap();
        assert_eq!(
            attempted_restore
                .records
                .iter()
                .find(|record| record.key_id == revoked.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Revoked
        );
    }

    #[test]
    fn write_store_atomically_replaces_an_existing_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("registry.json");
        fs::write(&path, b"old registry").unwrap();
        let active = record(8, NotaryKeyStatus::Active);
        let store = RegistryStore {
            format: REGISTRY_FORMAT.into(),
            generation: 2,
            registry_sha256: Some("registry-sha".into()),
            registry_source: Some("https://example.test/api/registry".into()),
            active_key_id: Some(active.key_id.clone()),
            records: vec![active],
        };

        write_store(&path, &store).unwrap();

        let loaded = load_store(&path).unwrap();
        assert_eq!(loaded.generation, 2);
        assert_eq!(loaded.registry_sha256.as_deref(), Some("registry-sha"));
        assert_eq!(
            loaded.registry_source.as_deref(),
            Some("https://example.test/api/registry")
        );
    }

    #[test]
    fn trust_store_rejects_a_non_public_registry_source() {
        let active = record(8, NotaryKeyStatus::Active);
        let mut store = RegistryStore {
            format: REGISTRY_FORMAT.into(),
            generation: 2,
            registry_sha256: Some("registry-sha".into()),
            registry_source: Some("https://user:secret@example.test/api/registry".into()),
            active_key_id: Some(active.key_id.clone()),
            records: vec![active],
        };
        assert!(validate_registry_store(&store).is_err());
        store.registry_source = Some("/Users/example/private/notary.json".into());
        assert!(validate_registry_store(&store).is_err());
    }

    #[test]
    fn rejects_registry_rollback_and_conflicting_same_generation() {
        let active = record(8, NotaryKeyStatus::Active);
        let initial = merge_store(
            RegistryStore::default(),
            Registry {
                format: REGISTRY_FORMAT.into(),
                generation: 10,
                active_key_id: active.key_id.clone(),
                notaries: vec![active.clone()],
            },
        )
        .unwrap();
        assert!(
            merge_store(
                initial.clone(),
                Registry {
                    format: REGISTRY_FORMAT.into(),
                    generation: 9,
                    active_key_id: active.key_id.clone(),
                    notaries: vec![active.clone()],
                }
            )
            .is_err()
        );
        let mut conflicting = active.clone();
        conflicting.host = "rollback.example".into();
        assert!(
            merge_store(
                initial,
                Registry {
                    format: REGISTRY_FORMAT.into(),
                    generation: 10,
                    active_key_id: conflicting.key_id.clone(),
                    notaries: vec![conflicting],
                }
            )
            .is_err()
        );
    }

    #[test]
    fn historical_cache_can_retain_more_than_the_live_registry_limit() {
        let active = record(1, NotaryKeyStatus::Active);
        let mut store = merge_store(
            RegistryStore::default(),
            Registry {
                format: REGISTRY_FORMAT.into(),
                generation: 1,
                active_key_id: active.key_id.clone(),
                notaries: vec![active],
            },
        )
        .unwrap();
        for generation in 2u64..=40 {
            let next = record(generation as u8, NotaryKeyStatus::Active);
            store = merge_store(
                store,
                Registry {
                    format: REGISTRY_FORMAT.into(),
                    generation,
                    active_key_id: next.key_id.clone(),
                    notaries: vec![next],
                },
            )
            .unwrap();
        }
        assert_eq!(store.records.len(), 40);
        validate_registry_store(&store).unwrap();
    }

    #[test]
    fn concurrent_pins_cannot_overwrite_a_newer_generation() {
        let root = std::env::temp_dir().join(format!(
            "notary-registry-lock-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("registry.json");
        let older = record(7, NotaryKeyStatus::Active);
        let newer = record(8, NotaryKeyStatus::Active);
        let barrier = Arc::new(Barrier::new(3));
        let spawn_pin =
            |generation: u64, active: RegistryRecord, barrier: Arc<Barrier>, path: PathBuf| {
                std::thread::spawn(move || {
                    barrier.wait();
                    pin_at_path(
                        &path,
                        Registry {
                            format: REGISTRY_FORMAT.into(),
                            generation,
                            active_key_id: active.key_id.clone(),
                            notaries: vec![active],
                        },
                        "https://example.test/api/registry",
                    )
                })
            };
        let old_thread = spawn_pin(1, older, Arc::clone(&barrier), path.clone());
        let new_key_id = newer.key_id.clone();
        let new_thread = spawn_pin(2, newer, Arc::clone(&barrier), path.clone());
        barrier.wait();
        let old_result = old_thread.join().unwrap();
        let new_result = new_thread.join().unwrap();
        assert!(new_result.is_ok());
        let _ = old_result;

        let store = load_store(&path).unwrap();
        assert_eq!(store.generation, 2);
        assert_eq!(store.active_key_id.as_deref(), Some(new_key_id.as_str()));
        validate_registry_store(&store).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_store_rejects_legacy_cache_formats() {
        let path = std::env::temp_dir().join(format!(
            "notary-legacy-registry-{}-{}.json",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        for format in [
            "llm-notary/notary-directory/v1",
            "llm-notary/notary-directory/v2",
        ] {
            std::fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({ "format": format })).unwrap(),
            )
            .unwrap();
            assert!(load_store(&path).is_err());
        }
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn registry_discovery_stays_on_the_configured_api_origin() {
        assert_eq!(
            registry_url(&ApiOrigin::parse("https://self-hosted.example").unwrap()).as_str(),
            "https://self-hosted.example/api/registry"
        );
        assert!(ApiOrigin::parse("file:///tmp/notary").is_err());
    }

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
}
