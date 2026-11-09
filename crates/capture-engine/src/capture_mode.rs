//! A host's durable capture mode and the trusted notary either capture mode
//! needs.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use capture_core::registry::NotaryEndpoint;
use tokio::sync::{Mutex, RwLock};

use crate::{metadata::CaptureMode, metadata_store::MetadataStore, proxy::CaptureModeSource};

/// Finds the trusted notary a host captures and seals with: a configured
/// endpoint, or one discovered through the notary Registry.
#[async_trait]
pub trait NotaryDiscovery: Send + Sync {
    async fn discover(&self) -> Result<NotaryEndpoint>;
}

/// The durable capture mode and the notary state it needs.
pub struct CaptureSetting {
    mode: AtomicU8,
    notary: RwLock<Option<NotaryEndpoint>>,
    transition: Mutex<()>,
    /// The persisted mode, re-read for each request because replicas share
    /// it.
    metadata: Arc<dyn MetadataStore>,
    discovery: Arc<dyn NotaryDiscovery>,
}

fn encode_mode(mode: CaptureMode) -> u8 {
    match mode {
        CaptureMode::Off => 0,
        CaptureMode::Witnessed => 1,
        CaptureMode::Notarized => 2,
    }
}

fn decode_mode(value: u8) -> CaptureMode {
    match value {
        1 => CaptureMode::Witnessed,
        2 => CaptureMode::Notarized,
        _ => CaptureMode::Off,
    }
}

impl CaptureSetting {
    pub fn new(
        mode: CaptureMode,
        notary: Option<NotaryEndpoint>,
        metadata: Arc<dyn MetadataStore>,
        discovery: Arc<dyn NotaryDiscovery>,
    ) -> Self {
        Self {
            mode: AtomicU8::new(encode_mode(mode)),
            notary: RwLock::new(notary),
            transition: Mutex::new(()),
            metadata,
            discovery,
        }
    }

    pub fn mode(&self) -> CaptureMode {
        decode_mode(self.mode.load(Ordering::Acquire))
    }

    /// Whether new requests are captured in either mode.
    pub fn enabled(&self) -> bool {
        self.mode() != CaptureMode::Off
    }

    async fn snapshot_mode(&self) -> Result<CaptureMode> {
        // PostgreSQL is the shared daemon setting. Refreshing at admission
        // lets replicas converge without keeping a competing process-local
        // preference or letting a stale value execute the wrong request path.
        let persisted = self.metadata.capture_mode().await?;
        if persisted != self.mode() {
            if persisted != CaptureMode::Off {
                self.ensure_notary().await?;
            }
            self.mode.store(encode_mode(persisted), Ordering::Release);
        }
        Ok(self.mode())
    }

    async fn current_notary(&self) -> Result<NotaryEndpoint> {
        self.notary
            .read()
            .await
            .clone()
            .context("capture mode has no initialized trusted notary")
    }

    async fn ensure_notary(&self) -> Result<NotaryEndpoint> {
        if let Some(notary) = self.notary.read().await.clone() {
            return Ok(notary);
        }
        let notary = self.discovery.discover().await?;
        *self.notary.write().await = Some(notary.clone());
        Ok(notary)
    }

    /// Resolve the same trusted endpoint used by capture and sealing without
    /// changing the durable capture setting.
    pub async fn trusted_notary(&self) -> Result<NotaryEndpoint> {
        self.ensure_notary().await
    }

    pub async fn set_mode(&self, mode: CaptureMode) -> Result<CaptureMode> {
        let _transition = self.transition.lock().await;
        let persisted = self.metadata.capture_mode().await?;
        // Both capture modes need trusted notary state. It is prepared before
        // the durable transition, so a discovery or trust failure cannot
        // leave the selected mode half-on.
        if mode != CaptureMode::Off {
            self.ensure_notary().await?;
        }
        if persisted == mode {
            self.mode.store(encode_mode(persisted), Ordering::Release);
            return Ok(persisted);
        }
        let authoritative = self
            .metadata
            .set_capture_mode(mode, current_unix_ms()?)
            .await?;
        self.mode
            .store(encode_mode(authoritative), Ordering::Release);
        Ok(authoritative)
    }
}

#[async_trait]
impl CaptureModeSource for CaptureSetting {
    async fn snapshot(&self) -> Result<CaptureMode> {
        self.snapshot_mode().await
    }

    async fn notary(&self) -> Result<NotaryEndpoint> {
        self.current_notary().await
    }

    async fn set_mode(&self, mode: CaptureMode) -> Result<CaptureMode> {
        CaptureSetting::set_mode(self, mode).await
    }
}

fn current_unix_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_millis()
        .try_into()
        .context("current time does not fit in u64 milliseconds")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use anyhow::{Result, bail};
    use capture_core::registry::NotaryEndpoint;

    use super::{CaptureSetting, NotaryDiscovery};
    use crate::{
        metadata::CaptureMode, metadata_store::MetadataStore, sqlite_metadata::SqliteMetadata,
        sqlite_metadata_store::SqliteMetadataStore,
    };

    struct FailingDiscovery;

    #[async_trait::async_trait]
    impl NotaryDiscovery for FailingDiscovery {
        async fn discover(&self) -> Result<NotaryEndpoint> {
            bail!("injected trusted notary initialization failure")
        }
    }

    #[tokio::test]
    async fn failed_enable_is_atomic_and_leaves_capture_off() {
        let metadata = Arc::new(SqliteMetadataStore::from_sqlite(
            SqliteMetadata::open(std::path::Path::new(":memory:"), true).unwrap(),
            true,
        ));
        metadata
            .set_capture_mode(CaptureMode::Off, 1)
            .await
            .unwrap();
        let mode = CaptureSetting::new(
            CaptureMode::Off,
            None,
            metadata.clone(),
            Arc::new(FailingDiscovery),
        );
        for requested in [CaptureMode::Witnessed, CaptureMode::Notarized] {
            assert!(mode.set_mode(requested).await.is_err());
            assert!(!mode.enabled());
            assert_eq!(metadata.capture_mode().await.unwrap(), CaptureMode::Off);
        }
    }
}
