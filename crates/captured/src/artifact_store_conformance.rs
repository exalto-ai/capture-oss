//! Backend conformance scenarios for [`ArtifactStore`](super::ArtifactStore).

use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use super::{ArtifactKey, ArtifactKind, ArtifactSource, ArtifactStore, ArtifactStoreError};

fn key(trace_id: &str, kind: ArtifactKind) -> ArtifactKey {
    ArtifactKey::new(trace_id, kind).unwrap()
}

async fn read(store: &dyn ArtifactStore, record: &super::ArtifactRecord, limit: u64) -> Vec<u8> {
    store
        .read_verified(record, limit)
        .await
        .unwrap()
        .into_bytes()
        .await
        .unwrap()
}

/// Runs the immutable-write, bounded-read, integrity, and concurrency contract.
pub(crate) async fn run(store: Arc<dyn ArtifactStore>) {
    let empty_key = key("trc-conformance-empty", ArtifactKind::CaptureCheckpoint);
    let empty = store
        .put(&empty_key, ArtifactSource::from_bytes(Vec::new()), 0)
        .await
        .unwrap();
    assert_eq!(empty.size_bytes, 0);
    assert_eq!(read(store.as_ref(), &empty, 0).await, Vec::<u8>::new());

    let round_trip_key = key("trc-conformance-roundtrip", ArtifactKind::CaptureCheckpoint);
    let content = b"vault-encrypted checkpoint".to_vec();
    let limit = content.len() as u64;
    let first = store
        .put(
            &round_trip_key,
            ArtifactSource::from_bytes(content.clone()),
            limit,
        )
        .await
        .unwrap();
    let second = store
        .put(
            &round_trip_key,
            ArtifactSource::from_bytes(content.clone()),
            limit,
        )
        .await
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.size_bytes, limit);
    assert_eq!(first.sha256, hex::encode(Sha256::digest(&content)));
    assert_eq!(
        store.find(&round_trip_key, limit).await.unwrap(),
        Some(first.clone())
    );
    assert_eq!(read(store.as_ref(), &first, limit).await, content);
    assert!(matches!(
        store.read_verified(&first, limit - 1).await.unwrap_err(),
        ArtifactStoreError::TooLarge { .. }
    ));

    assert_eq!(
        store
            .find(
                &key("trc-conformance-missing", ArtifactKind::CaptureCheckpoint),
                1024,
            )
            .await
            .unwrap(),
        None
    );

    let collision_key = key("trc-conformance-collision", ArtifactKind::TracePackage);
    let collision_record = store
        .put(
            &collision_key,
            ArtifactSource::from_bytes(b"first".to_vec()),
            5,
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .put(
                &collision_key,
                ArtifactSource::from_bytes(b"other".to_vec()),
                5,
            )
            .await
            .unwrap_err(),
        ArtifactStoreError::Conflict { .. }
    ));
    assert!(matches!(
        store
            .put(
                &collision_key,
                ArtifactSource::from_bytes(b"longer".to_vec()),
                6,
            )
            .await
            .unwrap_err(),
        ArtifactStoreError::Conflict { .. }
    ));
    assert_eq!(read(store.as_ref(), &collision_record, 5).await, b"first");

    for (trace_id, bytes, declared) in [
        ("trc-conformance-short", b"short".as_slice(), 6),
        ("trc-conformance-long", b"longer".as_slice(), 5),
    ] {
        let stream_key = key(trace_id, ArtifactKind::CaptureCheckpoint);
        let source = ArtifactSource::new(std::io::Cursor::new(bytes.to_vec()), declared);
        assert!(matches!(
            store.put(&stream_key, source, 10).await.unwrap_err(),
            ArtifactStoreError::Integrity { .. }
        ));
        assert_eq!(store.find(&stream_key, 10).await.unwrap(), None);
    }

    let mut corrupt_record = first.clone();
    corrupt_record.sha256 = "00".repeat(32);
    assert!(matches!(
        store
            .read_verified(&corrupt_record, limit)
            .await
            .unwrap_err(),
        ArtifactStoreError::Integrity { .. }
    ));
    let mut wrong_backend_record = corrupt_record.clone();
    wrong_backend_record.sha256 = hex::encode(Sha256::digest(&content));
    wrong_backend_record.locator =
        super::ArtifactLocator::from_stored("artifact/v1/unknown/bm90LWEta2V5").unwrap();
    assert!(matches!(
        store
            .read_verified(&wrong_backend_record, limit)
            .await
            .unwrap_err(),
        ArtifactStoreError::InvalidInput { .. }
    ));
    let concurrent_key = key("trc-conformance-concurrent", ArtifactKind::TracePackage);
    let concurrent_content = b"one immutable object".to_vec();
    let mut tasks = Vec::new();
    for _ in 0..12 {
        let store = store.clone();
        let key = concurrent_key.clone();
        let content = concurrent_content.clone();
        tasks.push(tokio::spawn(async move {
            store
                .put(
                    &key,
                    ArtifactSource::from_bytes(content.clone()),
                    content.len() as u64,
                )
                .await
                .unwrap()
        }));
    }
    let mut records = Vec::new();
    for task in tasks {
        records.push(task.await.unwrap());
    }
    assert!(records.iter().all(|record| record == &records[0]));
    assert_eq!(
        read(store.as_ref(), &records[0], concurrent_content.len() as u64).await,
        concurrent_content
    );

    let delete_key = key("trc-conformance-delete", ArtifactKind::CaptureCheckpoint);
    store
        .put(
            &delete_key,
            ArtifactSource::from_bytes(b"delete me".to_vec()),
            9,
        )
        .await
        .unwrap();
    store.delete(&delete_key).await.unwrap();
    store.delete(&delete_key).await.unwrap();
    assert_eq!(store.find(&delete_key, 9).await.unwrap(), None);

    let racing_key = key(
        "trc-conformance-racing-collision",
        ArtifactKind::TracePackage,
    );
    let mut racing_tasks = Vec::new();
    for index in 0..12 {
        let store = store.clone();
        let key = racing_key.clone();
        let bytes = if index % 2 == 0 {
            b"candidate-a".to_vec()
        } else {
            b"candidate-b".to_vec()
        };
        racing_tasks.push(tokio::spawn(async move {
            store
                .put(
                    &key,
                    ArtifactSource::from_bytes(bytes.clone()),
                    bytes.len() as u64,
                )
                .await
        }));
    }
    let mut successes = Vec::new();
    let mut conflicts = 0;
    for task in racing_tasks {
        match task.await.unwrap() {
            Ok(record) => successes.push(record),
            Err(ArtifactStoreError::Conflict { .. }) => conflicts += 1,
            Err(error) => panic!("unexpected concurrent collision error: {error}"),
        }
    }
    assert!(!successes.is_empty());
    assert!(conflicts > 0);
    assert!(successes.iter().all(|record| record == &successes[0]));
}
