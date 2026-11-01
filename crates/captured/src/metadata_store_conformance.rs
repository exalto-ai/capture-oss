//! Backend conformance tests for [`MetadataStore`](super::MetadataStore).
//!
//! Every backend supplies an asynchronous factory for isolated stores and runs
//! [`run`] unchanged. Keeping the scenarios backend-neutral prevents a new
//! backend from weakening lifecycle, pagination, or concurrency guarantees.

use std::{
    collections::HashSet,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::Barrier;

use crate::{
    NotarizationPhase, NotarizationProofProgress,
    artifact_store::{ArtifactKey, ArtifactKind, ArtifactLocator, ArtifactRecord},
    metadata::{
        CaptureCompletion, CaptureMode, EventFilters, NewTrace, OperationAttempt, OperationFilters,
        OperationPagePosition, TerminalOperationResult, TraceFilters, TracePagePosition,
        TraceShareRecord,
    },
};

use super::{
    MetadataResult, MetadataStore, MetadataStoreError, TraceDeletionOutcome,
    TraceDeletionPreparation,
};

/// Runs the complete metadata contract against isolated stores from `make_store`.
pub(crate) async fn run<F, Fut>(make_store: F, full_text_search: bool)
where
    F: Fn() -> Fut,
    Fut: Future<Output = Arc<dyn MetadataStore>>,
{
    make_store().await.readiness().await.unwrap();
    capture_mode_is_durable_and_evented(make_store()).await;
    auto_seal_is_off_by_default_durable_and_evented(make_store()).await;
    capture_lifecycle(make_store().await).await;
    witnessed_capture_is_sealed_on_completion(make_store().await).await;
    canonical_trace_share_is_durable(make_store().await).await;
    terminal_trace_deletion_is_atomic_and_safe(make_store().await).await;
    preview_search(make_store().await, full_text_search).await;
    capture_filters_pagination_and_counts(make_store().await).await;
    operation_filters_and_pagination(make_store().await).await;
    notarization_lifecycle(make_store().await).await;
    early_returns_leave_queued_work_claimable(make_store().await).await;
    concurrent_enqueue_is_deduplicated(make_store().await).await;
    concurrent_retry_is_deduplicated(make_store().await).await;
    event_page_and_high_water_are_atomic(make_store().await).await;
    invalid_limits_and_ranges(make_store().await).await;
}

async fn terminal_trace_deletion_is_atomic_and_safe(store: Arc<dyn MetadataStore>) {
    assert_eq!(
        store
            .prepare_trace_deletion("trc-delete-missing")
            .await
            .unwrap(),
        TraceDeletionPreparation::NotFound
    );
    assert_eq!(
        store.delete_trace("trc-delete-missing").await.unwrap(),
        TraceDeletionOutcome::NotFound
    );

    store
        .begin_capture(new_capture("trc-delete-capturing", 1))
        .await
        .unwrap();
    assert_eq!(
        store
            .prepare_trace_deletion("trc-delete-capturing")
            .await
            .unwrap(),
        TraceDeletionPreparation::CaptureActive
    );
    assert_eq!(
        store.delete_trace("trc-delete-capturing").await.unwrap(),
        TraceDeletionOutcome::CaptureActive
    );
    assert!(store.trace("trc-delete-capturing").await.unwrap().is_some());

    insert_completed(&store, new_capture("trc-delete-notarization", 10), 200).await;
    let (queued, _) = store
        .enqueue_notarization("trc-delete-notarization", 12)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .prepare_trace_deletion("trc-delete-notarization")
            .await
            .unwrap(),
        TraceDeletionPreparation::NotarizationActive
    );
    assert_eq!(
        store.delete_trace("trc-delete-notarization").await.unwrap(),
        TraceDeletionOutcome::NotarizationActive
    );
    let running = store.claim_next_notarization(13).await.unwrap().unwrap();
    assert_eq!(running.operation_id, queued.operation_id);
    assert_eq!(
        store
            .prepare_trace_deletion("trc-delete-notarization")
            .await
            .unwrap(),
        TraceDeletionPreparation::NotarizationActive
    );
    assert_eq!(
        store.delete_trace("trc-delete-notarization").await.unwrap(),
        TraceDeletionOutcome::NotarizationActive
    );
    store
        .fail_operation(&running.operation_id, 14, "notary_error")
        .await
        .unwrap();
    assert_eq!(
        store
            .prepare_trace_deletion("trc-delete-notarization")
            .await
            .unwrap(),
        TraceDeletionPreparation::Ready
    );
    assert!(
        store
            .trace("trc-delete-notarization")
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        store.delete_trace("trc-delete-notarization").await.unwrap(),
        TraceDeletionOutcome::Deleted
    );
    assert!(
        store
            .trace("trc-delete-notarization")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .artifacts("trc-delete-notarization")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .operation(&running.operation_id)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .operation_attempts(&running.operation_id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.delete_trace("trc-delete-notarization").await.unwrap(),
        TraceDeletionOutcome::NotFound
    );

    insert_completed(&store, new_capture("trc-delete-share", 20), 200).await;
    let active_share = TraceShareRecord {
        trace_id: "trc-delete-share".into(),
        hosted_trace_id: "trc-delete-share-hosted".into(),
        progress: "verifying".into(),
        visibility: "unlisted".into(),
        access_enabled: true,
        password_protected: false,
        expires_at_unix_ms: None,
        failure_code: None,
        share_url: None,
        package_url: None,
        updated_at_unix_ms: 21,
    };
    store.put_trace_share(active_share.clone()).await.unwrap();
    assert_eq!(
        store
            .prepare_trace_deletion("trc-delete-share")
            .await
            .unwrap(),
        TraceDeletionPreparation::ShareActive
    );
    assert_eq!(
        store.delete_trace("trc-delete-share").await.unwrap(),
        TraceDeletionOutcome::ShareActive
    );
    store
        .put_trace_share(TraceShareRecord {
            progress: "stopped".into(),
            access_enabled: false,
            updated_at_unix_ms: 22,
            ..active_share
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .prepare_trace_deletion("trc-delete-share")
            .await
            .unwrap(),
        TraceDeletionPreparation::Ready
    );
    assert_eq!(
        store.delete_trace("trc-delete-share").await.unwrap(),
        TraceDeletionOutcome::Deleted
    );
    assert!(
        store
            .trace_share("trc-delete-share")
            .await
            .unwrap()
            .is_none()
    );

    insert_completed(&store, new_capture("trc-delete-expired-share", 30), 200).await;
    store
        .put_trace_share(TraceShareRecord {
            trace_id: "trc-delete-expired-share".into(),
            hosted_trace_id: "trc-delete-expired-share-hosted".into(),
            progress: "shared".into(),
            visibility: "unlisted".into(),
            access_enabled: false,
            password_protected: false,
            expires_at_unix_ms: Some(29),
            failure_code: None,
            share_url: None,
            package_url: None,
            updated_at_unix_ms: 30,
        })
        .await
        .unwrap();
    assert_eq!(
        store
            .prepare_trace_deletion("trc-delete-expired-share")
            .await
            .unwrap(),
        TraceDeletionPreparation::Ready
    );
    assert_eq!(
        store
            .delete_trace("trc-delete-expired-share")
            .await
            .unwrap(),
        TraceDeletionOutcome::Deleted
    );
}

async fn canonical_trace_share_is_durable(store: Arc<dyn MetadataStore>) {
    insert_completed(&store, new_capture("trc-share", 1), 200).await;
    assert!(store.trace_share("trc-share").await.unwrap().is_none());

    let initial = TraceShareRecord {
        trace_id: "trc-share".into(),
        hosted_trace_id: "trc-hosted-one".into(),
        progress: "verifying".into(),
        visibility: "unlisted".into(),
        access_enabled: true,
        password_protected: false,
        expires_at_unix_ms: None,
        failure_code: None,
        share_url: None,
        package_url: None,
        updated_at_unix_ms: 10,
    };
    store.put_trace_share(initial.clone()).await.unwrap();
    assert_eq!(store.trace_share("trc-share").await.unwrap(), Some(initial));

    let updated = TraceShareRecord {
        hosted_trace_id: "trc-hosted-one".into(),
        progress: "shared".into(),
        visibility: "listed".into(),
        password_protected: true,
        expires_at_unix_ms: Some(20),
        share_url: Some("https://notary.example/traces/share-one".into()),
        package_url: Some(
            "https://notary.example/api/public/traces/share-one/package.llmtrace".into(),
        ),
        updated_at_unix_ms: 11,
        ..store.trace_share("trc-share").await.unwrap().unwrap()
    };
    store.put_trace_share(updated.clone()).await.unwrap();
    assert_eq!(store.trace_share("trc-share").await.unwrap(), Some(updated));
    let mut invalid = store.trace_share("trc-share").await.unwrap().unwrap();
    invalid.updated_at_unix_ms = u64::MAX;
    assert_invalid(
        store.put_trace_share(invalid).await,
        "timestamp_out_of_range",
    );
    let mut invalid = store.trace_share("trc-share").await.unwrap().unwrap();
    invalid.expires_at_unix_ms = Some(u64::MAX);
    assert_invalid(
        store.put_trace_share(invalid).await,
        "timestamp_out_of_range",
    );
    assert!(store.delete_trace_share("trc-share").await.unwrap());
    assert!(!store.delete_trace_share("trc-share").await.unwrap());
    assert!(store.trace_share("trc-share").await.unwrap().is_none());
}

async fn capture_mode_is_durable_and_evented<Fut>(store: Fut)
where
    Fut: Future<Output = Arc<dyn MetadataStore>>,
{
    let store = store.await;
    assert_eq!(store.capture_mode().await.unwrap(), CaptureMode::Notarized);
    assert_eq!(
        store.set_capture_mode(CaptureMode::Off, 1).await.unwrap(),
        CaptureMode::Off
    );
    assert_eq!(store.capture_mode().await.unwrap(), CaptureMode::Off);
    assert_eq!(
        store.set_capture_mode(CaptureMode::Off, 2).await.unwrap(),
        CaptureMode::Off
    );
    assert_eq!(
        store
            .set_capture_mode(CaptureMode::Witnessed, 3)
            .await
            .unwrap(),
        CaptureMode::Witnessed
    );
    assert_eq!(
        store
            .set_capture_mode(CaptureMode::Notarized, 4)
            .await
            .unwrap(),
        CaptureMode::Notarized
    );
    assert_eq!(store.capture_mode().await.unwrap(), CaptureMode::Notarized);
    let events = store
        .events_snapshot(EventFilters {
            limit: 20,
            ..EventFilters::default()
        })
        .await
        .unwrap()
        .events;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == "capture_disabled")
            .count(),
        1,
        "an idempotent write must not emit a duplicate activity event"
    );
    assert_eq!(events[0].event_type, "capture_notarized");
    assert_eq!(events[0].message, "Notarized capture enabled");
    assert_eq!(events[1].event_type, "capture_witnessed");
}

async fn auto_seal_is_off_by_default_durable_and_evented<Fut>(store: Fut)
where
    Fut: Future<Output = Arc<dyn MetadataStore>>,
{
    let store = store.await;
    assert!(!store.auto_seal_enabled().await.unwrap());
    assert!(store.set_auto_seal_enabled(true, 1).await.unwrap());
    assert!(store.set_auto_seal_enabled(true, 2).await.unwrap());
    assert!(store.auto_seal_enabled().await.unwrap());
    assert_eq!(store.capture_mode().await.unwrap(), CaptureMode::Notarized);
    assert!(!store.set_auto_seal_enabled(false, 3).await.unwrap());
    let events = store
        .events_snapshot(EventFilters {
            limit: 20,
            ..EventFilters::default()
        })
        .await
        .unwrap()
        .events;
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type == "auto_seal_enabled")
            .count(),
        1,
        "an idempotent write must not emit a duplicate activity event"
    );
    assert_eq!(events[0].event_type, "auto_seal_disabled");
    assert_eq!(events[0].message, "Auto-seal disabled");
}

async fn witnessed_capture_is_sealed_on_completion(store: Arc<dyn MetadataStore>) {
    use crate::metadata::EvidenceKind;

    let id = "trc-witnessed";
    let mut capture = new_capture(id, 1);
    capture.evidence_kind = EvidenceKind::Witnessed;
    store.begin_capture(capture).await.unwrap();
    let mut completion = completion(id, 2, 200);
    completion.evidence_kind = EvidenceKind::Witnessed;

    // A Witnessed completion commits its sealed trace package, never a
    // private checkpoint, and cannot be relabelled as Notarized.
    assert!(
        store
            .complete_capture(
                completion.clone(),
                artifact(id, ArtifactKind::CaptureCheckpoint, 1)
            )
            .await
            .is_err()
    );
    let mut relabelled = completion.clone();
    relabelled.evidence_kind = EvidenceKind::Notarized;
    assert!(store.prepare_capture_completion(relabelled).await.is_err());

    store
        .prepare_capture_completion(completion.clone())
        .await
        .unwrap();
    store
        .complete_capture(completion, artifact(id, ArtifactKind::TracePackage, 1))
        .await
        .unwrap();
    let trace = store.trace(id).await.unwrap().unwrap();
    assert_eq!(trace.evidence_kind, EvidenceKind::Witnessed);
    assert_eq!(trace.capture_status, "captured");
    assert_eq!(trace.notarization_status, "succeeded");
    assert_eq!(store.incomplete_captures().await.unwrap(), Vec::new());

    // It is already sealed, so it can never be queued for a proof.
    assert!(store.enqueue_notarization(id, 3).await.unwrap().is_none());
    assert_eq!(
        store.trace(id).await.unwrap().unwrap().notarization_status,
        "succeeded"
    );
}

pub(crate) fn new_capture(id: &str, created_at_unix_ms: u64) -> NewTrace {
    NewTrace {
        evidence_kind: crate::metadata::EvidenceKind::Notarized,
        trace_id: id.to_owned(),
        created_at_unix_ms,
        provider: "openai".to_owned(),
        operation: "responses".to_owned(),
        requested_model: Some("gpt-5".to_owned()),
        streaming: false,
        request_bytes: 12,
        prompt_preview: "Explain quarterly pricing".to_owned(),
        prompt_preview_truncated: false,
        config_fingerprint: "sha256:test".to_owned(),
    }
}

pub(crate) fn completion(
    id: &str,
    completed_at_unix_ms: u64,
    http_status: u16,
) -> CaptureCompletion {
    CaptureCompletion {
        evidence_kind: crate::metadata::EvidenceKind::Notarized,
        trace_id: id.to_owned(),
        completed_at_unix_ms,
        duration_ms: 7,
        http_status,
        response_bytes: 24,
        response_model: Some("gpt-5-verified".to_owned()),
        output_preview: "Quarterly pricing is available.".to_owned(),
        output_preview_truncated: false,
        expected_artifact_size_bytes: 11,
        expected_artifact_sha256: format!("{:064x}", 1),
    }
}

pub(crate) fn artifact(id: &str, kind: ArtifactKind, marker: u8) -> ArtifactRecord {
    ArtifactRecord::new(
        ArtifactKey::new(id, kind).unwrap(),
        ArtifactLocator::from_stored(format!("fixture://{id}/{}", kind.as_str())).unwrap(),
        u64::from(marker) + 10,
        format!("{marker:064x}"),
    )
    .unwrap()
}

async fn insert_completed(store: &Arc<dyn MetadataStore>, capture: NewTrace, http_status: u16) {
    let id = capture.trace_id.clone();
    let completed_at = capture.created_at_unix_ms + 1;
    store.begin_capture(capture).await.unwrap();
    let completion = completion(&id, completed_at, http_status);
    store
        .prepare_capture_completion(completion.clone())
        .await
        .unwrap();
    store
        .complete_capture(
            completion,
            artifact(&id, ArtifactKind::CaptureCheckpoint, 1),
        )
        .await
        .unwrap();
}

fn ids<T>(values: &[T], get: impl Fn(&T) -> &str) -> Vec<String> {
    values.iter().map(|value| get(value).to_owned()).collect()
}

fn assert_invalid<T>(result: MetadataResult<T>, expected: &'static str) {
    match result {
        Err(MetadataStoreError::InvalidInput(actual)) => assert_eq!(actual, expected),
        Err(error) => panic!("expected invalid input {expected}, got {error}"),
        Ok(_) => panic!("expected invalid input {expected}"),
    }
}

async fn capture_lifecycle(store: Arc<dyn MetadataStore>) {
    assert!(store.trace("trc-missing").await.unwrap().is_none());
    assert!(store.artifacts("trc-missing").await.unwrap().is_empty());
    assert!(store.incomplete_captures().await.unwrap().is_empty());
    assert!(
        store
            .mark_capture_failed("trc-missing", "notary_error")
            .await
            .is_err()
    );

    let first = new_capture("trc-lifecycle-complete", 10);
    store.begin_capture(first.clone()).await.unwrap();
    assert!(store.begin_capture(first).await.is_err());
    let pending = store
        .trace("trc-lifecycle-complete")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.capture_status, "capturing");
    assert_eq!(pending.notarization_status, "not_requested");
    assert_eq!(pending.requested_model.as_deref(), Some("gpt-5"));
    assert_eq!(pending.request_bytes, 12);
    assert_eq!(pending.prompt_preview, "Explain quarterly pricing");

    store
        .begin_capture(new_capture("trc-lifecycle-failed", 20))
        .await
        .unwrap();
    store
        .mark_capture_failed("trc-lifecycle-failed", "notary_error")
        .await
        .unwrap();
    store
        .mark_capture_failed("trc-lifecycle-failed", "notary_error")
        .await
        .unwrap();
    let failed = store.trace("trc-lifecycle-failed").await.unwrap().unwrap();
    assert_eq!(failed.capture_status, "failed");
    assert_eq!(failed.failure_code.as_deref(), Some("notary_error"));

    let mut capturing = store
        .incomplete_captures()
        .await
        .unwrap()
        .into_iter()
        .map(|capture| capture.trace_id)
        .collect::<Vec<_>>();
    capturing.sort();
    assert_eq!(capturing, vec!["trc-lifecycle-complete"]);

    let checkpoint = artifact("trc-lifecycle-complete", ArtifactKind::CaptureCheckpoint, 3);
    let mut completed = completion("trc-lifecycle-complete", 40, 200);
    completed.expected_artifact_size_bytes = checkpoint.size_bytes;
    completed.expected_artifact_sha256 = checkpoint.sha256.clone();
    store
        .prepare_capture_completion(completed.clone())
        .await
        .unwrap();
    store
        .prepare_capture_completion(completed.clone())
        .await
        .unwrap();
    let staged = store
        .trace("trc-lifecycle-complete")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(staged.capture_status, "capturing");
    assert_eq!(staged.completed_at_unix_ms, Some(40));
    assert_eq!(staged.http_status, Some(200));
    assert_eq!(
        store
            .incomplete_captures()
            .await
            .unwrap()
            .into_iter()
            .find(|capture| capture.trace_id == "trc-lifecycle-complete")
            .and_then(|capture| capture.completion),
        Some(completed.clone())
    );
    assert!(
        store
            .artifacts("trc-lifecycle-complete")
            .await
            .unwrap()
            .is_empty()
    );
    let mut conflicting_staged = completed.clone();
    conflicting_staged.response_bytes += 1;
    assert!(
        store
            .prepare_capture_completion(conflicting_staged)
            .await
            .is_err()
    );
    let mut conflicting_expectation = completed.clone();
    conflicting_expectation.expected_artifact_sha256 = "ff".repeat(32);
    assert!(
        store
            .prepare_capture_completion(conflicting_expectation)
            .await
            .is_err()
    );
    let mut wrong_checkpoint = checkpoint.clone();
    wrong_checkpoint.sha256 = "ee".repeat(32);
    assert!(
        store
            .complete_capture(completed.clone(), wrong_checkpoint)
            .await
            .is_err()
    );
    assert!(
        store
            .artifacts("trc-lifecycle-complete")
            .await
            .unwrap()
            .is_empty()
    );
    store
        .complete_capture(completed.clone(), checkpoint.clone())
        .await
        .unwrap();
    store
        .complete_capture(completed, checkpoint.clone())
        .await
        .unwrap();
    let mut conflicting_completion = completion("trc-lifecycle-complete", 40, 200);
    conflicting_completion.response_bytes += 1;
    assert!(
        store
            .prepare_capture_completion(completion("trc-missing", 50, 200))
            .await
            .is_err()
    );
    assert!(
        store
            .complete_capture(conflicting_completion, checkpoint.clone())
            .await
            .is_err()
    );
    assert!(
        store
            .mark_capture_failed("trc-lifecycle-complete", "late_failure")
            .await
            .is_err()
    );
    let captured = store
        .trace("trc-lifecycle-complete")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(captured.capture_status, "captured");
    assert_eq!(captured.completed_at_unix_ms, Some(40));
    assert_eq!(captured.http_status, Some(200));
    assert_eq!(captured.response_bytes, Some(24));
    assert_eq!(captured.response_model.as_deref(), Some("gpt-5-verified"));
    assert_eq!(
        store.artifacts("trc-lifecycle-complete").await.unwrap(),
        vec![checkpoint]
    );

    assert!(
        store
            .complete_capture(
                completion("trc-missing", 50, 200),
                artifact("trc-missing", ArtifactKind::CaptureCheckpoint, 5),
            )
            .await
            .is_err()
    );
    assert!(store.artifacts("trc-missing").await.unwrap().is_empty());
}

async fn preview_search(store: Arc<dyn MetadataStore>, full_text_search: bool) {
    let first = new_capture("trc-search-adjacent", 10);
    insert_completed(&store, first, 200).await;

    let mut separated = new_capture("trc-search-separated", 20);
    separated.prompt_preview = "Quarterly enterprise notes about pricing".to_owned();
    let separated_id = separated.trace_id.clone();
    store.begin_capture(separated).await.unwrap();
    let mut separated_completion = completion(&separated_id, 21, 200);
    separated_completion.output_preview = "No repeated phrase here.".to_owned();
    let separated_artifact = artifact(&separated_id, ArtifactKind::CaptureCheckpoint, 8);
    separated_completion.expected_artifact_size_bytes = separated_artifact.size_bytes;
    separated_completion.expected_artifact_sha256 = separated_artifact.sha256.clone();
    store
        .complete_capture(separated_completion, separated_artifact)
        .await
        .unwrap();

    let mut unicode = new_capture("trc-search-unicode", 30);
    unicode.prompt_preview = "Résumé CAFÉ 東京".to_owned();
    let unicode_id = unicode.trace_id.clone();
    store.begin_capture(unicode).await.unwrap();
    let mut unicode_completion = completion(&unicode_id, 31, 200);
    unicode_completion.output_preview = "International text fixture".to_owned();
    let unicode_artifact = artifact(&unicode_id, ArtifactKind::CaptureCheckpoint, 9);
    unicode_completion.expected_artifact_size_bytes = unicode_artifact.size_bytes;
    unicode_completion.expected_artifact_sha256 = unicode_artifact.sha256.clone();
    store
        .complete_capture(unicode_completion, unicode_artifact)
        .await
        .unwrap();

    let mut boundary = new_capture("trc-search-field-boundary", 40);
    boundary.prompt_preview = "Boundary alpha".to_owned();
    let boundary_id = boundary.trace_id.clone();
    store.begin_capture(boundary).await.unwrap();
    let mut boundary_completion = completion(&boundary_id, 41, 200);
    boundary_completion.output_preview = "omega boundary".to_owned();
    let boundary_artifact = artifact(&boundary_id, ArtifactKind::CaptureCheckpoint, 10);
    boundary_completion.expected_artifact_size_bytes = boundary_artifact.size_bytes;
    boundary_completion.expected_artifact_sha256 = boundary_artifact.sha256.clone();
    store
        .complete_capture(boundary_completion, boundary_artifact)
        .await
        .unwrap();

    let query = |value: &str| TraceFilters {
        query: Some(value.to_owned()),
        limit: 20,
        ..TraceFilters::default()
    };
    assert!(store.traces(query("")).await.unwrap().is_empty());
    if !full_text_search {
        for value in [
            "quarterly-pricing",
            "**quarterly**",
            "\"quarterly pricing\"",
        ] {
            assert_invalid(store.traces(query(value)).await, "preview_search_disabled");
        }
        return;
    }

    for value in ["quarterly-pricing", "**quarterly**"] {
        assert_eq!(store.traces(query(value)).await.unwrap().len(), 2);
    }
    assert_eq!(store.traces(query("QUARTERLY")).await.unwrap().len(), 2);
    for value in ["café", "東京"] {
        assert_eq!(
            ids(&store.traces(query(value)).await.unwrap(), |capture| {
                &capture.trace_id
            }),
            vec!["trc-search-unicode"]
        );
    }
    assert_eq!(
        ids(
            &store.traces(query("\"quarterly pricing\"")).await.unwrap(),
            |capture| &capture.trace_id,
        ),
        vec!["trc-search-adjacent"]
    );
    assert!(
        store
            .traces(query("\"alpha omega\""))
            .await
            .unwrap()
            .is_empty(),
        "a quoted phrase must not cross prompt/output fields"
    );
    assert_eq!(
        ids(
            &store.traces(query("alpha omega")).await.unwrap(),
            |capture| &capture.trace_id,
        ),
        vec!["trc-search-field-boundary"],
        "unquoted terms may match across prompt/output fields"
    );
    assert_eq!(
        ids(
            &store.traces(query("\"quarterly pricing")).await.unwrap(),
            |capture| &capture.trace_id,
        ),
        vec!["trc-search-adjacent"]
    );
    for value in ["\"pricing quarterly\"", "definitely-not-present-xyz", "**"] {
        assert!(
            store.traces(query(value)).await.unwrap().is_empty(),
            "query unexpectedly matched: {value}"
        );
    }
}

async fn capture_filters_pagination_and_counts(store: Arc<dyn MetadataStore>) {
    let mut a = new_capture("trc-filter-a", 100);
    a.streaming = true;
    insert_completed(&store, a, 200).await;

    let mut b = new_capture("trc-filter-b", 200);
    b.provider = "anthropic".to_owned();
    b.requested_model = Some("claude-sonnet".to_owned());
    insert_completed(&store, b, 503).await;

    let mut c = new_capture("trc-filter-c", 200);
    c.requested_model = Some("gpt-4.1".to_owned());
    store.begin_capture(c).await.unwrap();
    store
        .mark_capture_failed("trc-filter-c", "capture_error")
        .await
        .unwrap();

    let mut d = new_capture("trc-filter-d", 300);
    d.provider = "openrouter".to_owned();
    d.requested_model = None;
    d.streaming = true;
    store.begin_capture(d).await.unwrap();

    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    provider: Some("openai".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.trace_id,
        ),
        vec!["trc-filter-c", "trc-filter-a"]
    );
    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    model: Some("gpt-5".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.trace_id,
        ),
        vec!["trc-filter-a"]
    );
    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    capture_status: Some("captured".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.trace_id,
        ),
        vec!["trc-filter-b", "trc-filter-a"]
    );
    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    state: Some("captured".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |trace| &trace.trace_id,
        ),
        vec!["trc-filter-b", "trc-filter-a"]
    );
    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    status: Some("capturing".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |trace| &trace.trace_id,
        ),
        vec!["trc-filter-d"]
    );
    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    status: Some("capture_failed".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |trace| &trace.trace_id,
        ),
        vec!["trc-filter-c"]
    );
    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    status: Some("needs_attention".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |trace| &trace.trace_id,
        ),
        vec!["trc-filter-c"]
    );
    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    notarization_status: Some("not_requested".to_owned()),
                    streaming: Some(true),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.trace_id,
        ),
        vec!["trc-filter-d", "trc-filter-a"]
    );
    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    created_after_unix_ms: Some(200),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |capture| &capture.trace_id,
        ),
        vec!["trc-filter-d", "trc-filter-c", "trc-filter-b"]
    );
    assert_eq!(
        ids(
            &store
                .traces(TraceFilters {
                    created_before_unix_ms: Some(200),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap(),
            |trace| &trace.trace_id,
        ),
        vec!["trc-filter-c", "trc-filter-b", "trc-filter-a"]
    );

    let all = store
        .traces(TraceFilters {
            limit: 20,
            ..TraceFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(
        ids(&all, |capture| &capture.trace_id),
        vec![
            "trc-filter-d",
            "trc-filter-c",
            "trc-filter-b",
            "trc-filter-a"
        ]
    );
    let first_page = store
        .traces(TraceFilters {
            limit: 2,
            ..TraceFilters::default()
        })
        .await
        .unwrap();
    let second_page = store
        .traces(TraceFilters {
            cursor: Some(TracePagePosition::from(first_page.last().unwrap())),
            limit: 2,
            ..TraceFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(first_page, all[..2]);
    assert_eq!(second_page, all[2..]);

    let counts = store.counts().await.unwrap();
    assert_eq!(counts.captured, 2);
    assert_eq!(counts.notarizing, 0);
    assert_eq!(counts.notarized, 0);
    assert_eq!(counts.needs_attention, 1);
    assert_eq!(counts.capturing, 1);
    assert_eq!(counts.capture_failed, 1);
}

async fn operation_filters_and_pagination(store: Arc<dyn MetadataStore>) {
    for (id, created) in [("trc-ops-a", 1), ("trc-ops-b", 2), ("trc-ops-c", 3)] {
        insert_completed(&store, new_capture(id, created), 200).await;
    }
    let op_a = store
        .enqueue_notarization("trc-ops-a", 10)
        .await
        .unwrap()
        .unwrap()
        .0;
    store.enqueue_notarization("trc-ops-b", 20).await.unwrap();
    store.enqueue_notarization("trc-ops-c", 20).await.unwrap();

    let all = store
        .operations(OperationFilters {
            limit: 20,
            ..OperationFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(all.len(), 3);
    let first_page = store
        .operations(OperationFilters {
            limit: 2,
            ..OperationFilters::default()
        })
        .await
        .unwrap();
    let second_page = store
        .operations(OperationFilters {
            cursor: Some(OperationPagePosition::from(first_page.last().unwrap())),
            limit: 2,
            ..OperationFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(first_page, all[..2]);
    assert_eq!(second_page, all[2..]);
    assert_eq!(
        store
            .operations(OperationFilters {
                state: Some("queued".to_owned()),
                kind: Some("notarization".to_owned()),
                trace_id: Some("trc-ops-a".to_owned()),
                limit: 20,
                ..OperationFilters::default()
            })
            .await
            .unwrap(),
        vec![op_a.clone()]
    );
    assert!(
        store
            .operations(OperationFilters {
                trace_id: Some("trc-missing".to_owned()),
                limit: 20,
                ..OperationFilters::default()
            })
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store.operation(&op_a.operation_id).await.unwrap(),
        Some(op_a)
    );
    assert!(store.operation("op-missing").await.unwrap().is_none());
    assert_eq!(store.counts().await.unwrap().notarizing, 3);

    let claimed = store.claim_next_notarization(30).await.unwrap().unwrap();
    assert_eq!(claimed.trace_id, "trc-ops-a");
    assert_eq!(store.counts().await.unwrap().notarizing, 3);
}

async fn notarization_lifecycle(store: Arc<dyn MetadataStore>) {
    insert_completed(&store, new_capture("trc-notarize-ok", 1), 200).await;
    insert_completed(&store, new_capture("trc-notarize-http-error", 2), 401).await;
    assert!(
        store
            .enqueue_notarization("trc-notarize-http-error", 3)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        store
            .enqueue_notarization("trc-missing", 3)
            .await
            .unwrap()
            .is_none()
    );

    let (queued, duplicate) = store
        .enqueue_notarization("trc-notarize-ok", 4)
        .await
        .unwrap()
        .unwrap();
    assert!(!duplicate);
    let (same, duplicate) = store
        .enqueue_notarization("trc-notarize-ok", 5)
        .await
        .unwrap()
        .unwrap();
    assert!(duplicate);
    assert_eq!(same.operation_id, queued.operation_id);
    let package = artifact("trc-notarize-ok", ArtifactKind::TracePackage, 4);
    assert_eq!(
        store
            .complete_notarization(&queued.operation_id, package.clone(), 6)
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "queued".to_owned()
        }
    );
    assert_eq!(
        store
            .fail_operation(&queued.operation_id, 6, "too_early")
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "queued".to_owned()
        }
    );
    assert!(
        store
            .operation_attempts(&queued.operation_id)
            .await
            .unwrap()
            .is_empty()
    );

    let running = store.claim_next_notarization(7).await.unwrap().unwrap();
    assert_eq!(running.operation_id, queued.operation_id);
    assert_eq!(running.state, "running");
    assert_eq!(running.attempt, 1);
    assert!(
        store
            .update_operation_progress(&running.operation_id, NotarizationPhase::Signing, 8)
            .await
            .unwrap()
    );
    assert!(
        !store
            .update_operation_progress(&running.operation_id, NotarizationPhase::Signing, 9)
            .await
            .unwrap()
    );
    assert!(
        store
            .update_operation_proof_progress(
                &running.operation_id,
                NotarizationProofProgress {
                    bytes_completed: 2_048,
                    bytes_total: 8_192,
                    commitments_completed: 1,
                    commitments_total: 2,
                },
                10,
            )
            .await
            .unwrap()
    );
    let after_proof = store
        .operation(&running.operation_id)
        .await
        .unwrap()
        .unwrap();
    let progress_events_before = store
        .events_snapshot(EventFilters {
            event_type: Some("notarization_progress".to_owned()),
            operation_id: Some(running.operation_id.clone()),
            limit: 20,
            ..EventFilters::default()
        })
        .await
        .unwrap()
        .events
        .len();
    assert!(
        !store
            .update_operation_proof_progress(
                &running.operation_id,
                NotarizationProofProgress {
                    bytes_completed: 2_048,
                    bytes_total: 8_192,
                    commitments_completed: 1,
                    commitments_total: 2,
                },
                11,
            )
            .await
            .unwrap()
    );
    assert_eq!(
        store
            .operation(&running.operation_id)
            .await
            .unwrap()
            .unwrap()
            .progress_updated_at_unix_ms,
        after_proof.progress_updated_at_unix_ms,
        "an identical proof update must not churn its timestamp"
    );
    assert_eq!(
        store
            .events_snapshot(EventFilters {
                event_type: Some("notarization_progress".to_owned()),
                operation_id: Some(running.operation_id.clone()),
                limit: 20,
                ..EventFilters::default()
            })
            .await
            .unwrap()
            .events
            .len(),
        progress_events_before,
        "an identical proof update must not emit an event"
    );
    assert!(
        store
            .update_operation_proof_progress(
                &running.operation_id,
                NotarizationProofProgress {
                    bytes_completed: 1_024,
                    bytes_total: 8_192,
                    commitments_completed: 1,
                    commitments_total: 2,
                },
                11,
            )
            .await
            .is_err()
    );
    assert!(
        store
            .update_operation_proof_progress(
                &running.operation_id,
                NotarizationProofProgress {
                    bytes_completed: 4_096,
                    bytes_total: 16_384,
                    commitments_completed: 1,
                    commitments_total: 2,
                },
                11,
            )
            .await
            .is_err()
    );
    assert!(
        store
            .update_operation_proof_progress(
                &running.operation_id,
                NotarizationProofProgress {
                    bytes_completed: 4_096,
                    bytes_total: 8_192,
                    commitments_completed: 1,
                    commitments_total: 3,
                },
                11,
            )
            .await
            .is_err()
    );
    assert!(
        store
            .update_operation_progress(&running.operation_id, NotarizationPhase::Packaging, 11)
            .await
            .unwrap()
    );
    let progressed = store
        .operation(&running.operation_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(progressed.progress_phase, "packaging");
    assert_eq!(progressed.proof_bytes_completed, 2_048);
    assert_eq!(progressed.proof_bytes_total, 8_192);
    assert_eq!(progressed.proof_commitments_completed, 1);
    assert_eq!(progressed.proof_commitments_total, 2);

    assert_eq!(store.interrupt_running_operations(12).await.unwrap(), 1);
    assert_eq!(store.interrupt_running_operations(13).await.unwrap(), 0);
    assert_eq!(
        store
            .complete_notarization(&running.operation_id, package.clone(), 13)
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "interrupted".to_owned()
        }
    );
    assert_eq!(
        store
            .fail_operation(&running.operation_id, 13, "too_late")
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "interrupted".to_owned()
        }
    );
    assert!(
        !store
            .update_operation_progress(&running.operation_id, NotarizationPhase::Signing, 13)
            .await
            .unwrap()
    );

    let retried = store
        .retry_operation(&running.operation_id, 14)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(retried.state, "queued");
    assert_eq!(retried.progress_phase, "queued");
    assert_eq!(retried.proof_bytes_total, 0);
    assert!(
        store
            .retry_operation(&running.operation_id, 14)
            .await
            .unwrap()
            .is_none()
    );
    let second = store.claim_next_notarization(15).await.unwrap().unwrap();
    assert_eq!(second.attempt, 2);
    assert_eq!(
        store
            .fail_operation(&second.operation_id, 16, "proof_generation_failed")
            .await
            .unwrap(),
        TerminalOperationResult::Applied
    );
    assert_eq!(
        store
            .fail_operation(&second.operation_id, 17, "proof_generation_failed")
            .await
            .unwrap(),
        TerminalOperationResult::AlreadyApplied
    );
    assert_eq!(
        store
            .fail_operation(&second.operation_id, 17, "different_failure")
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "failed".to_owned()
        }
    );
    assert_eq!(
        store
            .complete_notarization(&second.operation_id, package.clone(), 17)
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "failed".to_owned()
        }
    );

    store
        .retry_operation(&second.operation_id, 18)
        .await
        .unwrap()
        .unwrap();
    let third = store.claim_next_notarization(19).await.unwrap().unwrap();
    assert_eq!(third.attempt, 3);
    assert!(
        store
            .complete_notarization(
                &third.operation_id,
                artifact("trc-different-capture", ArtifactKind::TracePackage, 4),
                20,
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .complete_notarization(&third.operation_id, package.clone(), 20)
            .await
            .unwrap(),
        TerminalOperationResult::Applied
    );
    assert_eq!(
        store
            .complete_notarization(&third.operation_id, package.clone(), 21)
            .await
            .unwrap(),
        TerminalOperationResult::AlreadyApplied
    );
    assert!(
        store
            .complete_notarization(
                &third.operation_id,
                artifact("trc-notarize-ok", ArtifactKind::TracePackage, 9),
                21,
            )
            .await
            .is_err()
    );
    assert_eq!(
        store
            .fail_operation(&third.operation_id, 21, "too_late")
            .await
            .unwrap(),
        TerminalOperationResult::Conflict {
            current_state: "succeeded".to_owned()
        }
    );
    assert!(
        store
            .retry_operation(&third.operation_id, 21)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        store
            .complete_notarization(
                "op-missing",
                artifact("trc-missing", ArtifactKind::TracePackage, 4),
                22,
            )
            .await
            .unwrap(),
        TerminalOperationResult::NotFound
    );
    assert_eq!(
        store
            .fail_operation("op-missing", 22, "op-missing")
            .await
            .unwrap(),
        TerminalOperationResult::NotFound
    );
    assert!(
        !store
            .update_operation_progress("op-missing", NotarizationPhase::Signing, 22)
            .await
            .unwrap()
    );
    assert!(
        !store
            .update_operation_proof_progress("op-missing", NotarizationProofProgress::default(), 22,)
            .await
            .unwrap()
    );
    assert!(
        store
            .retry_operation("op-missing", 22)
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(
        store.artifacts("trc-notarize-ok").await.unwrap().len(),
        2,
        "the capture checkpoint and trace package are both retained"
    );
    assert_eq!(
        store
            .trace("trc-notarize-ok")
            .await
            .unwrap()
            .unwrap()
            .notarization_status,
        "succeeded"
    );

    assert_eq!(
        store.operation_attempts(&third.operation_id).await.unwrap(),
        vec![
            OperationAttempt {
                attempt: 3,
                state: "succeeded".to_owned(),
                started_at_unix_ms: 19,
                completed_at_unix_ms: Some(20),
                failure_code: None,
            },
            OperationAttempt {
                attempt: 2,
                state: "failed".to_owned(),
                started_at_unix_ms: 15,
                completed_at_unix_ms: Some(16),
                failure_code: Some("proof_generation_failed".to_owned()),
            },
            OperationAttempt {
                attempt: 1,
                state: "interrupted".to_owned(),
                started_at_unix_ms: 7,
                completed_at_unix_ms: Some(12),
                failure_code: Some("service_restarted".to_owned()),
            },
        ]
    );

    let failed_events = store
        .events_snapshot(EventFilters {
            severity: Some("error".to_owned()),
            event_type: Some("notarization_failed".to_owned()),
            trace_id: Some("trc-notarize-ok".to_owned()),
            operation_id: Some(third.operation_id.clone()),
            created_after_unix_ms: Some(16),
            limit: 20,
            ..EventFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(failed_events.events.len(), 1);
    assert_eq!(
        failed_events.high_water,
        Some(failed_events.events[0].event_id)
    );
    let completed_events = store
        .events_snapshot(EventFilters {
            event_type: Some("notarization_completed".to_owned()),
            operation_id: Some(third.operation_id),
            limit: 20,
            ..EventFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(completed_events.events.len(), 1);
}

async fn concurrent_enqueue_is_deduplicated(store: Arc<dyn MetadataStore>) {
    insert_completed(&store, new_capture("trc-concurrent-enqueue", 1), 200).await;
    const CONCURRENCY: usize = 12;
    let barrier = Arc::new(Barrier::new(CONCURRENCY));
    let mut tasks = Vec::new();
    for _ in 0..CONCURRENCY {
        let store = store.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .enqueue_notarization("trc-concurrent-enqueue", 10)
                .await
                .unwrap()
                .unwrap()
        }));
    }
    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }
    assert_eq!(
        results.iter().filter(|(_, duplicate)| !duplicate).count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .map(|(operation, _)| operation.operation_id.as_str())
            .collect::<HashSet<_>>()
            .len(),
        1
    );
    assert_eq!(
        store
            .operations(OperationFilters {
                trace_id: Some("trc-concurrent-enqueue".to_owned()),
                limit: 20,
                ..OperationFilters::default()
            })
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .events_snapshot(EventFilters {
                event_type: Some("notarization_queued".to_owned()),
                trace_id: Some("trc-concurrent-enqueue".to_owned()),
                limit: 20,
                ..EventFilters::default()
            })
            .await
            .unwrap()
            .events
            .len(),
        1
    );
}

/// A call that returns early must release its row locks before it returns.
/// Claims skip locked rows, so a lock left for the connection pool to roll back
/// later makes a queued notarization look unclaimable to the next claim.
async fn early_returns_leave_queued_work_claimable(store: Arc<dyn MetadataStore>) {
    insert_completed(&store, new_capture("trc-early-return", 1), 200).await;
    let (queued, _) = store
        .enqueue_notarization("trc-early-return", 2)
        .await
        .unwrap()
        .unwrap();
    for round in 0..200_u64 {
        let now = 10 + round * 10;
        // A queued operation is not retryable, so this locks the row and
        // returns early.
        assert!(
            store
                .retry_operation(&queued.operation_id, now)
                .await
                .unwrap()
                .is_none()
        );
        let claimed = store.claim_next_notarization(now + 1).await.unwrap();
        assert!(
            claimed.is_some(),
            "round {round}: the queued notarization was skipped as locked"
        );
        assert_eq!(
            store
                .fail_operation(&queued.operation_id, now + 2, "early_return_probe")
                .await
                .unwrap(),
            TerminalOperationResult::Applied
        );
        store
            .retry_operation(&queued.operation_id, now + 3)
            .await
            .unwrap()
            .unwrap();
    }
}

async fn concurrent_retry_is_deduplicated(store: Arc<dyn MetadataStore>) {
    insert_completed(&store, new_capture("trc-concurrent-retry", 1), 200).await;
    let operation = store
        .enqueue_notarization("trc-concurrent-retry", 2)
        .await
        .unwrap()
        .unwrap()
        .0;
    let running = store.claim_next_notarization(3).await.unwrap().unwrap();
    assert_eq!(running.operation_id, operation.operation_id);
    assert_eq!(running.attempt, 1);
    assert_eq!(
        store
            .fail_operation(&running.operation_id, 4, "fixture_failure")
            .await
            .unwrap(),
        TerminalOperationResult::Applied
    );

    const CONCURRENCY: usize = 12;
    let barrier = Arc::new(Barrier::new(CONCURRENCY));
    let mut tasks = Vec::new();
    for _ in 0..CONCURRENCY {
        let store = store.clone();
        let barrier = barrier.clone();
        let operation_id = running.operation_id.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store.retry_operation(&operation_id, 5).await.unwrap()
        }));
    }
    let mut applied = Vec::new();
    for task in tasks {
        if let Some(operation) = task.await.unwrap() {
            applied.push(operation);
        }
    }
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].operation_id, running.operation_id);
    assert_eq!(applied[0].state, "queued");
    assert_eq!(applied[0].attempt, 1, "retry does not start an attempt");
    assert_eq!(
        store
            .operation_attempts(&running.operation_id)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .events_snapshot(EventFilters {
                event_type: Some("notarization_retried".to_owned()),
                operation_id: Some(running.operation_id),
                limit: 20,
                ..EventFilters::default()
            })
            .await
            .unwrap()
            .events
            .len(),
        1
    );
}

async fn event_page_and_high_water_are_atomic(store: Arc<dyn MetadataStore>) {
    const WRITERS: usize = 24;
    for index in 0..WRITERS {
        let id = format!("trc-event-atomic-{index:02}");
        insert_completed(&store, new_capture(&id, index as u64 + 1), 200).await;
    }

    let barrier = Arc::new(Barrier::new(WRITERS + 1));
    let complete = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for index in 0..WRITERS {
        let store = store.clone();
        let barrier = barrier.clone();
        let complete = complete.clone();
        tasks.push(tokio::spawn(async move {
            let id = format!("trc-event-atomic-{index:02}");
            barrier.wait().await;
            store.enqueue_notarization(&id, 100).await.unwrap();
            complete.fetch_add(1, Ordering::Release);
        }));
    }
    barrier.wait().await;

    loop {
        let snapshot = store
            .events_snapshot(EventFilters {
                event_type: Some("notarization_queued".to_owned()),
                limit: 201,
                ..EventFilters::default()
            })
            .await
            .unwrap();
        match snapshot.high_water {
            Some(high_water) => {
                assert!(!snapshot.events.is_empty());
                assert_eq!(
                    snapshot.events.iter().map(|event| event.event_id).max(),
                    Some(high_water),
                    "the high-water mark must come from the same snapshot as the complete page"
                );
            }
            None => assert!(snapshot.events.is_empty()),
        }
        if complete.load(Ordering::Acquire) == WRITERS {
            break;
        }
        tokio::task::yield_now().await;
    }
    for task in tasks {
        task.await.unwrap();
    }

    let snapshot = store
        .events_snapshot(EventFilters {
            event_type: Some("notarization_queued".to_owned()),
            limit: 201,
            ..EventFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(snapshot.events.len(), WRITERS);
    assert_eq!(snapshot.high_water, Some(snapshot.events[0].event_id));
    let high_water = snapshot.high_water.unwrap();
    assert!(
        store
            .events_snapshot(EventFilters {
                after: Some(high_water),
                event_type: Some("notarization_queued".to_owned()),
                limit: 201,
                ..EventFilters::default()
            })
            .await
            .unwrap()
            .events
            .is_empty()
    );
    let history = store
        .events_snapshot(EventFilters {
            before: Some(high_water),
            event_type: Some("notarization_queued".to_owned()),
            limit: 201,
            ..EventFilters::default()
        })
        .await
        .unwrap();
    assert_eq!(history.events.len(), WRITERS - 1);
    assert_eq!(history.high_water, Some(high_water));
}

async fn invalid_limits_and_ranges(store: Arc<dyn MetadataStore>) {
    for limit in [0, 202] {
        assert_invalid(
            store
                .traces(TraceFilters {
                    limit,
                    ..TraceFilters::default()
                })
                .await,
            "invalid_page_limit",
        );
        assert_invalid(
            store
                .operations(OperationFilters {
                    limit,
                    ..OperationFilters::default()
                })
                .await,
            "invalid_page_limit",
        );
        assert_invalid(
            store
                .events_snapshot(EventFilters {
                    limit,
                    ..EventFilters::default()
                })
                .await,
            "invalid_page_limit",
        );
    }
    assert_invalid(
        store
            .traces(TraceFilters {
                created_after_unix_ms: Some(u64::MAX),
                limit: 1,
                ..TraceFilters::default()
            })
            .await,
        "created_after_out_of_range",
    );
    assert_invalid(
        store
            .traces(TraceFilters {
                created_before_unix_ms: Some(u64::MAX),
                limit: 1,
                ..TraceFilters::default()
            })
            .await,
        "created_before_out_of_range",
    );
    assert_invalid(
        store
            .traces(TraceFilters {
                cursor: Some(TracePagePosition {
                    created_at_unix_ms: u64::MAX,
                    trace_id: "cursor".to_owned(),
                }),
                limit: 1,
                ..TraceFilters::default()
            })
            .await,
        "cursor_out_of_range",
    );
    assert_invalid(
        store
            .operations(OperationFilters {
                cursor: Some(OperationPagePosition {
                    created_at_unix_ms: u64::MAX,
                    operation_id: "cursor".to_owned(),
                }),
                limit: 1,
                ..OperationFilters::default()
            })
            .await,
        "cursor_out_of_range",
    );
    assert_invalid(
        store
            .events_snapshot(EventFilters {
                before: Some(1),
                after: Some(1),
                limit: 1,
                ..EventFilters::default()
            })
            .await,
        "conflicting_event_positions",
    );
    for filters in [
        EventFilters {
            before: Some(u64::MAX),
            limit: 1,
            ..EventFilters::default()
        },
        EventFilters {
            after: Some(u64::MAX),
            limit: 1,
            ..EventFilters::default()
        },
        EventFilters {
            created_after_unix_ms: Some(u64::MAX),
            limit: 1,
            ..EventFilters::default()
        },
    ] {
        assert_invalid(
            store.events_snapshot(filters).await,
            "event_position_out_of_range",
        );
    }

    assert_invalid(
        store.enqueue_notarization("trc-missing", u64::MAX).await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store.claim_next_notarization(u64::MAX).await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store
            .update_operation_progress("op-missing", NotarizationPhase::Signing, u64::MAX)
            .await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store
            .update_operation_proof_progress(
                "op-missing",
                NotarizationProofProgress {
                    bytes_completed: u64::MAX,
                    ..NotarizationProofProgress::default()
                },
                1,
            )
            .await,
        "proof_progress_out_of_range",
    );
    assert_invalid(
        store
            .update_operation_proof_progress(
                "op-missing",
                NotarizationProofProgress {
                    bytes_completed: 2,
                    bytes_total: 1,
                    commitments_completed: 0,
                    commitments_total: 1,
                },
                1,
            )
            .await,
        "invalid_proof_progress",
    );
    assert_invalid(
        store
            .update_operation_proof_progress(
                "op-missing",
                NotarizationProofProgress {
                    bytes_completed: 0,
                    bytes_total: 1,
                    commitments_completed: 2,
                    commitments_total: 1,
                },
                1,
            )
            .await,
        "invalid_proof_progress",
    );
    assert_invalid(
        store
            .complete_notarization(
                "op-missing",
                artifact("trc-missing", ArtifactKind::TracePackage, 1),
                u64::MAX,
            )
            .await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store
            .fail_operation("op-missing", u64::MAX, "failure")
            .await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store.interrupt_running_operations(u64::MAX).await,
        "timestamp_out_of_range",
    );
    assert_invalid(
        store.retry_operation("op-missing", u64::MAX).await,
        "timestamp_out_of_range",
    );

    let mut invalid_capture = new_capture("trc-invalid-capture", u64::MAX);
    assert_invalid(
        store.begin_capture(invalid_capture.clone()).await,
        "capture_created_at_out_of_range",
    );
    invalid_capture.created_at_unix_ms = 1;
    invalid_capture.trace_id = "cap-retired".to_owned();
    assert_invalid(
        store.begin_capture(invalid_capture.clone()).await,
        "invalid_trace_id",
    );
    invalid_capture.trace_id = "trc-invalid-capture".to_owned();
    invalid_capture.request_bytes = usize::MAX;
    if usize::BITS > 63 {
        assert_invalid(
            store.begin_capture(invalid_capture).await,
            "request_bytes_out_of_range",
        );
    }

    store
        .begin_capture(new_capture("trc-invalid-completion", 1))
        .await
        .unwrap();
    let valid_artifact = artifact(
        "trc-invalid-completion",
        ArtifactKind::CaptureCheckpoint,
        10,
    );
    let mut invalid_completion = completion("trc-invalid-completion", u64::MAX, 200);
    assert_invalid(
        store
            .complete_capture(invalid_completion.clone(), valid_artifact.clone())
            .await,
        "capture_completed_at_out_of_range",
    );
    invalid_completion.completed_at_unix_ms = 2;
    invalid_completion.duration_ms = u64::MAX;
    assert_invalid(
        store
            .complete_capture(invalid_completion.clone(), valid_artifact.clone())
            .await,
        "duration_out_of_range",
    );
    invalid_completion.duration_ms = 1;
    invalid_completion.response_bytes = u64::MAX;
    assert_invalid(
        store
            .complete_capture(invalid_completion, valid_artifact.clone())
            .await,
        "response_bytes_out_of_range",
    );
    let mut invalid_expectation = completion("trc-invalid-completion", 2, 200);
    invalid_expectation.expected_artifact_size_bytes = u64::MAX;
    assert_invalid(
        store.prepare_capture_completion(invalid_expectation).await,
        "artifact_size_out_of_range",
    );
    let mut invalid_expectation = completion("trc-invalid-completion", 2, 200);
    invalid_expectation.expected_artifact_sha256 = "NOT-A-DIGEST".to_owned();
    assert_invalid(
        store.prepare_capture_completion(invalid_expectation).await,
        "invalid_expected_artifact_sha256",
    );
    let mut oversized_artifact = valid_artifact;
    let mut invalid_digest = oversized_artifact.clone();
    invalid_digest.size_bytes = 10;
    invalid_digest.sha256 = "not-a-digest".to_owned();
    assert_invalid(
        store
            .complete_capture(completion("trc-invalid-completion", 2, 200), invalid_digest)
            .await,
        "invalid_artifact_record",
    );
    oversized_artifact.size_bytes = u64::MAX;
    assert_invalid(
        store
            .complete_capture(
                completion("trc-invalid-completion", 2, 200),
                oversized_artifact.clone(),
            )
            .await,
        "artifact_size_out_of_range",
    );
    oversized_artifact.key =
        ArtifactKey::new("trc-invalid-completion", ArtifactKind::TracePackage).unwrap();
    assert_invalid(
        store
            .complete_notarization("op-missing", oversized_artifact, 1)
            .await,
        "artifact_size_out_of_range",
    );
}
