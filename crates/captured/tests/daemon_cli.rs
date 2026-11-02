#![cfg(target_os = "linux")]

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::PermissionsExt as _,
    process::{Child, Command, Stdio},
    time::Duration,
};

use captured::{
    archive::MAX_ARCHIVE_WIRE_BYTES,
    artifact_store::{ArtifactKey, ArtifactKind, ArtifactSource, ArtifactStore},
    config::CapturedConfig,
    metadata::{CaptureCompletion, EvidenceKind, NewTrace},
    persistence::Persistence,
};

struct Daemon(Option<Child>);

impl Daemon {
    fn graceful_shutdown(&mut self) {
        let child = self.0.as_mut().unwrap();
        let terminated = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(terminated.success(), "could not signal the daemon");
        for _ in 0..200 {
            if child.try_wait().unwrap().is_some() {
                let status = self.0.take().unwrap().wait().unwrap();
                assert!(status.success(), "daemon did not shut down cleanly");
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("daemon did not drain after SIGTERM");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[tokio::test]
async fn daemon_uses_the_versioned_loopback_api_for_reads_and_mutations() {
    let directory = tempfile::tempdir().unwrap();
    let (proxy, admin) = unused_loopback_addresses();
    let mut config = CapturedConfig::default();
    config.proxy.listen = proxy;
    config.admin.listen = admin;
    config.metadata.path = directory.path().join("data/metadata.db");
    config.storage.checkpoint_dir = directory.path().join("data/checkpoints");
    config.storage.package_dir = directory.path().join("data/traces");
    config.notary.endpoint = Some("tcp://127.0.0.1:9".to_owned());
    let signing_key = k256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    config.notary.public_key = Some(hex::encode(
        signing_key.verifying_key().to_sec1_bytes().as_ref(),
    ));
    config.validate().unwrap();

    let persistence = Persistence::open(&config).await.unwrap();
    persistence
        .metadata
        .begin_capture(NewTrace {
            evidence_kind: EvidenceKind::Notarized,
            trace_id: "trc-daemon-cli".to_owned(),
            created_at_unix_ms: 1,
            provider: "openai".to_owned(),
            operation: "/v1/responses".to_owned(),
            requested_model: Some("gpt-test".to_owned()),
            streaming: false,
            request_bytes: 10,
            prompt_preview: "safe fixture".to_owned(),
            prompt_preview_truncated: false,
            config_fingerprint: "sha256:fixture".to_owned(),
        })
        .await
        .unwrap();
    let checkpoint = persistence
        .artifacts
        .put(
            &ArtifactKey::new("trc-daemon-cli", ArtifactKind::CaptureCheckpoint).unwrap(),
            ArtifactSource::from_bytes(b"encrypted test fixture".to_vec()),
            MAX_ARCHIVE_WIRE_BYTES,
        )
        .await
        .unwrap();
    persistence
        .metadata
        .complete_capture(
            CaptureCompletion {
                evidence_kind: EvidenceKind::Notarized,
                trace_id: "trc-daemon-cli".to_owned(),
                completed_at_unix_ms: 2,
                duration_ms: 1,
                http_status: 200,
                response_bytes: 20,
                response_model: Some("gpt-test".to_owned()),
                output_preview: "safe output".to_owned(),
                output_preview_truncated: false,
                expected_artifact_size_bytes: checkpoint.size_bytes,
                expected_artifact_sha256: checkpoint.sha256.clone(),
            },
            checkpoint,
        )
        .await
        .unwrap();
    drop(persistence);

    let config_path = directory.path().join("config.toml");
    fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();
    let passphrase_path = directory.path().join("vault-passphrase");
    fs::write(&passphrase_path, b"test-only-passphrase").unwrap();
    fs::set_permissions(&passphrase_path, fs::Permissions::from_mode(0o600)).unwrap();
    let isolated_config = directory.path().join("xdg-config");
    let isolated_data = directory.path().join("xdg-data");
    let daemon = Command::new(env!("CARGO_BIN_EXE_captured"))
        .args(["--config", config_path.to_str().unwrap()])
        .env("XDG_CONFIG_HOME", &isolated_config)
        .env("XDG_DATA_HOME", &isolated_data)
        .env("CAPTURED_VAULT_PASSPHRASE_FILE", &passphrase_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut daemon = Daemon(Some(daemon));

    let health_url = format!("http://{admin}/healthz");
    let client = reqwest::Client::new();
    let mut ready = false;
    for _ in 0..100 {
        if client
            .get(&health_url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "captured did not become healthy");

    let status: serde_json::Value = client
        .get(format!("http://{admin}/v1/status"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["admin_listener"], admin.to_string());
    assert_eq!(status["counts"]["captured"], 1);
    assert_eq!(status["counts"]["notarizing"], 0);
    assert_eq!(status["updates"]["current_build_id"], "dev");
    assert_eq!(status["updates"]["enabled"], false);

    let capture: serde_json::Value = client
        .get(format!("http://{admin}/v1/traces/trc-daemon-cli"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(capture["state"], "captured");
    assert_eq!(capture["status"], serde_json::Value::Null);

    let notarize: serde_json::Value = client
        .post(format!(
            "http://{admin}/v1/traces/trc-daemon-cli/notarizations"
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(notarize["operation"]["trace_id"], "trc-daemon-cli");
    assert!(
        notarize["operation"]["operation_id"]
            .as_str()
            .unwrap()
            .starts_with("op-")
    );
    daemon.graceful_shutdown();
}

fn unused_loopback_addresses() -> (SocketAddr, SocketAddr) {
    let first = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let second = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let first_port = first.local_addr().unwrap().port();
    let second_port = second.local_addr().unwrap().port();
    drop((first, second));
    (
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), first_port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), second_port),
    )
}
