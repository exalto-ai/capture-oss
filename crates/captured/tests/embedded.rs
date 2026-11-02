//! The local service run inside an application's process, as the desktop app
//! runs it. A separate test binary, so it can isolate the process environment.
#![cfg(target_os = "linux")]

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    sync::Arc,
    time::Duration,
};

use captured::{EmbeddedHost, config::CapturedConfig, run_embedded, vault::Vault};

#[test]
fn embedded_service_serves_until_its_host_asks_it_to_stop() {
    let directory = tempfile::tempdir().unwrap();
    // SAFETY: this is the binary's only test, and it sets the environment
    // before starting any other thread.
    unsafe {
        std::env::set_var("XDG_CONFIG_HOME", directory.path().join("xdg-config"));
        std::env::set_var("XDG_DATA_HOME", directory.path().join("xdg-data"));
    }
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
    let config_path = directory.path().join("config.toml");
    fs::write(&config_path, toml::to_string_pretty(&config).unwrap()).unwrap();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let service = tokio::spawn(run_embedded(
            Some(config_path),
            EmbeddedHost {
                vault: Arc::new(Vault::test_only()),
                shutdown: Box::pin(async {
                    let _ = stopped.await;
                }),
            },
        ));

        let client = reqwest::Client::new();
        for url in [
            format!("http://{admin}/healthz"),
            format!("http://{proxy}/healthz"),
        ] {
            let mut ready = false;
            for _ in 0..100 {
                if client
                    .get(&url)
                    .send()
                    .await
                    .is_ok_and(|response| response.status().is_success())
                {
                    ready = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(ready, "{url} did not become healthy");
        }
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
        assert_eq!(status["proxy_listener"], proxy.to_string());
        assert_eq!(status["notary"], "configured");

        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(30), service)
            .await
            .expect("the service did not drain after its host asked it to stop")
            .unwrap()
            .unwrap();
    });
    // Both listeners are released once the service returns.
    TcpListener::bind(proxy).unwrap();
    TcpListener::bind(admin).unwrap();
}

fn unused_loopback_addresses() -> (SocketAddr, SocketAddr) {
    let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let first_port = first.local_addr().unwrap().port();
    let second_port = second.local_addr().unwrap().port();
    drop((first, second));
    (
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), first_port),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), second_port),
    )
}
