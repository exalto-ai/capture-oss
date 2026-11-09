//! The server binary's startup contract.
#![cfg(target_os = "linux")]

use std::{fs, process::Command};

use capture_server::config::CapturedConfig;

#[test]
fn local_configurations_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("config.toml");
    fs::write(
        &config_path,
        toml::to_string_pretty(&CapturedConfig::default()).unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_capture-server"))
        .args(["--config", config_path.to_str().unwrap()])
        .env("XDG_CONFIG_HOME", directory.path().join("xdg-config"))
        .env("XDG_DATA_HOME", directory.path().join("xdg-data"))
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("capture-server runs only as a server"),
        "unexpected startup failure: {stderr}"
    );
}
