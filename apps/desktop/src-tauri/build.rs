fn main() {
    println!("cargo:rerun-if-env-changed=CAPTURE_BUILD_ID");
    println!("cargo:rerun-if-env-changed=CAPTURE_UPDATES_ENABLED");
    let build_id = std::env::var("CAPTURE_BUILD_ID").unwrap_or_else(|_| "dev".into());
    assert!(
        !build_id.is_empty()
            && !build_id.starts_with('.')
            && !build_id.contains("..")
            && build_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "CAPTURE_BUILD_ID must be a safe non-empty release identifier"
    );
    println!("cargo:rustc-env=CAPTURE_BUILD_ID={build_id}");
    let updates_enabled = std::env::var("CAPTURE_UPDATES_ENABLED").unwrap_or_else(|_| "0".into());
    assert!(
        matches!(updates_enabled.as_str(), "0" | "1"),
        "CAPTURE_UPDATES_ENABLED must be 0 or 1"
    );
    println!("cargo:rustc-env=CAPTURE_UPDATES_ENABLED={updates_enabled}");
    allow_plain_cargo_without_sidecar();
    tauri_build::build()
}

/// Lets `cargo check`, `clippy`, and `test` run before
/// `npm run prepare:sidecar:*` has produced the bundled `captured`; tauri-build
/// otherwise fails because `bundle.externalBin` names a missing file.
///
/// Only this build script's view of the configuration changes. The embedded
/// app context and the Tauri bundler still read `tauri.conf.json`, and Tauri
/// CLI builds (`tauri dev`, `tauri build`), which set `TAURI_CLI_VERBOSITY`,
/// keep the strict check, so a missing sidecar still fails loudly there.
fn allow_plain_cargo_without_sidecar() {
    let target = std::env::var("TARGET").expect("cargo sets TARGET");
    let extension = if target.contains("windows") {
        ".exe"
    } else {
        ""
    };
    let sidecar = format!("binaries/captured-{target}{extension}");
    println!("cargo:rerun-if-changed={sidecar}");
    println!("cargo:rerun-if-env-changed=TAURI_CLI_VERBOSITY");
    if std::path::Path::new(&sidecar).exists()
        || std::env::var_os("TAURI_CLI_VERBOSITY").is_some()
        || std::env::var_os("TAURI_CONFIG").is_some()
    {
        return;
    }
    println!(
        "cargo:warning={sidecar} is missing, so this cargo build skips the sidecar copy. \
         Run `npm run prepare:sidecar:debug` in apps/desktop before running the app."
    );
    // tauri-build merges TAURI_CONFIG into tauri.conf.json, and null removes the key.
    // SAFETY: the build script is single-threaded.
    unsafe { std::env::set_var("TAURI_CONFIG", r#"{"bundle":{"externalBin":null}}"#) };
}
