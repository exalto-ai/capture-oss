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
    tauri_build::build()
}
