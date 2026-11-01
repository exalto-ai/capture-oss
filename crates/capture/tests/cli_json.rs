use std::process::Command;

#[test]
fn json_mode_formats_argument_errors_without_plain_text() {
    let output = Command::new(env!("CARGO_BIN_EXE_capture"))
        .args(["--json", "not-a-command"])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "invalid_arguments");
    assert!(
        value["error"]["message"]
            .as_str()
            .unwrap()
            .contains("not-a-command")
    );
}
