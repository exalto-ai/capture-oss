//! Abort-safe regression tests for JSON transcript parsing on bounded stacks.
//!
//! Every application path that touches a plaintext transcript —
//! capture-completion budget enforcement, notarization, and local
//! presentation — funnels through `HttpTranscript::parse` and therefore the
//! `spansy` JSON parser. That parser previously recursed once per JSON escape
//! and per nesting level, so a realistic escape-dense LLM request overflowed
//! the client runtime stack and aborted the whole proxy process. The vendored
//! parser patch makes string scanning iterative and bounds nesting depth;
//! these tests pin that behavior.
//!
//! A stack overflow aborts the process rather than unwinding, so every
//! workload that would crash if the parser regressed runs in a re-executed
//! child copy of this test binary on a thread with a default-runtime-sized
//! stack. A regression then fails the parent's exit-status assertion instead
//! of killing the test runner.

use std::process::Command;

use capture_core::DEFAULT_MAX_ATTESTABLE_HTTP_BYTES;
use tlsn::transcript::Transcript;
use tlsn_formats::{
    http::{BodyContent, HttpTranscript},
    spansy::Span,
};

/// Set in the child process so the selected test runs its workload inline
/// instead of spawning another generation.
const CHILD_ENV: &str = "CAPTURE_TEST_JSON_STACK_SAFETY_CHILD";

/// Matches the default Tokio worker stack the client runtime uses; the parser
/// must fit within it with margin, not within a one-off enlarged stack.
const WORKLOAD_STACK_BYTES: usize = 2 << 20;

/// Byte size of the request that overflowed the unpatched parser in
/// production-shaped load testing: 544,933 bytes holding ~127,688 input
/// tokens of source-code-heavy prompt.
const REPRO_REQUEST_BYTES: usize = 544_933;

/// Returns `true` inside the re-executed child process.
fn in_child() -> bool {
    std::env::var_os(CHILD_ENV).is_some()
}

/// Runs `test_name` of this binary in a child process and asserts a clean
/// exit. A stack overflow in the child becomes an ordinary failed assertion.
fn assert_child_completes(test_name: &str) {
    let exe = std::env::current_exe().expect("locate test binary");
    // `--include-ignored` so opt-in (`#[ignore]`) workloads also run in the
    // child; without it the child would skip them and report a false pass.
    let status = Command::new(exe)
        .args([
            test_name,
            "--exact",
            "--nocapture",
            "--test-threads=1",
            "--include-ignored",
        ])
        .env(CHILD_ENV, "1")
        .status()
        .expect("spawn child test process");
    assert!(
        status.success(),
        "child process running {test_name} exited with {status}; \
         a non-zero exit here usually means the JSON parser overflowed its stack again"
    );
}

/// Runs the workload on a thread with a default-runtime-sized stack so the
/// test measures the parser, not an enlarged stack.
fn run_on_runtime_sized_stack(workload: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(WORKLOAD_STACK_BYTES)
        .spawn(workload)
        .expect("spawn workload thread")
        .join()
        .expect("workload thread panicked");
}

/// JSON text (raw bytes as matched by the parser) for a string dense in
/// escapes, resembling an LLM prompt full of quoted source code. Each
/// 16-byte unit carries three escapes, so the known reproduction size below
/// exercises ~100,000 escapes — at or above the escape count that crashed the
/// unpatched parser.
fn escape_dense_json_string(target_bytes: usize) -> String {
    const UNIT: &str = "\\\"word\\\"\\nplain "; // JSON text: \"word\"\nplain␠
    let mut text = UNIT.repeat(target_bytes / UNIT.len());
    text.push_str(&"x".repeat(target_bytes - text.len()));
    debug_assert_eq!(text.len(), target_bytes);
    text
}

fn openai_shaped_request(prompt_json_text: &str) -> Vec<u8> {
    let body = format!(
        "{{\"model\":\"gpt-5\",\"max_output_tokens\":2048,\
         \"input\":[{{\"role\":\"user\",\"content\":\"{prompt_json_text}\"}}]}}"
    );
    let mut message = format!(
        "POST /v1/responses HTTP/1.1\r\n\
         host: api.openai.com\r\n\
         authorization: Bearer sk-test-fixture\r\n\
         content-type: application/json\r\n\
         content-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    message.extend_from_slice(body.as_bytes());
    message
}

fn openai_shaped_response(output_json_text: &str) -> Vec<u8> {
    let body = format!(
        "{{\"id\":\"resp_fixture\",\"object\":\"response\",\
         \"output\":[{{\"type\":\"message\",\"role\":\"assistant\",\
         \"content\":[{{\"type\":\"output_text\",\"text\":\"{output_json_text}\"}}]}}]}}"
    );
    let mut message = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    message.extend_from_slice(body.as_bytes());
    message
}

/// A response framed as `Transfer-Encoding: chunked` with the JSON body split
/// into many small chunks, forcing the parser onto a non-contiguous view.
fn chunked_json_response(body: &[u8], chunk_bytes: usize) -> Vec<u8> {
    let mut message =
        b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n"
            .to_vec();
    for chunk in body.chunks(chunk_bytes) {
        message.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        message.extend_from_slice(chunk);
        message.extend_from_slice(b"\r\n");
    }
    message.extend_from_slice(b"0\r\n\r\n");
    message
}

fn sse_response(events: usize) -> Vec<u8> {
    let mut body = Vec::new();
    for index in 0..events {
        body.extend_from_slice(
            format!("data: {{\"delta\": \"chunk {index} \\\"quoted\\\"\\\\n\"}}\n\n").as_bytes(),
        );
    }
    let mut message =
        b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n"
            .to_vec();
    for chunk in body.chunks(97) {
        message.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        message.extend_from_slice(chunk);
        message.extend_from_slice(b"\r\n");
    }
    message.extend_from_slice(b"0\r\n\r\n");
    message
}

fn parse_single_roundtrip(sent: Vec<u8>, received: Vec<u8>) -> HttpTranscript {
    let transcript = Transcript::new(sent, received);
    let http = HttpTranscript::parse(&transcript).expect("parse HTTP transcript");
    assert_eq!(http.requests.len(), 1, "fixture must hold one request");
    assert_eq!(http.responses.len(), 1, "fixture must hold one response");
    http
}

fn json_body(http: &HttpTranscript, request: bool) -> tlsn_formats::spansy::json::Document {
    let body = if request {
        http.requests[0].body.as_ref()
    } else {
        http.responses[0].body.as_ref()
    }
    .expect("fixture has a body");
    let BodyContent::Json(document) = &body.content else {
        panic!("fixture body must be parsed as JSON");
    };
    document.clone()
}

/// The production failure: a ~545 KiB escape-dense JSON request with a
/// meaningful JSON response, parsed on a default-runtime-sized stack.
#[test]
fn escaped_string_reproduction_parses() {
    if !in_child() {
        assert_child_completes("escaped_string_reproduction_parses");
        return;
    }
    run_on_runtime_sized_stack(|| {
        let prompt = escape_dense_json_string(REPRO_REQUEST_BYTES);
        let output = escape_dense_json_string(32 * 1024);
        let http = parse_single_roundtrip(
            openai_shaped_request(&prompt),
            openai_shaped_response(&output),
        );
        let request = json_body(&http, true);
        assert_eq!(
            request
                .get("input.0.content")
                .expect("prompt field")
                .view()
                .len(),
            prompt.len(),
            "the prompt span must cover every escaped byte"
        );
        let response = json_body(&http, false);
        assert_eq!(
            response
                .get("output.0.content.0.text")
                .expect("output text field")
                .view()
                .len(),
            output.len()
        );
    });
}

/// A large JSON string with no escapes at all; the common case must stay
/// correct and fast.
#[test]
fn large_unescaped_string_parses() {
    if !in_child() {
        assert_child_completes("large_unescaped_string_parses");
        return;
    }
    run_on_runtime_sized_stack(|| {
        let prompt = "lorem ipsum dolor sit amet ".repeat(40_000);
        let http = parse_single_roundtrip(
            openai_shaped_request(&prompt),
            openai_shaped_response("done"),
        );
        let request = json_body(&http, true);
        assert_eq!(
            request.get("input.0.content").unwrap().view().len(),
            prompt.len()
        );
    });
}

/// Escape-dense JSON delivered as many small `Transfer-Encoding: chunked`
/// pieces: the parser sees a non-contiguous view of the same bytes.
#[test]
fn chunked_escape_dense_response_parses() {
    if !in_child() {
        assert_child_completes("chunked_escape_dense_response_parses");
        return;
    }
    run_on_runtime_sized_stack(|| {
        let output = escape_dense_json_string(256 * 1024);
        let response_body = format!(
            "{{\"id\":\"resp_fixture\",\"output\":[{{\"type\":\"message\",\
             \"content\":[{{\"type\":\"output_text\",\"text\":\"{output}\"}}]}}]}}"
        );
        let http = parse_single_roundtrip(
            openai_shaped_request("ping"),
            chunked_json_response(response_body.as_bytes(), 113),
        );
        let response = json_body(&http, false);
        let text = response.get("output.0.content.0.text").unwrap();
        assert_eq!(text.view().len(), output.len());
        assert!(
            !text.view().is_contiguous(),
            "the fixture must actually exercise the non-contiguous path"
        );
    });
}

/// SSE-shaped streaming traffic is not JSON to the parser and must pass
/// through untouched regardless of how much JSON-looking text it carries.
#[test]
fn sse_stream_stays_opaque() {
    if !in_child() {
        assert_child_completes("sse_stream_stays_opaque");
        return;
    }
    run_on_runtime_sized_stack(|| {
        let http = parse_single_roundtrip(openai_shaped_request("ping"), sse_response(2_000));
        let body = http.responses[0].body.as_ref().expect("response body");
        assert!(
            matches!(body.content, BodyContent::Unknown),
            "text/event-stream must not enter the JSON parser"
        );
    });
}

/// Nesting one level past the documented limit must be a typed parse error,
/// never an abort; the depth used here would overflow the workload stack if
/// the limit were removed.
#[test]
fn excessive_nesting_is_a_typed_error() {
    if !in_child() {
        assert_child_completes("excessive_nesting_is_a_typed_error");
        return;
    }
    run_on_runtime_sized_stack(|| {
        let depth = 50_000;
        let mut body = "[".repeat(depth);
        body.push_str(&"]".repeat(depth));
        let mut message = format!(
            "POST /v1/responses HTTP/1.1\r\nhost: api.openai.com\r\n\
             content-type: application/json\r\ncontent-length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        message.extend_from_slice(body.as_bytes());
        let transcript = Transcript::new(message, openai_shaped_response("ok"));
        let error = HttpTranscript::parse(&transcript).expect_err("over-limit nesting must fail");
        assert!(
            error.to_string().contains("nesting depth"),
            "unexpected error: {error}"
        );
    });
}

/// Nesting at the documented limit is accepted, and brackets inside strings
/// never count toward it. Safe to run inline: even without the depth check,
/// this depth cannot overflow any stack.
#[test]
fn nesting_at_the_limit_parses() {
    use tlsn_formats::spansy::json::{self, MAX_NESTING_DEPTH};

    let mut body = "[".repeat(MAX_NESTING_DEPTH - 1);
    body.push_str(&"]".repeat(MAX_NESTING_DEPTH - 1));
    let document = json::parse(body.as_bytes()).expect("nesting at the limit parses");

    let mut bracket_heavy = String::from("{\"s\": \"");
    for _ in 0..1_000 {
        bracket_heavy.push_str("[{\\\"}]");
    }
    bracket_heavy.push_str("\"}");
    let shallow = json::parse(bracket_heavy.as_bytes()).expect("string brackets are not nesting");
    assert_eq!(shallow.get("s").unwrap().view().len(), 6_000);
    drop(document);
}

/// Opt-in envelope proof: escape-dense JSON at the application's enforced
/// 15 MiB attestable budget in request-heavy, response-heavy, and balanced
/// shapes. Run explicitly with:
///
/// `cargo test -p capture-core --test json_stack_safety -- --ignored --nocapture`
#[test]
#[ignore = "envelope resource profile; invoke explicitly"]
fn escape_dense_json_parses_through_the_full_attestable_envelope() {
    if !in_child() {
        assert_child_completes("escape_dense_json_parses_through_the_full_attestable_envelope");
        return;
    }
    run_on_runtime_sized_stack(|| {
        let budget = DEFAULT_MAX_ATTESTABLE_HTTP_BYTES;
        for (request_bytes, response_bytes) in [
            (budget, 4 * 1024),       // request-heavy
            (4 * 1024, budget),       // response-heavy
            (budget / 2, budget / 2), // balanced
        ] {
            let prompt = escape_dense_json_string(request_bytes);
            let output = escape_dense_json_string(response_bytes);
            let http = parse_single_roundtrip(
                openai_shaped_request(&prompt),
                openai_shaped_response(&output),
            );
            assert_eq!(
                json_body(&http, true)
                    .get("input.0.content")
                    .unwrap()
                    .view()
                    .len(),
                prompt.len()
            );
            assert_eq!(
                json_body(&http, false)
                    .get("output.0.content.0.text")
                    .unwrap()
                    .view()
                    .len(),
                output.len()
            );
        }
    });
}
