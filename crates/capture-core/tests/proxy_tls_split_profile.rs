//! Opt-in, split-container resource benchmark for the production capture and
//! notarization protocol.
//!
//! Run a memory-limited `capture-notary serve --profile-sessions` container, then
//! run this test from a separate client container on the same Docker network.
//! The test deliberately sends an invalid, synthetic OpenAI credential: the
//! provider should reject it, but the request and response still exercise the
//! full Proxy-TLS capture and notarization paths without using an API
//! key or creating a billable inference.
//!
//! Example:
//! `TLSN_PROFILE_TOKENS=32768 TLSN_NOTARY_ADDR=notary:7047 \
//!   TLSN_NOTARY_PUBLIC_KEY=<compressed-sec1-hex> \
//!   cargo test --release -p capture-core --test proxy_tls_split_profile -- --ignored --nocapture`

use std::{env, time::Instant};

use anyhow::{Context, Result};
use capture_core::{
    CaptureConfig, DEFAULT_MAX_ATTESTABLE_HTTP_BYTES, DEFAULT_NOTARY_MAX_FRAME_BYTES,
    capture_streaming_request, chunked_request_body, notarize_capture_checkpoint,
    registry::{NotaryEndpoint, NotaryTransport},
};
use http::Request;
use hyper::body::Bytes;
use tiktoken_rs::o200k_base;

const DEFAULT_PROFILE_TOKENS: usize = 32_768;
const OPENAI_PROFILE_HOST: &str = "api.openai.com";

fn profile_tokens() -> Result<usize> {
    env::var("TLSN_PROFILE_TOKENS")
        .unwrap_or_else(|_| DEFAULT_PROFILE_TOKENS.to_string())
        .parse()
        .context("TLSN_PROFILE_TOKENS must be an unsigned token count")
}

fn body(tokens: usize) -> Result<Bytes> {
    let input = " a".repeat(tokens);
    let tokenizer = o200k_base().context("load the o200k_base tokenizer")?;
    let actual = tokenizer.encode_with_special_tokens(&input).len();
    anyhow::ensure!(actual == tokens, "expected {tokens} tokens, got {actual}");
    Ok(Bytes::from(format!(
        r#"{{"model":"gpt-4.1-nano","input":"{input}"}}"#
    )))
}

fn notary_public_key() -> Result<Vec<u8>> {
    let key = env::var("TLSN_NOTARY_PUBLIC_KEY")
        .context("TLSN_NOTARY_PUBLIC_KEY is required for the split profile")?;
    hex::decode(key).context("TLSN_NOTARY_PUBLIC_KEY must be hexadecimal")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "resource benchmark; run in separate client and notary containers"]
async fn profiles_capture_and_notarization_in_a_separate_notary_container() -> Result<()> {
    let tokens = profile_tokens()?;
    let body = body(tokens)?;
    let notary_endpoint = env::var("TLSN_NOTARY_ADDR").unwrap_or_else(|_| "notary:7047".to_owned());
    let notary_addr = tokio::net::lookup_host(&notary_endpoint)
        .await
        .with_context(|| format!("resolve TLSN_NOTARY_ADDR {notary_endpoint}"))?
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!("TLSN_NOTARY_ADDR {notary_endpoint} resolved to no addresses")
        })?;
    let notary = NotaryEndpoint::new(
        notary_addr.ip().to_string(),
        notary_addr.port(),
        NotaryTransport::Tcp,
    )?;
    let request = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("content-type", "application/json")
        // This is intentionally not a credential. The provider's 401/4xx
        // response still gives us an authenticated, representative transcript.
        .header("authorization", "Bearer notary-profile-invalid-key")
        .body(chunked_request_body(body.clone()))?;

    let capture_started = Instant::now();
    let mut response = capture_streaming_request(
        &notary,
        OPENAI_PROFILE_HOST,
        CaptureConfig {
            trace_id: "profile-capture".to_owned(),
            provider_name: "openai".to_owned(),
            created_at_unix_ms: 1,
            request_body_bytes: body.len(),
            max_attestable_http_bytes: DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
            max_frame_bytes: DEFAULT_NOTARY_MAX_FRAME_BYTES,
        },
        request,
        None,
    )
    .await?;
    let provider_status = response.status;
    let mut provider_response_bytes = 0usize;
    while let Some(chunk) = response.body.recv().await {
        provider_response_bytes += chunk?.len();
    }
    let checkpoint = response.checkpoint.await??;
    let capture_ms = capture_started.elapsed().as_millis();

    let notarization_started = Instant::now();
    let proof = notarize_capture_checkpoint(
        &notary,
        &checkpoint,
        &notary_public_key()?,
        DEFAULT_MAX_ATTESTABLE_HTTP_BYTES,
        DEFAULT_NOTARY_MAX_FRAME_BYTES,
        None,
        &|_| {},
    )
    .await?;
    let notarization_ms = notarization_started.elapsed().as_millis();

    eprintln!(
        "split_proxy_tls_profile tokens={tokens} request_bytes={} provider_status={provider_status} provider_response_bytes={provider_response_bytes} proof_bytes={} capture_ms={capture_ms} client_notarize_ms={notarization_ms}",
        body.len(),
        bincode::serialized_size(&proof)?,
    );
    Ok(())
}
