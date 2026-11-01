//! Raw Proxy-TLS notary fixture for the isolated daemon Docker E2E.
//!
//! This binary cannot be built unless the `daemon-e2e` feature is explicit.

use std::{env, fs, sync::Arc};

use anyhow::{Context as _, Result, bail};
use captured::{DEFAULT_NOTARY_MAX_FRAME_BYTES, run_notary_session};
use k256::ecdsa::SigningKey;
use tokio::net::TcpListener;

const LISTEN_ENV: &str = "CAPTURED_E2E_NOTARY_LISTEN";
const SIGNING_KEY_FILE_ENV: &str = "CAPTURED_E2E_SIGNING_KEY_FILE";
const PROVIDER_HOST: &str = "api.openai.com";

#[tokio::main]
async fn main() -> Result<()> {
    let key_path = env::var_os(SIGNING_KEY_FILE_ENV)
        .context("Docker E2E notary signing-key path is required")?;
    let key_text = fs::read_to_string(&key_path)
        .with_context(|| format!("reading Docker E2E signing key at {:?}", key_path))?;
    let key_bytes = hex::decode(key_text.trim()).context("signing key must be hexadecimal")?;
    if key_bytes.len() != 32 {
        bail!("signing key must contain exactly 32 bytes");
    }
    let signing_key =
        Arc::new(SigningKey::from_slice(&key_bytes).context("invalid Docker E2E secp256k1 key")?);
    let allowed_hosts = Arc::new(vec![PROVIDER_HOST.to_owned()]);
    let listen = env::var(LISTEN_ENV).unwrap_or_else(|_| "0.0.0.0:7047".to_owned());
    let listener = TcpListener::bind(&listen)
        .await
        .with_context(|| format!("binding Docker E2E notary at {listen}"))?;

    loop {
        let (socket, _) = listener.accept().await?;
        let signing_key = signing_key.clone();
        let allowed_hosts = allowed_hosts.clone();
        tokio::spawn(async move {
            if let Err(error) = run_notary_session(
                socket,
                signing_key,
                allowed_hosts,
                8 << 20,
                DEFAULT_NOTARY_MAX_FRAME_BYTES,
            )
            .await
            {
                eprintln!("Docker E2E notary session ended: {error:#}");
            }
        });
    }
}
