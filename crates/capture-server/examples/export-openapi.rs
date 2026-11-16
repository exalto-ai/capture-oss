//! Prints the server's OpenAPI contract, committed as `openapi.json` beside
//! this crate's manifest.

#![expect(clippy::print_stdout, reason = "the example prints the contract")]

fn main() -> anyhow::Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&capture_server::admin::openapi_document())?
    );
    Ok(())
}
