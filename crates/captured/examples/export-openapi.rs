//! Prints the server's OpenAPI contract, committed as `openapi.json` beside
//! this crate's manifest.

fn main() -> anyhow::Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&captured::admin::openapi_document())?
    );
    Ok(())
}
