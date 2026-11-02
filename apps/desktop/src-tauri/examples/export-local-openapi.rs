//! Prints the local service's OpenAPI contract, which the dashboard commits
//! and generates its client from.

fn main() -> anyhow::Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&capture_app::service::admin::openapi_document())?
    );
    Ok(())
}
