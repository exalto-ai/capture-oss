fn main() -> anyhow::Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&captured::admin::openapi_document())?
    );
    Ok(())
}
