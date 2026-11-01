#[tokio::main]
async fn main() -> anyhow::Result<()> {
    capture_notary::run().await
}
