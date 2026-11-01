#[tokio::main]
async fn main() {
    if let Err(error) = capture::run().await {
        if !error.is_reported() {
            eprintln!("{error}");
        }
        std::process::exit(error.exit_code());
    }
}
