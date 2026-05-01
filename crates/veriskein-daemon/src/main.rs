#[tokio::main]
async fn main() {
    if let Err(err) = veriskein_daemon::main_entry().await {
        // Keep the binary wrapper tiny so the library owns actual startup
        // behavior and remains directly testable.
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
