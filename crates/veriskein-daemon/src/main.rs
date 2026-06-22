#[tokio::main]
async fn main() {
    if let Err(err) = veriskein_daemon::main_entry().await {
        eprintln!("{err:#}");
        std::process::exit(1);
    }
}
