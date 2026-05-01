check:
    cargo fmt --check
    cargo clippy --workspace --all-targets --all-features
    cargo test --workspace

