use std::env;
use std::path::PathBuf;

use anyhow::Result;
use libbpf_cargo::SkeletonBuilder;

fn main() -> Result<()> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let repo_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("crate is nested under repo root");
    let source = repo_root.join("bpf/proc.bpf.c");
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    let obj = out_dir.join("proc.bpf.o");
    let skel = out_dir.join("proc.skel.rs");

    println!("cargo:rerun-if-changed={}", source.display());
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("bpf/vmlinux.h").display()
    );

    // Build and generate the skeleton from the repo-root BPF source so the Rust
    // crate can ship a compiled object plus bindings without manual sync work.
    let mut builder = SkeletonBuilder::new();
    builder.source(&source).obj(&obj).clang_args([
        format!("-I{}", repo_root.join("bpf").display()),
        "-Wno-compare-distinct-pointer-types".to_string(),
    ]);
    builder.build()?;
    builder.generate(&skel)?;

    Ok(())
}
