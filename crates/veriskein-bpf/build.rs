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
    let out_dir = PathBuf::from(env::var("OUT_DIR")?);
    println!(
        "cargo:rerun-if-changed={}",
        repo_root.join("bpf/vmlinux.h").display()
    );

    for stem in ["proc", "fs", "net"] {
        let source = repo_root.join(format!("bpf/{stem}.bpf.c"));
        let obj = out_dir.join(format!("{stem}.bpf.o"));
        println!("cargo:rerun-if-changed={}", source.display());

        let mut builder = SkeletonBuilder::new();
        builder.source(&source).obj(&obj).clang_args([
            format!("-I{}", repo_root.join("bpf").display()),
            "-Wno-compare-distinct-pointer-types".to_string(),
        ]);
        builder.build()?;
    }

    Ok(())
}
