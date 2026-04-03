use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let build_version = match resolve_git_revision() {
        Some(revision) => format!("{version} ({revision})"),
        None => version,
    };

    println!("cargo:rustc-env=KITEPASS_BUILD_VERSION={build_version}");
    emit_git_rerun_hints();
}

fn resolve_git_revision() -> Option<String> {
    let workspace_root = workspace_root();
    run_git(&workspace_root, &["rev-parse", "--short=8", "HEAD"]).or_else(|| {
        env::var("GITHUB_SHA")
            .ok()
            .map(|sha| sha.chars().take(8).collect::<String>())
            .filter(|sha| !sha.is_empty())
    })
}

fn emit_git_rerun_hints() {
    let git_dir = workspace_root().join(".git");
    if !git_dir.exists() {
        return;
    }

    println!("cargo:rerun-if-changed={}", git_dir.display());

    let head_path = git_dir.join("HEAD");
    if !head_path.exists() {
        return;
    }

    println!("cargo:rerun-if-changed={}", head_path.display());

    if let Ok(head) = fs::read_to_string(&head_path) {
        if let Some(reference) = head.strip_prefix("ref: ").map(str::trim) {
            let reference_path = git_dir.join(reference);
            if reference_path.exists() {
                println!("cargo:rerun-if-changed={}", reference_path.display());
            }
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(&env::var("CARGO_MANIFEST_DIR").expect("manifest dir should exist"))
        .ancestors()
        .nth(2)
        .expect("workspace root should exist")
        .to_path_buf()
}

fn run_git(repo_root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_root)
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let value = String::from_utf8(output.stdout).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
