//! Integration tests for enforcement_pack lints.
//!
//! These tests run `cargo dylint` on test files and verify the output.
//! This approach tests the lints as they're actually used in practice.

use std::process::Command;

#[test]
fn test_no_println_catches_violations() {
    let output = Command::new("cargo")
        .args(&[
            "dylint",
            "--lib",
            "enforcement_pack",
            "--",
            "--manifest-path",
            "Cargo.toml",
        ])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.."))
        .output()
        .expect("Failed to run cargo dylint");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // The lint should pass on the main codebase (no println!/eprintln!/dbg!)
    assert!(
        output.status.success(),
        "dylint should pass on main codebase, got: {}",
        stderr
    );
}

#[test]
fn test_no_println_lint_is_registered() {
    let output = Command::new("cargo")
        .args(&["dylint", "list", "--lib", "enforcement_pack"])
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../../.."))
        .output()
        .expect("Failed to run cargo dylint list");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("enforcement_pack::no_println"),
        "no_println lint should be registered"
    );
    assert!(
        stdout.contains("deny"),
        "no_println lint should be at deny level"
    );
}
