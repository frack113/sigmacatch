// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 sigmacatch contributors

//! Build script for the `ebpf` feature: produces the probe object embedded
//! by `src/ebpf.rs` via `include_bytes!`.
//!
//! Resolution order:
//! 1. `SIGMACATCH_EBPF_OBJECT` env override (prebuilt artifact);
//! 2. build the standalone nightly crate `crates/sigmacatch-ebpf` if the
//!    toolchain (nightly + rust-src + bpf-linker) is available;
//! 3. otherwise emit an empty placeholder — the loader will reject it at
//!    startup and collection falls back to the legacy syslog tail.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const OBJECT_NAME: &str = "sigmacatch_ebpf.o";
const PROBE_CRATE_DIR: &str = "../crates/sigmacatch-ebpf";
const PROBE_ARTIFACT: &str = "target/bpfel-unknown-none/release/sigmacatch-ebpf";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=SIGMACATCH_EBPF_OBJECT");
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    // Always-on execution trace: proves which binary revision runs and what
    // it sees (feature flags arrive via env, not compile-time cfg here).
    let _ = fs::write(
        out_dir.join("ebpf_script_trace.txt"),
        format!("ebpf_feature_env={:?}\n", env::var("CARGO_FEATURE_EBPF")),
    );
    // Build-script warnings are denied workspace-wide (Q7.1): every outcome
    // below is silent here and surfaced at runtime by src/ebpf.rs instead.
    if env::var("CARGO_FEATURE_EBPF").is_err() {
        return;
    }
    let dest = out_dir.join(OBJECT_NAME);

    if let Some(prebuilt) = env::var_os("SIGMACATCH_EBPF_OBJECT") {
        copy_object(Path::new(&prebuilt), &dest);
        return;
    }

    match build_probes(&manifest_dir.join(PROBE_CRATE_DIR), &out_dir) {
        Ok(artifact) => copy_object(&artifact, &dest),
        Err(reason) => {
            // Placeholder: the loader rejects it at startup and collection
            // falls back to the legacy syslog tail ("built without nightly
            // toolchain?" in the runtime error).
            let _ = fs::write(out_dir.join("ebpf_build_failure.txt"), &reason);
            fs::write(&dest, []).expect("write placeholder object");
        }
    }
}

fn copy_object(src: &Path, dest: &Path) {
    let bytes = fs::read(src).unwrap_or_else(|e| panic!("read eBPF object {}: {e}", src.display()));
    fs::write(dest, bytes).expect("write embedded object");
}

fn build_probes(crate_dir: &Path, _out_dir: &Path) -> Result<PathBuf, String> {
    if !crate_dir.join("Cargo.toml").is_file() {
        return Err(format!("missing crate dir {}", crate_dir.display()));
    }
    // Resolve the nightly cargo binary directly: rustup proxies in the
    // build-script environment have proven unreliable at honoring both
    // `rustup run` and RUSTUP_TOOLCHAIN under the parent cargo's exported
    // environment.
    // Resolve the nightly cargo binary directly: rustup proxies in the
    // build-script environment have proven unreliable at honoring both
    // `rustup run` and RUSTUP_TOOLCHAIN under the parent cargo's exported
    // environment.
    let nightly_cargo = Command::new("rustup")
        .args(["which", "--toolchain", "nightly", "cargo"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "cannot resolve nightly cargo via rustup which".to_string())?;

    let mut cmd = Command::new(nightly_cargo);
    // Run from the crate dir so its own `.cargo/config.toml` (bpfel target,
    // bpf-linker linker, build-std) is picked up — the workspace root config
    // must not leak into this excluded-crate build.
    //
    // RUSTC_BOOTSTRAP enables -Z build-std regardless of channel detection.
    cmd.arg("build")
        .arg("--release")
        .arg("-Z")
        .arg("build-std=core")
        .current_dir(crate_dir)
        .env("RUSTUP_TOOLCHAIN", "nightly")
        .env("RUSTC_BOOTSTRAP", "1");
    // Nested cargo must not inherit this cargo's toolchain plumbing: the
    // parent exports RUSTC/RUSTDOC/CARGO as ABSOLUTE stable-toolchain paths
    // (note: no `CARGO_` prefix, so the sweep below misses them — they are
    // removed explicitly). A nightly cargo driving the stable rustc is
    // exactly how build-std fails with "rust-src does not exist".
    for key in [
        "RUSTC",
        "RUSTDOC",
        "CARGO",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "MAKEFLAGS",
        "MFLAGS",
        "CARGO_MAKEFLAGS",
    ] {
        cmd.env_remove(key);
    }
    for (key, _) in env::vars() {
        if key.starts_with("CARGO_") {
            cmd.env_remove(key);
        }
    }

    let output = cmd.output().map_err(|e| format!("spawn cargo: {e}"))?;
    if !output.status.success() {
        // Best-effort: a broken/unavailable nightly toolchain (e.g. a floating
        // `nightly` whose rust-src no longer resolves for `bpfel-unknown-none`)
        // must not hard-fail the whole binary build. Surface the failure via
        // the placeholder path so the loader can fall back to syslog at runtime.
        return Err(format!(
            "ebpf subbuild failed\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let artifact = crate_dir.join(PROBE_ARTIFACT);
    if !artifact.is_file() {
        return Err(format!("artifact missing at {}", artifact.display()));
    }
    Ok(artifact)
}
