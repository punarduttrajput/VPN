use std::path::{Path, PathBuf};

fn main() {
    copy_wintun();
    tauri_build::build()
}

/// On Windows the data plane loads `wintun.dll` at runtime from the standard DLL
/// search path (the `wintun` crate calls `LoadLibrary`), so the DLL must sit next
/// to the executable. Copy the vendored, signed DLL (`vendor/wintun/<arch>/`) into
/// the build's profile dir so dev runs (`cargo run` / `tauri dev`) find it.
/// Installer bundling for release builds is handled separately via
/// `tauri.conf.json` bundle resources.
fn copy_wintun() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "amd64",
        Ok("aarch64") => "arm64",
        other => {
            println!("cargo:warning=wintun.dll: unsupported target arch {other:?}; not copying");
            return;
        }
    };
    let repo_root = PathBuf::from(env_var("CARGO_MANIFEST_DIR")).join("../../..");
    let rel = format!("vendor/wintun/{arch}/wintun.dll");
    let src = repo_root.join(&rel);
    let manifest = repo_root.join("vendor/SHA256SUMS");
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", manifest.display());
    verify_pinned(&manifest, &rel, &src);

    // OUT_DIR = target/<profile>/build/<crate>/out → the profile dir (where the
    // exe lands) is three ancestors up.
    let out_dir = PathBuf::from(env_var("OUT_DIR"));
    let Some(profile_dir) = out_dir.ancestors().nth(3) else {
        println!("cargo:warning=wintun.dll: could not derive profile dir from OUT_DIR");
        return;
    };
    let dst = profile_dir.join("wintun.dll");
    if let Err(e) = std::fs::copy(&src, &dst) {
        println!(
            "cargo:warning=wintun.dll: failed to copy {} -> {}: {e}",
            src.display(),
            dst.display()
        );
    }
}

/// Fail the build unless `file` hashes to the SHA-256 pinned for `rel` in
/// `vendor/SHA256SUMS` (SEC-008): the DLL runs in the elevated data path, so a
/// swapped or corrupted copy must never be shipped next to the exe.
fn verify_pinned(manifest: &Path, rel: &str, file: &Path) {
    use sha2::{Digest, Sha256};

    let pins = std::fs::read_to_string(manifest)
        .unwrap_or_else(|e| panic!("reading {}: {e}", manifest.display()));
    let expected = pins
        .lines()
        .filter_map(|l| l.split_once("  "))
        .find(|(_, path)| path.trim() == rel)
        .map(|(digest, _)| digest.to_ascii_lowercase())
        .unwrap_or_else(|| panic!("{rel} has no pinned SHA-256 in {}", manifest.display()));
    let bytes = std::fs::read(file).unwrap_or_else(|e| panic!("reading {}: {e}", file.display()));
    let actual: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(
        actual, expected,
        "{rel} does not match its pinned SHA-256 in vendor/SHA256SUMS — refusing to build \
         (see vendor/README.md)"
    );
}

fn env_var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} not set"))
}
