use std::path::PathBuf;

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
    let src = PathBuf::from(env_var("CARGO_MANIFEST_DIR"))
        .join("../../../vendor/wintun")
        .join(arch)
        .join("wintun.dll");
    println!("cargo:rerun-if-changed={}", src.display());

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

fn env_var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} not set"))
}
