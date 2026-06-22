//! Standalone binding generator (uniffi `--library` mode).
//!
//! Built only with `--features uniffi`. Generates Swift/Kotlin/etc. sources from
//! the FFI metadata embedded in the compiled `cdylib`. See the crate's
//! `Cargo.toml` for the exact invocation.
fn main() {
    uniffi::uniffi_bindgen_main()
}
