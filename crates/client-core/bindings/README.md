# uniffi bindings for `ferrum-client-core`

Foreign-language bindings for the Phase 5 client facade (`FfiFerrumClient`, see
[`../src/ffi.rs`](../src/ffi.rs)). The generated sources are a **reproducible
artifact** and are git-ignored — generate them on demand with the commands
below. They wrap the `uniffi` feature build, so nothing here ships in the
default crate.

## Generate

From the workspace root:

```sh
# 1. Build the cdylib that carries the FFI metadata.
cargo build -p ferrum-client-core --features uniffi

# 2. Generate bindings from the built library (--library mode).
LIB=target/debug/ferrum_client_core      # .dll (Windows) / .so (Linux) / .dylib (macOS)
cargo run -p ferrum-client-core --features uniffi --bin uniffi-bindgen -- \
    generate --library "$LIB" --language swift  --out-dir crates/client-core/bindings/swift
cargo run -p ferrum-client-core --features uniffi --bin uniffi-bindgen -- \
    generate --library "$LIB" --language kotlin --out-dir crates/client-core/bindings/kotlin
```

`uniffi-bindgen` also supports `--language python` (handy for a quick smoke test
of the FFI without an Apple/Android toolchain).

## What you get

- **Swift** — `ferrum_client_core.swift`, `ferrum_client_coreFFI.h`, `ferrum_client_coreFFI.modulemap`
- **Kotlin** — `uniffi/ferrum_client_core/ferrum_client_core.kt`

The exported surface (`FfiFerrumClient`):

| Rust | Swift | Kotlin |
|------|-------|--------|
| `new()` | `FfiFerrumClient()` | `FfiFerrumClient()` |
| `async connect(coordinator, identity)` | `func connect(...) async throws` | `suspend fun connect(...)` |
| `disconnect()` / `status()` / `address()` / `peers()` / `apply_peers(...)` | sync methods | sync methods |
| `async next_event() -> ClientEvent?` | `func nextEvent() async -> ClientEvent?` | `suspend fun nextEvent(): ClientEvent?` |

Records: `ClientIdentity`, `PeerSpec`, `PeerStatus`. Enums: `ConnectionState`,
`PeerPath`, `ClientEvent`. Errors surface as a flat `Error`.

## Consuming from a shell

Each native shell links the `cdylib` (`ferrum_client_core`) and drops in the
generated source. The shell owns the OS data-plane bring-up (TUN + `run_mesh`);
this facade owns control-plane sync, the state machine, and the peer view. See
the Phase 5 spec ([`../../../PRD/phase-5-clients.md`](../../../PRD/phase-5-clients.md)).
