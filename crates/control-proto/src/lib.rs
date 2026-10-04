//! Generated gRPC types and stubs for the control-plane coordinator
//! (PRD Phase 3). The service is defined in `proto/coordinator.proto` and
//! compiled by `build.rs`.

/// Coordinator service messages, client, and server stubs.
// tonic-build's generated client methods return `Result<_, tonic::Status>`,
// and `Status` is large (176+ bytes), which newer clippy flags as
// `result_large_err`. It's generated code we don't control, and the size is
// tonic's own design choice, so allow it here only. Likewise
// `double_must_use` (clippy 1.99+, CI's toolchain): the generated async-trait
// server methods carry a bare `#[must_use]` on an already-`must_use` future.
#[allow(clippy::result_large_err, clippy::double_must_use)]
pub mod coordinator {
    tonic::include_proto!("ferrum.coordinator.v1");
}
