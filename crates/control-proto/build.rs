//! Compiles the coordinator gRPC service from `proto/coordinator.proto`.
//! Uses a vendored `protoc` so no system protobuf compiler is required.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    tonic_build::compile_protos("proto/coordinator.proto")?;
    Ok(())
}
