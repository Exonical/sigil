fn main() -> Result<(), Box<dyn std::error::Error>> {
    let files = [
        "sigil/agent/v1/agent.proto",
        "sigil/agent/v1/grant.proto",
        "sigil/backend/v1/gateway.proto",
    ];
    let proto_root = std::path::Path::new("../../proto");
    for file in files {
        println!("cargo:rerun-if-changed={}", proto_root.join(file).display());
    }
    let descriptors = protox::compile(files.map(|file| proto_root.join(file)), [proto_root])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(descriptors)?;
    Ok(())
}
