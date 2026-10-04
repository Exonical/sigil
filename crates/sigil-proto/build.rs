fn main() -> Result<(), Box<dyn std::error::Error>> {
    let files = [
        "proto/sigil/agent/v1/agent.proto",
        "proto/sigil/agent/v1/grant.proto",
    ];
    for file in files {
        println!("cargo:rerun-if-changed={file}");
    }
    let descriptors = protox::compile(files, ["proto"])?;
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_fds(descriptors)?;
    Ok(())
}
