fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = "src/integration/grpc/out";
    std::env::set_var("PROTOBUFS", out_dir);
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir(out_dir)
        .compile_protos(
            &[
                "proto/acl/acl.proto",
                "proto/email/email.proto",
                "proto/files/files.proto",
            ],
            &["proto"],
        )?;

    Ok(())
}
