fn main() -> Result<(), Box<dyn std::error::Error>> {
    // tonic_build::compile_protos("../services/acl-service/src/grpc/proto/acl.proto")?;
    let acl_proto_path =
        std::path::Path::new("../services/acl-service/src/grpc/proto/acl.proto").canonicalize()?;
    println!("Compiling proto file at: {:?}", acl_proto_path);

    tonic_build::compile_protos(acl_proto_path)?;
    Ok(())
}
