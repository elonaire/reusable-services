fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/acl/acl.proto")?;
    tonic_build::compile_protos("proto/email/email.proto")?;
    tonic_build::compile_protos("proto/files/files.proto")?;
    Ok(())
}
