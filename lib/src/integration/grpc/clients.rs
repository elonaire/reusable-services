// should match the package name in the .proto file
pub mod acl_service {
    tonic::include_proto!("acl");
}

// should match the package name in the .proto file
pub mod email_service {
    tonic::include_proto!("email");
}

// should match the package name in the .proto file
pub mod files_service {
    tonic::include_proto!("files");
}
