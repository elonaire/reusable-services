// src/upload/config.rs
use std::{
    io::{Error, ErrorKind},
    path::PathBuf,
};

#[derive(Debug, Clone)]
pub struct UploadConfig {
    pub url_secret: Vec<u8>,
    pub public_base_url: String,
    pub upload_dir: PathBuf,
    pub max_upload_size: u64,
    pub max_multipart_part_size: u64,
    pub max_multipart_upload_size: u64,
    pub max_multipart_parts: u64,
    pub part_url_ttl_secs: u64,
}

impl UploadConfig {
    pub fn from_env() -> Result<Self, Error> {
        let url_secret = std::env::var("UPLOAD_URL_SECRET")
            .map_err(|_| Error::new(ErrorKind::Other, "UPLOAD_URL_SECRET is required"))?;

        if url_secret.len() < 32 {
            return Err(Error::new(
                ErrorKind::Other,
                "UPLOAD_URL_SECRET must be at least 32 bytes",
            ));
        }

        let public_base_url = std::env::var("PUBLIC_BASE_URL")
            .map_err(|_| Error::new(ErrorKind::Other, "PUBLIC_BASE_URL is required"))?;

        let upload_dir = std::env::var("FILE_UPLOADS_DIR")
            .map_err(|_| Error::new(ErrorKind::Other, "FILE_UPLOADS_DIR is required"))?
            .into();

        let max_upload_size = std::env::var("MAX_UPLOAD_SIZE_MB")
            .map_err(|_| Error::new(ErrorKind::Other, "MAX_UPLOAD_SIZE_MB is required"))?
            .parse::<u64>()
            .map_err(|_| {
                Error::new(
                    ErrorKind::Other,
                    "MAX_UPLOAD_SIZE_MB must be a valid number",
                )
            })?;

        let max_multipart_part_size = std::env::var("MAX_MULTIPART_PART_SIZE_MB")
            .map_err(|_| Error::new(ErrorKind::Other, "MAX_MULTIPART_PART_SIZE_MB is required"))?
            .parse::<u64>()
            .map_err(|_| {
                Error::new(
                    ErrorKind::Other,
                    "MAX_MULTIPART_PART_SIZE_MB must be a valid number",
                )
            })?;

        let max_multipart_upload_size = std::env::var("MAX_MULTIPART_UPLOAD_SIZE_GB")
            .map_err(|_| Error::new(ErrorKind::Other, "MAX_MULTIPART_UPLOAD_SIZE_GB is required"))?
            .parse::<u64>()
            .map_err(|_| {
                Error::new(
                    ErrorKind::Other,
                    "MAX_MULTIPART_UPLOAD_SIZE_GB must be a valid number",
                )
            })?;

        let max_multipart_parts = std::env::var("MAX_MULTIPART_PARTS")
            .map_err(|_| Error::new(ErrorKind::Other, "MAX_MULTIPART_PARTS is required"))?
            .parse::<u64>()
            .map_err(|_| {
                Error::new(
                    ErrorKind::Other,
                    "MAX_MULTIPART_PARTS must be a valid number",
                )
            })?;

        let part_url_ttl_secs = std::env::var("PART_URL_TTL_SECS")
            .map_err(|_| Error::new(ErrorKind::Other, "PART_URL_TTL_SECS is required"))?
            .parse::<u64>()
            .map_err(|_| {
                Error::new(ErrorKind::Other, "PART_URL_TTL_SECS must be a valid number")
            })?;

        Ok(Self {
            url_secret: url_secret.into_bytes(),
            public_base_url,
            upload_dir,
            max_upload_size,
            max_multipart_part_size,
            max_multipart_upload_size,
            max_multipart_parts,
            part_url_ttl_secs,
        })
    }
}
