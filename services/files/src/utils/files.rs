use std::io::{Error, ErrorKind};

use lib::utils::custom_traits::AsSurrealClient;

use crate::graphql::schemas::general::UploadedFile;

pub async fn get_file_id<T: Clone + AsSurrealClient>(
    db: &T,
    file_name: String,
) -> Result<String, Error> {
    let mut file_query = db
        .as_client()
        .query(
            "
        BEGIN TRANSACTION;

        LET $file = (SELECT * FROM ONLY file WHERE system_filename=$file_name LIMIT 1);

        RETURN $file;
        COMMIT TRANSACTION;
        ",
        )
        .bind(("file_name", file_name))
        .await
        .map_err(|e| {
            tracing::error!("Error: {}", e);
            Error::new(ErrorKind::Other, "DB Query failed")
        })?;

    let response: Option<UploadedFile> = file_query.take(0).map_err(|e| {
        tracing::error!("Error: {}", e);
        Error::new(ErrorKind::Other, "UploadedFile deserialization failed")
    })?;

    match response {
        Some(file) => Ok(file.id.as_ref().map(|t| &t.id).expect("id").to_raw()),
        None => Err(Error::new(ErrorKind::InvalidData, "Invalid parameters!")),
    }
}
pub async fn get_system_filename<T: Clone + AsSurrealClient>(
    db: &T,
    file_id: String,
) -> Result<String, Error> {
    let mut file_query = db
        .as_client()
        .query(
            "
        BEGIN TRANSACTION;
        LET $file_thing = type::thing($file_id);

        LET $file = (SELECT * FROM ONLY $file_thing LIMIT 1);

        RETURN $file;
        COMMIT TRANSACTION;
        ",
        )
        .bind(("file_id", format!("file:{}", file_id)))
        .await
        .map_err(|e| {
            tracing::error!("Error: {}", e);
            Error::new(ErrorKind::Other, "DB Query failed")
        })?;

    let response: Option<UploadedFile> = file_query.take(0).map_err(|e| {
        tracing::error!("Error: {}", e);
        Error::new(ErrorKind::Other, "UploadedFile deserialization failed")
    })?;

    match response {
        Some(file) => Ok(file.system_filename),
        None => Err(Error::new(ErrorKind::InvalidData, "Invalid parameters!")),
    }
}
