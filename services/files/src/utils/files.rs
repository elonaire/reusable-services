use std::{
    env,
    fs::Metadata,
    io::{Error, ErrorKind},
    path::Path,
    sync::Arc,
};

use lib::{
    integration::foreign_key::add_foreign_key_if_not_exists,
    utils::{
        custom_traits::AsSurrealClient,
        models::{CreateFileInfo, ForeignKey, PurchaseFileDetails, UserId},
    },
};
use surrealdb::{engine::remote::ws::Client, Surreal};
use tokio::{fs::File, io::AsyncWriteExt};
use uuid::Uuid;

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
        Some(file) => Ok(file.id.key().to_string()),
        None => Err(Error::new(ErrorKind::InvalidData, "Not Found!")),
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

        IF !$file_thing.exists() {
            THROW 'Invalid Input';
        };

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

pub async fn purchase_file<T: Clone + AsSurrealClient>(
    db: &T,
    purchase_details: PurchaseFileDetails,
) -> Result<bool, Error> {
    let user_fk = ForeignKey {
        table: "user_id".into(),
        column: "user_id".into(),
        foreign_key: purchase_details.buyer_id.into(),
    };

    let buyer_result: Option<UserId> = add_foreign_key_if_not_exists(db, user_fk).await;

    let mut purchase_file_query = db
        .as_client()
        .query(
            "
            BEGIN TRANSACTION;
            LET $file_thing = type::thing($file_id);
            IF !$file_thing.exists() {
                THROW 'Invalid Input';
            };
            LET $user = (SELECT * FROM ONLY user_id WHERE user_id = $user_id LIMIT 1);
            LET $purchased_file = (RELATE $user->bought_file->$file_thing RETURN AFTER);
            RETURN $user_id;
            COMMIT TRANSACTION;
        ",
        )
        .bind((
            "file_id",
            format!("file:{}", purchase_details.file_id.clone()),
        ))
        .bind(("user_id", buyer_result.unwrap().user_id))
        .await
        .map_err(|e| {
            tracing::error!("purchase_file_query Error: {}", e);
            Error::new(ErrorKind::Other, "DB Query failed")
        })?;

    let _response: Option<String> = purchase_file_query.take(0).map_err(|e| {
        tracing::error!("purchase_file_query Deserialization Error: {}", e);
        Error::new(ErrorKind::Other, "UploadedFile deserialization failed")
    })?;

    Ok(true)
}

pub async fn create_file_from_content<T: Clone + AsSurrealClient>(
    db: &T,
    file_info: &CreateFileInfo,
    user_id: &str,
) -> Result<String, Error> {
    let upload_dir = env::var("FILE_UPLOADS_DIR").map_err(|err| {
        tracing::error!(
            "Missing the FILE_UPLOADS_DIR environment variable.: {}",
            err
        );
        Error::new(ErrorKind::Other, "Server Error")
    })?;

    let system_filename = Uuid::new_v4();
    let filepath = Path::new(&upload_dir).join(&system_filename.to_string());

    // Create and open the file for writing
    let mut file = File::create(&filepath).await.map_err(|err| {
        tracing::error!("Failed to create file: {}", err);
        Error::new(ErrorKind::Other, "Failed to create file")
    })?;

    file.write_all(file_info.content.as_bytes()).await?;

    let file_metadata = file.metadata().await.map_err(|err| {
        tracing::error!("Failed to get file metadata: {}", err);
        Error::new(ErrorKind::Other, "Failed to get file metadata")
    })?;

    let user_fk_body = ForeignKey {
        table: "user_id".into(),
        column: "user_id".into(),
        foreign_key: user_id.to_owned(),
    };

    let user_fk: Option<UserId> = add_foreign_key_if_not_exists(db, user_fk_body).await;

    if user_fk.is_none() {
        return Err(Error::new(
            ErrorKind::Other,
            "Failed to insert file into database",
        ));
    }

    let user_id_raw = user_fk.unwrap().id.key().to_string();

    // Insert uploaded files into the database
    let mut db_query_result = db
        .as_client()
        .query(
            "
            BEGIN TRANSACTION;
            LET $user = type::thing('user_id', $user_id);

            IF !$user.exists() {
                THROW 'Invalid Input';
            };

            LET $new_file = (CREATE file CONTENT {
               	owner: $user,
               	name: $name,
                size: $size,
                mime_type: $mime_type,
                system_filename: $system_filename,
                is_free: $is_free
            });
            RETURN $new_file[0];
            COMMIT TRANSACTION;
            ",
        )
        .bind(("user_id", user_id_raw))
        .bind(("name", file_info.file_name.clone()))
        .bind(("size", file_metadata.len()))
        .bind((
            "mime_type",
            file_info.extension.fetch_mime_type().to_owned(),
        ))
        .bind(("is_free", file_info.is_free))
        .bind(("system_filename", format!("{}", system_filename)))
        .await
        .map_err(|e| {
            tracing::error!("Error creating file DB record: {}", e);
            Error::new(ErrorKind::Other, "Failed to insert file into database")
        })?;

    let saved_file: Option<UploadedFile> = db_query_result.take(0).map_err(|e| {
        tracing::error!("Failed to insert file into database: {}", e);
        Error::new(ErrorKind::Other, "Failed to insert file into database")
    })?;

    match saved_file {
        Some(file_info) => Ok(file_info.id.key().to_string()),
        None => Err(Error::new(
            ErrorKind::Other,
            "Failed to insert file into database",
        )),
    }
}
