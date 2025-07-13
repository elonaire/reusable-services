use std::io::{Error, ErrorKind};

use lib::{
    integration::foreign_key::add_foreign_key_if_not_exists,
    utils::{
        custom_traits::AsSurrealClient,
        models::{ForeignKey, PurchaseFileDetails, User},
    },
};

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

    let buyer_result: Option<User> = add_foreign_key_if_not_exists(db, user_fk).await;

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
