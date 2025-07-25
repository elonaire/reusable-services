use axum::{
    extract::{Extension, Multipart, Path as AxumUrlParams},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use lib::{
    integration::foreign_key::add_foreign_key_if_not_exists,
    utils::models::{ForeignKey, User},
};
use uuid::Uuid;

use std::{
    env,
    fs::{self, File},
    io::Write,
    path::Path,
    sync::Arc,
};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::graphql::schemas::general::{UploadedFile, UploadedFileResponse};

// use crate::graphql::schemas::general::UploadedFile;

pub async fn upload(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(current_user): Extension<String>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let upload_dir = env::var("FILE_UPLOADS_DIR");

    if let Err(e) = upload_dir {
        tracing::error!("Missing the FILE_UPLOADS_DIR environment variable.: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Server Error").into_response();
    }

    let user_fk_body = ForeignKey {
        table: "user_id".into(),
        column: "user_id".into(),
        foreign_key: current_user,
    };

    let user_fk =
        add_foreign_key_if_not_exists::<Arc<Surreal<Client>>, User>(&db, user_fk_body).await;

    if user_fk.is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let user_id_raw = user_fk
        .unwrap()
        .id
        .as_ref()
        .map(|t| &t.id)
        .expect("id")
        .to_raw();

    let mut total_size: u64 = 0;
    let mut filename = String::new();
    let system_filename = Uuid::new_v4();
    let mut mime_type = String::new();
    let upload_dir = upload_dir.unwrap();
    let filepath = format!("{}{}", &upload_dir, system_filename);
    let mut field_name = String::new();
    let mut is_free = true;

    // Ensure the directory exists
    if let Err(e) = std::fs::create_dir_all(&upload_dir) {
        tracing::error!("Failed to create upload directory: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Upload failed").into_response();
    }

    while let Some(field) = multipart.next_field().await.unwrap_or_else(|_| None) {
        let mut field = field;

        // Extract field name and filename
        filename = field
            .file_name()
            .map(|name| name.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        // filepath = format!("{}/{}", &upload_dir, filename);
        // Extract the MIME type
        mime_type = field
            .content_type()
            .map(|mime| mime.to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string());

        field_name = field
            .name()
            .map(|name| name.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        match field_name.as_str() {
            "premium_file" => {
                is_free = false;
            }
            _ => {
                is_free = true;
            }
        }

        // Create and open the file for writing
        let mut file = match File::create(&filepath) {
            Ok(file) => file,
            Err(e) => {
                tracing::error!("Failed to create file: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file")
                    .into_response();
            }
        };

        // Read each chunk and write to the file
        while let Some(chunk) = match field.chunk().await {
            Ok(Some(chunk)) => Some(chunk),
            Ok(None) => None,
            Err(e) => {
                tracing::error!("Failed to read chunk: {}", e);
                let _ = std::fs::remove_file(&filepath);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file")
                    .into_response();
            }
        } {
            total_size += chunk.len() as u64;
            if let Err(e) = file.write_all(&chunk) {
                tracing::error!("Failed to write chunk: {}", e);
                // Clean up file on error
                let _ = std::fs::remove_file(&filepath);
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file")
                    .into_response();
            }
        }

        // Ensure file is successfully flushed
        if let Err(e) = file.flush() {
            tracing::error!("Failed to flush file: {}", e);
            // Clean up file on error
            let _ = std::fs::remove_file(&filepath);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file").into_response();
        }
    }

    // Insert uploaded files into the database
    match db
        .query(
            "
            BEGIN TRANSACTION;
            LET $user = type::thing($user_id);

            IF !$user.exists() {
                THROW 'Invalid Input';
            };

            LET $new_file = (CREATE file CONTENT {
               	owner: type::thing($user),
               	name: $name,
                size: $size,
                mime_type: $mime_type,
                system_filename: $system_filename,
                is_free: $is_free
            });
            RETURN $new_file;
            COMMIT TRANSACTION;
            ",
        )
        .bind(("user_id", format!("user_id:{}", user_id_raw)))
        .bind(("name", filename))
        .bind(("size", total_size))
        .bind(("mime_type", mime_type))
        .bind(("is_free", is_free))
        .bind(("system_filename", format!("{}", system_filename)))
        .await
    {
        Ok(_result) => (
            StatusCode::CREATED,
            Json(UploadedFileResponse {
                field_name,
                file_id: system_filename.to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Failed to insert file into database: {}", e);
            let _ = std::fs::remove_file(&filepath);

            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file").into_response()
        }
    }
}

pub async fn download_file(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(current_user): Extension<String>,
    AxumUrlParams(file_name): AxumUrlParams<String>,
) -> Result<Response, StatusCode> {
    let upload_dir = env::var("FILE_UPLOADS_DIR");

    if let Err(e) = upload_dir {
        tracing::error!("Missing the FILE_UPLOADS_DIR environment variable.: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let upload_dir = upload_dir.unwrap();

    let path = Path::new(&upload_dir).join(&file_name);

    if path.exists() {
        let bytes = fs::read(&path).map_err(|_| StatusCode::NOT_FOUND)?;

        let mut file_details_query = db
            .query(
                "
                SELECT * FROM file WHERE system_filename=$file_name
                ",
            )
            .bind(("file_name", file_name.clone()))
            .await
            .map_err(|e| {
                tracing::error!("Failed database query: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let file_details: Option<UploadedFile> = file_details_query.take(0).map_err(|e| {
            tracing::error!("Failed deserialization: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        match file_details {
            Some(file_details) => {
                if !file_details.is_free {
                    // verify that they actually bought the file
                    let mut bought_file_query = db
                        .query(
                            "
                            BEGIN TRANSACTION;
                            LET $internal_user = (SELECT VALUE id FROM ONLY user_id WHERE user_id = $user_id LIMIT 1);
                            LET $bought_file = (SELECT * FROM (SELECT VALUE ->bought_file.out[*] FROM ONLY $internal_user LIMIT 1) WHERE system_filename = $file_name)[0];

                            RETURN $bought_file;
                            COMMIT TRANSACTION;
                            "
                        )
                            .bind(("user_id", current_user.clone()))
                            .bind(("file_name", file_name.clone()))
                            .await
                            .map_err(|e| {
                                tracing::error!("Failed database transaction: {}", e);
                                StatusCode::INTERNAL_SERVER_ERROR
                            })?;

                    let bought_file: Option<UploadedFile> =
                        bought_file_query.take(0).map_err(|e| {
                            tracing::error!("Failed deserialization: {}", e);
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;

                    match bought_file {
                        Some(_) => {
                            // Continue to generate the response
                        }
                        None => {
                            // verify that they own the file
                            let mut owned_file_query = db
                                .query(
                                    "
                                    BEGIN TRANSACTION;
                                    LET $internal_user = (SELECT VALUE id FROM ONLY user_id WHERE user_id=$user_id LIMIT 1);

                                    LET $owned_file = (SELECT * FROM ONLY file WHERE owner=$internal_user AND system_filename=$file_name LIMIT 1);

                                    RETURN $owned_file;
                                    COMMIT TRANSACTION;
                                    "
                                )
                                    .bind(("user_id", current_user))
                                    .bind(("file_name", file_name.clone()))
                                    .await
                                    .map_err(|e| {
                                        tracing::error!("Failed database transaction: {}", e);
                                        StatusCode::INTERNAL_SERVER_ERROR})?;

                            let file_info: Option<UploadedFile> =
                                owned_file_query.take(0).map_err(|e| {
                                    tracing::error!("Failed deserialization: {}", e);
                                    StatusCode::INTERNAL_SERVER_ERROR
                                })?;

                            match file_info {
                                Some(_) => {
                                    // Continue to generate the response
                                }
                                None => {
                                    return Ok((StatusCode::FORBIDDEN, format!("Not Allowed!"))
                                        .into_response());
                                }
                            }
                        }
                    }
                }

                let content_type = file_details.mime_type;

                // let file_name_with_extension = file_name.to_string();

                let response = Response::builder()
                    .header(
                        "Content-Disposition",
                        format!("attachment; filename=\"{}\"", &file_details.name),
                    )
                    .header("Content-Type", content_type.to_string())
                    .body(bytes.into())
                    .map_err(|err| {
                        tracing::error!("Failed to build response: {}", err);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
                Ok(response)
            }
            None => Err(StatusCode::NOT_FOUND),
        }
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn get_image(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    AxumUrlParams(file_name): AxumUrlParams<String>,
) -> Result<Response, StatusCode> {
    let upload_dir = env::var("FILE_UPLOADS_DIR");

    if let Err(e) = upload_dir {
        tracing::error!("Missing the FILE_UPLOADS_DIR environment variable.: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let upload_dir = upload_dir.unwrap();

    let path = Path::new(&upload_dir).join(&file_name);

    if path.exists() {
        let bytes = fs::read(path).map_err(|_| StatusCode::NOT_FOUND)?;

        let mut file_details_query = db
            .query(
                "
                SELECT * FROM file WHERE system_filename=$file_name
                ",
            )
            .bind(("file_name", file_name.clone()))
            .await
            .map_err(|e| {
                tracing::error!("Failed database query: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let file_details: Option<UploadedFile> = file_details_query.take(0).map_err(|e| {
            tracing::error!("Failed deserialization: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        match file_details {
            Some(file_details) => {
                let content_type = file_details.mime_type;

                let response = Response::builder()
                    .header("Content-Type", content_type.to_string())
                    .body(bytes.into())
                    .map_err(|e| {
                        tracing::error!("Failed database query: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
                Ok(response)
            }
            None => Err(StatusCode::NOT_FOUND),
        }
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
