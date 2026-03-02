use axum::{
    extract::{Extension, Multipart, Path as AxumUrlParams, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use image::{ImageFormat, ImageReader};
use lib::{
    integration::foreign_key::add_foreign_key_if_not_exists,
    utils::models::{AuthStatus, ForeignKey, User},
};
use tokio::{
    fs::{remove_file, File},
    io::{AsyncReadExt, AsyncWriteExt},
};
use uuid::Uuid;

use std::{env, io::Cursor, path::Path, sync::Arc};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::graphql::schemas::general::{UploadedFile, UploadedFileResponse};

#[derive(serde::Deserialize)]
pub struct ImageResizeParams {
    pub width: Option<u32>,
    pub height: Option<u32>,
}

pub async fn upload(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth_status): Extension<AuthStatus>,
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
        foreign_key: auth_status.sub,
    };

    let user_fk =
        add_foreign_key_if_not_exists::<Arc<Surreal<Client>>, User>(&db, user_fk_body).await;

    if user_fk.is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let user_id_raw = user_fk.unwrap().id.key().to_string();

    let mut total_size: u64 = 0;
    let mut filename;
    let mut mime_type;
    let upload_dir = upload_dir.unwrap();
    let mut field_name;
    let mut is_free;
    let mut all_uploaded_files_response = Vec::new() as Vec<UploadedFileResponse>;

    // Ensure the directory exists
    if let Err(e) = std::fs::create_dir_all(&upload_dir) {
        tracing::error!("Failed to create upload directory: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Upload failed").into_response();
    }

    while let Some(field) = multipart.next_field().await.unwrap_or_else(|_| None) {
        let system_filename = Uuid::new_v4();
        let filepath = Path::new(&upload_dir).join(&system_filename.to_string());
        let mut field = field;

        // Extract field name and filename
        filename = field
            .file_name()
            .map(|name| name.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        // Extract the MIME type
        mime_type = field
            .content_type()
            .map(|mime| mime.to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string());

        field_name = field
            .name()
            .map(|name| name.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        if field_name.contains("premium") {
            is_free = false;
        } else {
            is_free = true;
        };

        // Create and open the file for writing
        let mut file = match File::create(&filepath).await {
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
                let _ = remove_file(&filepath).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file")
                    .into_response();
            }
        } {
            total_size += chunk.len() as u64;
            if let Err(e) = file.write_all(&chunk).await {
                tracing::error!("Failed to write chunk: {}", e);
                // Clean up file on error
                let _ = remove_file(&filepath).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file")
                    .into_response();
            }
        }

        // Ensure file is successfully flushed
        if let Err(e) = file.flush().await {
            tracing::error!("Failed to flush file: {}", e);
            // Clean up file on error
            let _ = remove_file(&filepath).await;
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file").into_response();
        }

        // Insert uploaded files into the database
        let db_query_result = db
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
            .bind(("user_id", user_id_raw.clone()))
            .bind(("name", filename))
            .bind(("size", total_size))
            .bind(("mime_type", mime_type))
            .bind(("is_free", is_free))
            .bind(("system_filename", format!("{}", system_filename)))
            .await;

        if let Err(e) = &db_query_result {
            tracing::error!("Failed to insert file into database: {}", e);
            let _ = remove_file(&filepath).await;

            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file").into_response();
        } else {
            let stored_file = db_query_result.unwrap().take(0);

            if let Err(e) = stored_file {
                tracing::error!("Failed to retrieve file from database: {}", e);
                let _ = remove_file(&filepath).await;

                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file")
                    .into_response();
            }

            let stored_file: Option<UploadedFile> = stored_file.unwrap();

            if stored_file.is_none() {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to upload file")
                    .into_response();
            }

            let stored_file = stored_file.unwrap();

            all_uploaded_files_response.push(UploadedFileResponse {
                field_name,
                file_name: stored_file.system_filename,
                file_id: stored_file.id.key().to_string(),
            });
        }
    }

    (StatusCode::CREATED, Json(all_uploaded_files_response)).into_response()
}

pub async fn download_file(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth_status): Extension<AuthStatus>,
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
        let mut file = File::open(&path).await.map_err(|_| StatusCode::NOT_FOUND)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;

        let mut file_details_query = db
            .query(
                "
                SELECT * FROM ONLY file WHERE system_filename=$file_name LIMIT 1
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
                            .bind(("user_id", auth_status.sub.clone()))
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
                                    .bind(("user_id", auth_status.sub))
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
                    .body(buffer.into())
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
    Query(resize_params): Query<ImageResizeParams>,
) -> Result<Response, StatusCode> {
    let upload_dir = env::var("FILE_UPLOADS_DIR");

    if let Err(e) = upload_dir {
        tracing::error!("Missing the FILE_UPLOADS_DIR environment variable.: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let upload_dir = upload_dir.unwrap();

    let path = Path::new(&upload_dir).join(&file_name);

    if path.exists() {
        let mut file = File::open(&path).await.map_err(|_| StatusCode::NOT_FOUND)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;

        let mut file_details_query = db
            .query(
                "
                SELECT * FROM ONLY file WHERE system_filename=$file_name LIMIT 1
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

                // Resize only if query params are provided and the file is an image we can process
                let final_buffer = match (resize_params.width, resize_params.height) {
                    (None, None) => buffer,
                    (width, height) => {
                        match resize_image(&buffer, &content_type, width, height) {
                            Ok(resized) => resized,
                            Err(e) => {
                                // Non-fatal: log and fall back to the original
                                tracing::warn!("Could not resize image, serving original: {}", e);
                                buffer
                            }
                        }
                    }
                };

                let response = Response::builder()
                    .header("Content-Type", &content_type)
                    .body(final_buffer.into())
                    .map_err(|e| {
                        tracing::error!("Failed to build response: {}", e);
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

fn resize_image(
    buffer: &[u8],
    content_type: &str,
    width: Option<u32>,
    height: Option<u32>,
) -> Result<Vec<u8>, StatusCode> {
    let format = match content_type {
        "image/jpeg" | "image/jpg" => ImageFormat::Jpeg,
        "image/png" => ImageFormat::Png,
        "image/webp" => ImageFormat::WebP,
        "image/gif" => ImageFormat::Gif,
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let img = ImageReader::with_format(Cursor::new(buffer), format)
        .decode()
        .map_err(|e| {
            tracing::error!("Failed to decode image: {:?}", e);
            StatusCode::BAD_REQUEST
        })?;

    let resized = match (width, height) {
        (Some(w), Some(h)) => img.resize(w, h, image::imageops::FilterType::Lanczos3),
        (Some(w), None) => img.resize(w, img.height(), image::imageops::FilterType::Lanczos3),
        (None, Some(h)) => img.resize(img.width(), h, image::imageops::FilterType::Lanczos3),
        (None, None) => return Err(StatusCode::BAD_REQUEST),
    };

    let mut output = Cursor::new(Vec::new());
    resized.write_to(&mut output, format).map_err(|e| {
        tracing::error!("Failed to write image: {:?}", e);
        StatusCode::BAD_REQUEST
    })?;
    Ok(output.into_inner())
}
