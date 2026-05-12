use axum::{
    extract::{Extension, Multipart, Path as AxumUrlParams, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use exif::{In, Tag};
use hyper::HeaderMap;
use image::{ImageFormat, ImageReader};
use lib::{
    integration::foreign_key::add_foreign_key_if_not_exists,
    utils::{
        api_responses::synthesize_rest_response,
        custom_error::ApiError,
        models::{ApiResponseRest, AuthStatus, ForeignKey, UserId},
    },
};
use tokio::{
    fs::{create_dir_all, remove_file, File},
    io::{AsyncReadExt, AsyncWriteExt},
};
use uuid::Uuid;

use std::{
    env,
    io::{BufReader, Cursor},
    path::Path,
    sync::Arc,
};
use surrealdb::{engine::remote::ws::Client, types::RecordIdKey, Surreal};

use crate::graphql::schemas::general::{UploadedFile, UploadedFileResponse};

#[derive(serde::Deserialize)]
pub struct ImageResizeParams {
    pub width: Option<u32>,
    pub height: Option<u32>,
}

pub async fn upload(
    AxumUrlParams(path): AxumUrlParams<String>,
    headers: HeaderMap,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth_status): Extension<AuthStatus>,
    mut multipart: Multipart,
) -> Result<ApiResponseRest<Vec<UploadedFileResponse>>, ApiError> {
    let upload_dir = env::var("FILE_UPLOADS_DIR").map_err(|e| {
        tracing::error!("Missing FILE_UPLOADS_DIR environment variable: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let user_fk_body = ForeignKey {
        table: "user_id".into(),
        column: "user_id".into(),
        foreign_key: auth_status.sub,
    };

    let user_fk = add_foreign_key_if_not_exists::<Arc<Surreal<Client>>, UserId>(&db, user_fk_body)
        .await
        .ok_or(ApiError::Unauthorized("Unauthorized".into()))?;

    let Some(user_id_raw) = (match &user_fk.id.key {
        RecordIdKey::String(s) => Some(s.clone()),
        _ => None,
    }) else {
        tracing::error!("Invalid user");
        return Err(ApiError::BadRequest("Bad Request".into()));
    };

    create_dir_all(&upload_dir).await.map_err(|e| {
        tracing::error!("Failed to create upload directory: {}", e);
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let (bucket, key) = path
        .split_once('/')
        .map(|(b, k)| (b.to_owned(), Some(k.to_owned())))
        .unwrap_or_else(|| (path.clone(), None));

    let bucket_ref = &bucket;

    let split_keys = key
        .map(|provided_key| {
            provided_key
                .split('/')
                .map(|s| s.to_owned())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let split_keys_ref = split_keys.as_slice();

    let validation_result = db
        .query(
            r#"
            LET $bucket = (
                SELECT VALUE id
                FROM ONLY bucket
                WHERE name = $bucket_name
                LIMIT 1
            );
            IF $bucket = NONE {
                THROW 'Invalid Input';
            };

            IF array::len($split_keys) = 0 {
                RETURN true;
            } ELSE {
                LET $immediate_key = array::first($split_keys);
                LET $rest_keys = array::remove($split_keys, 0);

                LET $key_found_in_bucket = (
                    SELECT VALUE id
                    FROM ONLY key
                    WHERE
                        name = $immediate_key
                        AND ->(belongs_to WHERE out = $bucket)
                    LIMIT 1
                );

                IF $key_found_in_bucket = NONE {
                    THROW 'Invalid Input';
                };

                IF array::len($rest_keys) = 0 {
                    RETURN true;
                } ELSE {
                    LET $rest_keys_validity = $rest_keys.map(
                        |$key,$index| {
                            LET $parent_key = IF $index = 0 {
                                (
                                    SELECT VALUE id
                                    FROM ONLY key
                                    WHERE name = $immediate_key
                                    LIMIT 1
                                );
                            } ELSE {
                                LET $prev_index = $index - 1;

                                LET $prev_key = $split_keys.at($prev_index);

                                (
                                    SELECT VALUE id
                                    FROM ONLY key
                                    WHERE name = $prev_key
                                    LIMIT 1
                                );
                            };

                            LET $key_found = (
                                SELECT VALUE id
                                FROM ONLY key
                                WHERE
                                    name = $key
                                    AND ->(belongs_to WHERE out = $parent_key)
                                LIMIT 1
                            );

                            IF $key_found = NONE {
                                false;
                            } ELSE {
                                true;
                            };
                        }
                    );

                    RETURN $rest_keys_validity.reduce(|$key_one,$key_two| $key_one && $key_two);
                };
            };
            "#,
        )
        .bind(("bucket_name", bucket_ref.clone()))
        .bind(("split_keys", split_keys_ref.to_vec()))
        .await
        .map_err(|e| {
            tracing::error!("Failed to validate bucket and key: {}", e);
            ApiError::BadRequest("Invalid bucket or key".into())
        })
        .and_then(|mut res| {
            res.take(2).map_err(|e| {
                tracing::error!("Failed to deserialize: {}", e);
                ApiError::BadRequest("Invalid bucket or key".into())
            })
        });

    let bucket_key_are_valid: Option<bool> = match validation_result {
        Ok(val) => val,
        Err(e) => {
            while let Ok(Some(_)) = multipart.next_field().await {} // drain body to prevent ECONNRESET errors
            return Err(e);
        }
    };

    if bucket_key_are_valid != Some(true) {
        while let Ok(Some(_)) = multipart.next_field().await {} // drain body to prevent ECONNRESET errors
        return Err(ApiError::BadRequest("Invalid bucket or key".into()));
    };

    let mut all_uploaded_files_response: Vec<UploadedFileResponse> = Vec::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        tracing::error!("Multipart error: {}", e);
        ApiError::BadRequest("Invalid multipart payload".into())
    })? {
        let mut total_size: u64 = 0;
        let system_filename = Uuid::new_v4();
        let filepath = Path::new(&upload_dir).join(system_filename.to_string());
        let mut field = field;

        let filename = field
            .file_name()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let mime_type = field
            .content_type()
            .map(|m| m.to_string())
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let field_name = field
            .name()
            .map(|n| n.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let is_free = !field_name.contains("premium");

        let mut file = File::create(&filepath).await.map_err(|e| {
            tracing::error!("Failed to create file: {}", e);
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?;

        while let Some(chunk) = field.chunk().await.map_err(|e| {
            tracing::error!("Failed to read chunk: {}", e);
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })? {
            total_size += chunk.len() as u64;
            file.write_all(&chunk).await.map_err(|e| {
                tracing::error!("Failed to write chunk: {}", e);
                ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
            })?;
        }

        file.flush().await.map_err(|e| {
            tracing::error!("Failed to flush file: {}", e);
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?;

        let stored_file: Option<UploadedFile> = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $user = type::record('user_id', $user_id);

                LET $new_file = (CREATE file CONTENT {
                    owner: $user,
                    name: $name,
                    size: $size,
                    mime_type: $mime_type,
                    system_filename: $system_filename,
                    is_free: $is_free
                })[0];
                LET $file_record = (SELECT VALUE id FROM ONLY $new_file);

                IF array::len($split_keys) = 0 {
                    LET $bucket = (
                        SELECT VALUE id
                        FROM ONLY bucket
                        WHERE name = $bucket_name
                        LIMIT 1
                    );

                    RELATE $file_record->belongs_to->$bucket;
                } ELSE {
                    LET $last_key = array::at($split_keys, -1);

                    LET $key_id = (
                        SELECT VALUE id
                        FROM ONLY key
                        WHERE name = $last_key
                        LIMIT 1
                    );

                    RELATE $file_record->belongs_to->$key_id;
                };
                RETURN $new_file;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("user_id", user_id_raw.clone()))
            .bind(("name", filename))
            .bind(("size", total_size))
            .bind(("mime_type", mime_type))
            .bind(("is_free", is_free))
            .bind(("system_filename", system_filename.to_string()))
            .bind(("bucket_name", bucket_ref.clone()))
            .bind(("split_keys", split_keys_ref.to_vec()))
            .await
            .map_err(|e| {
                tracing::error!("Failed to insert file into database: {}", e);
                let filepath = filepath.clone();
                tokio::spawn(async move { remove_file(&filepath).await });
                ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
            })?
            .take(5)
            .map_err(|e| {
                tracing::error!("Failed to retrieve file from database: {}", e);
                let filepath = filepath.clone();
                tokio::spawn(async move { remove_file(&filepath).await });
                ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
            })?;

        let stored_file = stored_file.ok_or_else(|| {
            tracing::error!("Database returned no file after insert");
            ApiError::Internal(anyhow::anyhow!("Failed to upload file"))
        })?;

        let Some(file_id) = (match &stored_file.id.key {
            RecordIdKey::String(s) => Some(s.clone()),
            _ => None,
        }) else {
            tracing::error!("Invalid user");
            return Err(ApiError::BadRequest("Bad Request".into()));
        };

        all_uploaded_files_response.push(UploadedFileResponse {
            field_name,
            file_name: stored_file.system_filename,
            file_id,
            original_filename: stored_file.name,
        });
    }

    Ok(synthesize_rest_response(
        &headers,
        &all_uploaded_files_response,
        StatusCode::CREATED,
    ))
}

pub async fn download_file(
    AxumUrlParams(key): AxumUrlParams<String>,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth_status): Extension<AuthStatus>,
) -> Result<Response, StatusCode> {
    let upload_dir = env::var("FILE_UPLOADS_DIR");

    if let Err(e) = upload_dir {
        tracing::error!("Missing the FILE_UPLOADS_DIR environment variable.: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let upload_dir = upload_dir.unwrap();

    let (bucket, key) = key
        .split_once('/')
        .map(|(b, k)| (b.to_owned(), Some(k.to_owned())))
        .unwrap_or_else(|| (key.clone(), None));

    let bucket_ref = &bucket;

    let mut split_keys = key
        .map(|provided_key| {
            provided_key
                .split('/')
                .map(|s| s.to_owned())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let original_file_name = split_keys.pop();
    let split_keys_ref = split_keys.as_slice();

    let mut file_details_query = db
        .query(
            "
            LET $bucket = (
                SELECT VALUE id
                FROM ONLY bucket
                WHERE name = $bucket_name
                LIMIT 1
            );
            IF $bucket = NONE {
                THROW 'Invalid Input';
            };

            LET $bucket_and_key_are_valid = IF array::len($split_keys) = 0 {
                LET $file_found_in_bucket = (
                    SELECT <-belongs_to<-(file WHERE name = $file_name) AS files
                    FROM ONLY $bucket
                )['files'];

                IF array::len($file_found_in_bucket) = 0 {
                    THROW 'Invalid Input';
                };
                true
            } ELSE {
                LET $immediate_key = array::first($split_keys);
                LET $last_key = array::last($split_keys);
                LET $rest_keys = array::remove($split_keys, 0);

                LET $key_found_in_bucket = (
                    SELECT VALUE id
                    FROM ONLY key
                    WHERE
                        name = $immediate_key
                        AND ->(belongs_to WHERE out = $bucket)
                    LIMIT 1
                );

                IF $key_found_in_bucket = NONE {
                    THROW 'Invalid Input';
                };

                LET $key_is_valid = IF array::len($rest_keys) = 0 {
                    true
                } ELSE {
                    LET $rest_keys_validity = $rest_keys.map(
                        |$key,$index| {
                            LET $parent_key = IF $index = 0 {
                                (
                                    SELECT VALUE id
                                    FROM ONLY key
                                    WHERE name = $immediate_key
                                    LIMIT 1
                                );
                            } ELSE {
                                LET $prev_index = $index - 1;

                                LET $prev_key = $split_keys.at($prev_index);

                                (
                                    SELECT VALUE id
                                    FROM ONLY key
                                    WHERE name = $prev_key
                                    LIMIT 1
                                );
                            };

                            LET $key_found = (
                                SELECT VALUE id
                                FROM ONLY key
                                WHERE
                                    name = $key
                                    AND ->(belongs_to WHERE out = $parent_key)
                                LIMIT 1
                            );

                            IF $key_found = NONE {
                                false;
                            } ELSE {
                                true;
                            };
                        }
                    );

                    LET $file_found_in_last_key = (
                        SELECT <-belongs_to<-(file WHERE name = $file_name) AS files
                        FROM ONLY key
                        WHERE name = $last_key
                        LIMIT 1
                    )['files'];

                    LET $file_path_is_valid = array::len($file_found_in_last_key) > 0;

                    $rest_keys_validity.reduce(|$key_one,$key_two| $key_one && $key_two) && $file_path_is_valid
                };

                $key_is_valid
            };

            RETURN IF $bucket_and_key_are_valid {
                (SELECT * FROM ONLY file WHERE name=$file_name LIMIT 1)
            } ELSE {
                NONE
            };
            ",
        )
        .bind(("file_name", original_file_name.clone()))
        .bind(("bucket_name", bucket_ref.clone()))
        .bind(("split_keys", split_keys_ref.to_vec()))
        .await
        .map_err(|e| {
            tracing::error!("Failed database query: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let file_details: Option<UploadedFile> = file_details_query.take(3).map_err(|e| {
        tracing::error!("Failed deserialization: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some(file_details) = file_details else {
        tracing::error!("File does not exist!");
        return Err(StatusCode::NOT_FOUND);
    };

    let file_details_ref = &file_details;

    let path = Path::new(&upload_dir).join(file_details_ref.system_filename.clone());

    if path.exists() {
        let mut file = File::open(&path).await.map_err(|_| StatusCode::NOT_FOUND)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;

        if !file_details_ref.is_free {
            // verify that they actually bought the file
            let mut bought_file_query = db
                .query(
                    "
                    LET $internal_user = (SELECT VALUE id FROM ONLY user_id WHERE user_id = $user_id LIMIT 1);
                    LET $bought_file = (SELECT * FROM (SELECT VALUE ->bought.out[*] FROM ONLY $internal_user LIMIT 1) WHERE system_filename = $file_name)[0];

                    RETURN $bought_file;
                    "
                )
                    .bind(("user_id", auth_status.sub.clone()))
                    .bind(("file_name", file_details_ref.system_filename.clone()))
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed database transaction: {}", e);
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;

            let bought_file: Option<UploadedFile> = bought_file_query.take(2).map_err(|e| {
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
                            LET $internal_user = (SELECT VALUE id FROM ONLY user_id WHERE user_id=$user_id LIMIT 1);

                            LET $owned_file = (SELECT * FROM ONLY file WHERE owner=$internal_user AND system_filename=$file_name LIMIT 1);

                            RETURN $owned_file;
                            "
                        )
                            .bind(("user_id", auth_status.sub))
                            .bind(("file_name", file_details_ref.system_filename.clone()))
                            .await
                            .map_err(|e| {
                                tracing::error!("Failed database transaction: {}", e);
                                StatusCode::INTERNAL_SERVER_ERROR})?;

                    let file_info: Option<UploadedFile> =
                        owned_file_query.take(2).map_err(|e| {
                            tracing::error!("Failed deserialization: {}", e);
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;

                    match file_info {
                        Some(_) => {
                            // Continue to generate the response
                        }
                        None => {
                            return Ok(
                                (StatusCode::FORBIDDEN, format!("Not Allowed!")).into_response()
                            );
                        }
                    }
                }
            }
        }

        let content_type = file_details_ref.mime_type.clone();

        let response = Response::builder()
            .header(
                "Content-Disposition",
                format!("attachment; filename=\"{}\"", file_details_ref.name),
            )
            .header("Content-Type", content_type.to_string())
            .body(buffer.into())
            .map_err(|err| {
                tracing::error!("Failed to build response: {}", err);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        Ok(response)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

pub async fn get_image(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    AxumUrlParams(key): AxumUrlParams<String>,
    Query(resize_params): Query<ImageResizeParams>,
) -> Result<Response, StatusCode> {
    let upload_dir = env::var("FILE_UPLOADS_DIR");

    if let Err(e) = upload_dir {
        tracing::error!("Missing the FILE_UPLOADS_DIR environment variable.: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let upload_dir = upload_dir.unwrap();

    let (bucket, key) = key
        .split_once('/')
        .map(|(b, k)| (b.to_owned(), Some(k.to_owned())))
        .unwrap_or_else(|| (key.clone(), None));

    let bucket_ref = &bucket;

    let mut split_keys = key
        .map(|provided_key| {
            provided_key
                .split('/')
                .map(|s| s.to_owned())
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let original_file_name = split_keys.pop();
    let split_keys_ref = split_keys.as_slice();

    let mut file_details_query = db
        .query(
            "
            LET $bucket = (
                SELECT VALUE id
                FROM ONLY bucket
                WHERE name = $bucket_name
                LIMIT 1
            );
            IF $bucket = NONE {
                THROW 'Invalid Input';
            };

            LET $bucket_and_key_are_valid = IF array::len($split_keys) = 0 {
                LET $file_found_in_bucket = (
                    SELECT <-belongs_to<-(file WHERE name = $file_name) AS files
                    FROM ONLY $bucket
                )['files'];

                IF array::len($file_found_in_bucket) = 0 {
                    THROW 'Invalid Input';
                };
                true
            } ELSE {
                LET $immediate_key = array::first($split_keys);
                LET $last_key = array::last($split_keys);
                LET $rest_keys = array::remove($split_keys, 0);

                LET $key_found_in_bucket = (
                    SELECT VALUE id
                    FROM ONLY key
                    WHERE
                        name = $immediate_key
                        AND ->(belongs_to WHERE out = $bucket)
                    LIMIT 1
                );

                IF $key_found_in_bucket = NONE {
                    THROW 'Invalid Input';
                };

                LET $key_is_valid = IF array::len($rest_keys) = 0 {
                    true
                } ELSE {
                    LET $rest_keys_validity = $rest_keys.map(
                        |$key,$index| {
                            LET $parent_key = IF $index = 0 {
                                (
                                    SELECT VALUE id
                                    FROM ONLY key
                                    WHERE name = $immediate_key
                                    LIMIT 1
                                );
                            } ELSE {
                                LET $prev_index = $index - 1;

                                LET $prev_key = $split_keys.at($prev_index);

                                (
                                    SELECT VALUE id
                                    FROM ONLY key
                                    WHERE name = $prev_key
                                    LIMIT 1
                                );
                            };

                            LET $key_found = (
                                SELECT VALUE id
                                FROM ONLY key
                                WHERE
                                    name = $key
                                    AND ->(belongs_to WHERE out = $parent_key)
                                LIMIT 1
                            );

                            IF $key_found = NONE {
                                false;
                            } ELSE {
                                true;
                            };
                        }
                    );

                    LET $file_found_in_last_key = (
                        SELECT <-belongs_to<-(file WHERE name = $file_name) AS files
                        FROM ONLY key
                        WHERE name = $last_key
                        LIMIT 1
                    )['files'];

                    LET $file_path_is_valid = array::len($file_found_in_last_key) > 0;

                    $rest_keys_validity.reduce(|$key_one,$key_two| $key_one && $key_two) && $file_path_is_valid
                };

                $key_is_valid
            };

            RETURN IF $bucket_and_key_are_valid {
                (SELECT * FROM ONLY file WHERE name=$file_name LIMIT 1)
            } ELSE {
                NONE
            };
            ",
        )
        .bind(("file_name", original_file_name))
        .bind(("bucket_name", bucket_ref.clone()))
        .bind(("split_keys", split_keys_ref.to_vec()))
        .await
        .map_err(|e| {
            tracing::error!("Failed database query: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let file_details: Option<UploadedFile> = file_details_query.take(3).map_err(|e| {
        tracing::error!("Failed deserialization: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let Some(file_details) = file_details else {
        tracing::error!("File does not exist!");
        return Err(StatusCode::NOT_FOUND);
    };

    let file_details_ref = &file_details;

    let path = Path::new(&upload_dir).join(file_details_ref.system_filename.clone());

    if path.exists() {
        let mut file = File::open(&path).await.map_err(|_| StatusCode::NOT_FOUND)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .await
            .map_err(|_| StatusCode::NOT_FOUND)?;

        let content_type = file_details_ref.mime_type.clone();

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

    // Apply EXIF orientation before resizing
    let img = apply_exif_orientation(img, buffer);

    let resized = match (width, height) {
        (Some(w), Some(h)) => img.resize(w, h, image::imageops::FilterType::Lanczos3),
        (Some(w), None) => img.resize(w, u32::MAX, image::imageops::FilterType::Lanczos3),
        (None, Some(h)) => img.resize(u32::MAX, h, image::imageops::FilterType::Lanczos3),
        (None, None) => return Err(StatusCode::BAD_REQUEST),
    };

    let mut output = Cursor::new(Vec::new());
    resized.write_to(&mut output, format).map_err(|e| {
        tracing::error!("Failed to write image: {:?}", e);
        StatusCode::BAD_REQUEST
    })?;

    Ok(output.into_inner())
}

fn apply_exif_orientation(img: image::DynamicImage, buffer: &[u8]) -> image::DynamicImage {
    let mut reader = BufReader::new(Cursor::new(buffer));
    let exif_reader = exif::Reader::new();

    let Ok(exif) = exif_reader.read_from_container(&mut reader) else {
        return img;
    };

    let Some(orientation) = exif.get_field(Tag::Orientation, In::PRIMARY) else {
        return img;
    };

    match orientation.value.get_uint(0) {
        Some(2) => img.fliph(),
        Some(3) => img.rotate180(),
        Some(4) => img.flipv(),
        Some(5) => img.rotate90().fliph(),
        Some(6) => img.rotate90(),
        Some(7) => img.rotate270().fliph(),
        Some(8) => img.rotate270(),
        _ => img, // 1 or unknown — no transform needed
    }
}
