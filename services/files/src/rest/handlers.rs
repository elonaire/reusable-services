use axum::{
    extract::{Extension, Multipart, Path as AxumUrlParams},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use lib::{
    integration::{auth::check_auth_from_acl, foreign_key::add_foreign_key_if_not_exists_rest},
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
    headers: HeaderMap,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    match check_auth_from_acl(headers.clone()).await {
        Ok(auth_status) => {
            let upload_dir = env::var("FILE_UPLOADS_DIR")
                .expect("Missing the FILE_UPLOADS_DIR environment variable.");

            let user_fk_body = ForeignKey {
                table: "user_id".into(),
                column: "user_id".into(),
                foreign_key: auth_status.sub,
            };

            let user_fk = add_foreign_key_if_not_exists_rest::<User>(&db, user_fk_body).await;
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
            let filepath = format!("{}{}", &upload_dir, system_filename);
            let mut field_name = String::new();
            let mut is_free = true;

            // Ensure the directory exists
            if let Err(e) = std::fs::create_dir_all(&upload_dir) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to create upload directory: {}", e),
                )
                    .into_response();
            }

            while let Some(field) = multipart.next_field().await.unwrap_or_else(|_| None) {
                let mut field = field;
                println!("field: ");

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
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to create file: {}", e),
                        )
                            .into_response()
                    }
                };

                // Read each chunk and write to the file
                while let Some(chunk) = match field.chunk().await {
                    Ok(Some(chunk)) => Some(chunk),
                    Ok(None) => None,
                    Err(e) => {
                        let _ = std::fs::remove_file(&filepath);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to read chunk: {}", e),
                        )
                            .into_response();
                    }
                } {
                    total_size += chunk.len() as u64;
                    if let Err(e) = file.write_all(&chunk) {
                        // Clean up file on error
                        let _ = std::fs::remove_file(&filepath);
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Failed to write to file: {}", e),
                        )
                            .into_response();
                    }
                }

                // Ensure file is successfully flushed
                if let Err(e) = file.flush() {
                    // Clean up file on error
                    let _ = std::fs::remove_file(&filepath);
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to flush file: {}", e),
                    )
                        .into_response();
                }
            }

            // Insert uploaded files into the database
            match db
                // .create::<Vec<UploadedFile>>("file")
                // .content(uploaded_file.clone())
                .query(
                    "
                    BEGIN TRANSACTION;
                    LET $user = type::thing($user_id);

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
                    let _ = std::fs::remove_file(&filepath);

                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to insert into database: {}", e),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to update order: {:?}", e);
            return (StatusCode::UNAUTHORIZED, format!("Auth failed! {:?}", e)).into_response();
        }
    }
}

pub async fn download_file(
    headers: HeaderMap,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    AxumUrlParams(file_name): AxumUrlParams<String>,
) -> Result<Response, StatusCode> {
    let upload_dir =
        env::var("FILE_UPLOADS_DIR").expect("Missing the FILE_UPLOADS_DIR environment variable.");
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
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let file_details: Option<UploadedFile> = file_details_query
            .take(0)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        match file_details {
            Some(file_details) => {
                if !file_details.is_free {
                    match check_auth_from_acl(headers.clone()).await {
                        Ok(auth_status) => {
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
                                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                            println!("bought_file_query: {:?}", bought_file_query);

                            let bought_file: Option<UploadedFile> = bought_file_query
                                .take(0)
                                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                            match bought_file {
                                Some(_) => {
                                    // Continue to generate the response
                                }
                                None => {
                                    // return Err(StatusCode::FORBIDDEN);
                                    // return Ok((
                                    //     StatusCode::FORBIDDEN,
                                    //     format!("Not Allowed!"),
                                    // ).into_response())
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
                                            .bind(("user_id", auth_status.sub.clone()))
                                            .bind(("file_name", file_name.clone()))
                                            .await
                                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                                    let file_info: Option<UploadedFile> = owned_file_query
                                        .take(0)
                                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                                    match file_info {
                                        Some(_) => {
                                            // Continue to generate the response
                                        }
                                        None => {
                                            eprintln!("Not Allowed! Not owned");
                                            return Ok((
                                                StatusCode::FORBIDDEN,
                                                format!("Not Allowed!"),
                                            )
                                                .into_response());
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Auth failed!: {:?}", e);
                            return Ok((StatusCode::FORBIDDEN, format!("Not Allowed!! {:?}", e))
                                .into_response());
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
                    .unwrap();
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
    let upload_dir =
        env::var("FILE_UPLOADS_DIR").expect("Missing the FILE_UPLOADS_DIR environment variable.");
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
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let file_details: Option<UploadedFile> = file_details_query
            .take(0)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        match file_details {
            Some(file_details) => {
                let content_type = file_details.mime_type;

                let response = Response::builder()
                    .header("Content-Type", content_type.to_string())
                    .body(bytes.into())
                    .unwrap();
                Ok(response)
            }
            None => Err(StatusCode::NOT_FOUND),
        }
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
