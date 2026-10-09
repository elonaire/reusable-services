//! Multipart upload for large files.
//!
//! See module-level notes at the top of the previous version for the flow
//! description; omitted here for brevity.

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Extension, Path as AxumUrlParams, Query};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Json;
use futures_util::StreamExt;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use surrealdb::engine::remote::ws::Client;
use surrealdb::types::{RecordId, RecordIdKey, SurrealValue};
use surrealdb::Surreal;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

use lib::utils::{
    api_responses::synthesize_rest_response,
    custom_error::ApiError,
    models::{ApiResponseRest, AuthStatus},
};

use crate::graphql::schemas::general::{Bucket, FileMeta};
use crate::rest::handlers::{create_file_record, resolve_container, user_record_id};
use lib::configs::uploads::UploadConfig;

// ============================================================================
// Models
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, SurrealValue)]
pub enum UploadStatus {
    InProgress,
    Completed,
    Aborted,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct UploadSession {
    pub id: RecordId,
    pub user: RecordId,
    pub upload_id: String,
    pub file_name: String,
    pub total_size: u64,
    pub mime_type: String,
    pub bucket: RecordId,
    pub key: Option<RecordId>,
    pub bucket_path: String,
    pub part_size: u64,
    pub total_parts: u64,
    pub status: UploadStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct UploadPart {
    pub id: RecordId,
    pub session: RecordId,
    pub part_number: i64,
    pub system_filename: String,
    pub size: i64,
    pub etag: String,
    pub received_at: chrono::DateTime<chrono::Utc>,
}

/// Typed payload for creating a new `upload_session` row.
///
/// Serialized directly into SurrealDB via `.content(...)`. Field names
/// mirror the schema so any drift shows up as a runtime `SCHEMAFULL` error
/// naming the offending field, not as a silently dropped column.
#[derive(Debug, Serialize, Clone, SurrealValue)]
struct NewUploadSession {
    user: RecordId,
    upload_id: String,
    file_name: String,
    total_size: i64,
    mime_type: String,
    bucket: RecordId,
    key: Option<RecordId>,
    bucket_path: String,
    part_size: i64,
    total_parts: i64,
    status: UploadStatus,
}

// ----------------------------------------------------------------------------
// Wire types
// ----------------------------------------------------------------------------

#[derive(Debug, Deserialize, Clone)]
pub struct InitiateRequest {
    pub file_name: String,
    pub total_size: u64,
    pub mime_type: String,
    pub bucket_path: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct InitiateResponse {
    pub upload_id: String,
    pub part_size: u64,
    pub total_parts: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PartUrlQuery {
    pub part_number: u32,
}

#[derive(Debug, Serialize, Clone)]
pub struct PartUrlResponse {
    pub url: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PartInfo {
    pub part_number: u32,
    pub size: u64,
    pub etag: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CompleteRequest {
    pub parts: Vec<PartInfo>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CompleteResponse {
    pub file_id: String,
    pub system_filename: String,
    pub original_filename: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct AbortResponse {
    pub upload_id: String,
    pub status: &'static str,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PartUploadQuery {
    pub upload_id: String,
    pub part_number: u32,
    pub expires: i64,
    pub sig: String,
}

// ============================================================================
// Signing
// ============================================================================

#[derive(Debug, Clone, Copy)]
pub enum SignatureError {
    Expired,
    Invalid,
}

fn canonical(upload_id: &str, part_number: u32, expires_at: i64) -> String {
    format!("v1:{upload_id}:{part_number}:{expires_at}")
}

fn sign_part_url(secret: &[u8], upload_id: &str, part_number: u32, expires_at: i64) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(canonical(upload_id, part_number, expires_at).as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn verify_part_url(
    secret: &[u8],
    upload_id: &str,
    part_number: u32,
    expires_at: i64,
    signature: &str,
    now: i64,
) -> Result<(), SignatureError> {
    if now > expires_at {
        return Err(SignatureError::Expired);
    }
    let expected = sign_part_url(secret, upload_id, part_number, expires_at);
    if expected.as_bytes().ct_eq(signature.as_bytes()).into() {
        Ok(())
    } else {
        Err(SignatureError::Invalid)
    }
}

// ============================================================================
// Local helpers
// ============================================================================

fn part_system_filename(upload_id: &str, part_number: u32) -> String {
    let name = format!("part:{upload_id}:{part_number}");
    Uuid::new_v5(&Uuid::NAMESPACE_OID, name.as_bytes()).to_string()
}

fn record_key_string(id: &RecordId) -> Option<String> {
    match &id.key {
        RecordIdKey::String(s) => Some(s.clone()),
        _ => None,
    }
}

async fn load_in_progress_session(
    db: &Surreal<Client>,
    upload_id: &str,
) -> Result<UploadSession, ApiError> {
    let session: Option<UploadSession> = db
        .query(
            "SELECT * FROM ONLY upload_session \
             WHERE upload_id = $id AND status.InProgress != NONE",
        )
        .bind(("id", upload_id.to_string()))
        .await
        .map_err(ApiError::db)?
        .take(0)
        .map_err(ApiError::db)?;

    session.ok_or_else(|| {
        tracing::warn!(upload_id, "session not found or not in_progress");
        ApiError::NotFound("upload session not found".into())
    })
}

// ============================================================================
// Handlers
// ============================================================================

pub async fn initiate(
    headers: HeaderMap,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth): Extension<AuthStatus>,
    Extension(cfg): Extension<Arc<UploadConfig>>,
    Json(req): Json<InitiateRequest>,
) -> Result<ApiResponseRest<InitiateResponse>, ApiError> {
    let limit = cfg.max_multipart_upload_size * 1024 * 1024 * 1024;
    if req.total_size == 0 || req.total_size > limit {
        return Err(ApiError::BadRequest(format!(
            "file size must be between 1 and {} bytes",
            limit
        )));
    }

    let user = user_record_id(&db, &auth).await?;
    let resolved = resolve_container(&db, &req.bucket_path, Some(&user)).await?;

    let part_limit = cfg.max_multipart_part_size * 1024 * 1024;
    let raw = part_limit.max(req.total_size.div_ceil(cfg.max_multipart_parts as u64));
    let part_size = (raw + (1 << 20) - 1) & !((1 << 20) - 1);
    let total_parts = req.total_size.div_ceil(part_size) as u32;
    let upload_id = Uuid::new_v4().to_string();

    let new_session = NewUploadSession {
        user,
        upload_id: upload_id.clone(),
        file_name: req.file_name,
        total_size: req.total_size as i64,
        mime_type: req.mime_type,
        bucket: resolved.bucket,
        key: resolved.key,
        bucket_path: req.bucket_path,
        part_size: part_size as i64,
        total_parts: total_parts as i64,
        status: UploadStatus::InProgress,
    };

    let session: Option<UploadSession> = db
        .create("upload_session")
        .content(new_session)
        .await
        .map_err(ApiError::db)?;

    if session.is_none() {
        tracing::error!("upload_session create returned no row");
        return Err(ApiError::Internal(anyhow::anyhow!(
            "Failed to create upload session"
        )));
    }

    tracing::info!(
        upload_id = %upload_id,
        total_size = req.total_size,
        part_size,
        total_parts,
        "upload session initiated"
    );

    Ok(synthesize_rest_response(
        &headers,
        &InitiateResponse {
            upload_id,
            part_size,
            total_parts,
        },
        StatusCode::CREATED,
    ))
}

pub async fn part_url(
    headers: HeaderMap,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth): Extension<AuthStatus>,
    Extension(cfg): Extension<Arc<UploadConfig>>,
    AxumUrlParams((upload_id, part_number)): AxumUrlParams<(String, u32)>,
) -> Result<ApiResponseRest<PartUrlResponse>, ApiError> {
    let user = user_record_id(&db, &auth).await?;
    let session = load_in_progress_session(&db, &upload_id).await?;

    if session.user != user {
        tracing::warn!(upload_id, "user does not own session");
        return Err(ApiError::NotFound("upload session not found".into()));
    }

    if part_number == 0 || part_number > session.total_parts as u32 {
        return Err(ApiError::BadRequest(format!(
            "part_number must be between 1 and {}",
            session.total_parts
        )));
    }

    let expires_at = chrono::Utc::now().timestamp() + cfg.part_url_ttl_secs as i64;
    let sig = sign_part_url(&cfg.url_secret, &upload_id, part_number, expires_at);

    let url = format!(
        "{}/multipart-upload/parts?upload_id={}&part_number={}&expires={}&sig={}",
        cfg.public_base_url, upload_id, part_number, expires_at, sig
    );

    Ok(synthesize_rest_response(
        &headers,
        &PartUrlResponse { url, expires_at },
        StatusCode::OK,
    ))
}

pub async fn list_parts(
    headers: HeaderMap,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth): Extension<AuthStatus>,
    AxumUrlParams(upload_id): AxumUrlParams<String>,
) -> Result<ApiResponseRest<Vec<PartInfo>>, ApiError> {
    let user = user_record_id(&db, &auth).await?;
    let session = load_in_progress_session(&db, &upload_id).await?;

    if session.user != user {
        return Err(ApiError::NotFound("upload session not found".into()));
    }

    let parts: Vec<UploadPart> = db
        .query("SELECT * FROM upload_part WHERE session = $s ORDER BY part_number")
        .bind(("s", session.id.clone()))
        .await
        .map_err(ApiError::db)?
        .take(0)
        .map_err(ApiError::db)?;

    let infos: Vec<PartInfo> = parts
        .into_iter()
        .map(|p| PartInfo {
            part_number: p.part_number as u32,
            size: p.size as u64,
            etag: p.etag,
        })
        .collect();

    Ok(synthesize_rest_response(&headers, &infos, StatusCode::OK))
}

pub async fn complete(
    headers: HeaderMap,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth): Extension<AuthStatus>,
    Extension(cfg): Extension<Arc<UploadConfig>>,
    AxumUrlParams(upload_id): AxumUrlParams<String>,
    Json(req): Json<CompleteRequest>,
) -> Result<ApiResponseRest<CompleteResponse>, ApiError> {
    let user = user_record_id(&db, &auth).await?;
    let session = load_in_progress_session(&db, &upload_id).await?;

    if session.user != user {
        return Err(ApiError::NotFound("upload session not found".into()));
    }

    let stored: Vec<UploadPart> = db
        .query("SELECT * FROM upload_part WHERE session = $s ORDER BY part_number")
        .bind(("s", session.id.clone()))
        .await
        .map_err(ApiError::db)?
        .take(0)
        .map_err(ApiError::db)?;

    if stored.len() != session.total_parts as usize {
        return Err(ApiError::BadRequest(format!(
            "expected {} parts, have {}",
            session.total_parts,
            stored.len()
        )));
    }

    use std::collections::HashMap;
    let expected: HashMap<u32, &str> = stored
        .iter()
        .map(|p| (p.part_number as u32, p.etag.as_str()))
        .collect();

    for p in &req.parts {
        match expected.get(&p.part_number) {
            Some(etag) if *etag == p.etag.as_str() => {}
            _ => {
                tracing::warn!(part_number = p.part_number, "etag mismatch");
                return Err(ApiError::BadRequest(format!(
                    "etag mismatch for part {}",
                    p.part_number
                )));
            }
        }
    }

    let final_filename = Uuid::new_v4().to_string();
    let tmp_filename = format!("{final_filename}.tmp");
    let final_path = cfg.upload_dir.join(&final_filename);
    let tmp_path = cfg.upload_dir.join(&tmp_filename);

    if let Err(e) = assemble_parts(&cfg, &stored, &tmp_path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e);
    }

    tokio::fs::rename(&tmp_path, &final_path)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "final rename failed");
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?;

    let bucket: Option<Bucket> = db
        .query("SELECT * FROM ONLY $b")
        .bind(("b", session.bucket.clone()))
        .await
        .map_err(ApiError::db)?
        .take(0)
        .map_err(ApiError::db)?;

    let bucket = bucket.ok_or_else(|| {
        tracing::error!(bucket = ?session.bucket, "bucket no longer exists");
        ApiError::Internal(anyhow::anyhow!("Destination no longer exists"))
    })?;

    let meta = FileMeta {
        name: session.file_name.clone(),
        size: session.total_size,
        mime_type: session.mime_type.clone(),
        system_filename: final_filename.clone(),
        is_premium: bucket.is_premium,
        is_public: false,
    };

    let file = create_file_record(&db, &user, &meta, &session.bucket, session.key.as_ref())
        .await
        .map_err(|e| {
            let path = final_path.clone();
            tokio::spawn(async move {
                let _ = tokio::fs::remove_file(&path).await;
            });
            e
        })?;

    let file_id = record_key_string(&file.id).ok_or_else(|| {
        tracing::error!(id = ?file.id, "file id is not a string record key");
        ApiError::Internal(anyhow::anyhow!("Invalid file id"))
    })?;

    db.query("UPDATE upload_session SET status = { Completed: {} } WHERE upload_id = $id")
        .bind(("id", upload_id.clone()))
        .await
        .map_err(ApiError::db)?;

    let upload_dir = cfg.upload_dir.clone();
    let part_filenames: Vec<String> = stored.iter().map(|p| p.system_filename.clone()).collect();
    let session_id = session.id.clone();
    let db_bg = db.clone();
    tokio::spawn(async move {
        for name in &part_filenames {
            let path = upload_dir.join(name);
            if let Err(e) = tokio::fs::remove_file(&path).await {
                tracing::warn!(error = %e, path = %path.display(), "failed to remove part file");
            }
        }
        if let Err(e) = db_bg
            .query("DELETE upload_part WHERE session = $s")
            .bind(("s", session_id))
            .await
        {
            tracing::warn!(error = %e, "failed to remove part rows");
        }
    });

    tracing::info!(
        upload_id = %upload_id,
        file_id = %file_id,
        bytes = session.total_size,
        "upload session completed"
    );

    Ok(synthesize_rest_response(
        &headers,
        &CompleteResponse {
            file_id,
            system_filename: final_filename,
            original_filename: session.file_name,
        },
        StatusCode::CREATED,
    ))
}

pub async fn abort(
    headers: HeaderMap,
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(auth): Extension<AuthStatus>,
    Extension(cfg): Extension<Arc<UploadConfig>>,
    AxumUrlParams(upload_id): AxumUrlParams<String>,
) -> Result<ApiResponseRest<AbortResponse>, ApiError> {
    let user = user_record_id(&db, &auth).await?;
    let session = load_in_progress_session(&db, &upload_id).await?;

    if session.user != user {
        return Err(ApiError::NotFound("upload session not found".into()));
    }

    let parts: Vec<UploadPart> = db
        .query("SELECT * FROM upload_part WHERE session = $s")
        .bind(("s", session.id.clone()))
        .await
        .map_err(ApiError::db)?
        .take(0)
        .map_err(ApiError::db)?;

    db.query("UPDATE upload_session SET status = { Aborted: {} } WHERE upload_id = $id")
        .bind(("id", upload_id.clone()))
        .await
        .map_err(ApiError::db)?;

    let upload_dir = cfg.upload_dir.clone();
    let session_id = session.id.clone();
    let db_bg = db.clone();
    tokio::spawn(async move {
        for part in &parts {
            let path = upload_dir.join(&part.system_filename);
            if let Err(e) = tokio::fs::remove_file(&path).await {
                tracing::warn!(error = %e, path = %path.display(), "failed to remove part file");
            }
        }
        let _ = db_bg
            .query("DELETE upload_part WHERE session = $s")
            .bind(("s", session_id))
            .await;
    });

    tracing::info!(upload_id = %upload_id, "upload session aborted");

    Ok(synthesize_rest_response(
        &headers,
        &AbortResponse {
            upload_id,
            status: "aborted",
        },
        StatusCode::OK,
    ))
}

/// The signed-URL receiver. No auth middleware — the URL signature is the auth.
///
/// Deliberately returns a raw `Response` (not `ApiResponseRest`) because this
/// endpoint mirrors S3's `UploadPart`: the client only cares about the status
/// code and the `ETag` header, and wrapping it in an application envelope would
/// mean the client has to parse JSON just to read a header.
pub async fn upload_part(
    Extension(db): Extension<Arc<Surreal<Client>>>,
    Extension(cfg): Extension<Arc<UploadConfig>>,
    Query(q): Query<PartUploadQuery>,
    body: Body,
) -> Result<Response, ApiError> {
    let now = chrono::Utc::now().timestamp();
    verify_part_url(
        &cfg.url_secret,
        &q.upload_id,
        q.part_number,
        q.expires,
        &q.sig,
        now,
    )
    .map_err(|e| match e {
        SignatureError::Expired => ApiError::Unauthorized("upload URL has expired".into()),
        SignatureError::Invalid => ApiError::Unauthorized("invalid upload URL".into()),
    })?;

    let session = load_in_progress_session(&db, &q.upload_id).await?;

    if q.part_number == 0 || q.part_number > session.total_parts as u32 {
        return Err(ApiError::BadRequest("part_number out of range".into()));
    }

    let expected_size = if q.part_number == session.total_parts as u32 {
        let consumed = session.part_size as u64 * (session.total_parts as u64 - 1);
        session.total_size as u64 - consumed
    } else {
        session.part_size as u64
    };

    let system_filename = part_system_filename(&q.upload_id, q.part_number);
    let part_path = cfg.upload_dir.join(&system_filename);
    let tmp_path = cfg.upload_dir.join(format!("{system_filename}.tmp"));

    let mut file = File::create(&tmp_path).await.map_err(|e| {
        tracing::error!(error = %e, path = %tmp_path.display(), "failed to create part file");
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut stream = body.into_data_stream();

    let write_result: Result<(), ApiError> = async {
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| {
                tracing::error!(error = %e, "part body read failed");
                ApiError::BadRequest("part upload aborted".into())
            })?;

            total += chunk.len() as u64;
            if total > expected_size {
                return Err(ApiError::PayloadTooLarge(format!(
                    "part exceeds expected size of {expected_size} bytes"
                )));
            }

            hasher.update(&chunk);
            file.write_all(&chunk).await.map_err(|e| {
                tracing::error!(error = %e, "part write failed");
                ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
            })?;
        }
        file.flush().await.map_err(|e| {
            tracing::error!(error = %e, "part flush failed");
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?;
        Ok(())
    }
    .await;

    if let Err(e) = write_result {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(e);
    }

    if total != expected_size {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        return Err(ApiError::BadRequest(format!(
            "part size mismatch: expected {expected_size}, got {total}"
        )));
    }

    tokio::fs::rename(&tmp_path, &part_path)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "part rename failed");
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })?;

    let etag = hex::encode(hasher.finalize());

    db.query(
        r#"
            DELETE upload_part WHERE session = $session AND part_number = $part_number;

            CREATE upload_part CONTENT {
                session: $session,
                part_number: $part_number,
                system_filename: $system_filename,
                size: $size,
                etag: $etag,
            };
        "#,
    )
    .bind(("session", session.id.clone()))
    .bind(("part_number", q.part_number as i64))
    .bind(("system_filename", system_filename.clone()))
    .bind(("size", total as i64))
    .bind(("etag", etag.clone()))
    .await
    .map_err(ApiError::db)?;

    tracing::debug!(
        upload_id = %q.upload_id,
        part_number = q.part_number,
        bytes = total,
        "part received"
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("ETag", format!("\"{etag}\""))
        .body(Body::empty())
        .map_err(|e| {
            tracing::error!(error = %e, "failed to build part response");
            ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
        })
}

// ============================================================================
// Assembly helper
// ============================================================================

async fn assemble_parts(
    cfg: &UploadConfig,
    parts: &[UploadPart],
    out_path: &std::path::Path,
) -> Result<(), ApiError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut out = File::create(out_path).await.map_err(|e| {
        tracing::error!(error = %e, path = %out_path.display(), "failed to create assembly target");
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    let mut buf = vec![0u8; 1024 * 1024];

    for part in parts {
        let part_path = cfg.upload_dir.join(&part.system_filename);
        let mut inp = File::open(&part_path).await.map_err(|e| {
            tracing::error!(error = %e, path = %part_path.display(), "missing part file");
            ApiError::Internal(anyhow::anyhow!("Part file missing"))
        })?;

        loop {
            let n = inp.read(&mut buf).await.map_err(|e| {
                tracing::error!(error = %e, "part read failed");
                ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
            })?;
            if n == 0 {
                break;
            }
            out.write_all(&buf[..n]).await.map_err(|e| {
                tracing::error!(error = %e, "assembly write failed");
                ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
            })?;
        }
    }

    out.flush().await.map_err(|e| {
        tracing::error!(error = %e, "assembly flush failed");
        ApiError::Internal(anyhow::anyhow!("Something went wrong!"))
    })?;

    Ok(())
}

// ============================================================================
// Stale session sweeper
// ============================================================================

pub fn spawn_session_sweeper(
    db: Arc<Surreal<Client>>,
    cfg: Arc<UploadConfig>,
    stale_after: chrono::Duration,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));

        loop {
            tick.tick().await;

            let cutoff = chrono::Utc::now() - stale_after;

            let stale: Result<Vec<UploadSession>, _> = db
                .query(
                    "SELECT * FROM upload_session WHERE status.InProgress != NONE AND created_at < $cutoff",
                )
                .bind(("cutoff", cutoff))
                .await
                .and_then(|mut r| r.take(0));

            let stale = match stale {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "sweeper: query failed");
                    continue;
                }
            };

            if stale.is_empty() {
                continue;
            }

            tracing::info!(count = stale.len(), "sweeper: cleaning stale sessions");

            for session in stale {
                let parts: Vec<UploadPart> = match db
                    .query("SELECT * FROM upload_part WHERE session = $s")
                    .bind(("s", session.id.clone()))
                    .await
                    .and_then(|mut r| r.take(0))
                {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!(error = %e, upload_id = %session.upload_id, "sweeper: part lookup failed");
                        continue;
                    }
                };

                for part in &parts {
                    let path = cfg.upload_dir.join(&part.system_filename);
                    if let Err(e) = tokio::fs::remove_file(&path).await {
                        tracing::warn!(error = %e, path = %path.display(), "sweeper: failed to remove file");
                    }
                }

                let _ = db
                    .query("DELETE upload_part WHERE session = $s")
                    .bind(("s", session.id.clone()))
                    .await;

                let _ = db
                    .query("UPDATE upload_session SET status = { Aborted: {} } WHERE id = $id")
                    .bind(("id", session.id.clone()))
                    .await;

                tracing::info!(upload_id = %session.upload_id, "sweeper: aborted stale session");
            }
        }
    });
}
