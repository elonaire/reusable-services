use std::io::{Error, ErrorKind};

use lib::utils::custom_traits::AsSurrealClient;
use surrealdb::RecordId;

use crate::graphql::schemas::user::{User, UserInput};

pub async fn create_user<T: Clone + AsSurrealClient>(
    db: &T,
    user: UserInput,
) -> Result<Option<User>, Error> {
    let response: Option<User> =
        db.as_client()
            .create("user")
            .content(user)
            .await
            .map_err(|e| {
                tracing::error!("Error creating user: {}", e);
                Error::new(ErrorKind::InvalidData, "Failed to sign up")
            })?;

    Ok(response)
}

pub async fn fetch_site_owner_id<T: Clone + AsSurrealClient>(db: &T) -> Result<String, Error> {
    let mut query_result = db
        .as_client()
        .query(
            "
            SELECT VALUE id FROM ONLY user WHERE ->assigned->(role WHERE role_name = 'SUPERADMIN') LIMIT 1
            ",
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user: {}", e);
            Error::new(ErrorKind::Other, "DB Query failed: Get user")
        })?;
    let user_record: Option<RecordId> = query_result.take(0).map_err(|e| {
        tracing::error!("Failed to deserialize user(take(0)): {}", e);
        Error::new(ErrorKind::Other, "Failed to fetch user")
    })?;

    match user_record {
        Some(record_id) => Ok(record_id.key().to_string()),
        None => Err(Error::new(ErrorKind::Other, "No site owner found")),
    }
}
