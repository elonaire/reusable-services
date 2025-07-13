use std::io::{Error, ErrorKind};

use lib::utils::custom_traits::AsSurrealClient;

use crate::graphql::schemas::user::User;

pub async fn create_user<T: Clone + AsSurrealClient>(
    db: &T,
    user: User,
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
