use std::sync::Arc;

use async_graphql::{Context, Object, Result};
use axum::Extension;
use lib::{
    middleware::auth::false_graphql::confirm_authentication,
    utils::{
        api_responses::synthesize_graphql_response,
        custom_error::ExtendedError,
        grpc::confirm_authorization,
        models::{AdminPrivilege, AuthorizationConstraint, Email},
    },
};

use hyper::{HeaderMap, StatusCode};
use surrealdb::{engine::remote::ws::Client, RecordId, Surreal};

use crate::{
    graphql::schemas::email::{
        GraphQLApiResponse, MailingList, MailingListInput, Subscription, SubscriptionInput,
    },
    utils,
};

#[derive(Default)]
pub struct EmailMutation;

#[Object]
impl EmailMutation {
    pub async fn send_email(
        &self,
        ctx: &Context<'_>,
        email: Email,
    ) -> Result<GraphQLApiResponse<String>> {
        let authenticated = confirm_authentication(ctx).await?;
        let authenticated_ref = &authenticated;

        let send_email_res = utils::email::send_email(&email).await;

        match send_email_res {
            Ok(send_email_res) => {
                let send_email_res = send_email_res.to_owned();
                let api_response =
                    synthesize_graphql_response(ctx, &send_email_res, Some(authenticated_ref))
                        .ok_or_else(|| {
                            tracing::error!("Failed to synthesize response!");
                            ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str())
                                .build()
                        })?;

                Ok(api_response.into())
            }
            Err(e) => {
                tracing::error!("Error sending email: {}", e);
                Err(
                    ExtendedError::new("Error sending email", StatusCode::BAD_REQUEST.as_str())
                        .build(),
                )
            }
        }
    }

    pub async fn create_mailing_list(
        &self,
        ctx: &Context<'_>,
        mailing_list_input: MailingListInput,
    ) -> Result<GraphQLApiResponse<MailingList>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let headers = ctx.data::<HeaderMap>().map_err(|e| {
            tracing::error!("Error HeaderMap: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let authenticated = confirm_authentication(ctx).await?;
        let authenticated_ref = &authenticated;

        let authorization_constraint = AuthorizationConstraint {
            permissions: vec!["write:mailing_list".into()],
            privilege: AdminPrivilege::Admin,
        };

        let authorized =
            confirm_authorization(authenticated_ref, &authorization_constraint, headers)
                .await
                .map_err(|e| {
                    tracing::error!("Error creating mailing list: {}", e);
                    ExtendedError::new("Failed to assign role", StatusCode::BAD_REQUEST.as_str())
                        .build()
                })?;

        if !authorized {
            return Err(ExtendedError::new("Forbidden", StatusCode::FORBIDDEN.as_str()).build());
        }

        let mut query = db
            .query(
                "
                CREATE mailing_list CONTENT $mailing_list_input
                ",
            )
            .bind(("mailing_list_input", mailing_list_input))
            .await
            .map_err(|e| {
                tracing::error!("Error creating mailing list: {}", e);
                ExtendedError::new("Failed to assign role", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        let db_response: Option<MailingList> = query.take(0).map_err(|e| {
            tracing::error!("Failed to create mailing list: {}", e);
            ExtendedError::new(
                "Failed to create mailing list",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()
        })?;

        match db_response {
            Some(mailing_list) => {
                let api_response =
                    synthesize_graphql_response(ctx, &mailing_list, Some(authenticated_ref))
                        .ok_or_else(|| {
                            tracing::error!("Failed to synthesize response!");
                            ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str())
                                .build()
                        })?;
                Ok(api_response.into())
            }
            None => Err(ExtendedError::new(
                "Failed to create mailing_list",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }

    pub async fn subscribe_to_mailing_list(
        &self,
        ctx: &Context<'_>,
        mut subscription_input: SubscriptionInput,
    ) -> Result<GraphQLApiResponse<Subscription>> {
        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        subscription_input.mailing_list = Some(RecordId::from_table_key(
            "mailing_list",
            &subscription_input
                .subscription_input_metadata
                .mailing_list_id,
        ));

        let mut query = db
            .query(
                "
                BEGIN TRANSACTION;
                LET $existing_subscriber = (SELECT VALUE id FROM ONLY subscriber WHERE email = $subscription_input.subscriber.email LIMIT 1);
                LET $subscriber = (IF $existing_subscriber != NONE
               	{ $existing_subscriber }
                                ELSE
               	{ (SELECT VALUE id FROM ONLY (CREATE subscriber CONTENT $subscription_input.subscriber) LIMIT 1) }
                );
                LET $mailing_list = $subscription_input.mailing_list;
                LET $subscription_id = (SELECT VALUE id FROM ONLY (RELATE $subscriber -> subscription -> $mailing_list RETURN AFTER) LIMIT 1);
                LET $subscription = (SELECT *, (<-subscriber)[0][*] AS subscriber, (->mailing_list)[0][*] AS mailing_list FROM ONLY $subscription_id LIMIT 1);
                RETURN $subscription;
                COMMIT TRANSACTION;
                ",
            )
            .bind(("subscription_input", subscription_input))
            .await
            .map_err(|e| {
                tracing::error!("Error creating subscription: {}", e);
                ExtendedError::new("Failed to create subscription", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        let db_response: Option<Subscription> = query.take(0).map_err(|e| {
            tracing::error!("Failed to create subscription: {}", e);
            ExtendedError::new(
                "Failed to create subscription",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()
        })?;

        match db_response {
            Some(subscription) => {
                let api_response = synthesize_graphql_response(ctx, &subscription, None)
                    .ok_or_else(|| {
                        tracing::error!("Failed to synthesize response!");
                        ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
                    })?;
                Ok(api_response.into())
            }
            None => Err(ExtendedError::new(
                "Failed to create subscription",
                StatusCode::BAD_REQUEST.as_str(),
            )
            .build()),
        }
    }
}
