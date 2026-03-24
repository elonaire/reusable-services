use std::{env, sync::Arc};

// use crate::graphql::schemas::general::ExchangeRatesResponse;
use async_graphql::{Context, Object, Result};
use axum::{http::HeaderMap, Extension};
use hyper::{
    header::{AUTHORIZATION, COOKIE},
    StatusCode,
};
use lib::{
    integration::{
        foreign_key::add_foreign_key_if_not_exists,
        grpc::clients::acl_service::{
            acl_client::AclClient, FetchSiteOwnerIdRequest, FetchSiteOwnerIdResponse,
        },
    },
    middleware::auth::false_graphql::confirm_authentication,
    utils::{
        api_responses::synthesize_graphql_response,
        custom_error::ExtendedError,
        grpc::{create_grpc_client, AuthMetaData},
        models::{ForeignKey, InitializePaymentResponse, UserId, UserPaymentDetails},
    },
};
use surrealdb::{engine::remote::ws::Client, Surreal};
use tonic::{transport::Channel, Response, Result as GrpcResult};

use crate::{
    graphql::schemas::{
        pandascrow::{PandascrowEscrow, PandascrowMilestoneEscrow},
        shared::GraphQLApiResponse,
    },
    utils::payments::{create_pandascrow_escrow, initiate_payment_integration},
};

#[derive(Default)]
pub struct PaymentMutation;

#[Object]
impl PaymentMutation {
    pub async fn initiate_payment(
        &self,
        ctx: &Context<'_>,
        mut user_payment_details: UserPaymentDetails,
    ) -> Result<GraphQLApiResponse<InitializePaymentResponse>> {
        let auth_status = confirm_authentication(ctx).await?;
        let auth_status_ref = &auth_status;

        let payment_req = initiate_payment_integration(&mut user_payment_details).await?;

        let api_response = synthesize_graphql_response(ctx, &payment_req, Some(auth_status_ref))
            .ok_or_else(|| {
                tracing::error!("Failed to synthesize response!");
                ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str()).build()
            })?;

        Ok(api_response.into())
    }

    pub async fn create_pandascrow_milestone_escrow(
        &self,
        ctx: &Context<'_>,
        mut pandascrow_escrow: PandascrowMilestoneEscrow,
    ) -> Result<GraphQLApiResponse<PandascrowEscrow>> {
        let auth_status = confirm_authentication(ctx).await?;
        let authenticated_ref = &auth_status;

        let headers = ctx.data::<HeaderMap>().map_err(|e| {
            tracing::error!("Error HeaderMap: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;
        let auth_header = headers.get(AUTHORIZATION);
        let cookie_header = headers.get(COOKIE);

        let db = ctx.data::<Extension<Arc<Surreal<Client>>>>().map_err(|e| {
            tracing::error!("Error extracting Surreal Client: {:?}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let user_fk = ForeignKey {
            table: "user_id".to_string(),
            column: "user_id".to_string(),
            foreign_key: authenticated_ref.sub.to_owned(),
        };

        let Some(internal_user_id) =
            add_foreign_key_if_not_exists::<Extension<Arc<Surreal<Client>>>, UserId>(db, user_fk)
                .await
        else {
            tracing::error!("Failed to add user_id");
            return Err(ExtendedError::new(
                "Something went wrong",
                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
            )
            .build());
        };

        let mut query_result = db
            .query(
                r#"
                BEGIN TRANSACTION;
                LET $pandascrow_escrow = (CREATE pandascrow_escrow CONTENT {
                    created_by: $internal_user_id
                });
                RETURN $pandascrow_escrow;
                COMMIT TRANSACTION;
            "#,
            )
            .bind(("internal_user_id", internal_user_id.id))
            .await
            .map_err(|e| {
                tracing::error!("Error creating escrow: {}", e);
                ExtendedError::new("Error creating escrow", StatusCode::BAD_REQUEST.as_str())
                    .build()
            })?;

        let response: Option<PandascrowEscrow> = query_result.take(0).map_err(|e| {
            tracing::error!("PandascrowEscrow deserialization error: {}", e);
            ExtendedError::new("Server Error", StatusCode::INTERNAL_SERVER_ERROR.as_str()).build()
        })?;

        let mut request = tonic::Request::new(FetchSiteOwnerIdRequest {});

        let auth_metadata: AuthMetaData<FetchSiteOwnerIdRequest> = AuthMetaData {
            auth_header,
            cookie_header,
            constructed_grpc_request: Some(&mut request),
        };

        let acl_service_grpc = env::var("OAUTH_SERVICE_GRPC").map_err(|e| {
            tracing::error!(
                "Missing the OAUTH_SERVICE_GRPC environment variable.: {}",
                e
            );
            ExtendedError::new(
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
            )
            .build()
        })?;

        let mut acl_grpc_client =
            create_grpc_client::<FetchSiteOwnerIdRequest, AclClient<Channel>>(
                &acl_service_grpc,
                true,
                Some(auth_metadata),
            )
            .await
            .map_err(|e| {
                tracing::error!("Failed to connect to ACL service: {}", e);
                ExtendedError::new(
                    "Internal Server Error",
                    StatusCode::INTERNAL_SERVER_ERROR.as_str(),
                )
                .build()
            })?;

        tracing::debug!("acl_grpc_client was created successfully!");

        let Ok(site_owner_id_response) = acl_grpc_client.fetch_site_owner_id(request).await
            as GrpcResult<Response<FetchSiteOwnerIdResponse>>
        else {
            return Err(ExtendedError::new(
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR.as_str(),
            )
            .build());
        };

        tracing::debug!("site_owner_id_response: {site_owner_id_response:?}");

        match response {
            Some(escrow) => {
                let escrow_ref = &escrow;
                pandascrow_escrow.uuid = site_owner_id_response.into_inner().user_id;
                pandascrow_escrow.initiator_id = authenticated_ref.sub.clone();
                let _ = create_pandascrow_escrow(&mut pandascrow_escrow).await?;
                let api_response =
                    synthesize_graphql_response(ctx, escrow_ref, Some(authenticated_ref))
                        .ok_or_else(|| {
                            tracing::error!("Failed to synthesize response!");
                            ExtendedError::new("Bad Request", StatusCode::BAD_REQUEST.as_str())
                                .build()
                        })?;

                Ok(api_response.into())
            }
            None => {
                return Err(ExtendedError::new(
                    "Failed to create pandascrow escrow",
                    StatusCode::BAD_REQUEST.as_str(),
                )
                .build());
            }
        }
    }
}
