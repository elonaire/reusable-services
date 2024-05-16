use std::{sync::Arc, time::Duration};

use async_graphql::{Context, Error, Object, Upload};
use aws_config::meta::region::RegionProviderChain;
use aws_sdk_s3::{presigning::PresigningConfig, Client as AWSClient};
use axum::Extension;
// use gql_client::Client as GQLClient;

use lib::utils::custom_error::ExtendedError;
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use crate::graphql::schemas::user;
use crate::graphql::schemas::{file::TestResponse, user::UserProfessionalInfo};
use crate::middleware::auth::check_auth_from_acl;

// const CHUNK_SIZE: u64 = 1024 * 1024 * 5; // 5MB

pub struct Mutation;

#[Object]
impl Mutation {
    // multipart upload to AWS S3
    async fn upload_file(
        &self,
        ctx: &Context<'_>,
        file: Upload,
    ) -> async_graphql::Result<TestResponse> {
        println!("file: {:?}", file.value(ctx).unwrap().size());
        // let file_size_in_mb = file.value(ctx).unwrap().size().unwrap() / 1024 / 1024;
        // let file_size_in_bytes = file.value(ctx).unwrap().size().unwrap();
        let bucket = "shamba-up-files";
        let key = "test_file";

        let region_provider = RegionProviderChain::default_provider().or_else("us-east-1");
        let config = aws_config::from_env().region(region_provider).load().await;
        let client = AWSClient::new(&config);

        // let multipart_upload_res: CreateMultipartUploadOutput = client
        //     .create_multipart_upload()
        //     .bucket(bucket.clone())
        //     .key(key.clone())
        //     .send()
        //     .await
        //     .unwrap();

        let presigned_url_expiry = Duration::from_secs(60 * 60 * 24 * 7);
        // let mut presigned_urls = vec![];
        let mut response = TestResponse {
            message: "test".to_string(),
            // presigned_urls: None,
            // upload_id: None,
            presigned_url: None,
        };

        // if file_size_in_bytes > CHUNK_SIZE {
        //     let upload_id = multipart_upload_res.upload_id.unwrap();
        //     // upload in parts
        //     let iterations = if file_size_in_bytes % CHUNK_SIZE == 0 {
        //         file_size_in_bytes / CHUNK_SIZE
        //     } else {
        //         file_size_in_bytes / CHUNK_SIZE + 1
        //     };

        //     for i in 0..iterations {
        //         let part_number = i + 1;
        //         let presigned_request = client
        //             .upload_part()
        //             .bucket(bucket.clone())
        //             .key(key.clone())
        //             .part_number(part_number.try_into().unwrap())
        //             .upload_id(upload_id.clone())
        //             .presigned(PresigningConfig::expires_in(presigned_url_expiry)?)
        //             .await?;
        //         let presigned_url = presigned_request.uri().to_string();

        //         presigned_urls.push(presigned_url);

        //         // println!("presigned_request: {:?}", presigned_request.uri());
        //     }

        //     response.presigned_urls = Some(presigned_urls);
        //     response.upload_id = Some(upload_id);
        // } else {
        //     // upload in one go
        //     let presigned_request = client
        //         .put_object()
        //         .bucket(bucket.clone())
        //         .key(key.clone())
        //         .presigned(PresigningConfig::expires_in(presigned_url_expiry)?)
        //         .await?;

        //     let presigned_url = presigned_request.uri().to_string();
        //     response.presigned_url = Some(presigned_url);

        //     println!("presigned_request: {:?}", presigned_request.uri());
        // }

        // upload in one go
        let presigned_request = client
            .put_object()
            .bucket(bucket)
            .key(key)
            .presigned(PresigningConfig::expires_in(presigned_url_expiry)?)
            .await?;

        let presigned_url = presigned_request.uri().to_string();
        response.presigned_url = Some(presigned_url);

        println!("presigned_request: {:?}", presigned_request.uri());

        Ok(response)
    }

    async fn add_professional_details(
        &self,
        ctx: &Context<'_>,
        professional_details: UserProfessionalInfo,
    ) -> async_graphql::Result<Vec<UserProfessionalInfo>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                ).await;

                if !id_added {
                    return Err(ExtendedError::new(
                        "Failed to add user_id",
                        Some(500.to_string()),
                    )
                    .build());
                }

                let response: Vec<UserProfessionalInfo> = db
                    .create("professional_details")
                    .content(UserProfessionalInfo {
                        ..professional_details
                    })
                    .await
                    .map_err(|e| Error::new(e.to_string()))?;

                let mut user_from_db_res = db
                    .query("SELECT * FROM type::table($table) WHERE user_id = $user_id LIMIT 1")
                    .bind(("table", "user_id"))
                    .bind(("user_id", auth_status.decode_token.clone()))
                    .await?;

                let user_from_db: Option<user::User> = user_from_db_res.take(0).unwrap();

                let relate_to_user_query = format!("
                    RELATE {}->has_professional_details->{} CONTENT {{
                        in: {},
                        out: {}
                    }}
                ", user_from_db.clone().unwrap().id.as_ref().unwrap().to_raw(), response[0].clone().id.as_ref().unwrap().to_raw(), user_from_db.clone().unwrap().id.as_ref().unwrap().to_raw(), response[0].clone().id.as_ref().unwrap().to_raw());

                let _relate_to_user = db
                .query(relate_to_user_query)
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    pub async fn add_user_service(
        &self,
        ctx: &Context<'_>,
        user_service: user::UserService,
    ) -> async_graphql::Result<Vec<user::UserService>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                ).await;

                if !id_added {
                    return Err(ExtendedError::new(
                        "Failed to add user_id",
                        Some(500.to_string()),
                    )
                    .build());
                }

                let response: Vec<user::UserService> = db
                    .create("service")
                    .content(user_service)
                    .await
                    .map_err(|e| Error::new(e.to_string()))?;

                let mut user_from_db_res = db
                    .query("SELECT * FROM type::table($table) WHERE user_id = $user_id LIMIT 1")
                    .bind(("table", "user_id"))
                    .bind(("user_id", auth_status.decode_token.clone()))
                    .await?;

                let user_from_db: Option<user::User> = user_from_db_res.take(0).unwrap();

                let relate_to_user_query = format!("
                    RELATE {}->offers_service->{} CONTENT {{
                        in: {},
                        out: {}
                    }}
                ", user_from_db.clone().unwrap().id.as_ref().unwrap().to_raw(), response[0].clone().id.as_ref().unwrap().to_raw(), user_from_db.clone().unwrap().id.as_ref().unwrap().to_raw(), response[0].clone().id.as_ref().unwrap().to_raw());

                let _relate_to_user = db
                .query(relate_to_user_query)
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    pub async fn add_portfolio_item(
        &self,
        ctx: &Context<'_>,
        portfolio_item: user::UserPortfolio,
    ) -> async_graphql::Result<Vec<user::UserPortfolio>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                ).await;

                if !id_added {
                    return Err(ExtendedError::new(
                        "Failed to add user_id",
                        Some(500.to_string()),
                    )
                    .build());
                }

                let response: Vec<user::UserPortfolio> = db
                    .create("portfolio")
                    .content(portfolio_item)
                    .await
                    .map_err(|e| Error::new(e.to_string()))?;

                let mut user_from_db_res = db
                    .query("SELECT * FROM type::table($table) WHERE user_id = $user_id LIMIT 1")
                    .bind(("table", "user_id"))
                    .bind(("user_id", auth_status.decode_token.clone()))
                    .await?;

                let user_from_db: Option<user::User> = user_from_db_res.take(0).unwrap();

                let relate_to_user_query = format!("
                    RELATE {}->has_portfolio->{} CONTENT {{
                        in: {},
                        out: {}
                    }}
                ", user_from_db.clone().unwrap().id.as_ref().unwrap().to_raw(), response[0].clone().id.as_ref().unwrap().to_raw(), user_from_db.clone().unwrap().id.as_ref().unwrap().to_raw(), response[0].clone().id.as_ref().unwrap().to_raw());

                let _relate_to_user = db
                .query(relate_to_user_query)
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }
}
