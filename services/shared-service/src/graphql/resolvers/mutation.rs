use std::sync::Arc;

use async_graphql::{Context, Error, Object};
use axum::Extension;
// use gql_client::Client as GQLClient;

use lib::utils::custom_error::ExtendedError;
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use crate::graphql::schemas::{blog, shared, user};
use crate::graphql::schemas::user::UserProfessionalInfo;
use crate::middleware::auth::check_auth_from_acl;

// const CHUNK_SIZE: u64 = 1024 * 1024 * 5; // 5MB

pub struct Mutation;

#[Object]
impl Mutation {
    /// Create new professional details
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
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    LET $professional_details = CREATE professional_details CONTENT $professional_details_input;
                    LET $user = (SELECT id FROM type::table($table) WHERE user_id = $user_id LIMIT 1);
                    
                    LET $professional_details_id = (SELECT VALUE id FROM $professional_details);
                    RELATE $user->has_professional_details->$professional_details_id;
                    RETURN $professional_details;
                    COMMIT TRANSACTION;    
                    "
                )
                .bind(("professional_details_input", professional_details))
                .bind(("table", "user_id"))
                .bind(("user_id", auth_status.decode_token.clone()))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<UserProfessionalInfo> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// Create a new user service
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
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    LET $user_service = CREATE service CONTENT $user_service_input;
                    LET $user = (SELECT id FROM type::table($table) WHERE user_id = $user_id LIMIT 1);
                    
                    LET $user_service_id = (SELECT VALUE id FROM $user_service);
                    RELATE $user->offers_service->$user_service_id;
                    RETURN $user_service;
                    COMMIT TRANSACTION;    
                    "
                )
                .bind(("user_service_input", user_service))
                .bind(("table", "user_id"))
                .bind(("user_id", auth_status.decode_token.clone()))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<user::UserService> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// Create a new user project/portfolio item
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
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    LET $portfolio_item = CREATE portfolio CONTENT $portfolio_item_input;
                    LET $user = (SELECT id FROM type::table($table) WHERE user_id = $user_id LIMIT 1);
                    
                    LET $portfolio_item_id = (SELECT VALUE id FROM $portfolio_item);
                    RELATE $user->has_portfolio->$portfolio_item_id;
                    RETURN $portfolio_item;
                    COMMIT TRANSACTION;    
                    "
                )
                .bind(("portfolio_item_input", portfolio_item))
                .bind(("table", "user_id"))
                .bind(("user_id", auth_status.decode_token.clone()))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<user::UserPortfolio> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// Create a new user resume item
    pub async fn add_resume_item(
        &self,
        ctx: &Context<'_>,
        resume_item: user::UserResume,
    ) -> async_graphql::Result<Vec<user::UserResume>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    LET $resume_item = CREATE resume CONTENT $resume_item_input;
                    LET $user = (SELECT id FROM type::table($table) WHERE user_id = $user_id LIMIT 1);
                    
                    LET $resume_item_id = (SELECT VALUE id FROM $resume_item);
                    RELATE $user->has_resume->$resume_item_id;
                    RETURN $resume_item;
                    COMMIT TRANSACTION;    
                    "
                )
                .bind(("resume_item_input", resume_item))
                .bind(("table", "user_id"))
                .bind(("user_id", auth_status.decode_token.clone()))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<user::UserResume> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// Create a new user resume item achievement
    pub async fn add_resume_item_achievement(
        &self,
        ctx: &Context<'_>,
        resume_item_achievement: user::ResumeAchievement,
        resume_id: String,
    ) -> async_graphql::Result<Vec<user::ResumeAchievement>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    LET $resume_item_achievement = CREATE achievement CONTENT $resume_item_achievement_input;
                    LET $resume = (SELECT id FROM type::table($table) WHERE id = type::thing($resume_id) LIMIT 1);
                    
                    LET $resume_item_achievement_id = (SELECT VALUE id FROM $resume_item_achievement);
                    RELATE $resume->has_achievement->$resume_item_achievement_id;
                    RETURN $resume_item_achievement;
                    COMMIT TRANSACTION;    
                    "
                )
                .bind(("resume_item_achievement_input", resume_item_achievement))
                .bind(("table", "resume"))
                .bind(("resume_id", format!("resume:{}", resume_id)))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<user::ResumeAchievement> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// Create a new user skill
    pub async fn add_skill(
        &self,
        ctx: &Context<'_>,
        skill: user::UserSkill,
    ) -> async_graphql::Result<Vec<user::UserSkill>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    LET $skill = CREATE skill CONTENT $skill_input;
                    LET $user = (SELECT id FROM type::table($table) WHERE user_id = $user_id LIMIT 1);
                    
                    LET $skill_id = (SELECT VALUE id FROM $skill);
                    RELATE $user->has_skill->$skill_id;
                    RETURN $skill;
                    COMMIT TRANSACTION;    
                    "
                )
                .bind(("skill_input", skill))
                .bind(("table", "user_id"))
                .bind(("user_id", auth_status.decode_token.clone()))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<user::UserSkill> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// Create a new blog post
    pub async fn add_blog_post(
        &self,
        ctx: &Context<'_>,
        blog_post: blog::BlogPost,
    ) -> async_graphql::Result<Vec<blog::BlogPost>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    LET $blog_post = CREATE blog_post CONTENT $blog_post_input;
                    LET $user = (SELECT id FROM type::table($table) WHERE user_id = $user_id LIMIT 1);
                    
                    LET $blog_post_id = (SELECT VALUE id FROM $blog_post);
                    RELATE $user->has_blog_post->$blog_post_id;
                    RETURN $blog_post;
                    COMMIT TRANSACTION;    
                    "
                )
                .bind(("blog_post_input", blog_post))
                .bind(("table", "user_id"))
                .bind(("user_id", auth_status.decode_token.clone()))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<blog::BlogPost> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// Add a comment to a blog post
    pub async fn add_comment_to_blog_post(
        &self,
        ctx: &Context<'_>,
        blog_comment: blog::BlogComment,
        blog_post_id: String,
    ) -> async_graphql::Result<Vec<blog::BlogComment>> {
        // TODO: Might have to allow anonymous comments?
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    -- Get the user
                    LET $user = (SELECT id FROM type::table($user_table) WHERE user_id = $user_id LIMIT 1);
                    -- Get the blog post
                    LET $blog_post = (SELECT id FROM type::table($blog_table) WHERE id = type::thing($blog_post_id) LIMIT 1);
                    -- Create comment
                    LET $blog_comment = CREATE comment CONTENT $blog_comment_input;
                    LET $blog_comment_id = (SELECT VALUE id FROM $blog_comment);
                    
                    -- Relate the comment to the blog post
                    RELATE $blog_post->has_comment->$blog_comment_id;
                    -- Relate the comment to the user
                    RELATE $user->has_comment->$blog_comment_id;
                    RETURN $blog_comment;
                    COMMIT TRANSACTION;
                    "
                )
                .bind(("blog_comment_input", blog_comment))
                .bind(("blog_table", "blog_post"))
                .bind(("blog_post_id", format!("blog_post:{}", blog_post_id)))
                .bind(("user_id", auth_status.decode_token.clone()))
                .bind(("user_table", "user_id"))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<blog::BlogComment> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// Reply to a comment
    pub async fn reply_to_a_comment(
        &self,
        ctx: &Context<'_>,
        blog_comment: blog::BlogComment,
        comment_id: String,
        blog_post_id: String,
    ) -> async_graphql::Result<Vec<blog::BlogComment>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    -- Get the user, parent comment and blog post
                    LET $parent_comment = (SELECT id FROM type::table($comment_table) WHERE id = type::thing($comment_id) LIMIT 1);
                    LET $user = (SELECT id FROM type::table($user_table) WHERE user_id = $user_id LIMIT 1);
                    LET $blog_post = (SELECT id FROM type::table($blog_table) WHERE id = type::thing($blog_post_id) LIMIT 1);

                    -- Create comment reply
                    LET $comment_reply = CREATE comment CONTENT $blog_comment_input;
                    LET $comment_reply_id = (SELECT VALUE id FROM $comment_reply);
                    
                    -- Relate the comment reply to the parent comment and the user
                    RELATE $parent_comment->has_reply->$comment_reply_id;
                    RELATE $user->has_comment->$comment_reply_id;

                    RETURN $comment_reply;
                    COMMIT TRANSACTION;
                    "
                )
                .bind(("blog_comment_input", blog_comment))
                .bind(("comment_table", "comment"))
                .bind(("comment_id", format!("comment:{}", comment_id)))
                .bind(("user_id", auth_status.decode_token.clone()))
                .bind(("user_table", "user_id"))
                .bind(("blog_table", "blog_post"))
                .bind(("blog_post_id", format!("blog_post:{}", blog_post_id)))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<blog::BlogComment> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// React to a blog post
    pub async fn react_to_blog_post(
        &self,
        ctx: &Context<'_>,
        reaction: shared::Reaction,
        blog_post_id: String,
    ) -> async_graphql::Result<Vec<shared::Reaction>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    -- Get the user and blog post
                    LET $user = (SELECT id FROM type::table($user_table) WHERE user_id = $user_id LIMIT 1);
                    LET $blog_post = (SELECT id FROM type::table($blog_table) WHERE id = type::thing($blog_post_id) LIMIT 1);

                    -- Create reaction
                    LET $reaction = CREATE reaction CONTENT $reaction_input;
                    LET $reaction_id = (SELECT VALUE id FROM $reaction);
                    
                    -- Relate the reaction to the user
                    RELATE $user->has_reaction->$reaction_id;

                    -- Relate the reaction to the blog post
                    RELATE $blog_post->has_reaction->$reaction_id;

                    RETURN $reaction;
                    COMMIT TRANSACTION;
                    "
                )
                .bind(("reaction_input", reaction))
                .bind(("user_id", auth_status.decode_token.clone()))
                .bind(("user_table", "user_id"))
                .bind(("blog_table", "blog_post"))
                .bind(("blog_post_id", format!("blog_post:{}", blog_post_id)))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<shared::Reaction> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// React to a blog comment
    pub async fn react_to_blog_comment(
        &self,
        ctx: &Context<'_>,
        reaction: shared::Reaction,
        comment_id: String,
    ) -> async_graphql::Result<Vec<shared::Reaction>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(auth_status) => {
                let id_added = crate::middleware::user_id::add_user_id_if_not_exists(
                    ctx,
                    auth_status.decode_token.clone(),
                )
                .await;

                if !id_added {
                    return Err(
                        ExtendedError::new("Failed to add user_id", Some(500.to_string())).build(),
                    );
                }

                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    -- Get the user, comment and blog post
                    LET $user = (SELECT id FROM type::table($user_table) WHERE user_id = $user_id LIMIT 1);
                    LET $comment = (SELECT id FROM type::table($comment_table) WHERE id = type::thing($comment_id) LIMIT 1);

                    -- Create reaction
                    LET $reaction = CREATE reaction CONTENT $reaction_input;
                    LET $reaction_id = (SELECT VALUE id FROM $reaction);
                    
                    -- Relate the reaction to the user
                    RELATE $user->has_reaction->$reaction_id;

                    -- Relate the reaction to the comment
                    RELATE $comment->has_reaction->$reaction_id;

                    RETURN $reaction;
                    COMMIT TRANSACTION;
                    "
                )
                .bind(("reaction_input", reaction))
                .bind(("user_id", auth_status.decode_token.clone()))
                .bind(("user_table", "user_id"))
                .bind(("comment_table", "comment"))
                .bind(("comment_id", format!("comment:{}", comment_id)))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<shared::Reaction> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }

    /// Send a message
    pub async fn send_message(
        &self,
        ctx: &Context<'_>,
        message: shared::Message,
    ) -> async_graphql::Result<Vec<shared::Message>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let message: Vec<shared::Message> = db
            .create("message")
            .content(message)
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        Ok(message)
    }

    /// Relate a skill to a portfolio item
    pub async fn relate_skill_to_portfolio_item(
        &self,
        ctx: &Context<'_>,
        skill_id: String,
        portfolio_item_id: String,
    ) -> async_graphql::Result<Vec<user::UserSkill>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let auth_res_from_acl = check_auth_from_acl(ctx).await?;

        match auth_res_from_acl {
            Some(_) => {
                let mut database_transaction = db
                .query(
                    "
                    BEGIN TRANSACTION;
                    -- Get the skill and portfolio item
                    LET $skill = (SELECT * FROM type::table($skill_table) WHERE id = type::thing($skill_id) LIMIT 1);
                    LET $portfolio_item = (SELECT id FROM type::table($portfolio_table) WHERE id = type::thing($portfolio_item_id) LIMIT 1);

                    -- Relate the skill to the portfolio item
                    LET $skill_id = (SELECT VALUE id FROM $skill);
                    RELATE $portfolio_item->has_skill->$skill_id;

                    RETURN $skill;
                    COMMIT TRANSACTION;
                    "
                )
                .bind(("skill_id", format!("skill:{}", skill_id)))
                .bind(("skill_table", "skill"))
                .bind(("portfolio_item_id", format!("portfolio:{}", portfolio_item_id)))
                .bind(("portfolio_table", "portfolio"))
                .await
                .map_err(|e| Error::new(e.to_string()))?;

                let response: Vec<user::UserSkill> = database_transaction.take(0).unwrap();

                Ok(response)
            }
            None => Err(ExtendedError::new("Not Authorized!", Some(403.to_string())).build()),
        }
    }
}
