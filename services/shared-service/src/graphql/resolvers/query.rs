use std::sync::Arc;

use async_graphql::{Context, Error, Object};
use axum::Extension;
use surrealdb::{engine::remote::ws::Client as SurrealClient, Surreal};

use crate::graphql::schemas::{
    blog, shared::SurrealRelationQueryResponse, user::{self, ResumeAchievements, UserResources, UserResume}
};

pub struct Query;

#[Object]
impl Query {
    /// Get all blog posts
    pub async fn get_blog_posts(
        &self,
        ctx: &Context<'_>,
        id: Option<String>
    ) -> async_graphql::Result<Vec<blog::BlogPost>> {
        println!("id: {} is just a trick for Nginx to accept my request", id.unwrap_or("".to_string()));
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let result = db
            .select("blog_post")
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        Ok(result)
    }

    /// Get a single blog post by link(Unique field which is also used as the file name for the markdown content, and the URL slug for the post)
    pub async fn get_single_blog_post(
        &self,
        ctx: &Context<'_>,
        link: String,
    ) -> async_graphql::Result<blog::BlogPost> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let mut result = db
            .query("SELECT * FROM blog_post WHERE link = $link LIMIT 1")
            .bind(("link", link))
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        let post: Option<blog::BlogPost> = result.take(0).unwrap();

        match post {
            Some(post) => Ok(post),
            None => Err(Error::new("Post not found!")),
        }
    }

    /// Get user resources \
    /// Combines all the resources of a user into a single graphql query
    pub async fn get_user_resources(
        &self,
        ctx: &Context<'_>,
        user_id: String,
    ) -> async_graphql::Result<UserResources> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let mut user_query_result = db
            .query("SELECT * FROM user_id WHERE user_id = $user_id LIMIT 1")
            .bind(("user_id", user_id))
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        let user: Option<user::User> = user_query_result.take(0).unwrap();

        match user {
            Some(user) => {
                let mut query_results = db
                    .query("SELECT ->has_blog_post.out.* FROM type::thing($user_id)")
                    .query("SELECT ->has_professional_details.out.* FROM type::thing($user_id)")
                    .query("SELECT ->has_portfolio.out.* FROM type::thing($user_id)")
                    .query("SELECT ->has_resume.out.* FROM type::thing($user_id)")
                    .query("SELECT ->has_skill.out.* FROM type::thing($user_id)")
                    .query("SELECT ->offers_service.out.* FROM type::thing($user_id)")
                    .bind(("user_id", format!("user_id:{}", user.id.as_ref().map(|t| &t.id).expect("id").to_raw())))
                    .await
                    .map_err(|e| Error::new(e.to_string()))?;

                let blog_posts: Option<SurrealRelationQueryResponse<blog::BlogPost>> = query_results.take(0)?;
                let professional_info: Option<SurrealRelationQueryResponse<user::UserProfessionalInfo>> =
                    query_results.take(1)?;
                let portfolio: Option<SurrealRelationQueryResponse<user::UserPortfolio>> = query_results.take(2)?;
                let resume: Option<SurrealRelationQueryResponse<user::UserResume>> = query_results.take(3)?;
                let skills: Option<SurrealRelationQueryResponse<user::UserSkill>> = query_results.take(4)?;
                let services: Option<SurrealRelationQueryResponse<user::UserService>> = query_results.take(5)?;
                let mut achievements: ResumeAchievements = ResumeAchievements::new();

                let resume_vec = match resume {
                    Some(resume) => {
                        let user_resume: Vec<UserResume> = resume.get("->has_resume").unwrap().get("out").unwrap().into_iter().map(|resume| resume.to_owned()).collect();

                        for resume in user_resume.clone().into_iter() {
                            let user_resume = resume.clone();
                            let mut query_results = db
                                .query("SELECT ->has_achievement.out.* FROM type::thing($resume_id)")
                                .bind(("resume_id", format!("resume:{}", user_resume.id.as_ref().map(|t| &t.id).expect("id").to_raw())))
                                .await
                                .map_err(|e| Error::new(e.to_string()))?;

                            let resume_achievements: Option<SurrealRelationQueryResponse<user::ResumeAchievement>> = query_results.take(0)?;

                            achievements.insert(resume.id.as_ref().map(|t| &t.id).expect("id").to_raw(), resume_achievements.unwrap().get("->has_achievement").unwrap().get("out").unwrap().into_iter().map(|achievement| achievement.to_owned().description).collect());
                        }

                        user_resume
                    },
                    None => vec![],
                };

                let user_resources = UserResources {
                    blog_posts: blog_posts.unwrap().get("->has_blog_post").unwrap().get("out").unwrap().into_iter().map(|blog| blog.to_owned()).collect(),
                    professional_info: professional_info.unwrap().get("->has_professional_details").unwrap().get("out").unwrap().into_iter().map(|info| info.to_owned()).collect(),
                    portfolio: portfolio.unwrap().get("->has_portfolio").unwrap().get("out").unwrap().into_iter().map(|portfolio| portfolio.to_owned()).collect(),
                    resume: resume_vec,
                    skills: skills.unwrap().get("->has_skill").unwrap().get("out").unwrap().into_iter().map(|skill| skill.to_owned()).collect(),
                    achievements: achievements,
                    services: services.unwrap().get("->offers_service").unwrap().get("out").unwrap().into_iter().map(|service| service.to_owned()).collect(),
                };

                Ok(user_resources)
            }
            None => Err(Error::new("User not found!")),
        }
    }

    /// Get resume achievements by user_id and resume_id
    /// This query is used to get the achievements of a resume
    pub async fn get_resume_achievements(
        &self,
        ctx: &Context<'_>,
        resume_id: String,
    ) -> async_graphql::Result<Vec<user::ResumeAchievement>> {
        let db = ctx
            .data::<Extension<Arc<Surreal<SurrealClient>>>>()
            .unwrap();

        let mut query_results = db
            .query("SELECT ->has_achievement.out.* FROM type::thing($resume_id)")
            .bind(("resume_id", format!("resume:{}", resume_id)))
            .await
            .map_err(|e| Error::new(e.to_string()))?;

        let achievements: Option<SurrealRelationQueryResponse<user::ResumeAchievement>> = query_results.take(0)?;

        Ok(achievements.unwrap().get("->has_achievement").unwrap().get("out").unwrap().into_iter().map(|achievement| achievement.to_owned()).collect())
    }
}
