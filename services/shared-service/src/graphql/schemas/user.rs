use std::collections::HashMap;

use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

use super::blog::BlogPost;
pub type ResumeAchievements = HashMap<String, Vec<String>>;
pub type UserPortfolioSkills = HashMap<String, Vec<UserSkill>>;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserProfessionalInfoInput")]
#[graphql(complex)]
pub struct UserProfessionalInfo {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub description: String,
    pub active: bool,
    pub occupation: String,
    pub start_date: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserPortfolioInput")]
#[graphql(complex)]
pub struct UserPortfolio {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub title: String,
    pub description: String,
    pub start_date: String,
    pub end_date: Option<String>,
    pub link: String,
    pub category: UserPortfolioCategory,
    pub image: String,
}

// enum for UserPortfolio category
#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum UserPortfolioCategory {
    #[graphql(name = "JavaScript")]
    JavaScript,
    #[graphql(name = "Rust")]
    Rust,
    #[graphql(name = "Database")]
    Database,
    #[graphql(name = "DevOps")]
    DevOps,
    #[graphql(name = "Cloud")]
    Cloud,
    #[graphql(name = "Mobile")]
    Mobile,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserResumeInput")]
#[graphql(complex)]
pub struct UserResume {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub title: String,
    pub more_info: Option<String>,
    pub start_date: String,
    pub end_date: Option<String>,
    pub link: Option<String>,
    pub section: UserResumeSection,
}


#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum UserResumeSection {
    #[graphql(name = "Education")]
    Education,
    #[graphql(name = "Experience")]
    Experience,
    #[graphql(name = "Achievements")]
    Achievements,
    #[graphql(name = "Projects")]
    Projects,
    #[graphql(name = "Certifications")]
    Certifications,
    #[graphql(name = "Volunteer")]
    Volunteer,
    #[graphql(name = "Publications")]
    Publications,
    #[graphql(name = "Languages")]
    Languages,
    #[graphql(name = "Interests")]
    Interests,
    #[graphql(name = "References")]
    References,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "ResumeAchievementInput")]
#[graphql(complex)]
pub struct ResumeAchievement {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub description: String,
}

// UserSkill
#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserSkillInput")]
#[graphql(complex)]
pub struct UserSkill {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub image: String,
    pub name: String,
    pub level: Option<UserSkillLevel>,
    pub r#type: UserSkillType,
    pub start_date: String,
}

// UserSkillType enum
#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum UserSkillType {
    #[graphql(name = "Technical")]
    Technical,
    #[graphql(name = "Soft")]
    Soft,
}

// UserSkillLevel enum
#[derive(Clone, Debug, Serialize, Deserialize, Enum, Copy, Eq, PartialEq)]
pub enum UserSkillLevel {
    #[graphql(name = "Beginner")]
    Beginner,
    #[graphql(name = "Intermediate")]
    Intermediate,
    #[graphql(name = "Advanced")]
    Advanced,
    #[graphql(name = "Expert")]
    Expert,
}

// UserService
#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserServiceInput")]
#[graphql(complex)]
pub struct UserService {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub title: String,
    pub description: String,
    pub image: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct UserResources {
    pub blog_posts: Vec<BlogPost>,
    pub professional_info: Vec<UserProfessionalInfo>,
    pub portfolio: Vec<UserPortfolio>,
    pub resume: Vec<UserResume>,
    pub skills: Vec<UserSkill>,
    pub services: Vec<UserService>,
    pub achievements: ResumeAchievements,
    pub portfolio_skills: UserPortfolioSkills,
}

#[ComplexObject]
impl UserProfessionalInfo {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }

    async fn years_of_experience(&self) -> u32 {
        // calculate years of experience from &self.start_date
        let parsed_start_date =
            DateTime::parse_from_rfc3339(&self.start_date).expect("Invalid date format");
        let start_date_ymd = NaiveDate::from_ymd_opt(
            parsed_start_date.year(),
            parsed_start_date.month(),
            parsed_start_date.day(),
        )
        .unwrap();

        let today = Utc::now().date_naive();
        today.years_since(start_date_ymd).unwrap()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject)]
pub struct User {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub user_id: String,
}

#[ComplexObject]
impl UserPortfolio {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }

    async fn years_of_experience(&self) -> u32 {
        // calculate years of experience from &self.start_date
        let parsed_start_date =
            DateTime::parse_from_rfc3339(&self.start_date).expect("Invalid date format");
        let start_date_ymd = NaiveDate::from_ymd_opt(
            parsed_start_date.year(),
            parsed_start_date.month(),
            parsed_start_date.day(),
        )
        .unwrap();

        match &self.end_date {
            Some(end_date) => {
                let parsed_end_date =
                    DateTime::parse_from_rfc3339(end_date).expect("Invalid date format");

                let end_date_ymd = NaiveDate::from_ymd_opt(
                    parsed_end_date.year(),
                    parsed_end_date.month(),
                    parsed_end_date.day(),
                )
                .unwrap();

                end_date_ymd.years_since(start_date_ymd).unwrap()
            }
            None => {
                let today = Utc::now().date_naive();
                today.years_since(start_date_ymd).unwrap()
            }
        }
    }
}

#[ComplexObject]
impl UserResume {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }

    async fn years_of_experience(&self) -> u32 {
        // TODO: factor in months, currently only years e.g. 1 year 6 months
        // calculate years of experience from &self.start_date
        let parsed_start_date =
            DateTime::parse_from_rfc3339(&self.start_date).expect("Invalid date format");
        let start_date_ymd = NaiveDate::from_ymd_opt(
            parsed_start_date.year(),
            parsed_start_date.month(),
            parsed_start_date.day(),
        )
        .unwrap();

        match &self.end_date {
            Some(end_date) => {
                let parsed_end_date =
                    DateTime::parse_from_rfc3339(end_date).expect("Invalid date format");
                let end_date_ymd = NaiveDate::from_ymd_opt(
                    parsed_end_date.year(),
                    parsed_end_date.month(),
                    parsed_end_date.day(),
                )
                .unwrap();

                end_date_ymd.years_since(start_date_ymd).unwrap()
            }
            None => {
                let today = Utc::now().date_naive();
                today.years_since(start_date_ymd).unwrap()
            }
        }
    }
}

#[ComplexObject]
impl ResumeAchievement {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}

#[ComplexObject]
impl UserSkill {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}

#[ComplexObject]
impl UserService {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }
}
