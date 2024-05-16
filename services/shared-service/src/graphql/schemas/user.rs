use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use surrealdb::sql::Thing;

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserProfessionalInfoInput")]
#[graphql(complex)]
pub struct UserProfessionalInfo {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub description: String,
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
    JavaScript,
    Rust,
    Database,
    DevOps,
    Cloud,
}

#[derive(Clone, Debug, Serialize, Deserialize, SimpleObject, InputObject)]
#[graphql(input_name = "UserResumeInput")]
#[graphql(complex)]
pub struct UserResume {
    #[graphql(skip)]
    pub id: Option<Thing>,
    pub title: String,
    pub description: String,
    pub start_date: String,
    pub end_date: Option<String>,
    pub link: String,
    pub section: String,
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
    pub level: String,
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

#[ComplexObject]
impl UserProfessionalInfo {
    async fn id(&self) -> String {
        self.id.as_ref().map(|t| &t.id).expect("id").to_raw()
    }

    async fn years_of_experience(&self) -> u32 {
        // calculate years of experience from &self.start_date
        let parsed_start_date = DateTime::parse_from_rfc3339(&self.start_date).expect("Invalid date format");
        let start_date_ymd = NaiveDate::from_ymd_opt(parsed_start_date.year(), parsed_start_date.month0(), parsed_start_date.day0()).unwrap();

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
        let parsed_start_date = DateTime::parse_from_rfc3339(&self.start_date).expect("Invalid date format");
        let start_date_ymd = NaiveDate::from_ymd_opt(parsed_start_date.year(), parsed_start_date.month0(), parsed_start_date.day0()).unwrap();

        match &self.end_date {
            Some(end_date) => {
                let parsed_end_date = DateTime::parse_from_rfc3339(end_date).expect("Invalid date format");
                println!("parsed_end_date: {:?}", parsed_end_date.year());
                let end_date_ymd = NaiveDate::from_ymd_opt(parsed_end_date.year(), parsed_end_date.month0(), parsed_end_date.day0()).unwrap();

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
        // calculate years of experience from &self.start_date
        let parsed_start_date = DateTime::parse_from_rfc3339(&self.start_date).expect("Invalid date format");
        let start_date_ymd = NaiveDate::from_ymd_opt(parsed_start_date.year(), parsed_start_date.month0(), parsed_start_date.day0()).unwrap();

        match &self.end_date {
            Some(end_date) => {
                let parsed_end_date = DateTime::parse_from_rfc3339(end_date).expect("Invalid date format");
                let end_date_ymd = NaiveDate::from_ymd_opt(parsed_end_date.year(), parsed_end_date.month0(), parsed_end_date.day0()).unwrap();

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
