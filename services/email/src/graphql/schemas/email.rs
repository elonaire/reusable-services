use async_graphql::{ComplexObject, Enum, InputObject, OutputType, SimpleObject};
use lib::utils::models::ApiResponse;

use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Enum, Eq)]
pub enum SubscriberStatus {
    #[graphql(name = "Active")]
    Active,
    #[graphql(name = "Unsubscribed")]
    Unsubscribed,
    #[graphql(name = "Bounced")]
    Bounced,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct Subscriber {
    #[graphql(skip)]
    pub id: RecordId,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub status: SubscriberStatus,
    pub created_at: String,
    pub updated_at: String,
}

#[ComplexObject]
impl Subscriber {
    async fn id(&self) -> String {
        self.id.key().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, InputObject)]
pub struct SubscriberInput {
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct MailingList {
    #[graphql(skip)]
    pub id: RecordId,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

#[ComplexObject]
impl MailingList {
    async fn id(&self) -> String {
        self.id.key().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, InputObject)]
pub struct MailingListInput {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SimpleObject)]
#[graphql(complex)]
pub struct Subscription {
    #[graphql(skip)]
    pub id: RecordId,
    pub subscriber: Subscriber,
    pub mailing_list: MailingList,
    pub created_at: String,
}

#[ComplexObject]
impl Subscription {
    async fn id(&self) -> String {
        self.id.key().to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, InputObject)]
pub struct SubscriptionInput {
    pub subscriber: SubscriberInput,
    #[graphql(skip)]
    pub mailing_list: Option<RecordId>,
    pub subscription_input_metadata: SubscriptionInputMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, InputObject)]
pub struct SubscriptionInputMetadata {
    pub mailing_list_id: String,
}

#[derive(SimpleObject)]
#[graphql(concrete(name = "SubscriberResponse", params(Subscriber)))]
#[graphql(concrete(name = "SendEmailResponse", params(String)))]
#[graphql(concrete(name = "MailingListResponse", params(MailingList)))]
#[graphql(concrete(name = "SubscriptionResponse", params(Subscription)))]
pub struct GraphQLApiResponse<T: OutputType> {
    pub data: T,
    pub metadata: GraphQLApiResponseMetadata,
}

#[derive(SimpleObject)]
pub struct GraphQLApiResponseMetadata {
    pub request_id: String,
    pub new_access_token: Option<String>,
}

impl<T: Send + Sync + Clone + OutputType> From<ApiResponse<T>> for GraphQLApiResponse<T> {
    fn from(standard_res: ApiResponse<T>) -> Self {
        Self {
            data: standard_res.get_data(),
            metadata: GraphQLApiResponseMetadata {
                request_id: standard_res.get_request_id(),
                new_access_token: standard_res.get_new_access_token(),
            },
        }
    }
}
