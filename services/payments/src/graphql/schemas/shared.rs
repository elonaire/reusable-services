use async_graphql::{OutputType, SimpleObject};
use lib::utils::models::{ApiResponse, InitializePaymentResponse};

use crate::graphql::schemas::{general::Currency, pandascrow::PandascrowEscrow};

type Currencies = Vec<Currency>;

#[derive(SimpleObject)]
#[graphql(concrete(
    name = "InitializePaymentResResponse",
    params(InitializePaymentResponse)
))]
#[graphql(concrete(name = "PandascrowEscrowResponse", params(PandascrowEscrow)))]
#[graphql(concrete(name = "CurrenciesResponse", params(Currencies)))]
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
