use async_graphql::{ComplexObject, Enum, InputObject, SimpleObject};
use serde::{Deserialize, Serialize};
use surrealdb::RecordId;

#[derive(Debug, Serialize, Deserialize, Clone, Enum, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EscrowType {
    Onetime,
    Milestone,
    Recurring,
}

#[derive(Debug, Serialize, Deserialize, Clone, Enum, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InitiatorRole {
    Buyer,
    Seller,
}

#[derive(Debug, Serialize, Deserialize, Clone, Enum, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WhoPayFees {
    Buyer,
    Seller,
    Split,
}

#[derive(Debug, Serialize, Deserialize, Clone, Enum, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum HowDisputeIsHandled {
    Arbitration,
    Mediation,
    PlatformDecision,
}

#[derive(Debug, Serialize, Deserialize, Clone, Enum, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DepositOption {
    Full,
    Partial,
}

#[derive(Debug, Serialize, Deserialize, Clone, Enum, Copy, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PayoutType {
    Bank,
    Crypto,
    MobileMoney,
}

#[derive(Debug, Serialize, Deserialize, InputObject)]
pub struct PandascrowPartyDetails {
    pub name: String,
    pub email: String,
    pub phone: String,
}

#[derive(Debug, Serialize, Deserialize, InputObject)]
pub struct PandascrowMilestone {
    pub title: String,
    pub description: String,
    pub amount: String,
    pub due_date: String,
    pub inspection_hrs: String,
}

#[derive(Debug, Serialize, Deserialize, InputObject)]
pub struct PandascrowPayout {
    pub payout_type: PayoutType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bank_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swift_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iban: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crypto_network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_money_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile_money_number: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, InputObject)]
pub struct PandascrowMilestoneEscrow {
    #[graphql(skip)]
    pub uuid: String,
    pub escrow_type: EscrowType, // always EscrowType::Milestone
    pub initiator_role: InitiatorRole,
    #[graphql(skip)]
    pub initiator_id: String,
    pub receiver_id: Option<String>,
    pub title: String,
    pub currency: String,
    pub description: String,
    pub acceptance_criteria: Option<String>,
    pub inspection_period: String,
    pub delivery_date: String,
    pub how_dispute_is_handled: HowDisputeIsHandled,
    pub who_pay_fees: WhoPayFees,
    pub dispute_window: Option<String>,
    pub deposit_option: DepositOption,
    pub callback_url: Option<String>,
    pub prd_url: Option<String>, // for product requirements
    pub milestones: PandascrowMilestone,
    pub buyer_details: Option<Vec<PandascrowPartyDetails>>,
    pub seller_details: Option<Vec<PandascrowPartyDetails>>,
    pub payout: Option<PandascrowPayout>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PandascrowEscrowInput {
    pub created_by: RecordId,
}

#[derive(Debug, Serialize, Deserialize, SimpleObject, Clone)]
#[graphql(complex)]
pub struct PandascrowEscrow {
    #[graphql(skip)]
    pub id: RecordId,
    #[graphql(skip)]
    pub created_by: RecordId,
    pub created_at: String,
    pub updated_at: String,
}

#[ComplexObject]
impl PandascrowEscrow {
    pub async fn id(&self) -> String {
        self.id.key().to_string().to_owned()
    }

    pub async fn created_by(&self) -> String {
        self.created_by.key().to_string().to_owned()
    }
}
