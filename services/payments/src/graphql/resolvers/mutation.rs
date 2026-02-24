use async_graphql::MergedObject;

use super::payments::mutation::PaymentMutation;

#[derive(MergedObject, Default)]
pub struct Mutation(PaymentMutation);
