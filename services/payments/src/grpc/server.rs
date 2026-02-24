use std::sync::Arc;

use lib::integration::grpc::clients::payments_service::{
    payments_service_server::PaymentsService, PaymentIntegrationResponse, UserPaymentDetails,
};
use surrealdb::{engine::remote::ws::Client, Surreal};
use tonic::{Request, Response, Status};

use crate::utils;

pub struct PaymentsServiceImplementation {
    db: Arc<Surreal<Client>>,
}

impl PaymentsServiceImplementation {
    pub fn new(db: Arc<Surreal<Client>>) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl PaymentsService for PaymentsServiceImplementation {
    async fn initiate_payment_integration(
        &self,
        request: Request<UserPaymentDetails>,
    ) -> Result<Response<PaymentIntegrationResponse>, Status> {
        match utils::payments::initiate_payment_integration(&mut request.into_inner().into()).await
        {
            Ok(res) => Ok(Response::new(PaymentIntegrationResponse {
                authorization_url: res.data.authorization_url,
            })),
            Err(_e) => Err(Status::internal("Failed")),
        }
    }
}
