use reqwest::{header::HeaderMap as ReqWestHeaderMap, Client as ReqWestClient};
use std::{
    env,
    io::{Error, ErrorKind},
};

// use crate::graphql::schemas::general::ExchangeRatesResponse;
use hyper::http::Method;
use lib::utils::models::{InitializePaymentResponse, UserPaymentDetails};

use crate::graphql::schemas::general::ExchangeRatesResponse;

pub async fn initiate_payment_integration(
    user_payment_details: &mut UserPaymentDetails,
) -> Result<InitializePaymentResponse, Error> {
    let client = ReqWestClient::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build Reqwest Client: {}", e);
            Error::new(ErrorKind::Other, "Internal server error")
        })?;
    let borrowed_client = &client;
    let paystack_secret = env::var("PAYSTACK_SECRET").map_err(|e| {
        tracing::error!("Missing the PAYSTACK_SECRET environment variable.: {}", e);
        Error::new(ErrorKind::Other, "Internal server error")
    })?;
    let exchange_rates_api_key = env::var("EXCHANGE_RATES_API_KEY").map_err(|e| {
        tracing::error!(
            "Missing the EXCHANGE_RATES_API_KEY environment variable.: {}",
            e
        );
        Error::new(ErrorKind::Other, "Internal server error")
    })?;

    let mut req_headers = ReqWestHeaderMap::new();
    req_headers.insert(
        "Authorization",
        format!("Bearer {}", paystack_secret)
            .as_str()
            .parse()
            .map_err(|e| {
                tracing::error!("Failed to build parse str to HeaderValue: {}", e);
                Error::new(ErrorKind::Other, "Unauthorized!")
            })?,
    );

    req_headers.append(
        "Cache-Control",
        "no-cache".parse().map_err(|e| {
            tracing::error!("Failed to build parse str to HeaderValue: {}", e);
            Error::new(ErrorKind::Other, "Unauthorized!")
        })?,
    );

    let default_currency = env::var("DEFAULT_CURRENCY").map_err(|e| {
        tracing::error!("Missing the DEFAULT_CURRENCY environment variable.: {}", e);
        Error::new(ErrorKind::Other, "Internal server error")
    })?;

    let exchangerates_response = borrowed_client
        .request(Method::GET, &format!("https://v6.exchangerate-api.com/v6/{exchange_rates_api_key}/pair/{}/{default_currency}", user_payment_details.currency))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Sending error(Exchange Rates): {:?}", e);
            Error::new(ErrorKind::Other, "Internal server error")
        })?;

    let exchangerates_response_data = exchangerates_response
        .json::<ExchangeRatesResponse>()
        .await
        .map_err(|e| {
            tracing::error!("Decoding error(ExchangeRatesResponse): {:?}", e);
            Error::new(ErrorKind::Other, "Internal server error")
        })?;

    // Apply FOREX and convert amount to subunits
    user_payment_details.amount = user_payment_details
        .amount
        .parse::<f64>()
        .ok()
        .map(|val| {
            ((val * exchangerates_response_data.conversion_rate * 100 as f64).round() as i32)
                .to_string()
        })
        .ok_or_else(|| {
            tracing::error!("Invalid Amount: {}", user_payment_details.amount);
            Error::new(ErrorKind::Other, "Invalid Amount")
        })?;
    // Change currency after exchange
    user_payment_details.currency = default_currency;

    let paystack_initialize_payment_endpoint = env::var("PAYSTACK_INITIALIZE_PAYMENT_ENDPOINT")
        .map_err(|e| {
            tracing::error!(
                "Missing the PAYSTACK_INITIALIZE_PAYMENT_ENDPOINT environment variable.: {}",
                e
            );
            Error::new(ErrorKind::Other, "Internal server error")
        })?;

    let paystack_response = borrowed_client
        .request(Method::POST, &paystack_initialize_payment_endpoint)
        .headers(req_headers)
        .json::<UserPaymentDetails>(&user_payment_details)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Sending error(Paystack): {:?}", e);
            Error::new(ErrorKind::Other, "Internal server error")
        })?;

    // let response_text = paystack_response.text().await.map_err(|e| {
    //     tracing::debug!("Failed to read response body: {:?}", e);
    //     Error::new(ErrorKind::Other, "Failed to read response body")
    // })?;
    // tracing::debug!("Rate limit response: {}", response_text);

    // let paystack_response_data = serde_json::from_str::<InitializePaymentResponse>(&response_text)
    //     .map_err(|e| {
    //         tracing::debug!("Paystack response deserialization failed: {:?}", e);
    //         Error::new(ErrorKind::Other, "Paystack response deserialization failed")
    //     })?;

    let paystack_response_data = paystack_response
        .json::<InitializePaymentResponse>()
        .await
        .map_err(|e| {
            tracing::error!("Decoding error(InitializePaymentResponse): {:?}", e);
            Error::new(ErrorKind::Other, "Internal server error")
        })?;

    Ok(paystack_response_data)
}
