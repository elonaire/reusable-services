use reqwest::{header::HeaderMap as ReqWestHeaderMap, Client as ReqWestClient};
use std::{
    env,
    io::{Error, ErrorKind},
};

// use crate::graphql::schemas::general::ExchangeRatesResponse;
use hyper::http::Method;
use lib::utils::models::{InitializePaymentResponse, UserPaymentDetails};

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
    let paystack_secret = env::var("PAYSTACK_SECRET").map_err(|e| {
        tracing::error!("Missing the PAYSTACK_SECRET environment variable.: {}", e);
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

    // let forex_secret_key = env::var("EXCHANGE_RATES_API_KEY")
    //                 .expect("Missing the EXCHANGE_RATES_API_KEY environment variable.");

    // let forex_response = client
    //     .request(
    //         Method::GET,
    //         format!("https://api.exchangeratesapi.io/v1/latest?access_key={}&base=USD&symbols=KES", forex_secret_key).as_str(),
    //     )
    //     .send()
    //     .await.map_err(|e| {
    //         println!("Error sending: {:?}", e);
    //         Error::new(e.to_string())
    //     })?
    //     .json::<ExchangeRatesResponse>()
    //     .await.map_err(|e| {
    //         println!("Error deserializing: {:?}", e);
    //         Error::new(e.to_string())
    //     })?;

    // println!("Passes forex_response! {:?}", forex_response);
    // let conversion_rate = forex_response.rates.get("KES").unwrap();
    let conversion_rate = 130.00;

    user_payment_details.amount =
        (user_payment_details.amount as f64 * conversion_rate * 100.0) as u64;

    let paystack_response = client
        .request(
            Method::POST,
            "https://api.paystack.co/transaction/initialize",
        )
        .headers(req_headers)
        .json::<UserPaymentDetails>(&user_payment_details)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Sending error: {:?}", e);
            Error::new(ErrorKind::Other, "Internal server error")
        })?
        .json::<InitializePaymentResponse>()
        .await
        .map_err(|e| {
            tracing::error!("Decoding error: {:?}", e);
            Error::new(ErrorKind::Other, "Internal server error")
        })?;

    Ok(paystack_response)
}
