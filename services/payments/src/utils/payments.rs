use reqwest::{header::HeaderMap as ReqWestHeaderMap, Client as ReqWestClient};
use serde::Serialize;
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

    let default_currency = env::var("DEFAULT_CURRENCY").map_err(|e| {
        tracing::error!("Missing the DEFAULT_CURRENCY environment variable.: {}", e);
        Error::new(ErrorKind::Other, "Internal server error")
    })?;

    user_payment_details.currency = Some(default_currency);

    let paystack_initialize_payment_endpoint = env::var("PAYSTACK_INITIALIZE_PAYMENT_ENDPOINT")
        .map_err(|e| {
            tracing::error!(
                "Missing the PAYSTACK_INITIALIZE_PAYMENT_ENDPOINT environment variable.: {}",
                e
            );
            Error::new(ErrorKind::Other, "Internal server error")
        })?;

    let paystack_response = client
        .request(Method::POST, &paystack_initialize_payment_endpoint)
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

pub async fn create_pandascrow_escrow<T>(pandascrow_escrow: &T) -> Result<String, Error>
where
    T: Serialize,
{
    let client = ReqWestClient::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build Reqwest Client: {}", e);
            Error::new(ErrorKind::Other, "Internal server error")
        })?;
    let pandascrow_pk = env::var("PANDASCROW_PUBLIC_KEY").map_err(|e| {
        tracing::error!(
            "Missing the PANDASCROW_PUBLIC_KEY environment variable.: {}",
            e
        );
        Error::new(ErrorKind::Other, "Internal server error")
    })?;

    let mut req_headers = ReqWestHeaderMap::new();
    req_headers.insert(
        "Token",
        format!("{}", pandascrow_pk).as_str().parse().map_err(|e| {
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

    let pandascrow_create_escrow_endpoint =
        env::var("PANDASCROW_CREATE_ESCROW_ENDPOINT").map_err(|e| {
            tracing::error!(
                "Missing the PANDASCROW_CREATE_ESCROW_ENDPOINT environment variable.: {}",
                e
            );
            Error::new(ErrorKind::Other, "Internal server error")
        })?;

    // let pandascrow_response = client
    //     .request(Method::POST, &pandascrow_create_escrow_endpoint)
    //     .headers(req_headers)
    //     .json::<T>(&pandascrow_escrow)
    //     .send()
    //     .await
    //     .map_err(|e| {
    //         tracing::error!("Sending error: {:?}", e);
    //         Error::new(ErrorKind::Other, "Internal server error")
    //     })?
    //     .json::<String>()
    //     .await
    //     .map_err(|e| {
    //         tracing::error!("Decoding error: {:?}", e);
    //         Error::new(ErrorKind::Other, "Internal server error")
    //     })?;

    let response = client
        .request(Method::POST, &pandascrow_create_escrow_endpoint)
        .headers(req_headers)
        .json(&pandascrow_escrow)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Sending error: {:?}", e);
            Error::new(ErrorKind::Other, "Internal server error")
        })?;

    let status = response.status();
    let response_text = response.text().await.map_err(|e| {
        tracing::error!("Failed to read response body: {:?}", e);
        Error::new(ErrorKind::Other, "Internal server error")
    })?;

    tracing::debug!("PandaEscrow status: {}, body: {}", status, response_text);

    if !status.is_success() {
        tracing::error!(
            "PandaEscrow rejected request: {} - {}",
            status,
            response_text
        );
        return Err(Error::new(ErrorKind::Other, "PandaEscrow request failed"));
    }

    // let pandascrow_response = serde_json::from_str::<serde_json::Value>(&response_text)
    //     .map_err(|e| {
    //         tracing::error!("Decoding error: {:?}", e);
    //         Error::new(ErrorKind::Other, "Internal server error")
    //     })?;

    Ok(String::from("Success!"))
}
