use axum::{
    extract::{Extension, Json},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use hex;
use hmac::{Hmac, Mac};

use rumqttc::v5::mqttbytes::QoS;
use serde_json::Value;
use sha2::Sha512;
use std::{env, sync::Arc};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::AppState;

// Type alias for HMAC-SHA512
type HmacSha512 = Hmac<Sha512>;

pub async fn handle_paystack_webhook(
    Extension(_db): Extension<Arc<Surreal<Client>>>,
    Extension(shared_state): Extension<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Retrieve the x-paystack-signature header
    let signature = headers
        .get("x-paystack-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Get the secret key
    let secret = env::var("PAYSTACK_SECRET");

    if let Err(e) = secret {
        tracing::error!("Missing the PAYSTACK_SECRET environment variable.: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Server Error").into_response();
    }
    let secret = secret.unwrap();

    let deployment_env = env::var("ENVIRONMENT").unwrap_or_else(|_| "prod".to_string()); // default to production because it's the most secure

    // Verify the webhook payload
    let mut mac =
        HmacSha512::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(
        serde_json::to_string(&body)
            .expect("Failed to serialize body")
            .as_bytes(),
    );
    let result = mac.finalize();
    let hash = hex::encode(result.into_bytes());

    let paystack_signature_is_valid = match deployment_env.as_str() {
        "prod" => hash == signature,
        _ => true,
    };

    if paystack_signature_is_valid {
        // HMAC validation passed
        if let Some(event) = body.get("event").and_then(|e| e.as_str()) {
            if event == "charge.success" {
                if let Some(data) = body.get("data") {
                    // This is the reference to the resource in question that is being paid for. Should not be confused with Rust references.
                    if let Some(reference) = data.get("reference").and_then(|r| r.as_str()) {
                        let owned_reference = reference.to_string();
                        let borrowed_reference = &owned_reference;

                        let Some((resource, id)) = borrowed_reference.split_once(':') else {
                            tracing::error!("The reference is wrongly formatted. It needs a \":\" to separate resource and id. Nothing will proceed from here. Consider manual reconciliation urgently!");
                            // if let Err(e) = shared_state
                            //     .mqtt_client
                            //     .publish(
                            //         &format!("{resource}/payment/failed"),
                            //         QoS::ExactlyOnce,
                            //         false,
                            //         format!("The reference is wrongly formatted. It needs a \":\" to separate resource and id."),
                            //     )
                            //     .await
                            // {
                            //     tracing::error!("Failed to publish payment successful event: {}", e);
                            // };

                            return (StatusCode::CREATED, format!("Transaction successful!"))
                                .into_response();
                        };

                        if let Err(e) = shared_state
                            .mqtt_client
                            .publish(
                                &format!("{resource}/payment/successful"),
                                QoS::ExactlyOnce,
                                false,
                                id.to_string(),
                            )
                            .await
                        {
                            tracing::error!(
                                "Failed to publish payment successful event for {resource}: {}",
                                e
                            );
                        }
                    }
                }
                (StatusCode::CREATED, format!("Transaction successful!")).into_response()
            } else {
                (
                    StatusCode::BAD_REQUEST,
                    format!("Unhandled event type: {}", event),
                )
                    .into_response()
            }
        } else {
            (
                StatusCode::BAD_REQUEST,
                format!("Event type missing or invalid"),
            )
                .into_response()
        }
    } else {
        tracing::error!("Invalid signature: expected {}, got {}", signature, hash);
        (StatusCode::BAD_REQUEST, format!("Transaction failed!")).into_response()
    }
}
