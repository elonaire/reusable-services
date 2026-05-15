use std::sync::Arc;

use lib::utils::models::{Email, EmailMQTTPayload, EmailUser};
use rumqttc::v5::{mqttbytes::v5::Packet, Event};
use surrealdb::{engine::remote::ws::Client, Surreal};

use crate::utils::email::{send_email, synthesize_email};

pub async fn handle_events(db: &Arc<Surreal<Client>>, event: &Event) -> () {
    match event {
        Event::Incoming(packet) => {
            // Handle Incoming event
            match packet {
                Packet::Publish(message) => {
                    // Handle Publish event
                    match message.topic.as_ref() {
                        b"email/send" => {
                            // tracing::debug!("Payload: {:?}", &message.payload);

                            let Ok(deserialized_payload) = serde_json::from_slice(&message.payload)
                            else {
                                return;
                            };

                            let Ok(email_arg) = synthesize_email(db, &deserialized_payload).await
                            else {
                                return;
                            };

                            // Send email using email service
                            send_email(&email_arg)
                                .await
                                .map_err(|e| {
                                    tracing::error!("(email/send)Failed to send email: {}", e);
                                })
                                .ok();
                        }
                        _ => {
                            tracing::error!("Unknown topic: {:?}", message.topic);
                            // Handle other topics
                        }
                    }
                }
                _ => {}
            }
        }
        Event::Outgoing(_) => {
            // Handle Outgoing event
        }
    }
}
