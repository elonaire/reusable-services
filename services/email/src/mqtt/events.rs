use lib::utils::models::{Email, EmailMQTTPayload, EmailUser};
use rumqttc::v5::{mqttbytes::v5::Packet, Event};

use crate::utils::email::send_email;

pub async fn handle_events(event: &Event) -> () {
    match event {
        Event::Incoming(packet) => {
            // Handle Incoming event
            match packet {
                Packet::Publish(message) => {
                    // Handle Publish event
                    match message.topic.as_ref() {
                        b"email/send" => {
                            tracing::debug!("Payload: {:?}", &message.payload);

                            let deserialized_payload: EmailMQTTPayload =
                                serde_json::from_slice(&message.payload).unwrap();

                            let email_arg = Email {
                                recipient: EmailUser {
                                    email_address: deserialized_payload.recipient.to_string(),
                                    full_name: None,
                                },
                                subject: deserialized_payload.subject.to_string(),
                                title: deserialized_payload.title.to_string(),
                                body: deserialized_payload.template,
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
