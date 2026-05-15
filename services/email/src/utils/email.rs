use axum::body::Bytes;
use handlebars::Handlebars;
use lib::utils::models::{Email, EmailMQTTPayload, EmailUser};
use std::{
    env,
    io::{Error, ErrorKind},
    sync::Arc,
};
use surrealdb::{engine::remote::ws::Client, Surreal};

// use async_graphql::{Context, Error, Object, Result};
use lettre::{
    message::{header::ContentType, Attachment, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use reqwest::Client as ReqWestClient;

use crate::graphql::schemas::email::EmailTemplate;

pub async fn send_email(email: &Email) -> Result<&'static str, Error> {
    let smtp_user = env::var("SMTP_USER").map_err(|e| {
        tracing::error!("Missing SMTP_USER: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;
    let smtp_password = env::var("SMTP_PASSWORD").map_err(|e| {
        tracing::error!("Missing SMTP_PASSWORD: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;
    let smtp_server = env::var("SMTP_SERVER").map_err(|e| {
        tracing::error!("Missing SMTP_SERVER: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;
    let business_name = env::var("BUSINESS_NAME").map_err(|e| {
        tracing::error!("Missing BUSINESS_NAME: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;

    let client = ReqWestClient::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build HTTP client: {:?}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?;

    // Fetch all attachment bytes upfront, in parallel
    let attachment_futures: Vec<_> = email
        .attachments
        .iter()
        .map(|att| {
            let client = client.clone();
            let url = att.url.clone();
            async move {
                client
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to fetch attachment {}: {:?}", url, e);
                        Error::new(ErrorKind::Other, "Failed to fetch attachment")
                    })?
                    .bytes()
                    .await
                    .map_err(|e| {
                        tracing::error!("Failed to read attachment bytes {}: {:?}", url, e);
                        Error::new(ErrorKind::Other, "Failed to read attachment")
                    })
            }
        })
        .collect();

    let attachment_bytes: Vec<Bytes> = futures::future::try_join_all(attachment_futures)
        .await
        .map_err(|e| {
            tracing::error!("Failed to join attachment futures: {:?}", e);
            Error::new(ErrorKind::Other, "Invalid attachment content type")
        })?;

    // Build the related part starting with the HTML body
    let mut related = MultiPart::related().singlepart(SinglePart::html(email.body.clone()));

    // Separate inline and regular attachments with their bytes
    let mut regular_parts: Vec<SinglePart> = Vec::new();

    for (att, bytes) in email.attachments.iter().zip(attachment_bytes.iter()) {
        let content_type: ContentType = att.content_type.parse().map_err(|e| {
            tracing::error!("Invalid content type '{}': {}", att.content_type, e);
            Error::new(ErrorKind::Other, "Invalid attachment content type")
        })?;

        if att.inline {
            let cid = att.cid.clone().ok_or_else(|| {
                tracing::error!("Inline attachment '{}' missing cid", att.filename);
                Error::new(ErrorKind::Other, "Inline attachment missing cid")
            })?;
            related =
                related.singlepart(Attachment::new_inline(cid).body(bytes.to_vec(), content_type));
        } else {
            regular_parts
                .push(Attachment::new(att.filename.clone()).body(bytes.to_vec(), content_type));
        }
    }

    // Fold regular attachments into the mixed builder
    let multipart = if regular_parts.is_empty() {
        MultiPart::mixed().multipart(related)
    } else {
        regular_parts
            .into_iter()
            .fold(MultiPart::mixed().multipart(related), |builder, part| {
                builder.singlepart(part)
            })
    };

    let message = Message::builder()
        .from(
            format!("{} <{}>", business_name, smtp_user)
                .parse()
                .map_err(|e| {
                    tracing::error!("Failed to parse sender: {}", e);
                    Error::new(ErrorKind::Other, "Failed to send email")
                })?,
        )
        .reply_to(format!("<{}>", smtp_user).parse().map_err(|e| {
            tracing::error!("Failed to parse reply-to: {}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?)
        .to(format!(
            "{} <{}>",
            email.recipient.full_name.clone().unwrap_or_default(),
            email.recipient.email_address
        )
        .parse()
        .map_err(|e| {
            tracing::error!("Failed to parse recipient: {}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?)
        .subject(&email.subject)
        .multipart(multipart)
        .map_err(|e| {
            tracing::error!("Failed to build message: {}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?;

    let creds = Credentials::new(smtp_user, smtp_password);
    let mailer = SmtpTransport::starttls_relay(&smtp_server)
        .map_err(|e| {
            tracing::error!("Failed to start TLS relay: {}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?
        .credentials(creds)
        .build();

    match mailer.send(&message) {
        Ok(_) => Ok("Email sent successfully!"),
        Err(e) => {
            tracing::error!("Can't send email: {}", e);
            Err(Error::new(ErrorKind::Other, "Failed to send email"))
        }
    }
}

pub async fn synthesize_email(
    db: &Arc<Surreal<Client>>,
    payload: &EmailMQTTPayload,
) -> Result<Email, Error> {
    let mut result = db
        .query(
            r#"
            LET $template_record = type::record('email_template', $payload.template_id);
            SELECT * FROM email_template WHERE id = $template_record LIMIT 1;
            "#,
        )
        .bind(("payload", payload.clone()))
        .await
        .map_err(|e| {
            tracing::error!("{}", e);
            Error::new(ErrorKind::Other, "Database query failed")
        })?;

    let response: Option<EmailTemplate> = result.take(1).map_err(|e| {
        tracing::error!("{}", e);
        Error::new(ErrorKind::Other, "Database query deserialization failed")
    })?;

    let Some(email_template) = response else {
        return Err(Error::new(ErrorKind::Other, "Email template not found!"));
    };

    for variable in &email_template.variables {
        if payload.variables.get(variable).is_none() {
            tracing::error!("Payload is missing a required template variable!");
            return Err(Error::new(
                ErrorKind::Other,
                "Payload is missing a required template variable!",
            ));
        }
    }

    let mut handlebars = Handlebars::new();
    handlebars
        .register_template_string("email_template", email_template.html)
        .map_err(|e| {
            tracing::error!("register_template_string: {:?}", e);
            Error::new(
                ErrorKind::Other,
                "Error encountered while parsing template!",
            )
        })?;

    let body = handlebars
        .render("email_template", &payload.variables)
        .map_err(|e| {
            tracing::error!("render: {:?}", e);
            Error::new(
                ErrorKind::Other,
                "Error encountered while rendering template!",
            )
        })?;

    Ok(Email {
        recipient: EmailUser {
            email_address: payload.recipient.to_string(),
            full_name: None,
        },
        subject: payload.subject.to_string(),
        body,
        attachments: email_template
            .attachments
            .into_iter()
            .chain(payload.attachments.clone().unwrap_or_default().into_iter())
            .collect(),
    })
}
