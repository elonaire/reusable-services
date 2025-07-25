use lib::utils::models::Email;
use std::{
    env,
    io::{Error, ErrorKind},
    time::SystemTime,
};

// use async_graphql::{Context, Error, Object, Result};
use hyper::Method;
use lettre::{
    message::{Attachment, Body, MultiPart, SinglePart},
    transport::smtp::authentication::Credentials,
    Message, SmtpTransport, Transport,
};
use reqwest::Client as ReqWestClient;

pub async fn send_email(email: &Email) -> Result<&'static str, Error> {
    let smtp_user = env::var("SMTP_USER").map_err(|e| {
        tracing::error!("Missing the SMTP_USER environment variable.: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;
    let smtp_password = env::var("SMTP_PASSWORD").map_err(|e| {
        tracing::error!("Missing the SMTP_PASSWORD environment variable.: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;
    let smtp_server = env::var("SMTP_SERVER").map_err(|e| {
        tracing::error!("Missing the SMTP_SERVER environment variable.: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;
    let files_service = env::var("FILES_SERVICE").map_err(|e| {
        tracing::error!("Missing the FILES_SERVICE environment variable.: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;
    let primary_logo = env::var("PRIMARY_LOGO").map_err(|e| {
        tracing::error!("Missing the PRIMARY_LOGO environment variable.: {:?}", e);
        Error::new(ErrorKind::Other, "Server Error")
    })?;

    let current_year = {
        let now = SystemTime::now();
        let datetime: chrono::DateTime<chrono::Utc> = now.into();
        datetime.format("%Y").to_string()
    };

    let email_title = &email.title;
    let email_content = &email.body;

    let logo_url = format!("{}/view/{}", files_service, primary_logo);
    let client = ReqWestClient::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to build client: {:?}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?;
    // let logo_image = fs::read("https://imagedelivery.net/fa3SWf5GIAHiTnHQyqU8IQ/5d0feb5f-2b15-4b86-9cf3-1f99372f4600/public")?;
    let logo_image = client
        .request(Method::GET, logo_url.as_str())
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Error sending: {:?}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?
        .bytes()
        .await
        .map_err(|e| {
            tracing::error!("Error deserializing: {:?}", e);
            // Error::new(e.to_string())
            Error::new(ErrorKind::Other, "Failed to send email")
        })?;

    let email_body = format!(
        r#"
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                /* General email body styling */
                body {{
                    font-family: Arial, sans-serif;
                    margin: 0 30px;
                    padding: 0;
                    background-color: #FFF7EF;
                }}
                .email-container {{
                    width: 100%;
                    background-color: #ffffff;
                }}
                .header {{
                    background-color: #FFB161;
                    padding: 10px;
                    text-align: center;
                }}
                .header img {{
                    width: 200px;
                }}
                .title {{
                    text-align: center;
                }}
                .content {{
                    padding: 20px;
                    color: #333333;
                }}
                .footer {{
                    background-color: #FFB161;
                    color: #ffffff;
                    text-align: center;
                    padding: 10px 0;
                }}
            </style>
        </head>
        <body>
            <div class="email-container">
                <!-- Header with logo -->
                <div class="header">
                    <img src=cid:logo alt="Rusty Templates Logo">
                </div>

                <!-- Main content -->
                <div class="content">
                    <!-- Replace the content below with your email-specific content -->
                    <h1 class="title">{email_title}</h1>
                    {email_content}
                    <!-- End of email-specific content -->
                </div>
                    <!-- Footer -->
                    <div class="footer">
                        <div style="text-align: center; padding: 10px; font-size: 12px; color: #888888;">
                            <p>Rusty Templates | Tatu City, Kenya | info@rustytemplates.com</p>
                        </div>
                        &copy; {current_year} Rusty Templates. All rights reserved.
                    </div>
                </div>
            </body>
            </html>
        "#
    );

    let logo_image_body = Body::new(logo_image.to_vec());

    let message = Message::builder()
        .from(
            format!("Rusty Templates <{}>", &smtp_user)
                .parse()
                .map_err(|e| {
                    tracing::error!("Failed to parse sender email address: {}", e);
                    Error::new(ErrorKind::Other, "Failed to send email")
                })?,
        )
        .reply_to(format!(" <{}>", &smtp_user).parse().map_err(|e| {
            tracing::error!("Failed to parse reply-to email address: {}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?)
        .to(format!(
            "{} <{}>",
            &email.recipient.clone().full_name.unwrap_or(String::new()),
            &email.recipient.clone().email_address
        )
        .parse()
        .map_err(|e| {
            tracing::error!("Failed to parse recipient email address: {}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?)
        .subject(&email.subject)
        .multipart(
            MultiPart::related()
                .singlepart(SinglePart::html(email_body))
                .singlepart(Attachment::new_inline(String::from("logo")).body(
                    logo_image_body,
                    "image/png".parse().map_err(|e| {
                        tracing::error!("Failed to parse image content type: {}", e);
                        Error::new(ErrorKind::Other, "Failed to send email")
                    })?,
                )),
        )
        .map_err(|e| {
            tracing::error!("Failed to send email: {}", e);
            Error::new(ErrorKind::Other, "Failed to send email")
        })?;

    let creds = Credentials::new(smtp_user.to_owned(), smtp_password.to_owned());

    // Open a remote connection to smtp server
    let mailer = (SmtpTransport::starttls_relay(&smtp_server).map_err(|e| {
        tracing::error!("Failed to start TLS relay: {}", e);
        Error::new(ErrorKind::Other, "Failed to send email")
    })?)
    .credentials(creds)
    .build();

    // Send the email
    match mailer.send(&message) {
        Ok(_) => Ok("Email sent successfully!"),
        Err(e) => {
            tracing::error!("Can't send email: {}", e);
            Err(Error::new(ErrorKind::Other, "Failed to send email"))
        }
    }
}
