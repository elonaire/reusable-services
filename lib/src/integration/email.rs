use crate::utils::{
    graphql_api::perform_mutation_or_query_with_vars,
    models::{Email, SendEmailResponse, SendEmailVar},
};
use hyper::HeaderMap;
use std::{env, io::Error};

/// Integration method for Email service, used across all the services
pub async fn send_email(headers: HeaderMap, email: Email) -> Result<String, Error> {
    // check auth status from ACL service(graphql query)
    let gql_query = r#"
        mutation EmailMutation($email: EmailInput!) {
            sendEmail(email: $email)
        }
    "#;

    let variables = SendEmailVar { email };

    match headers.get("Authorization") {
        Some(_auth_header) => {
            // let mut auth_headers = HashMap::new();
            // auth_headers.insert("Authorization".to_string(), auth_header.to_str().unwrap().to_string());

            let endpoint =
                env::var("EMAIL_SERVICE").expect("Missing the EMAIL_SERVICE environment variable.");

            let send_email_response = perform_mutation_or_query_with_vars::<
                SendEmailResponse,
                SendEmailVar,
            >(None, &endpoint, gql_query, variables)
            .await;

            println!("send_email_response: {:?}", send_email_response);

            match send_email_response.get_data() {
                Some(send_email_response) => Ok(send_email_response.send_email.clone()),
                None => Err(Error::new(
                    std::io::ErrorKind::Other,
                    format!("Email Service not responding!"),
                )),
            }
        }
        None => Err(Error::new(std::io::ErrorKind::Other, "Not Authorized!")),
    }
}
