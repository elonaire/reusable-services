use std::{
    env,
    io::{Error, ErrorKind},
    time::Duration,
};

use rumqttc::v5::{AsyncClient, EventLoop, MqttOptions};

pub struct MqttClient;

impl MqttClient {
    pub async fn new(id: &str, host: &str, port: u16) -> Result<(AsyncClient, EventLoop), Error> {
        let mosquitto_user = env::var("MOSQUITTO_USER").map_err(|e| {
            tracing::error!("Missing the MOSQUITTO_USER environment variable.: {}", e);
            Error::new(ErrorKind::PermissionDenied, "Unauthorized!")
        })?;
        let mosquitto_user_password = env::var("MOSQUITTO_USER_PASSWORD").map_err(|e| {
            tracing::error!(
                "Missing the MOSQUITTO_USER_PASSWORD environment variable.: {}",
                e
            );
            Error::new(ErrorKind::PermissionDenied, "Unauthorized!")
        })?;

        let mut mqttoptions = MqttOptions::new(id, host, port);
        mqttoptions.set_keep_alive(Duration::from_secs(5));
        mqttoptions.set_credentials(mosquitto_user.as_str(), mosquitto_user_password.as_str());
        Ok(AsyncClient::new(mqttoptions, 10))
    }
}
