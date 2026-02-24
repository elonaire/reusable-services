use rumqttc::v5::{mqttbytes::QoS, AsyncClient};

pub async fn register_subscriptions(client: &AsyncClient) -> () {
    client
        .subscribe("email/send", QoS::AtLeastOnce)
        .await
        .map_err(|e| {
            tracing::error!("Failed to subscribe to email/send event: {}", e);
        })
        .ok();
}
