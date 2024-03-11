use std::collections::BTreeMap;

use async_graphql::{Error, ErrorExtensions, Value};

// Wrapper type for the original Error
pub struct ExtendedError {
    message: String,
    status: Option<String>,
}

impl ExtendedError {
    // Constructor
    pub fn new(message: impl Into<String>, status: Option<String>) -> Self {
        ExtendedError {
            message: message.into(),
            status,
        }
    }

    // Setter for status
    pub fn set_status(&mut self, status: String) {
        self.status = Some(status);
    }

    // Build the async_graphql::Error with extensions
    pub fn build(self) -> Error {
        let mut extensions = BTreeMap::new();
        if let Some(status) = self.status {
            extensions.insert("status".to_string(), Value::from(status));
        }

        Error::new(self.message).extend_with(|_err, e| {
            for (key, value) in extensions {
                e.set(key, value);
            }
        })
    }
}