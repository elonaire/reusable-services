use std::collections::BTreeMap;

use async_graphql::{Error, ErrorExtensions, Value};

// Wrapper type for the original Error
pub struct ExtendedError {
    message: String,
    status_code: String,
}

impl ExtendedError {
    // Constructor
    pub fn new(message: impl Into<String>, status_code: &str) -> Self {
        ExtendedError {
            message: message.into(),
            status_code: status_code.to_owned(),
        }
    }

    // Setter for status
    pub fn set_status(&mut self, status_code: &str) {
        self.status_code = status_code.to_owned();
    }

    // Build the async_graphql::Error with extensions
    pub fn build(self) -> Error {
        let mut extensions = BTreeMap::new();
        extensions.insert("status".to_string(), Value::from(self.status_code));

        Error::new(self.message).extend_with(|_err, e| {
            for (key, value) in extensions {
                e.set(key, value);
            }
        })
    }
}
