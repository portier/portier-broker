use config::Config;
use error::BrokerResult;
use iron::{Handler, IronResult, Request, Response};
use serde_json::builder::ObjectBuilder;
use std::sync::Arc;
use super::{handle_error, json_response};

/// Iron handler for the root path, returns human-friendly message.
///
/// This is not actually used in the protocol.
broker_handler!(WelcomeHandler, |_app, _req| {
    json_response(&ObjectBuilder::new()
        .insert("ladaemon", "Welcome")
        .insert("version", env!("CARGO_PKG_VERSION"))
        .build())
});
