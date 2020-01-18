#[macro_use]
mod macros;

mod bridges;
mod config;
mod crypto;
mod email_address;
mod error;
mod handlers;
mod http_ext;
mod pemfile;
mod router;
mod serde_helpers;
mod store;
mod store_cache;
mod store_limits;
mod validation;
mod web;
mod webfinger;

use crate::config::{ConfigBuilder, ConfigRc};
use crate::web::{BoxError, Service};
use futures_util::future;
use hyper::{server::Server, service::make_service_fn};
use log::info;
use serde_derive::Deserialize;
use std::net::SocketAddr;

/// Defines the program's version, as set by Cargo at compile time.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Defines the program's usage string.
///
/// [Docopt](http://docopt.org) parses this and generates a custom argv parser.
const USAGE: &str = r#"
Portier Broker

Usage:
  portier-broker [CONFIG]
  portier-broker --version
  portier-broker --help

Options:
  --version       Print version information and exit
  --help          Print this help message and exit
"#;

/// Holds parsed command line parameters.
#[derive(Deserialize)]
#[allow(non_snake_case)]
struct Args {
    arg_CONFIG: Option<String>,
}

/// The `main()` method. Will loop forever to serve HTTP requests.
#[tokio::main]
async fn main() {
    env_logger::init();

    let args: Args = docopt::Docopt::new(USAGE)
        .map(|docopt| docopt.version(Some(VERSION.to_owned())))
        .and_then(|docopt| docopt.deserialize())
        .unwrap_or_else(|e| e.exit());

    let mut builder = ConfigBuilder::new();
    if let Some(ref path) = args.arg_CONFIG {
        builder
            .update_from_file(path)
            .unwrap_or_else(|err| panic!(format!("failed to read config file: {}", err)));
    }
    builder.update_from_common_env();
    builder.update_from_broker_env();
    let app = ConfigRc::new(
        builder
            .done()
            .await
            .unwrap_or_else(|err| panic!(format!("failed to build configuration: {}", err))),
    );

    // TODO: Add unix socket support.
    let builder = match listenfd::ListenFd::from_env().take_tcp_listener(0) {
        Ok(Some(tcp_listener)) => {
            let builder = Server::from_tcp(tcp_listener).expect("Socket activation failed");
            info!("Listening on the socket received from the service manager");
            builder
        }
        Ok(None) => {
            let ip_addr = app
                .listen_ip
                .parse()
                .expect("Unable to parse listen address");
            let addr = SocketAddr::new(ip_addr, app.listen_port);
            let builder = Server::bind(&addr);
            info!("Listening on {}", addr);
            builder
        }
        Err(err) => {
            panic!("Socket activation failed: {}", err);
        }
    };

    #[cfg(unix)]
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])
        .expect("Failed to signal ready to the service manager");

    let make_service = make_service_fn(|stream| {
        let app = ConfigRc::clone(&app);
        future::ok::<_, BoxError>(Service::new(app, stream))
    });
    builder.serve(make_service).await.expect("Server error");
}
