//! # Let's Auth - Authentication Daemon
//!
//! A microservice for authenticating email addresses.

extern crate docopt;
extern crate iron;
extern crate ladaemon;
#[macro_use(router)]
extern crate router;
extern crate rustc_serialize;

use docopt::Docopt;
use iron::prelude::Iron;
use ladaemon::AppConfig;
use ladaemon::handlers;
use std::io::{Write, stderr};

/// Defines the program's version, as set by Cargo at compile time.
const VERSION: &'static str = env!("CARGO_PKG_VERSION");

/// Defines the program's usage string.
///
/// [Docopt](http://docopt.org) parses this and generates a custom argv parser.
const USAGE: &'static str = "
Let's Auth.

Usage:
  ladaemon CONFIG
  ladaemon -V | --version
  ladaemon -h | --help

Options:
  -V, --version  Print version information and exit
  -h, --help     Print this help message and exit
";

/// Holds parsed command line parameters.
#[derive(RustcDecodable)]
#[allow(non_snake_case)]
struct Args {
    arg_CONFIG: String,
}

/// Starts the server.
fn main() {
    let args: Args = Docopt::new(USAGE)
                         .and_then(|d| d.version(Some(VERSION.to_string())).decode())
                         .unwrap_or_else(|e| e.exit());

    let app = AppConfig::from_json_file(&args.arg_CONFIG).unwrap_or_else(|e| {
        write!(stderr(), "Failed to read configuration: {}\n", e).ok();
        std::process::exit(1)
    });

    let router = router!{
        // Website Endpoints
        get  "/" => handlers::Welcome { app: app.clone() },
        get  "/confirm" => handlers::Confirm { app: app.clone() },

        // OpenID Connect Provider Endpoints
        get  "/.well-known/openid-configuration" => handlers::OIDCConfig { app: app.clone() },
        get  "/keys.json" => handlers::Keys { app: app.clone() },
        post "/auth" => handlers::Auth { app: app.clone() },

        // OpenID Connect Relying Party Endpoints
        get  "/callback" => handlers::Callback { app: app.clone() },
    };

    Iron::new(router).http("0.0.0.0:3333").unwrap();
}
