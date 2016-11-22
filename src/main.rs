extern crate docopt;
extern crate env_logger;
extern crate iron;
#[macro_use]
extern crate log;
extern crate portier_broker;
#[macro_use(router)]
extern crate router;
extern crate staticfile;
extern crate rustc_serialize;

use portier_broker as broker;
use docopt::Docopt;
use iron::{Iron, Chain};
use std::error::Error;
use std::str::FromStr;
use std::sync::Arc;
use std::path::Path;


/// Defines the program's version, as set by Cargo at compile time.
const VERSION: &'static str = env!("CARGO_PKG_VERSION");


/// Defines the program's usage string.
///
/// [Docopt](http://docopt.org) parses this and generates a custom argv parser.
const USAGE: &'static str = r#"
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
#[derive(RustcDecodable)]
#[allow(non_snake_case)]
struct Args {
    arg_CONFIG: Option<String>,
}


/// The `main()` method. Will loop forever to serve HTTP requests.
fn main() {
    if let Err(err) = env_logger::init() {
        panic!(format!("failed to initialize logger: {}", err.description()));
    }
    let args: Args = Docopt::new(USAGE)
                         .and_then(|d| d.version(Some(VERSION.to_string())).decode())
                         .unwrap_or_else(|e| e.exit());

    let mut builder = broker::config::ConfigBuilder::new();
    if let Some(path) = args.arg_CONFIG {
        builder.update_from_file(&path).unwrap_or_else(|err| {
            panic!(format!("failed to read config file: {}", err.description()))
        });
    }
    builder.update_from_common_env();
    builder.update_from_broker_env();
    let app = Arc::new(builder.done().unwrap_or_else(|err| {
        panic!(format!("failed to build configuration: {}", err.description()))
    }));

    let router = router!{
        // Human-targeted endpoints
        get "/" => broker::handlers::pages::Index,
        get "/ver.txt" => broker::handlers::pages::Version,
        get "/confirm" => broker::handlers::email::Confirmation::new(&app),

        // OpenID Connect provider endpoints
        get "/.well-known/openid-configuration" =>
               broker::handlers::oidc::Discovery::new(&app),
        get "/keys.json" => broker::handlers::oidc::KeySet::new(&app),
        get "/auth" => broker::handlers::oidc::Auth::new(&app),
        post "/auth" => broker::handlers::oidc::Auth::new(&app),

        // OpenID Connect relying party endpoints
        get "/callback" => broker::handlers::oauth2::Callback::new(&app),

        // Lastly, fall back to trying to serve static files out of ./res/
        get "/*" => staticfile::Static::new(Path::new("./res/")),
    };

    let mut chain = Chain::new(router);
    chain.link_before(broker::middleware::LogRequest);
    chain.link_after(broker::middleware::SecurityHeaders);

    let ipaddr = std::net::IpAddr::from_str(&app.listen_ip).expect("Unable to parse listen IP address");
    let socket = std::net::SocketAddr::new(ipaddr, app.listen_port);
    info!("listening on http://{}", socket);

    Iron::new(chain).http(socket).expect("Unable to start http server");
}
