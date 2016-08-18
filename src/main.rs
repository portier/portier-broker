extern crate docopt;
extern crate iron;
extern crate portier_broker;
#[macro_use(router)]
extern crate router;
extern crate rustc_serialize;

use portier_broker as broker;
use docopt::Docopt;
use iron::Iron;
use std::str::FromStr;


/// Defines the program's version, as set by Cargo at compile time.
const VERSION: &'static str = env!("CARGO_PKG_VERSION");


/// Defines the program's usage string.
///
/// [Docopt](http://docopt.org) parses this and generates a custom argv parser.
const USAGE: &'static str = r#"
Portier broker

Usage:
  portier_broker [options] CONFIG
  portier_broker --version
  portier_broker --help

Options:
  --address=<ip>  Address to listen on [default: 127.0.0.1]
  --port=<port>   Port to listen on [default: 3333]
  --version       Print version information and exit
  --help          Print this help message and exit
"#;


/// Holds parsed command line parameters.
#[derive(RustcDecodable)]
#[allow(non_snake_case)]
struct Args {
    arg_CONFIG: String,
    flag_address: String,
    flag_port: u16,
}


/// The `main()` method. Will loop forever to serve HTTP requests.
fn main() {
    let args: Args = Docopt::new(USAGE)
                         .and_then(|d| d.version(Some(VERSION.to_string())).decode())
                         .unwrap_or_else(|e| e.exit());

    // Read the configuration from the provided file.
    let app = broker::AppConfig::from_json_file(&args.arg_CONFIG).unwrap();

    // TODO: cloning the configuration object is ugly, but apparently necessary
    // with how the Iron `Handler` trait is defined. Also, it would be cleaner
    // if the handlers could just be functions, instead of single-method impls.
    let router = router!{
        // Human-targeted endpoints
        get "/" => broker::WelcomeHandler { app: app.clone() },
        get "/.well-known/*" => broker::WellKnownHandler { app: app.clone() },
        get "/confirm" => broker::ConfirmHandler { app: app.clone() },

        // OpenID Connect provider endpoints
        get "/.well-known/openid-configuration" =>
               broker::OIDConfigHandler { app: app.clone() },
        get "/keys.json" => broker::KeysHandler { app: app.clone() },
        post "/auth" => broker::AuthHandler { app: app.clone() },

        // OpenID Connect relying party endpoints
        get "/callback" => broker::CallbackHandler { app: app.clone() },
    };

    let ip_address = std::net::IpAddr::from_str(&args.flag_address).unwrap();
    let socket = std::net::SocketAddr::new(ip_address, args.flag_port);

    println!("Listening on http://{}", socket);

    Iron::new(router).http("0.0.0.0:3333").unwrap();
}
