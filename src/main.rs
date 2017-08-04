extern crate docopt;
extern crate emailaddress;
extern crate env_logger;
extern crate futures;
extern crate gettext;
extern crate hyper;
extern crate lettre;
#[macro_use]
extern crate log;
extern crate mustache;
extern crate openssl;
extern crate rand;
extern crate redis;
extern crate rustc_serialize;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate time;
extern crate tokio_core;
extern crate toml;
extern crate url;

mod config;
mod crypto;
mod email_bridge;
mod error;
mod handlers;
mod http;
mod oidc_bridge;
mod store;
mod store_cache;
mod store_limits;
mod validation;

use docopt::Docopt;
use futures::{future, Future, Stream};
use hyper::{Method, StatusCode};
use hyper::server::{Http, Request, Response};
use std::net::SocketAddr;
use std::sync::Arc;


/// Route the request, returning a handler
fn route(req: &Request) -> http::Handler {
    match (req.method(), req.path()) {
        // Human-targeted endpoints
        (&Method::Get, "/") => handlers::pages::index,
        (&Method::Get, "/ver.txt") => handlers::pages::version,
        (&Method::Get, "/confirm") => handlers::email::confirmation,

        // OpenID Connect provider endpoints
        (&Method::Get, "/.well-known/openid-configuration") => handlers::oidc::discovery,
        (&Method::Get, "/keys.json") => handlers::oidc::key_set,
        (&Method::Get, "/auth") | (&Method::Post, "/auth") => handlers::oidc::auth,

        // OpenID Connect relying party endpoints
        (&Method::Get, "/callback") | (&Method::Post, "/callback") => handlers::oauth2::callback,

        // Lastly, fall back to trying to serve static files out of ./res/
        // TODO

        _ => handle_unmatched,
    }
}


/// Handler used when no routing matches nothing
fn handle_unmatched(_: Request, _: http::ContextHandle) -> http::HandlerResult {
    let res = Response::new()
        .with_status(StatusCode::BadRequest);
    future::ok(res).boxed()
}


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
        panic!(format!("failed to initialize logger: {}", err));
    }
    let args: Args = Docopt::new(USAGE)
                         .and_then(|d| d.version(Some(VERSION.to_string())).decode())
                         .unwrap_or_else(|e| e.exit());

    let mut builder = config::ConfigBuilder::new();
    if let Some(path) = args.arg_CONFIG {
        builder.update_from_file(&path).unwrap_or_else(|err| {
            panic!(format!("failed to read config file: {}", err))
        });
    }
    builder.update_from_common_env();
    builder.update_from_broker_env();
    let app = Arc::new(builder.done().unwrap_or_else(|err| {
        panic!(format!("failed to build configuration: {}", err))
    }));

    let mut core = tokio_core::reactor::Core::new()
        .expect("Could not start the event loop");
    let handle = core.handle();
    let proto = Http::new();

    let ip_addr = app.listen_ip.parse()
        .expect("Unable to parse listen address");
    let addr = SocketAddr::new(ip_addr, app.listen_port);
    let listener = tokio_core::net::TcpListener::bind(&addr, &handle)
        .expect("Unable to bind listen address");
    info!("Listening on http://{}", addr);

    core.run(
        listener.incoming()
            .for_each(move |(sock, addr)| {
                proto.bind_connection(&handle, sock, addr, http::Service {
                    app: app.clone(),
                    handle: handle.remote().clone(),
                    route: route,
                });
                Ok(())
            })
            .map_err(|err| {
                error!("{}", err);
                ()
            })
    ).expect("Unhandled failure running the server");
}
