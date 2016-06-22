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

// Usage string, parsed according to http://docopt.org/
const USAGE: &'static str = "
Let's Auth.

Usage: ladaemon CONFIG
";

#[derive(RustcDecodable)]
#[allow(non_snake_case)]
struct Args {
    arg_CONFIG: String,
}

fn main() {
    let args: Args = Docopt::new(USAGE)
        .and_then(|d| d.decode())
        .unwrap_or_else(|e| e.exit());

    let app = AppConfig::from_json_file(&args.arg_CONFIG);

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

    // Iron will take care of stuff from here. It should spin up a number of
    // threads according to the number of cores available. TODO: make the
    // interface on which we listen configurable.
    Iron::new(router).http("0.0.0.0:3333").unwrap();
}
