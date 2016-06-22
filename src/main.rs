extern crate iron;
extern crate ladaemon;

#[macro_use(router)]
extern crate router;

use iron::prelude::Iron;
use ladaemon::AppConfig;
use ladaemon::handlers;
use std::env;
use std::io::{self, Write};
use std::process::exit;

const USAGE: &'static str = "Usage: ladaemon file";

fn main() {

    // Make sure we get a file name where we can find configuration.
    let args = env::args().collect::<Vec<String>>();
    if args.len() != 2 {
        let error = if args.len() < 2 {
                "Error: No configuration file specified"
            } else {
                "Error: Too many parameters specified"
            };

        write!(io::stderr(), "{}\n{}\n", error, USAGE).unwrap_or(());
        exit(1);
    }

    // Read the configuration from the provided file.
    let app = AppConfig::from_json_file(&args[1]);

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
