extern crate iron;
extern crate ladaemon;

#[macro_use(router)]
extern crate router;

use iron::Iron;
use std::env;
use std::io::{self, Write};


/// The `main()` method. Will loop forever to serve HTTP requests.
fn main() {

    // Make sure we get a file name where we can find configuration.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        io::stderr().write(b"no configuration file specified\n").unwrap();
        return;
    }

    // Read the configuration from the provided file.
    let app = ladaemon::AppConfig::from_json_file(&args[1]);

    // Register all handlers with a router object. TODO: cloning the
    // configuration object is kind of ugly, but is apparently needed with
    // the way the Iron `Handler` trait is defined. Also, it would be cleaner
    // if the handlers could just be a function, instead of single-method
    // impls.
    let router = router!{

        // Human-targeted endpoints
        get "/" => ladaemon::WelcomeHandler { app: app.clone() },
        get "/confirm" => ladaemon::email::ConfirmHandler { app: app.clone() },

        // OpenID Connect provider endpoints
        get "/.well-known/openid-configuration" =>
               ladaemon::OIDConfigHandler { app: app.clone() },
        get "/keys.json" => ladaemon::KeysHandler { app: app.clone() },
        post "/auth" => ladaemon::AuthHandler { app: app.clone() },

        // OpenID Connect relying party endpoints
        get "/callback" => ladaemon::oidc::CallbackHandler { app: app.clone() },

    };

    // Iron will take care of stuff from here. It should spin up a number of
    // threads according to the number of cores available. TODO: make the
    // interface on which we listen configurable.
    Iron::new(router).http("0.0.0.0:3333").unwrap();

}
