extern crate iron;
extern crate openssl;
extern crate router;
extern crate serde_json;

use std::io::BufReader;
use std::fs::File;
use iron::prelude::*;
use iron::status;
use openssl::crypto::rsa::RSA;
use std::collections::HashMap;
use iron::headers::ContentType;
use router::Router;


const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const SCHEME: &'static str = "http";
const HOST: &'static str = "xavamedia.nl:8000";


fn json_response(obj: &HashMap<&str, &str>) -> IronResult<Response> {
	let content = serde_json::to_string(&obj).unwrap();
	let mut rsp = Response::with((status::Ok, content));
	rsp.headers.set(ContentType::json());
    return Ok(rsp);
}


fn welcome(_: &mut Request) -> IronResult<Response> {
	let mut obj = HashMap::new();
	obj.insert("ladaemon", "Welcome");
	obj.insert("version", VERSION);
	return json_response(&obj);
}


fn main() {

    let priv_key_file = File::open("private.pem").unwrap();
    let mut reader = BufReader::new(priv_key_file);
    let priv_key = RSA::private_key_from_pem(&mut reader).unwrap();

    let mut router = Router::new();
    router.get("/", welcome);
    Iron::new(router).http("0.0.0.0:8000").unwrap();

}
