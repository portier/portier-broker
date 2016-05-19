extern crate iron;
extern crate openssl;
extern crate router;
extern crate serde_json;

use std::io::BufReader;
use std::fs::File;
use iron::prelude::*;
use iron::status;
use openssl::crypto::rsa::RSA;
use iron::headers::ContentType;
use router::Router;
use serde_json::builder::ObjectBuilder;
use serde_json::value::Value;


const VERSION: &'static str = env!("CARGO_PKG_VERSION");
const SELF_BASE: &'static str = "http://xavamedia.nl:8000";


fn json_response(obj: &Value) -> IronResult<Response> {
	let content = serde_json::to_string(&obj).unwrap();
	let mut rsp = Response::with((status::Ok, content));
	rsp.headers.set(ContentType::json());
    return Ok(rsp);
}


fn welcome(_: &mut Request) -> IronResult<Response> {
	return json_response(&ObjectBuilder::new()
	    .insert("ladaemon", "Welcome")
	    .insert("version", VERSION)
	    .unwrap());
}


fn oid_config(_: &mut Request) -> IronResult<Response> {
    return json_response(&ObjectBuilder::new()
        .insert("issuer", SELF_BASE)
        .insert("authorization_endpoint", format!("{}/auth", SELF_BASE))
        .insert("jwks_uri", format!("{}/keys.json", SELF_BASE))
        .insert("scopes_supported", vec!["openid", "email"])
        .insert("claims_supported", vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"])
        .insert("response_types_supported", vec!["id_token"])
        .insert("response_modes_supported", vec!["form_post"])
        .insert("grant_types_supported", vec!["implicit"])
        .insert("subject_types_supported", vec!["public"])
        .insert("id_token_signing_alg_values_supported", vec!["RS256"])
        .unwrap());
}


fn main() {

    let priv_key_file = File::open("private.pem").unwrap();
    let mut reader = BufReader::new(priv_key_file);
    let priv_key = RSA::private_key_from_pem(&mut reader).unwrap();

    let mut router = Router::new();
    router.get("/", welcome);
    router.get("/.well-known/openid-configuration", oid_config);
    Iron::new(router).http("0.0.0.0:8000").unwrap();

}
