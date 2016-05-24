extern crate iron;
extern crate lettre;
extern crate openssl;
extern crate rand;
extern crate redis;
extern crate router;
extern crate rustc_serialize;
extern crate serde_json;
extern crate urlencoded;

use iron::headers::ContentType;
use iron::middleware::Handler;
use iron::prelude::*;
use iron::status;
use lettre::email::EmailBuilder;
use lettre::transport::smtp::SmtpTransportBuilder;
use lettre::transport::EmailTransport;
use urlencoded::UrlEncodedBody;
use openssl::bn::BigNum;
use openssl::crypto::pkey::PKey;
use serde_json::builder::ObjectBuilder;
use serde_json::value::Value;
use redis::{Client, Commands, RedisResult};
use router::Router;
use rustc_serialize::base64::{self, ToBase64};
use std::error::Error;
use std::fs::File;
use std::io::BufReader;


fn json_response(obj: &Value) -> IronResult<Response> {
	let content = serde_json::to_string(&obj).unwrap();
	let mut rsp = Response::with((status::Ok, content));
	rsp.headers.set(ContentType::json());
    return Ok(rsp);
}


struct WelcomeHandler { app: AppConfig }
impl Handler for WelcomeHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
	    return json_response(&ObjectBuilder::new()
	        .insert("ladaemon", "Welcome")
	        .insert("version", &self.app.version)
	        .unwrap());
	}
}


struct OIDConfigHandler { app: AppConfig }
impl Handler for OIDConfigHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        return json_response(&ObjectBuilder::new()
            .insert("issuer", &self.app.base_url)
            .insert("authorization_endpoint", format!("{}/auth", self.app.base_url))
            .insert("jwks_uri", format!("{}/keys.json", self.app.base_url))
            .insert("scopes_supported", vec!["openid", "email"])
            .insert("claims_supported", vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"])
            .insert("response_types_supported", vec!["id_token"])
            .insert("response_modes_supported", vec!["form_post"])
            .insert("grant_types_supported", vec!["implicit"])
            .insert("subject_types_supported", vec!["public"])
            .insert("id_token_signing_alg_values_supported", vec!["RS256"])
            .unwrap());
	}
}


#[derive(Clone)]
struct AppConfig {
    version: String,
    base_url: String,
    priv_key: PKey,
    store: Client,
    expire_keys: usize,
    sender: String,
}


fn json_big_num(n: &BigNum) -> String {
    return n.to_vec().to_base64(base64::URL_SAFE);
}


struct KeysHandler { app: AppConfig }
impl Handler for KeysHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        let rsa = self.app.priv_key.get_rsa();
        return json_response(&ObjectBuilder::new()
            .insert_array("keys", |builder| {
                builder.push_object(|builder| {
                    builder
                        .insert("kty", "RSA")
                        .insert("alg", "RS256")
                        .insert("use", "sig")
                        .insert("kid", "base")
                        .insert("n", json_big_num(&rsa.n().unwrap()))
                        .insert("e", json_big_num(&rsa.e().unwrap()))
            })
        }).unwrap());
    }
}


const CODE_CHARS: &'static [char] = &[
    '2', '3', '4', '6', '7', '9', 'a', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 't', 'v', 'w', 'x', 'y', 'z',
];


struct AuthHandler { app: AppConfig }
impl Handler for AuthHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let chars: String = (0..6).map(|_| CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]).collect();
        let params = req.get_ref::<UrlEncodedBody>().unwrap();
        let email_addr = &params.get("login_hint").unwrap()[0];
        let client_id = &params.get("client_id").unwrap()[0];
        let key = format!("{}:{}", email_addr, client_id);
        let _: RedisResult<String> = self.app.store.hset_multiple(key.clone(), &[
            ("code", chars.clone()),
            ("redirect", params.get("redirect_uri").unwrap()[0].clone()),
        ]);
        let _: RedisResult<String> = self.app.store.expire(key.clone(), self.app.expire_keys);

        let email = EmailBuilder::new()
            .to(email_addr.as_str())
            .from(self.app.sender.as_str())
            .body(&format!("code: {}", chars))
            .subject("Your login code")
            .build().unwrap();
        let mut mailer = SmtpTransportBuilder::localhost().unwrap().build();
        let result = mailer.send(email);
        mailer.close();

        let mut obj = ObjectBuilder::new()
            .insert("code", chars);
        if !result.is_ok() {
            let error = result.unwrap_err();
            obj = obj.insert("error", error.to_string());
            obj = match error {
                lettre::transport::error::Error::IoError(inner)
                    => obj.insert("cause", inner.description()),
                _ => obj,
            }
        }
        return json_response(&obj.unwrap());

    }
}


fn main() {

    let priv_key_file = File::open("private.pem").unwrap();
    let mut reader = BufReader::new(priv_key_file);
    let app = AppConfig {
        version: env!("CARGO_PKG_VERSION").to_string(),
        base_url: "https://letsauth.xavamedia.nl".to_string(),
        priv_key: PKey::private_key_from_pem(&mut reader).unwrap(),
        store: Client::open("redis://127.0.0.1/5").unwrap(),
        expire_keys: 60 * 15,
        sender: "Let's Auth <letsauth@xavamedia.nl>".to_string(),
    };

    let mut router = Router::new();
    router.get("/", WelcomeHandler { app: app.clone() });
    router.get("/.well-known/openid-configuration", OIDConfigHandler { app: app.clone() });
    router.get("/keys.json", KeysHandler { app: app.clone() });
    router.post("/auth", AuthHandler { app: app.clone() });
    Iron::new(router).http("0.0.0.0:8000").unwrap();

}
