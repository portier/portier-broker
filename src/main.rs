extern crate emailaddress;
extern crate iron;
extern crate lettre;
extern crate openssl;
extern crate rand;
extern crate redis;
extern crate router;
extern crate rustc_serialize;
extern crate serde_json;
extern crate time;
extern crate url;
extern crate urlencoded;

use emailaddress::EmailAddress;
use iron::headers::ContentType;
use iron::middleware::Handler;
use iron::prelude::*;
use iron::status;
use lettre::email::EmailBuilder;
use lettre::transport::smtp::SmtpTransportBuilder;
use lettre::transport::EmailTransport;
use urlencoded::{UrlEncodedBody, UrlEncodedQuery};
use openssl::bn::BigNum;
use openssl::crypto::pkey::PKey;
use openssl::crypto::hash;
use serde_json::builder::ObjectBuilder;
use serde_json::de::from_reader;
use serde_json::value::Value;
use redis::{Client, Commands, RedisResult};
use router::Router;
use rustc_serialize::base64::{self, ToBase64};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::iter::Iterator;
use time::now_utc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};


fn json_response(obj: &Value) -> IronResult<Response> {
    let content = serde_json::to_string(&obj).unwrap();
    let mut rsp = Response::with((status::Ok, content));
    rsp.headers.set(ContentType::json());
    Ok(rsp)
}


struct WelcomeHandler { app: AppConfig }
impl Handler for WelcomeHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        json_response(&ObjectBuilder::new()
            .insert("ladaemon", "Welcome")
            .insert("version", &self.app.version)
            .unwrap())
    }
}


struct OIDConfigHandler { app: AppConfig }
impl Handler for OIDConfigHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        json_response(&ObjectBuilder::new()
            .insert("issuer", &self.app.base_url)
            .insert("authorization_endpoint",
                    format!("{}/auth", self.app.base_url))
            .insert("jwks_uri", format!("{}/keys.json", self.app.base_url))
            .insert("scopes_supported", vec!["openid", "email"])
            .insert("claims_supported",
                    vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"])
            .insert("response_types_supported", vec!["id_token"])
            .insert("response_modes_supported", vec!["form_post"])
            .insert("grant_types_supported", vec!["implicit"])
            .insert("subject_types_supported", vec!["public"])
            .insert("id_token_signing_alg_values_supported", vec!["RS256"])
            .unwrap())
    }
}


#[derive(Clone)]
struct ProviderConfig {
    discovery: String,
    client_id: String,
    secret: String,
}


#[derive(Clone)]
struct AppConfig {
    version: String,
    base_url: String,
    priv_key: PKey,
    store: Client,
    expire_keys: usize,
    sender: String,
    token_validity: i64,
    providers: BTreeMap<String, ProviderConfig>,
}


fn json_big_num(n: &BigNum) -> String {
    n.to_vec().to_base64(base64::URL_SAFE)
}


struct KeysHandler { app: AppConfig }
impl Handler for KeysHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        let rsa = self.app.priv_key.get_rsa();
        json_response(&ObjectBuilder::new()
            .insert_array("keys", |builder| {
                builder.push_object(|builder| {
                    builder.insert("kty", "RSA")
                        .insert("alg", "RS256")
                        .insert("use", "sig")
                        .insert("kid", "base")
                        .insert("n", json_big_num(&rsa.n().unwrap()))
                        .insert("e", json_big_num(&rsa.e().unwrap()))
                })
            })
            .unwrap())
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
        let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]);
        let client_id = &params.get("client_id").unwrap()[0];
        let key = format!("{}:{}", email_addr, client_id);
        let set_res: RedisResult<String> = self.app.store.hset_multiple(key.clone(), &[
            ("code", chars.clone()),
            ("redirect", params.get("redirect_uri").unwrap()[0].clone()),
        ]);
        let exp_res: RedisResult<bool> = self.app.store.expire(key.clone(), self.app.expire_keys);

        let href = format!("{}/confirm?email={}&origin={}&code={}",
                           self.app.base_url,
                           utf8_percent_encode(&email_addr.to_string(), QUERY_ENCODE_SET),
                           utf8_percent_encode(client_id, QUERY_ENCODE_SET),
                           utf8_percent_encode(&chars, QUERY_ENCODE_SET));
        let email = EmailBuilder::new()
            .to(email_addr.to_string().as_str())
            .from(self.app.sender.as_str())
            .body(&format!("Enter your login code:\n\n{}\n\nOr click this link:\n\n{}",
                           chars, href))
            .subject(&format!("Code: {} - Finish logging in to {}", chars, client_id))
            .build().unwrap();
        let mut mailer = SmtpTransportBuilder::localhost().unwrap().build();
        let result = mailer.send(email);
        mailer.close();

        let mut obj = ObjectBuilder::new()
            .insert("href", href);
        if !result.is_ok() {
            let error = result.unwrap_err();
            obj = obj.insert("error", error.to_string());
            obj = match error {
                lettre::transport::error::Error::IoError(inner) => {
                    obj.insert("cause", inner.description())
                }
                _ => obj,
            }
        }
        if !set_res.is_ok() {
            obj = obj.insert("hset_multiple", set_res.unwrap_err().to_string());
        }
        if !exp_res.is_ok() {
            obj = obj.insert("expire", exp_res.unwrap_err().to_string());
        }
        json_response(&obj.unwrap())

    }
}


fn create_jwt(key: &PKey, header: &str, payload: &str) -> String {
    let mut input = Vec::<u8>::new();
    input.extend(header.as_bytes().to_base64(base64::URL_SAFE).into_bytes());
    input.push(b'.');
    input.extend(payload.as_bytes().to_base64(base64::URL_SAFE).into_bytes());
    let sha256 = hash::hash(hash::Type::SHA256, &input);
    let sig = key.sign(&sha256);
    input.push(b'.');
    input.extend(sig.to_base64(base64::URL_SAFE).into_bytes());
    String::from_utf8(input).unwrap()
}


const FORWARD_TEMPLATE: &'static str = r#"<!DOCTYPE html>
<html>
  <head>
    <title>Let's Auth</title>
    <script>
      document.addEventListener('DOMContentLoaded', function() {
        document.getElementById('form').submit();
      });
    </script>
  </head>
  <body>
    <form id="form" action="{{ return_url }}" method="post">
      <input type="hidden" name="id_token" value="{{ jwt }}">
    </form>
  </body>
</html>"#;


fn send_jwt_response(email: &str, origin: &str, redirect: &str, app: &AppConfig) -> IronResult<Response> {

    let now = now_utc().to_timespec().sec;
    let payload = ObjectBuilder::new()
        .insert("aud", origin)
        .insert("email", email)
        .insert("email_verified", email)
        .insert("exp", now + app.token_validity)
        .insert("iat", now)
        .insert("iss", &app.base_url)
        .insert("sub", email)
        .unwrap();
    let headers = ObjectBuilder::new()
        .insert("kid", "base")
        .insert("alg", "RS256")
        .unwrap();
    let jwt = create_jwt(&app.priv_key,
                         &serde_json::to_string(&headers).unwrap(),
                         &serde_json::to_string(&payload).unwrap());

    let html = FORWARD_TEMPLATE.replace("{{ return_url }}", redirect)
        .replace("{{ jwt }}", &jwt);
    let mut rsp = Response::with((status::Ok, html));
    rsp.headers.set(ContentType::html());
    Ok(rsp)

}


struct ConfirmHandler { app: AppConfig }
impl Handler for ConfirmHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let params = req.get_ref::<UrlEncodedQuery>().unwrap();
        let email = &params.get("email").unwrap()[0];
        let origin = &params.get("origin").unwrap()[0];
        let key = format!("{}:{}", email, origin);
        let stored: HashMap<String, String> = self.app.store.hgetall(key.clone()).unwrap();

        let req_code = &params.get("code").unwrap()[0];
        if stored.get("code").is_none() || req_code != stored.get("code").unwrap() {
            let mut obj = ObjectBuilder::new().insert("error", "code fail");
            obj = obj.insert("stored", stored);
            return json_response(&obj.unwrap());
        }

        let redirect = stored.get("redirect").unwrap();
        send_jwt_response(email, origin, redirect, &self.app)

    }
}



fn main() {

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        io::stderr().write(b"no configuration file specified\n").unwrap();
        return;
    }

    let config_file = File::open(&args[1]).unwrap();
    let config_reader = BufReader::new(config_file);
    let config: Value = from_reader(config_reader).unwrap();

    let key_file_name = config.find("private_key_file").unwrap().as_string().unwrap();
    let priv_key_file = File::open(key_file_name).unwrap();
    let mut reader = BufReader::new(priv_key_file);
    let app = AppConfig {
        version: env!("CARGO_PKG_VERSION").to_string(),
        base_url: config.find("base_url").unwrap().as_string().unwrap().to_string(),
        priv_key: PKey::private_key_from_pem(&mut reader).unwrap(),
        store: Client::open(config.find("redis").unwrap().as_string().unwrap()).unwrap(),
        expire_keys: config.find("expire_keys").unwrap().as_u64().unwrap() as usize,
        sender: "Let's Auth <letsauth@xavamedia.nl>".to_string(),
        token_validity: config.find("token_validity").unwrap().as_i64().unwrap(),
        providers: config.find("providers").unwrap().as_object().unwrap().iter()
            .map(|(host, params)| {
                let pobj = params.as_object().unwrap();
                (host.clone(), ProviderConfig {
                    discovery: pobj["discovery"].as_string().unwrap().to_string(),
                    client_id: pobj["client_id"].as_string().unwrap().to_string(),
                    secret: pobj["secret"].as_string().unwrap().to_string(),
                })
            })
            .collect::<BTreeMap<String, ProviderConfig>>(),
    };

    let mut router = Router::new();
    router.get("/", WelcomeHandler { app: app.clone() });
    router.get("/.well-known/openid-configuration",
               OIDConfigHandler { app: app.clone() });
    router.get("/keys.json", KeysHandler { app: app.clone() });
    router.post("/auth", AuthHandler { app: app.clone() });
    router.get("/confirm", ConfirmHandler { app: app.clone() });
    Iron::new(router).http("0.0.0.0:3333").unwrap();

}
