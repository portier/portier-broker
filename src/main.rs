extern crate emailaddress;
extern crate hyper;
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
use hyper::client::Client as HttpClient;
use hyper::header::ContentType as HyContentType;
use hyper::header::Headers;
use iron::headers::ContentType;
use iron::middleware::Handler;
use iron::modifiers;
use iron::prelude::*;
use iron::status;
use iron::Url;
use lettre::email::EmailBuilder;
use lettre::transport::EmailTransport;
use lettre::transport::smtp::SmtpTransportBuilder;
use openssl::bn::BigNum;
use openssl::crypto::hash;
use openssl::crypto::pkey::PKey;
use openssl::crypto::rsa::RSA;
use serde_json::builder::ObjectBuilder;
use serde_json::de::{from_reader, from_slice};
use serde_json::value::Value;
use rand::{OsRng, Rng};
use redis::{Client, Commands, RedisResult};
use router::Router;
use rustc_serialize::base64::{self, FromBase64, ToBase64};
use rustc_serialize::hex::ToHex;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::iter::Iterator;
use time::now_utc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use urlencoded::{QueryMap, UrlEncodedBody, UrlEncodedQuery};


fn json_response(obj: &Value) -> IronResult<Response> {
    let content = serde_json::to_string(&obj).unwrap();
    let mut rsp = Response::with((status::Ok, content));
    rsp.headers.set(ContentType::json());
    Ok(rsp)
}


#[derive(Clone)]
struct ProviderConfig {
    discovery: String,
    client_id: String,
    secret: String,
    issuer: String,
}


#[derive(Clone)]
struct AppConfig {
    version: String,
    base_url: String,
    priv_key: PKey,
    store: Client,
    expire_keys: usize,
    sender: (String, String),
    token_validity: i64,
    providers: BTreeMap<String, ProviderConfig>,
}


impl AppConfig {
    fn from_json_file(file_name: &str) -> AppConfig {

        let config_file = File::open(file_name).unwrap();
        let config_value: Value = from_reader(BufReader::new(config_file)).unwrap();
        let config = config_value.as_object().unwrap();

        let key_file_name = config["private_key_file"].as_string().unwrap();
        let priv_key_file = File::open(key_file_name).unwrap();
        let mut reader = BufReader::new(priv_key_file);
        let sender = config["sender"].as_object().unwrap();
        AppConfig {
            version: env!("CARGO_PKG_VERSION").to_string(),
            base_url: config["base_url"].as_string().unwrap().to_string(),
            priv_key: PKey::private_key_from_pem(&mut reader).unwrap(),
            store: Client::open(config["redis"].as_string().unwrap()).unwrap(),
            expire_keys: config["expire_keys"].as_u64().unwrap() as usize,
            sender: (
                sender["address"].as_string().unwrap().to_string(),
                sender["name"].as_string().unwrap().to_string(),
            ),
            token_validity: config["token_validity"].as_i64().unwrap(),
            providers: config["providers"].as_object().unwrap().iter()
                .map(|(host, params)| {
                    let pobj = params.as_object().unwrap();
                    (host.clone(), ProviderConfig {
                        discovery: pobj["discovery"].as_string().unwrap().to_string(),
                        client_id: pobj["client_id"].as_string().unwrap().to_string(),
                        secret: pobj["secret"].as_string().unwrap().to_string(),
                        issuer: pobj["issuer"].as_string().unwrap().to_string(),
                    })
                })
                .collect::<BTreeMap<String, ProviderConfig>>(),
        }

    }
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


fn oauth_request(app: &AppConfig, params: &QueryMap) -> IronResult<Response> {

    let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]);
    let client_id = &params.get("client_id").unwrap()[0];
    let key = format!("{}:{}", email_addr, client_id);

    let mut rng = OsRng::new().unwrap();
    let mut bytes_iter = rng.gen_iter();
    let rand_bytes: Vec<u8> = (0..128).map(|_| bytes_iter.next().unwrap()).collect();
    let state = hash::hash(hash::Type::SHA256, &rand_bytes).to_hex();

    let _: String = app.store.hset_multiple(key.clone(), &[
        ("state", state.clone()),
        ("redirect", params.get("redirect_uri").unwrap()[0].clone()),
    ]).unwrap();
    let _: bool = app.store.expire(key.clone(), app.expire_keys).unwrap();

    let provider = &app.providers[&email_addr.domain];
    let client = HttpClient::new();
    let discovery_rsp = client.get(&provider.discovery).send().unwrap();
    let discovery: Value = from_reader(discovery_rsp).unwrap();
    let authz_base = discovery.find("authorization_endpoint").unwrap().as_string().unwrap();
    let auth_url = Url::parse(&vec![
        authz_base,
        "?",
        "client_id=",
        &utf8_percent_encode(&provider.client_id, QUERY_ENCODE_SET).to_string(),
        "&response_type=code",
        "&scope=",
        &utf8_percent_encode("openid email", QUERY_ENCODE_SET).to_string(),
        "&redirect_uri=",
        &utf8_percent_encode(&format!("{}/callback", &app.base_url),
                             QUERY_ENCODE_SET).to_string(),
        "&state=",
        &utf8_percent_encode(&format!("{}:{}", key, state), QUERY_ENCODE_SET).to_string(),
        "&login_hint=",
        &utf8_percent_encode(&email_addr.to_string(), QUERY_ENCODE_SET).to_string(),
        "\n",
    ].join("")).unwrap();
    Ok(Response::with((status::Found, modifiers::Redirect(auth_url))))

}


struct AuthHandler { app: AppConfig }
impl Handler for AuthHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let chars: String = (0..6).map(|_| CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]).collect();
        let params = req.get_ref::<UrlEncodedBody>().unwrap();
        let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]);
        if self.app.providers.contains_key(&email_addr.domain) {
            return oauth_request(&self.app, &params);
        }

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
            .from((self.app.sender.0.as_str(), self.app.sender.1.as_str()))
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

struct CallbackHandler { app: AppConfig }
impl Handler for CallbackHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let params = req.get_ref::<UrlEncodedQuery>().unwrap();
        let state: Vec<&str> = params.get("state").unwrap()[0].split(":").collect();
        let email_addr = EmailAddress::new(state[0]);
        let origin = state[1..state.len() - 1].join(":");
        let nonce = state[state.len() - 1];

        let key = format!("{}:{}", state[0], origin);
        let stored: HashMap<String, String> = self.app.store.hgetall(key.clone()).unwrap();
        if stored.get("state").is_none() || nonce != stored.get("state").unwrap() {
            let obj = ObjectBuilder::new()
                .insert("error", "nonce fail")
                .insert("key", key)
                .insert("stored", stored);
            return json_response(&obj.unwrap());
        }

        let client = HttpClient::new();
        let provider = &self.app.providers[&email_addr.domain];
        let discovery_rsp = client.get(&provider.discovery).send().unwrap();
        let discovery: Value = from_reader(discovery_rsp).unwrap();
        let token_url = discovery.find("token_endpoint").unwrap().as_string().unwrap();
        let code = &params.get("code").unwrap()[0];
        let body: String = vec![
            "code=",
            &utf8_percent_encode(code, QUERY_ENCODE_SET).to_string(),
            "&client_id=",
            &utf8_percent_encode(&provider.client_id, QUERY_ENCODE_SET).to_string(),
            "&client_secret=",
            &utf8_percent_encode(&provider.secret, QUERY_ENCODE_SET).to_string(),
            "&redirect_uri=",
            &utf8_percent_encode(&format!("{}/callback", &self.app.base_url),
                                 QUERY_ENCODE_SET).to_string(),
            "&grant_type=authorization_code",
        ].join("");

        let mut headers = Headers::new();
        headers.set(HyContentType::form_url_encoded());
        let token_rsp = client.post(token_url).headers(headers).body(&body).send().unwrap();
        let token_obj: Value = from_reader(token_rsp).unwrap();
        let id_token = token_obj.find("id_token").unwrap().as_string().unwrap();

        let keys_url = discovery.find("jwks_uri").unwrap().as_string().unwrap();
        let keys_rsp = client.get(keys_url).send().unwrap();
        let keys_doc: Value = from_reader(keys_rsp).unwrap();
        let parts: Vec<&str> = id_token.split(".").collect();
        let jwt_header: Value = from_slice(&parts[0].from_base64().unwrap()).unwrap();
        let kid = jwt_header.find("kid").unwrap().as_string().unwrap();
        let keys = keys_doc.find("keys").unwrap().as_array().unwrap().iter()
            .filter(|key_obj| {
                key_obj.find("kid").unwrap().as_string().unwrap() == kid &&
                key_obj.find("use").unwrap().as_string().unwrap() == "sig"
            })
            .collect::<Vec<&Value>>();

        assert!(keys.len() == 1);
        let n_b64 = keys[0].find("n").unwrap().as_string().unwrap();
        let e_b64 = keys[0].find("e").unwrap().as_string().unwrap();
        let n = BigNum::new_from_slice(&n_b64.from_base64().unwrap()).unwrap();
        let e = BigNum::new_from_slice(&e_b64.from_base64().unwrap()).unwrap();
        let mut pub_key = PKey::new();
        pub_key.set_rsa(&RSA::from_public_components(n, e).unwrap());
        let message = format!("{}.{}", parts[0], parts[1]);
        let sha256 = hash::hash(hash::Type::SHA256, &message.as_bytes());
        let sig = parts[2].from_base64().unwrap();
        let verified = pub_key.verify(&sha256, &sig);
        assert!(verified);

        let jwt_payload: Value = from_slice(&parts[1].from_base64().unwrap()).unwrap();
        let iss = jwt_payload.find("iss").unwrap().as_string().unwrap();
        let issuer_origin = vec!["https://", &provider.issuer].join("");
        assert!(iss == provider.issuer || iss == issuer_origin);
        let aud = jwt_payload.find("aud").unwrap().as_string().unwrap();
        assert!(aud == provider.client_id);
        let token_addr = jwt_payload.find("email").unwrap().as_string().unwrap();
        assert!(token_addr == state[0]);
        let now = now_utc().to_timespec().sec;
        let exp = jwt_payload.find("exp").unwrap().as_i64().unwrap();
        assert!(now < exp);

        let redirect = stored.get("redirect").unwrap();
        send_jwt_response(state[0], &origin, redirect, &self.app)

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

    let app = AppConfig::from_json_file(&args[1]);
    let mut router = Router::new();
    router.get("/", WelcomeHandler { app: app.clone() });
    router.get("/.well-known/openid-configuration",
               OIDConfigHandler { app: app.clone() });
    router.get("/keys.json", KeysHandler { app: app.clone() });
    router.post("/auth", AuthHandler { app: app.clone() });
    router.get("/confirm", ConfirmHandler { app: app.clone() });
    router.get("/callback", CallbackHandler { app: app.clone() });
    Iron::new(router).http("0.0.0.0:3333").unwrap();

}
