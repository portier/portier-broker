use iron::middleware::Handler;
use iron::prelude::{IronResult, Request, Response};
use serde_json::builder::ObjectBuilder;
use AppConfig;
use super::{json_big_num, json_response};

/// Iron handler for the JSON Web Key Set document.
///
/// Currently only supports a single RSA key (as configured), which is
/// published with the `"base"` key ID, scoped to signing usage. Relying
/// Parties will need to fetch this data to be able to verify identity tokens
/// issued by this daemon instance.
pub struct Keys { pub app: AppConfig }
impl Handler for Keys {
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
