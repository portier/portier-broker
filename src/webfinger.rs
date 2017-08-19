use config::Config;
use email_address::EmailAddress;
use error::BrokerError;
use futures::future::{self, Future};
use std::error::Error;
use std::rc::Rc;
use store_cache::{CacheKey, fetch_json_url};
use url::Url;


// Our relation string in WebFinger
const WEBFINGER_PORTIER_REL: &'static str = "https://portier.io/specs/auth/1.0/idp";


/// Query WebFinger for the given email address
///
/// This queries the WebFinger endpoint of the domain for the given email
/// address. The resource queried is the email address itself, as an `acct` URL.
/// Request failures of any kind simply result in an empty list.
pub fn query(app: &Rc<Config>, email_addr: &Rc<EmailAddress>)
    -> Box<Future<Item=Vec<Url>, Error=BrokerError>> {

    // Build the WebFinger query URL. We can safely do string concatenation here, because the
    // domain has already been validated using the `url` crate.
    #[cfg(feature = "insecure")]
    let url = format!("http://{}/.well-known/webfinger", email_addr.domain());
    #[cfg(not(feature = "insecure"))]
    let url = format!("https://{}/.well-known/webfinger", email_addr.domain());

    let result = Url::parse_with_params(&url, &[
        ("resource", format!("acct:{}", email_addr).as_str()),
        ("rel", WEBFINGER_PORTIER_REL),
    ]).map_err(|e| BrokerError::Internal(
        format!("could not build query url: {}", e.description())));
    let f = future::result(result);

    // Make the request.
    let app = app.clone();
    let email_addr2 = email_addr.clone();
    let f = f.and_then(move |url| {
        let acct = email_addr2.as_str();
        fetch_json_url(&app, url, &CacheKey::Discovery { acct })
    });

    let f = f.map(|value| {
        value.get("links").and_then(|val| val.as_array())
            .map_or_else(|| vec![], |links| {
                links.iter()
                    // Filter on the Portier relation.
                    .filter(|link| {
                        let opt = link.get("rel").and_then(|val| val.as_str());
                        opt == Some(WEBFINGER_PORTIER_REL)
                    })
                    // Extract all endpoints, parse the URLs.
                    .filter_map(|link| {
                        link.get("href")
                            .and_then(|val| val.as_str())
                            .ok_or(())
                            .and_then(|href| href.parse().map_err(|_| ()))
                            .ok()
                    })
                    .collect()
            })
    });

    // Accept all provider failures, and simply return an empty list.
    let email_addr = email_addr.clone();
    let f = f.or_else(move |err| {
        match err {
            BrokerError::Provider(_) => {
                info!("query failed for {}: {}", email_addr, err);
                future::ok(vec![])
            },
            err => {
                future::err(err)
            },
        }
    });

    Box::new(f)
}
