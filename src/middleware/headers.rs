use hyper::header::StrictTransportSecurity;
use iron::middleware::AfterMiddleware;
use iron::modifiers;
use iron::{IronError, IronResult, Request, Response, Set};

header! { (ContentSecurityPolicy, "Content-Security-Policy") => [String] }
header! { (XContentSecurityPolicy, "X-Content-Security-Policy") => [String] }
header! { (XContentTypeOptions, "X-Content-Type-Options") => [String] }
header! { (XXSSProtection, "X-XSS-Protection") => [String] }
header! { (XFrameOptions, "X-Frame-Options") => [String] }

/// Middleware that enforces common security headers on all outgoing responses.
pub struct SecurityHeaders;

impl AfterMiddleware for SecurityHeaders {
    fn after(&self, _: &mut Request, mut res: Response) -> IronResult<Response> {
        set_headers(&mut res);
        Ok(res)
    }

    fn catch(&self, _: &mut Request, mut err: IronError) -> IronResult<Response> {
        set_headers(&mut err.response);
        Err(err)
    }
}

/// Mutate an `iron::Response` to set common security headers.
fn set_headers(res: &mut Response) {
    // Specify a tight content security policy. We need to be able to POST
    // redirect anywhere, and run our own inline scripts.
    let csp = vec![
        "sandbox allow-scripts allow-forms",
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "form-action *",
    ].join("; ");

    res.set_mut((modifiers::Header(StrictTransportSecurity::excluding_subdomains(31536000u64)),
                 modifiers::Header(ContentSecurityPolicy(csp.clone())),
                 modifiers::Header(XContentSecurityPolicy(csp)),
                 modifiers::Header(XContentTypeOptions("nosniff".to_string())),
                 modifiers::Header(XXSSProtection("1; mode=block".to_string())),
                 modifiers::Header(XFrameOptions("DENY".to_string()))));
}

#[cfg(test)]
mod tests {
    use iron::Response;
    use super::set_headers;

    #[test]
    fn sets_expected_headers() {
        let mut res = Response::new();
        set_headers(&mut res);

        assert!(res.headers.get_raw("Strict-Transport-Security").is_some());
        assert!(res.headers.get_raw("Content-Security-Policy").is_some());
        assert!(res.headers.get_raw("X-Content-Security-Policy").is_some());
        assert!(res.headers.get_raw("X-Content-Type-Options").is_some());
        assert!(res.headers.get_raw("X-XSS-Protection").is_some());
        assert!(res.headers.get_raw("X-Frame-Options").is_some());
    }
}
