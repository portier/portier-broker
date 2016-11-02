use hyper::header::StrictTransportSecurity;
use iron::middleware::AfterMiddleware;
use iron::modifiers;
use iron::{IronError, IronResult, Request, Response, Set};

header! { (ContentSecurityPolicy, "Content-Security-Policy") => [String] }
header! { (XContentSecurityPolicy, "X-Content-Security-Policy") => [String] }
header! { (XContentTypeOptions, "X-Content-Type-Options") => [String] }
header! { (XXSSProtection, "X-XSS-Protection") => [String] }
header! { (XFrameOptions, "X-Frame-Options") => [String] }

/// Middleware that sets common headers.
pub struct SecurityHeaders;
impl SecurityHeaders {
    fn set_headers(&self, res: &mut Response) {
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
}
impl AfterMiddleware for SecurityHeaders {
    fn after(&self, _: &mut Request, mut res: Response) -> IronResult<Response> {
        self.set_headers(&mut res);
        Ok(res)
    }
    fn catch(&self, _: &mut Request, mut err: IronError) -> IronResult<Response> {
        self.set_headers(&mut err.response);
        Err(err)
    }
}
