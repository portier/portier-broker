use prometheus::{
    register_histogram, register_int_counter, register_int_counter_vec, Histogram, IntCounter,
    IntCounterVec,
};

lazy_static::lazy_static! {
    pub static ref HTTP_CONNECTIONS: IntCounter = register_int_counter!(
        "portier_http_connections",
        "Number of HTTP connections accepted"
    ).unwrap();

    pub static ref HTTP_REQUESTS: IntCounter = register_int_counter!(
        "portier_http_requests",
        "Number of HTTP requests processed"
    ).unwrap();

    pub static ref HTTP_RESPONSE_STATUS: IntCounterVec = register_int_counter_vec!(
        "portier_http_response_status",
        "Number of HTTP responses by status category",
        &["code"]
    ).unwrap();
    pub static ref HTTP_RESPONSE_STATUS_1XX: IntCounter =
        HTTP_RESPONSE_STATUS.with_label_values(&["1xx"]);
    pub static ref HTTP_RESPONSE_STATUS_2XX: IntCounter =
        HTTP_RESPONSE_STATUS.with_label_values(&["2xx"]);
    pub static ref HTTP_RESPONSE_STATUS_3XX: IntCounter =
        HTTP_RESPONSE_STATUS.with_label_values(&["3xx"]);
    pub static ref HTTP_RESPONSE_STATUS_4XX: IntCounter =
        HTTP_RESPONSE_STATUS.with_label_values(&["4xx"]);
    pub static ref HTTP_RESPONSE_STATUS_5XX: IntCounter =
        HTTP_RESPONSE_STATUS.with_label_values(&["5xx"]);

    pub static ref AUTH_LIMITED: IntCounter = register_int_counter!(
        "portier_auth_limited",
        "Number of rate-limited authentication requests"
    ).unwrap();

    pub static ref AUTH_REQUESTS: IntCounter = register_int_counter!(
        "portier_auth_requests",
        "Number of authentication requests"
    ).unwrap();

    pub static ref AUTH_WEBFINGER_DURATION: Histogram = register_histogram!(
        "portier_auth_webfinger_duration",
        "Latency of outgoing Webfinger requests."
    ).unwrap();

    pub static ref AUTH_EMAIL_REQUESTS: IntCounter = register_int_counter!(
        "portier_auth_email_requests",
        "Number of authentication requests that used email"
    ).unwrap();

    pub static ref AUTH_EMAIL_SEND_DURATION: Histogram = register_histogram!(
        "portier_auth_email_send_duration",
        "Latency of sending email"
    ).unwrap();

    pub static ref AUTH_EMAIL_COMPLETED: IntCounter = register_int_counter!(
        "portier_auth_email_completed",
        "Number of successful email authentications"
    ).unwrap();

    pub static ref AUTH_EMAIL_CODE_INCORRECT: IntCounter = register_int_counter!(
        "portier_auth_email_code_incorrect",
        "Number of email confirmation attempts with an invalid code"
    ).unwrap();

    pub static ref AUTH_OIDC_REQUESTS: IntCounterVec = register_int_counter_vec!(
        "portier_auth_oidc_requests",
        "Number of authentication requests that used OpenID Connect",
        &["rel"]
    ).unwrap();
    pub static ref AUTH_OIDC_REQUESTS_PORTIER: IntCounter =
        AUTH_OIDC_REQUESTS.with_label_values(&["portier"]);
    pub static ref AUTH_OIDC_REQUESTS_GOOGLE: IntCounter =
        AUTH_OIDC_REQUESTS.with_label_values(&["google"]);

    pub static ref AUTH_OIDC_FETCH_CONFIG_DURATION: Histogram = register_histogram!(
        "portier_auth_oidc_fetch_config_duration",
        "Latency of outgoing requests for OpenID Connect configuration documents"
    ).unwrap();

    pub static ref AUTH_OIDC_FETCH_JWKS_DURATION: Histogram = register_histogram!(
        "portier_auth_oidc_fetch_jwks_duration",
        "Latency of outgoing requests for OpenID Connect JWKs"
    ).unwrap();

    pub static ref AUTH_OIDC_COMPLETED: IntCounter = register_int_counter!(
        "portier_auth_oidc_completed",
        "Number of successful OpenID Connect authentications"
    ).unwrap();

    pub static ref DOMAIN_VALIDATION_ERROR: IntCounterVec = register_int_counter_vec!(
        "portier_domain_validation_error",
        "Number of authentication requests for invalid domains",
        &["reason"]
    ).unwrap();
    pub static ref DOMAIN_VALIDATION_INVALID_NAME: IntCounter =
        DOMAIN_VALIDATION_ERROR.with_label_values(&["invalid_name"]);
    pub static ref DOMAIN_VALIDATION_BLOCKED: IntCounter =
        DOMAIN_VALIDATION_ERROR.with_label_values(&["blocked"]);
    pub static ref DOMAIN_VALIDATION_NULL_MX: IntCounter =
        DOMAIN_VALIDATION_ERROR.with_label_values(&["null_mx"]);
    pub static ref DOMAIN_VALIDATION_NO_SERVERS: IntCounter =
        DOMAIN_VALIDATION_ERROR.with_label_values(&["no_servers"]);
    pub static ref DOMAIN_VALIDATION_NO_PUBLIC_IPS: IntCounter =
        DOMAIN_VALIDATION_ERROR.with_label_values(&["no_public_ips"]);
}
