use std::{
    fmt,
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

pub static HTTP_CONNECTIONS: Counter = Counter::new();
pub static HTTP_REQUESTS: Counter = Counter::new();

pub static HTTP_RESPONSE_STATUS_1XX: Counter = Counter::new();
pub static HTTP_RESPONSE_STATUS_2XX: Counter = Counter::new();
pub static HTTP_RESPONSE_STATUS_3XX: Counter = Counter::new();
pub static HTTP_RESPONSE_STATUS_4XX: Counter = Counter::new();
pub static HTTP_RESPONSE_STATUS_5XX: Counter = Counter::new();

pub static AUTH_LIMITED: Counter = Counter::new();
pub static AUTH_REQUESTS: Counter = Counter::new();

pub static AUTH_WEBFINGER_DURATION: Histogram = Histogram::new();

pub static AUTH_EMAIL_REQUESTS: Counter = Counter::new();
pub static AUTH_EMAIL_SEND_DURATION: Histogram = Histogram::new();

pub static AUTH_EMAIL_COMPLETED: Counter = Counter::new();
pub static AUTH_EMAIL_CODE_INCORRECT: Counter = Counter::new();

pub static AUTH_OIDC_REQUESTS_PORTIER: Counter = Counter::new();
pub static AUTH_OIDC_REQUESTS_GOOGLE: Counter = Counter::new();
pub static AUTH_OIDC_FETCH_CONFIG_DURATION: Histogram = Histogram::new();
pub static AUTH_OIDC_FETCH_JWKS_DURATION: Histogram = Histogram::new();
pub static AUTH_OIDC_COMPLETED: Counter = Counter::new();

pub static DOMAIN_VALIDATION_INVALID_NAME: Counter = Counter::new();
pub static DOMAIN_VALIDATION_BLOCKED: Counter = Counter::new();
pub static DOMAIN_VALIDATION_NULL_MX: Counter = Counter::new();
pub static DOMAIN_VALIDATION_NO_SERVERS: Counter = Counter::new();
pub static DOMAIN_VALIDATION_NO_PUBLIC_IPS: Counter = Counter::new();

pub fn write_metrics(w: &mut impl fmt::Write) -> Result<(), fmt::Error> {
    fn header(
        w: &mut impl fmt::Write,
        name: &str,
        kind: &str,
        help: &str,
    ) -> Result<(), fmt::Error> {
        writeln!(w, "# HELP {name} {help}")?;
        writeln!(w, "# TYPE {name} {kind}")?;
        Ok(())
    }

    fn header_and_metric(
        w: &mut impl fmt::Write,
        name: &str,
        kind: &str,
        help: &str,
        metric: &impl Metric,
    ) -> Result<(), fmt::Error> {
        header(w, name, kind, help)?;
        metric.format(w, name)
    }

    header_and_metric(
        w,
        "portier_http_connections",
        "counter",
        "Number of HTTP connections accepted.",
        &HTTP_CONNECTIONS,
    )?;
    header_and_metric(
        w,
        "portier_http_requests",
        "counter",
        "Number of HTTP requests processed.",
        &HTTP_REQUESTS,
    )?;
    header(
        w,
        "portier_http_response_status",
        "counter",
        "Number of HTTP responses by status category.",
    )?;
    HTTP_RESPONSE_STATUS_1XX.format(w, "portier_http_response_status{code=\"1xx\"}")?;
    HTTP_RESPONSE_STATUS_2XX.format(w, "portier_http_response_status{code=\"2xx\"}")?;
    HTTP_RESPONSE_STATUS_3XX.format(w, "portier_http_response_status{code=\"3xx\"}")?;
    HTTP_RESPONSE_STATUS_4XX.format(w, "portier_http_response_status{code=\"4xx\"}")?;
    HTTP_RESPONSE_STATUS_5XX.format(w, "portier_http_response_status{code=\"5xx\"}")?;

    header_and_metric(
        w,
        "portier_auth_limited",
        "counter",
        "Number of rate-limited authentication requests.",
        &AUTH_LIMITED,
    )?;
    header_and_metric(
        w,
        "portier_auth_requests",
        "counter",
        "Number of authentication requests.",
        &AUTH_REQUESTS,
    )?;

    header_and_metric(
        w,
        "portier_auth_webfinger_duration",
        "histogram",
        "Latency of outgoing Webfinger requests.",
        &AUTH_WEBFINGER_DURATION,
    )?;

    header_and_metric(
        w,
        "portier_auth_email_requests",
        "counter",
        "Number of authentication requests that used email.",
        &AUTH_EMAIL_REQUESTS,
    )?;
    header_and_metric(
        w,
        "portier_auth_email_send_duration",
        "histogram",
        "Latency of sending email.",
        &AUTH_EMAIL_SEND_DURATION,
    )?;
    header_and_metric(
        w,
        "portier_auth_email_completed",
        "counter",
        "Number of successful email authentications.",
        &AUTH_EMAIL_COMPLETED,
    )?;
    header_and_metric(
        w,
        "portier_auth_email_code_incorrect",
        "counter",
        "Number of email confirmation attempts with an invalid code.",
        &AUTH_EMAIL_CODE_INCORRECT,
    )?;

    header(
        w,
        "portier_auth_oidc_requests",
        "counter",
        "Number of authentication requests that used OpenID Connect.",
    )?;
    AUTH_OIDC_REQUESTS_PORTIER.format(w, "portier_auth_oidc_requests{rel=\"portier\"}")?;
    AUTH_OIDC_REQUESTS_GOOGLE.format(w, "portier_auth_oidc_requests{rel=\"google\"}")?;
    header_and_metric(
        w,
        "portier_auth_oidc_fetch_config_duration",
        "histogram",
        "Latency of outgoing requests for OpenID Connect configuration documents.",
        &AUTH_OIDC_FETCH_CONFIG_DURATION,
    )?;
    header_and_metric(
        w,
        "portier_auth_oidc_fetch_jwks_duration",
        "histogram",
        "Latency of outgoing requests for OpenID Connect JWKs.",
        &AUTH_OIDC_FETCH_JWKS_DURATION,
    )?;
    header_and_metric(
        w,
        "portier_auth_oidc_completed",
        "counter",
        "Number of successful OpenID Connect authentications.",
        &AUTH_OIDC_COMPLETED,
    )?;

    header(
        w,
        "portier_domain_validation_error",
        "counter",
        "Number of authentication requests for invalid domains.",
    )?;
    DOMAIN_VALIDATION_INVALID_NAME.format(
        w,
        "portier_domain_validation_error{reason=\"invalid_name\"}",
    )?;
    DOMAIN_VALIDATION_BLOCKED.format(w, "portier_domain_validation_error{reason=\"blocked\"}")?;
    DOMAIN_VALIDATION_NULL_MX.format(w, "portier_domain_validation_error{reason=\"null_mx\"}")?;
    DOMAIN_VALIDATION_NO_SERVERS
        .format(w, "portier_domain_validation_error{reason=\"no_servers\"}")?;
    DOMAIN_VALIDATION_NO_PUBLIC_IPS.format(
        w,
        "portier_domain_validation_error{reason=\"no_public_ips\"}",
    )?;

    Ok(())
}

trait Metric {
    fn format(&self, w: &mut impl fmt::Write, name: &str) -> Result<(), fmt::Error>;
}

pub struct Counter(AtomicU64);
impl Counter {
    pub const fn new() -> Counter {
        Counter(AtomicU64::new(0))
    }
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}
impl Metric for Counter {
    fn format(&self, w: &mut impl fmt::Write, name: &str) -> Result<(), fmt::Error> {
        writeln!(w, "{name} {}", self.0.load(Ordering::Relaxed))
    }
}

pub struct Histogram(RwLock<HistogramInner>);
struct HistogramInner {
    le_5: u64,
    le_10: u64,
    le_25: u64,
    le_50: u64,
    le_100: u64,
    le_250: u64,
    le_500: u64,
    le_1000: u64,
    le_2500: u64,
    le_5000: u64,
    le_10000: u64,
    sum: Duration,
    count: u64,
}
impl Histogram {
    pub const fn new() -> Histogram {
        Histogram(RwLock::new(HistogramInner {
            le_5: 0,
            le_10: 0,
            le_25: 0,
            le_50: 0,
            le_100: 0,
            le_250: 0,
            le_500: 0,
            le_1000: 0,
            le_2500: 0,
            le_5000: 0,
            le_10000: 0,
            sum: Duration::ZERO,
            count: 0,
        }))
    }
    pub fn record(&self, time: Duration) {
        let mut inner = self.0.write().unwrap();
        if time <= Duration::from_millis(5) {
            inner.le_5 += 1;
        }
        if time <= Duration::from_millis(10) {
            inner.le_10 += 1;
        }
        if time <= Duration::from_millis(25) {
            inner.le_25 += 1;
        }
        if time <= Duration::from_millis(50) {
            inner.le_50 += 1;
        }
        if time <= Duration::from_millis(100) {
            inner.le_100 += 1;
        }
        if time <= Duration::from_millis(250) {
            inner.le_250 += 1;
        }
        if time <= Duration::from_millis(500) {
            inner.le_500 += 1;
        }
        if time <= Duration::from_millis(1000) {
            inner.le_1000 += 1;
        }
        if time <= Duration::from_millis(2500) {
            inner.le_2500 += 1;
        }
        if time <= Duration::from_millis(5000) {
            inner.le_5000 += 1;
        }
        if time <= Duration::from_millis(10000) {
            inner.le_10000 += 1;
        }
        inner.sum += time;
        inner.count += 1;
    }
    pub fn start_timer(&self) -> HistogramTimer<'_> {
        HistogramTimer {
            inner: self,
            start: Instant::now(),
        }
    }
}
impl Metric for Histogram {
    fn format(&self, w: &mut impl fmt::Write, name: &str) -> Result<(), fmt::Error> {
        let inner = self.0.read().unwrap();
        writeln!(w, "{name}_bucket{{le=\"0.005\"}} {}", inner.le_5)?;
        writeln!(w, "{name}_bucket{{le=\"0.01\"}} {}", inner.le_10)?;
        writeln!(w, "{name}_bucket{{le=\"0.025\"}} {}", inner.le_25)?;
        writeln!(w, "{name}_bucket{{le=\"0.05\"}} {}", inner.le_50)?;
        writeln!(w, "{name}_bucket{{le=\"0.1\"}} {}", inner.le_100)?;
        writeln!(w, "{name}_bucket{{le=\"0.25\"}} {}", inner.le_250)?;
        writeln!(w, "{name}_bucket{{le=\"0.5\"}} {}", inner.le_500)?;
        writeln!(w, "{name}_bucket{{le=\"1\"}} {}", inner.le_1000)?;
        writeln!(w, "{name}_bucket{{le=\"2.5\"}} {}", inner.le_2500)?;
        writeln!(w, "{name}_bucket{{le=\"5\"}} {}", inner.le_5000)?;
        writeln!(w, "{name}_bucket{{le=\"10\"}} {}", inner.le_10000)?;
        writeln!(w, "{name}_bucket{{le=\"+Inf\"}} {}", inner.count)?;
        writeln!(
            w,
            "{name}_sum {}.{:09}",
            inner.sum.as_secs(),
            inner.sum.subsec_nanos()
        )?;
        writeln!(w, "{name}_count {}", inner.count)?;
        Ok(())
    }
}

pub struct HistogramTimer<'a> {
    inner: &'a Histogram,
    start: Instant,
}
impl HistogramTimer<'_> {
    pub fn observe_duration(self) {
        self.inner.record(Instant::now().duration_since(self.start));
    }
}
