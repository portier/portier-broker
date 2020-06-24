use http::{header::HeaderName, Request};
use ipnetwork::IpNetwork;
use std::{
    iter::once,
    net::{IpAddr, SocketAddr},
};

lazy_static::lazy_static! {
    static ref X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
}

/// Get the real IP-address of the client.
///
/// This takes the socket address, the HTTP request, and a list of configured proxies to trust.
/// Walks the path indicated by `X-Forwarded-For` until it finds the first non-proxy IP address.
pub fn real_ip<B>(received_from: SocketAddr, req: &Request<B>, trusted: &[IpNetwork]) -> IpAddr {
    let received_from = received_from.ip();
    let list = req
        .headers()
        .get(&*X_FORWARDED_FOR)
        .and_then(|input| input.to_str().ok())
        .and_then(|input| {
            input
                .rsplit(',')
                .map(|ip| ip.trim().parse())
                .collect::<Result<_, _>>()
                .ok()
        })
        .unwrap_or_else(|| vec![]);

    let mut iter = once(received_from).chain(list).peekable();
    loop {
        let ip = iter.next().unwrap();
        if iter.peek().is_none() || !trusted.iter().any(|net| net.contains(ip)) {
            return ip;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{real_ip, X_FORWARDED_FOR};
    use http::header::HeaderValue;
    use std::net::IpAddr;

    #[test]
    fn test_no_header() {
        test_one("10.0.1.1:1234", "", &[], "10.0.1.1");
        test_one("10.0.1.1:1234", "", &["10.0.2.1"], "10.0.1.1");
        test_one("10.0.1.1:1234", "", &["10.0.2.1/24"], "10.0.1.1");
        test_one("10.0.1.1:1234", "", &["10.0.1.1"], "10.0.1.1");
        test_one("10.0.1.1:1234", "", &["10.0.1.1/32"], "10.0.1.1");
        test_one("10.0.1.1:1234", "", &["10.0.1.1/24"], "10.0.1.1");
        test_one("10.0.1.1:1234", "", &["0.0.0.0/0"], "10.0.1.1");
    }

    #[test]
    fn test_single_level() {
        test_one("10.0.1.1:1234", "10.0.2.1", &[], "10.0.1.1");
        test_one("10.0.1.1:1234", "10.0.2.1", &["10.0.2.1"], "10.0.1.1");
        test_one("10.0.1.1:1234", "10.0.2.1", &["10.0.2.1/24"], "10.0.1.1");
        test_one("10.0.1.1:1234", "10.0.2.1", &["10.0.1.1"], "10.0.2.1");
        test_one("10.0.1.1:1234", "10.0.2.1", &["10.0.1.1/32"], "10.0.2.1");
        test_one("10.0.1.1:1234", "10.0.2.1", &["10.0.1.1/24"], "10.0.2.1");
        test_one("10.0.1.1:1234", "10.0.2.1", &["0.0.0.0/0"], "10.0.2.1");
    }

    #[test]
    fn test_multi_level() {
        test_one(
            "10.0.1.1:1234",
            "10.0.3.1, 10.0.2.1",
            &["10.0.2.1"],
            "10.0.1.1",
        );
        test_one(
            "10.0.1.1:1234",
            "10.0.3.1, 10.0.2.1",
            &["10.0.1.1"],
            "10.0.2.1",
        );
        test_one(
            "10.0.1.1:1234",
            "10.0.3.1, 10.0.2.1",
            &["10.0.1.1", "10.0.2.1"],
            "10.0.3.1",
        );
        test_one(
            "10.0.1.1:1234",
            "10.0.3.1, 10.0.2.1",
            &["10.0.1.1", "10.0.2.1", "10.0.3.1"],
            "10.0.3.1",
        );
        test_one(
            "10.0.1.1:1234",
            "10.0.3.1, 10.0.2.1",
            &["0.0.0.0/0"],
            "10.0.3.1",
        );
    }

    #[test]
    fn test_v6() {
        test_one("[fc00::1:1]:1234", "fc00::2:1", &["fc00::1:1"], "fc00::2:1");
        test_one(
            "[fc00::1:1]:1234",
            "fc00::2:1",
            &["fc00::1:1/128"],
            "fc00::2:1",
        );
        test_one("[fc00::1:1]:1234", "fc00::2:1", &["::/0"], "fc00::2:1");

        test_one("[fc00::1:1]:1234", "10.0.2.1", &["fc00::1:1"], "10.0.2.1");
        test_one("[fc00::1:1]:1234", "10.0.2.1", &["::/0"], "10.0.2.1");
        test_one("[fc00::1:1]:1234", "10.0.2.1", &["0.0.0.0/0"], "fc00::1:1");

        test_one("10.0.1.1:1234", "fc00::2:1", &["10.0.1.1"], "fc00::2:1");
        test_one("10.0.1.1:1234", "fc00::2:1", &["0.0.0.0/0"], "fc00::2:1");
        test_one("10.0.1.1:1234", "fc00::2:1", &["::/0"], "10.0.1.1");
    }

    fn test_one(received_from: &str, header: &'static str, trusted: &[&str], expect: &str) {
        let received_from = received_from.parse().unwrap();
        let expect: IpAddr = expect.parse().unwrap();
        let trusted: Vec<_> = trusted.iter().map(|net| net.parse().unwrap()).collect();

        let mut req = http::Request::new(());
        if header != "" {
            req.headers_mut()
                .insert(&*X_FORWARDED_FOR, HeaderValue::from_static(header));
        }

        let ip = real_ip(received_from, &req, &trusted);
        assert_eq!(ip, expect);
    }
}
