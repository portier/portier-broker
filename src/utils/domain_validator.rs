use std::{
    collections::HashSet,
    io,
    net::{IpAddr, ToSocketAddrs},
    time::Duration,
};
use thiserror::Error;
use trust_dns_resolver::{
    config::{LookupIpStrategy, NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    proto::{error::ProtoError, rr::rdata::MX},
    Name, TokioAsyncResolver,
};

use crate::metrics;

/// Errors produced by `DomainValidator::validate`.
#[derive(Debug, Error)]
pub enum DomainValidationError {
    #[error("invalid domain name: {0}")]
    Invalid(ProtoError),
    #[error("the domain is blocked")]
    Blocked,
    #[error("the domain indicated it does not accept mail")]
    NullMx,
    #[error("could not resolve the domain mail servers")]
    NoServers,
    #[error("none of the domain mail servers have public IP addresses")]
    NoPublicIps,
}

impl DomainValidationError {
    /// Count this error in metrics.
    pub fn apply_metric(&self) {
        match self {
            Self::Invalid(_) => metrics::DOMAIN_VALIDATION_INVALID_NAME.inc(),
            Self::Blocked => metrics::DOMAIN_VALIDATION_BLOCKED.inc(),
            Self::NullMx => metrics::DOMAIN_VALIDATION_NULL_MX.inc(),
            Self::NoServers => metrics::DOMAIN_VALIDATION_NO_SERVERS.inc(),
            Self::NoPublicIps => metrics::DOMAIN_VALIDATION_NO_PUBLIC_IPS.inc(),
        }
    }
}

/// Validates domains based on some configuration.
pub struct DomainValidator {
    /// Exact domains to allow.
    allowed_domains: HashSet<Name>,
    /// Exact domains to block.
    blocked_domains: HashSet<Name>,
    /// DNS resolver for email domain validation.
    dns_resolver: Option<TokioAsyncResolver>,
    /// Whether to ignore reserved IP addresses in DNS results.
    pub verify_public_ip: bool,
    /// Whether to treat anything not in the allow-list as blocked.
    pub allowed_domains_only: bool,
}

impl DomainValidator {
    pub fn new() -> Self {
        Self {
            allowed_domains: HashSet::new(),
            blocked_domains: HashSet::new(),
            dns_resolver: None,
            verify_public_ip: true,
            allowed_domains_only: false,
        }
    }

    /// Add a domain to the set of allowed domains.
    pub fn add_allowed_domain(&mut self, domain: &str) -> Result<(), ProtoError> {
        let mut domain = Name::from_utf8(domain)?.to_lowercase();
        domain.set_fqdn(true);
        self.allowed_domains.insert(domain);
        Ok(())
    }

    /// Add a domain to the set of blocked domains.
    pub fn add_blocked_domain(&mut self, domain: &str) -> Result<(), ProtoError> {
        let mut domain = Name::from_utf8(domain)?.to_lowercase();
        domain.set_fqdn(true);
        self.blocked_domains.insert(domain);
        Ok(())
    }

    /// Set the DNS resolver for email domain validation.
    pub fn set_resolver(&mut self, addr: Option<&str>) -> Result<(), io::Error> {
        let addr = match addr {
            Some(addr) => addr,
            None => {
                self.dns_resolver = None;
                return Ok(());
            }
        };

        let mut cfg = ResolverConfig::new();
        for socket_addr in addr.to_socket_addrs()? {
            cfg.add_name_server(NameServerConfig {
                socket_addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_nx_responses: true,
                bind_addr: None,
            });
        }

        let mut opts = ResolverOpts::default();
        // Email domains must always be FQDNs.
        opts.ndots = 0;
        // Tighter timeouts and retries, because we're handling a user agent request.
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 1;
        // Trust the server, don't do DNSSEC ourselves.
        opts.validate = false;
        // Assume mail servers still require IPv4, so try query only A-records first.
        // This creates an edge case with `verify_public_ip`, where the mail server only has
        // private IPv4, but public IPv6, yet we fail. We consider this extremely unlikely.
        opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
        // Leave all caching to the server.
        opts.cache_size = 0;
        // Per our config docs, using `/etc/hosts` would be surprising behaviour.
        opts.use_hosts_file = false;

        // Unwrap, because this currently doesn't appear to fail ever.
        self.dns_resolver = Some(TokioAsyncResolver::tokio(cfg, opts).unwrap());
        Ok(())
    }

    /// Validate a domain.
    pub async fn validate(&self, domain: &str) -> Result<(), DomainValidationError> {
        // Use trust-dns to do domain name validation. This does the punycode transform for us, as
        // well as validating there are no invalid characters or empty labels.
        let mut domain = Name::from_utf8(domain)
            .map_err(DomainValidationError::Invalid)?
            .to_lowercase();
        // Mark as FQDN. (It's likely the domain did not contain a trailing dot.)
        domain.set_fqdn(true);

        // Short-circuit for allow/block-lists.
        if self.allowed_domains.contains(&domain) {
            return Ok(());
        }
        if self.allowed_domains_only || self.blocked_domains.contains(&domain) {
            return Err(DomainValidationError::Blocked);
        }

        // Validate with a resolver if requested.
        if let Some(ref resolver) = self.dns_resolver {
            // Start with just an MX lookup. The spec allows just A/AAAA records, but it's very
            // likely a real mail domain has MX records.
            let res = resolver.mx_lookup(domain.clone()).await;
            let mut has_mx = false;
            let mail_servers: Vec<&Name> = match res {
                Ok(ref mx) => {
                    has_mx = true;
                    // Answers should always be FQDNs. We also ignore priority.
                    mx.iter()
                        .map(MX::exchange)
                        .filter(|name| name.is_fqdn())
                        .collect()
                }
                Err(err) => {
                    log::debug!(
                        "Falling back to A/AAAA lookup for domain '{}', because MX lookup failed: {}",
                        domain,
                        err
                    );
                    vec![&domain]
                }
            };

            // Check for a null MX record.
            if mail_servers.len() == 1 && mail_servers[0].is_root() {
                return Err(DomainValidationError::NullMx);
            }

            // If we didn't find an MX record, do a regular IP lookup of the domain itself. Also do
            // an IP lookup of mail servers if config is set to allow only public IP addresses.
            if !has_mx || self.verify_public_ip {
                let mut ok = false;
                let mut has_private_ips = false;
                for server in mail_servers {
                    match resolver.lookup_ip(server.clone()).await {
                        Ok(_) if !self.verify_public_ip => ok = true,
                        Ok(ref ips) => {
                            // TODO: Once stabilized, see: https://github.com/rust-lang/rust/issues/27709
                            // In fact, we currently cannot check for IPv6 private address space. :(
                            //ok = ips.iter().any(|ip| match ip {
                            //    IpAddr::V4(ip) => ip.is_global(),
                            //    IpAddr::V6(ip) => ip.is_unicast_global(),
                            //});
                            ok = ips.iter().any(|ip| match ip {
                                IpAddr::V4(ip) => {
                                    !ip.is_private()
                                        && !ip.is_loopback()
                                        && !ip.is_link_local()
                                        && !ip.is_broadcast()
                                        && !ip.is_documentation()
                                        && !ip.is_multicast()
                                        && !ip.is_unspecified()
                                }
                                IpAddr::V6(ip) => {
                                    !ip.is_multicast() && !ip.is_loopback() && !ip.is_unspecified()
                                }
                            });
                            if !ok {
                                has_private_ips = true;
                            }
                        }
                        Err(err) => {
                            log::debug!(
                                "Could not resolve mail server '{}' for domain '{}': {}",
                                server,
                                domain,
                                err
                            );
                        }
                    }
                    if ok {
                        break;
                    }
                }
                if !ok {
                    return Err(if has_private_ips {
                        DomainValidationError::NoPublicIps
                    } else {
                        DomainValidationError::NoServers
                    });
                }
            }
        }

        Ok(())
    }
}
