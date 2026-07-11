// SPDX-License-Identifier: Apache-2.0
//! Registration validation — the security-critical core of the register path.
//!
//! Two guards, both pure and fully testable:
//!  - `validate_intent`  — intent URN format (iicp-core §7 / ADR-007)
//!  - `endpoint_routable` — the RoutableEndpoint invariant (iicp-dir §3.1, IICP-E035):
//!    in production/staging the directory MUST reject endpoints whose host is not
//!    publicly routable (localhost / RFC1918 / link-local / reserved suffix / bare host).
//!  - `is_declared_reachable` — carries the RT-04 fix (#378): `nat_type="unknown"` is the
//!    ABSENCE of a topology assertion and MUST NOT grant a probe bypass.

/// Deployment environment — gates the routability check (dev bypasses it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Env {
    Production,
    Staging,
    Local,
    Testing,
}

impl Env {
    fn enforces_routability(self) -> bool {
        matches!(self, Env::Production | Env::Staging)
    }
}

/// Intent URN: `urn:iicp:intent:<domain>:<action>:v<n>` (lowercase, hyphenated labels ok).
pub fn validate_intent(urn: &str) -> bool {
    let rest = match urn.strip_prefix("urn:iicp:intent:") {
        Some(r) => r,
        None => return false,
    };
    // At least domain:action:vN — 3 colon-separated segments after the prefix.
    let segs: Vec<&str> = rest.split(':').collect();
    if segs.len() < 3 {
        return false;
    }
    // Last segment is the version: v<digits>.
    let ver = segs[segs.len() - 1];
    if !(ver.starts_with('v') && ver.len() > 1 && ver[1..].chars().all(|c| c.is_ascii_digit())) {
        return false;
    }
    // Every other segment is a non-empty [a-z0-9_-] label.
    segs[..segs.len() - 1].iter().all(|s| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum EndpointReject {
    BadScheme,
    NonRoutableHost,
    BareHostname,
    UnresolvableHost,
}

use std::net::{IpAddr, ToSocketAddrs};

/// RoutableEndpoint invariant (iicp-dir §3.1, IICP-E035). In production/staging, reject
/// endpoints whose host is not publicly routable. Local/testing bypasses for dev workflows.
pub fn endpoint_routable(endpoint: &str, env: Env) -> Result<(), EndpointReject> {
    let after_scheme = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))
        .ok_or(EndpointReject::BadScheme)?;

    if !env.enforces_routability() {
        return Ok(());
    }

    // Host = up to the first '/', ':' (port), strip brackets for IPv6.
    let host_port = after_scheme.split('/').next().unwrap_or("");
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port)
        .trim_start_matches('[')
        .trim_end_matches(']');

    if host.is_empty() {
        return Err(EndpointReject::NonRoutableHost);
    }

    let lower = host.to_ascii_lowercase();

    // localhost / loopback / link-local / reserved suffixes
    const RESERVED_SUFFIX: &[&str] = &[
        ".local",
        ".test",
        ".example",
        ".invalid",
        ".lan",
        ".internal",
    ];
    if lower == "localhost"
        || lower == "::1"
        || lower.starts_with("127.")
        || lower.starts_with("169.254.")
        || RESERVED_SUFFIX.iter().any(|s| lower.ends_with(s))
    {
        return Err(EndpointReject::NonRoutableHost);
    }

    // RFC1918 private ranges
    if lower.starts_with("10.")
        || lower.starts_with("192.168.")
        || (lower.starts_with("172.")
            && lower
                .split('.')
                .nth(1)
                .and_then(|o| o.parse::<u8>().ok())
                .is_some_and(|o| (16..=31).contains(&o)))
    {
        return Err(EndpointReject::NonRoutableHost);
    }

    // IPv6 unique-local fc00::/7 (only when it's actually an IPv6 literal)
    if (lower.starts_with("fc") || lower.starts_with("fd")) && lower.contains(':') {
        return Err(EndpointReject::NonRoutableHost);
    }

    // A public IP (has a dot or colon) or an FQDN (has a dot) is fine; a bare hostname is not.
    let is_ip_or_fqdn = lower.contains('.') || lower.contains(':');
    if !is_ip_or_fqdn {
        return Err(EndpointReject::BareHostname);
    }

    // IP literals are validated directly; hostnames are DNS-resolved and checked for only
    // globally routable addresses to reduce DNS-rebinding and SSRF-style bypasses.
    if let Ok(ip) = lower.parse::<IpAddr>() {
        if !is_publicly_routable_ip(&ip) {
            return Err(EndpointReject::NonRoutableHost);
        }
    } else {
        ensure_host_dns_is_public(&lower)?;
    }

    Ok(())
}

fn is_publicly_routable_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_private()
                && !v4.is_loopback()
                && !v4.is_unspecified()
                && !v4.is_link_local()
                && !v4.is_broadcast()
                && !v4.is_multicast()
                && !v4.is_documentation()
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let is_ula = (segments[0] & 0xfe00) == 0xfc00;
            let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
            !v6.is_loopback()
                && !v6.is_unspecified()
                && !v6.is_multicast()
                && !is_ula
                && !is_link_local
        }
    }
}

fn ensure_host_dns_is_public(host: &str) -> Result<(), EndpointReject> {
    let mut found = false;
    for sock in (host, 443)
        .to_socket_addrs()
        .map_err(|_| EndpointReject::UnresolvableHost)?
    {
        found = true;
        if !is_publicly_routable_ip(&sock.ip()) {
            return Err(EndpointReject::NonRoutableHost);
        }
    }
    if found {
        Ok(())
    } else {
        Err(EndpointReject::UnresolvableHost)
    }
}

/// RT-04 (#378): does the registration carry a trustworthy reachability declaration that
/// lets the directory skip the liveness probe? `unknown` is NOT trustworthy — it falls
/// through to a probe. Only a concrete topology + a transport method bypasses.
pub fn is_declared_reachable(nat_type: Option<&str>, transport_method: Option<&str>) -> bool {
    let nat_ok = matches!(nat_type, Some(n) if !n.is_empty() && n != "none" && n != "unknown");
    let transport_ok = matches!(transport_method, Some(t) if !t.is_empty());
    nat_ok && transport_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_accepts_standard_and_custom() {
        assert!(validate_intent("urn:iicp:intent:llm:chat:v1"));
        assert!(validate_intent("urn:iicp:intent:x:acme-corp:thing:v2"));
        assert!(!validate_intent("urn:iicp:intent:llm:chat")); // no version
        assert!(!validate_intent("urn:iicp:intent:LLM:chat:v1")); // uppercase
        assert!(!validate_intent("http://not-a-urn")); // wrong prefix
        assert!(!validate_intent("urn:iicp:intent::chat:v1")); // empty label
    }

    #[test]
    fn routable_rejects_private_and_reserved_in_prod() {
        for bad in [
            "http://localhost:8090",
            "https://127.0.0.1",
            "http://10.0.0.5:8080",
            "http://192.168.1.10",
            "http://172.16.4.4",
            "https://node.local",
            "https://x.test",
            "http://169.254.1.1",
            "https://barehost",
            "https://[fd00::1]:9484",
        ] {
            assert!(
                endpoint_routable(bad, Env::Production).is_err(),
                "should reject {bad}"
            );
        }
    }

    #[test]
    fn routable_accepts_public_in_prod() {
        for ok in ["http://1.1.1.1:8090", "http://8.8.8.8", "https://1.1.1.1"] {
            assert!(
                endpoint_routable(ok, Env::Production).is_ok(),
                "should accept {ok}"
            );
        }
    }

    #[test]
    fn routable_accepts_dns_resolved_hostname_when_available() {
        // Resolution behavior is environment dependent in CI sandboxes; allow either
        // pass or explicit unresolvable failure for the hostname path.
        match endpoint_routable("https://example.com", Env::Production) {
            Ok(_) => {}
            Err(EndpointReject::UnresolvableHost) => {}
            Err(err) => panic!("unexpected hostname validation path: {err:?}"),
        }
    }

    #[test]
    fn routable_bypasses_in_local_env() {
        assert!(endpoint_routable("http://localhost:8090", Env::Local).is_ok());
        assert!(endpoint_routable("http://10.0.0.1", Env::Testing).is_ok());
    }

    #[test]
    fn rt04_unknown_nat_does_not_bypass_probe() {
        // concrete topology + transport → bypass OK
        assert!(is_declared_reachable(
            Some("full_cone"),
            Some("upnp_mapped")
        ));
        // RT-04: 'unknown' must NOT bypass
        assert!(!is_declared_reachable(Some("unknown"), Some("direct")));
        // 'none' / missing → no bypass
        assert!(!is_declared_reachable(Some("none"), Some("direct")));
        assert!(!is_declared_reachable(None, Some("direct")));
        assert!(!is_declared_reachable(Some("full_cone"), None));
    }

    #[test]
    fn routable_rejects_private_resolved_ip_address() {
        assert!(!is_publicly_routable_ip(
            &"10.0.0.5".parse().expect("valid private ip")
        ));
        assert!(!is_publicly_routable_ip(
            &"fd00::1".parse().expect("valid private ip")
        ));
    }
}
