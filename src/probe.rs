// SPDX-License-Identifier: Apache-2.0

//! SSRF-guarded directory reachability probe.

use std::net::ToSocketAddrs;
use std::time::Duration;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::Json;

#[derive(Debug, serde::Deserialize)]
pub(crate) struct ProbeParams {
    #[serde(default)]
    host: String,
    #[serde(default)]
    port: u16,
}

/// `GET /v1/probe` — SSRF-guarded node reachability check.
pub(crate) async fn probe_node(
    Query(params): Query<ProbeParams>,
) -> (StatusCode, Json<serde_json::Value>) {
    let host = params.host.trim();
    if host.is_empty() || params.port < 1024 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "validation_error",
                "message": "host and port (≥1024) required"
            })),
        );
    }
    if is_private_host(host) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "reachable": false,
                "latency_ms": null,
                "error": "private_address"
            })),
        );
    }

    match probe_node_host(host, params.port).await {
        Ok((true, latency_ms)) => (
            StatusCode::OK,
            Json(serde_json::json!({"reachable": true, "latency_ms": latency_ms})),
        ),
        Ok((false, _)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "reachable": false,
                "latency_ms": null,
                "error": "unreachable"
            })),
        ),
        Err(error) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "reachable": false,
                "latency_ms": null,
                "error": error
            })),
        ),
    }
}

async fn probe_node_host(host: &str, port: u16) -> Result<(bool, Option<u64>), &'static str> {
    let addresses = resolve_probe_addresses(host, port)?;
    for address in addresses {
        let start = std::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(&address),
        )
        .await;
        if result.is_ok_and(|connection| connection.is_ok()) {
            return Ok((true, Some(start.elapsed().as_millis() as u64)));
        }
    }
    Ok((false, None))
}

fn resolve_probe_addresses(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, &'static str> {
    let mut addresses = Vec::new();
    for address in (host, port)
        .to_socket_addrs()
        .map_err(|_| "unresolved_host")?
    {
        if is_private_host(&address.ip().to_string()) {
            return Err("unroutable_address");
        }
        addresses.push(address);
    }
    if addresses.is_empty() {
        return Err("unresolved_host");
    }
    Ok(addresses)
}

fn is_private_host(host: &str) -> bool {
    let host = host.trim_matches(|character| character == '[' || character == ']');
    crate::behavior_contract::blocked_ip(host)
        || is_loopback_or_unspecified(host)
        || is_rfc1918_v4(host)
        || is_ipv6_private(host)
}

fn is_loopback_or_unspecified(host: &str) -> bool {
    host.starts_with("127.")
        || host == "0.0.0.0"
        || host == "::1"
        || host == "localhost"
        || host == "::"
}

fn is_rfc1918_v4(host: &str) -> bool {
    if host.starts_with("10.") || host.starts_with("192.168.") || host.starts_with("169.254.") {
        return true;
    }
    host.strip_prefix("172.")
        .and_then(|remainder| remainder.split('.').next())
        .and_then(|octet| octet.parse::<u8>().ok())
        .is_some_and(|octet| (16..=31).contains(&octet))
}

fn is_ipv6_private(host: &str) -> bool {
    host.starts_with("fe80:") || host.starts_with("fc") || host.starts_with("fd")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_hosts_block_loopback_and_unspecified_addresses() {
        for host in ["127.0.0.1", "127.0.0.10", "0.0.0.0", "::1", "::"] {
            assert!(is_private_host(host), "expected {host} to be blocked");
        }
    }

    #[test]
    fn private_hosts_block_rfc1918_addresses() {
        for host in [
            "10.0.0.1",
            "10.255.255.255",
            "192.168.1.1",
            "172.16.0.1",
            "172.31.255.255",
        ] {
            assert!(is_private_host(host), "expected {host} to be blocked");
        }
        assert!(!is_private_host("172.15.0.1"));
        assert!(!is_private_host("172.32.0.1"));
    }

    #[test]
    fn private_hosts_allow_public_addresses() {
        for host in ["1.2.3.4", "8.8.8.8", "2606:4700::6810:84e5"] {
            assert!(!is_private_host(host), "expected {host} to be allowed");
        }
    }

    #[tokio::test]
    async fn handler_rejects_loopback_before_network_access() {
        let (status, Json(body)) = probe_node(Query(ProbeParams {
            host: "127.0.0.1".to_string(),
            port: 9484,
        }))
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["error"], "private_address");
    }

    #[tokio::test]
    async fn handler_rejects_rfc1918_before_network_access() {
        let (status, _) = probe_node(Query(ProbeParams {
            host: "10.0.0.1".to_string(),
            port: 9484,
        }))
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }
}
