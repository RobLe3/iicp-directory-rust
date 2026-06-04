// SPDX-License-Identifier: Apache-2.0
//! Wire types for the IICP directory read path.
//!
//! Mirrors `spec/iicp-dir.md` v0.9.0 (Protocol Suite v1.9.0). Field-for-field with
//! the PHP reference implementation's `/v1/discover` NODELIST (§3.4) and `/v1/stats`
//! Public Stats (§3.9b) so a client cannot tell which implementation served it.
//!
//! Forward-compatibility: serde defaults on every optional field so a directory at a
//! newer spec can add fields without breaking older clients (mirrors the SDK rule).

use serde::{Deserialize, Serialize};

/// A single node in the `/v1/discover` NODELIST response (iicp-dir §3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub node_id: String,
    pub endpoint: String,
    pub region: String,
    pub score: f64,
    pub available: bool,
    #[serde(default)]
    pub load: f64,
    #[serde(default)]
    pub active_jobs: u32,
    #[serde(default)]
    pub max_concurrent: u32,
    #[serde(default)]
    pub reputation_score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_estimate_ms: Option<u32>,
    #[serde(default)]
    pub completed_tasks_count: u64,
    /// #385 Phase-B — failed tasks (from heartbeat metrics), for the success
    /// ratio in NodeHealthService. completed_tasks_count is the total.
    #[serde(default)]
    pub tasks_failed: u64,
    /// ADR-044 composed health label (healthy/degraded/impaired/critical/offline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_label: Option<String>,
    /// ADR-043 8-category network exposure classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exposure_mode: Option<String>,
    /// CIP §5.1.1 tier: none / silver / gold / platinum (REACH valid_tiers per DIR-CIP-03).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_endpoint: Option<String>,
    /// CIP §5.2 REP1: CIP-Provider (allow_remote_inference=true) or CIP-None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cip_conformance_level: Option<String>,
    /// Models declared by the node's capabilities (PHP discover includes this).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub models: Vec<String>,
    /// ADR-019 pricing metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing: Option<serde_json::Value>,
    // ── Phase 5 NODELIST fields (iicp-dir §3.4, ADR-040/ADR-043) ─────────────
    /// NAT traversal type (full_cone / restricted_cone / port_restricted / symmetric / unknown).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat_type: Option<String>,
    /// Transport method (direct / upnp_mapped / stun_hole_punch / turn_relay / external_tunnel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_method: Option<String>,
    /// Whether the node can act as a relay for CGNAT-blocked peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_capable: Option<bool>,
    /// SDK implementation language.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk_language: Option<String>,
    /// SDK version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk_version: Option<String>,
    /// Derived from endpoint host: ipv4 | ipv6 | hostname | unknown (PHP NodeScorer parity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_family: Option<String>,
    /// CIP opt-in policy block (S.12 §2.1 — always present, never null in NODELIST).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cip_policy: Option<serde_json::Value>,
    /// cx_public_key identity object (PHP column cx_public_key, ADR-030).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<serde_json::Value>,
    /// NAT traversal metadata blob (ADR-043 transport_metadata).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_metadata: Option<serde_json::Value>,
    /// Distinct quantization strings across all capabilities (e.g. ["q4_k_m"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quantization: Vec<String>,
    /// Distinct inference engine strings across all capabilities (e.g. ["llama.cpp"]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inference_engine: Vec<String>,
    // ── #400 — discover field parity with PHP (NodeScorer emits these) ────────
    /// ADR-019 credit pricing multiplier (base 1.0 credits/1000 tokens).
    #[serde(default = "default_credit_multiplier")]
    pub credit_cost_multiplier: f64,
    /// ADR-019 pricing model — per_token / per_request / flat.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing_model: Option<String>,
    /// Attestation flag (TEE / hardware attestation declared at registration).
    #[serde(default)]
    pub attested: bool,
    /// #397 — transport protocols the node speaks (http/https/iicp-native),
    /// derived server-side from endpoint schemes at discover time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transport: Vec<String>,
    /// #385 Phase-B — precomputed reachability health signal (1.0 direct / 0.5 relay
    /// / 0.0 unreachable) derived in `From<NodeRow>` from `public_reachable` +
    /// `relay_capable`. Internal health input only — not part of the discover wire
    /// contract, hence `#[serde(skip)]`.
    #[serde(skip)]
    pub reachability_signal: f64,
}

/// PHP `credit_cost_multiplier ?? 1.0` default — used when deserialising a
/// discover response from an older directory that omits the field.
fn default_credit_multiplier() -> f64 {
    1.0
}

/// `/v1/discover` response envelope (iicp-dir §3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeList {
    pub nodes: Vec<Node>,
    pub count: u32,
    #[serde(default)]
    pub query_ms: u32,
}

/// ADR-044 mesh health — node aggregate (median over active provider nodes).
/// Used in types tests; production code now returns JSON directly (PHP parity iter-1626).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshHealth {
    pub score: u32,
    pub label: String,
    pub sample: u32,
}

/// `/v1/stats` Public Stats response — kept for tests.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stats {
    pub server: ServerInfo,
    pub mesh_health: MeshHealth,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub active_nodes: u32,
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_roundtrips_with_optional_fields_absent() {
        let json =
            r#"{"node_id":"n1","endpoint":"https://x","region":"eu","score":0.9,"available":true}"#;
        let n: Node = serde_json::from_str(json).unwrap();
        assert_eq!(n.node_id, "n1");
        assert!(n.health_label.is_none());
        assert!(n.reputation_tier.is_none());
    }

    #[test]
    fn node_parses_v1_9_0_fields() {
        let json = r#"{"node_id":"n1","endpoint":"https://x","region":"eu","score":0.9,
            "available":true,"health_label":"healthy","exposure_mode":"ipv4_public_direct",
            "reputation_tier":"bronze"}"#;
        let n: Node = serde_json::from_str(json).unwrap();
        assert_eq!(n.health_label.as_deref(), Some("healthy"));
        assert_eq!(n.reputation_tier.as_deref(), Some("bronze"));
    }

    #[test]
    fn stats_serializes_to_spec_shape() {
        let s = Stats {
            server: ServerInfo {
                active_nodes: 3,
                version: "v0.1.0-rs".into(),
            },
            mesh_health: MeshHealth {
                score: 65,
                label: "degraded".into(),
                sample: 3,
            },
        };
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["server"]["active_nodes"], 3);
        assert_eq!(v["mesh_health"]["label"], "degraded");
    }
}
