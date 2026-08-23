// SPDX-License-Identifier: Apache-2.0
//! Optional DNS-SD advertisement and signed local-directory descriptor.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use ed25519_compact::{KeyPair, Seed};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use serde_json::{json, Value};

use crate::state::AppState;

pub(crate) const SERVICE_TYPE: &str = "_iicp-dir._tcp.local.";
pub(crate) const DESCRIPTOR_PATH: &str = "/.well-known/iicp-directory.json";
const PROFILE_ID: &str = "urn:iicp:profile:local-directory-discovery:v1";
const SIGNATURE_DOMAIN: &[u8] = b"IICP-LOCAL-DIRECTORY-DESCRIPTOR-V0\n";
const MAX_TXT_BYTES: usize = 512;
const DESCRIPTOR_LIFETIME_SECONDS: i64 = 300;

#[derive(Clone, Debug)]
pub(crate) struct LocalDirectoryAdvertisement {
    pub(crate) enabled: bool,
    pub(crate) instance_name: String,
    pub(crate) hostname: String,
    pub(crate) port: u16,
    pub(crate) role: String,
    pub(crate) did: String,
    pub(crate) api_endpoint: String,
    pub(crate) signing_key: Option<String>,
}

impl LocalDirectoryAdvertisement {
    pub(crate) fn from_env(state: &AppState, replica: bool) -> Result<Self, String> {
        let enabled = flag("IICP_LOCAL_DIRECTORY_ADVERTISE");
        let role = std::env::var("IICP_LOCAL_DIRECTORY_ROLE")
            .unwrap_or_else(|_| if replica { "replica" } else { "standalone" }.into());
        let config = Self {
            enabled,
            instance_name: std::env::var("IICP_LOCAL_DIRECTORY_INSTANCE")
                .unwrap_or_else(|_| "IICP Directory".into()),
            hostname: std::env::var("IICP_LOCAL_DIRECTORY_HOSTNAME").unwrap_or_default(),
            port: std::env::var("IICP_LOCAL_DIRECTORY_PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(443),
            role,
            did: state.directory_did.clone(),
            api_endpoint: state.directory_service_endpoint.clone(),
            signing_key: state.signing_key.clone(),
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if std::env::var("IICP_OPERATING_MODE").ok().as_deref() == Some("local_only") {
            return Err("local-only mode forbids multicast directory advertisement".into());
        }
        if self.hostname.trim().is_empty()
            || self.hostname.chars().any(char::is_whitespace)
            || !self.hostname.ends_with(".local.")
        {
            return Err(
                "IICP_LOCAL_DIRECTORY_HOSTNAME must be a non-empty .local. DNS name".into(),
            );
        }
        if self.instance_name.trim().is_empty() || self.instance_name.len() > 63 {
            return Err("IICP_LOCAL_DIRECTORY_INSTANCE must contain 1 to 63 bytes".into());
        }
        if !matches!(self.role.as_str(), "seed" | "replica" | "standalone") {
            return Err("IICP_LOCAL_DIRECTORY_ROLE must be seed, replica or standalone".into());
        }
        if !self.api_endpoint.starts_with("https://") {
            return Err("local directory advertisement requires an HTTPS API endpoint".into());
        }
        if self
            .signing_key
            .as_deref()
            .is_none_or(|key| !valid_secret(key))
        {
            return Err(
                "local directory advertisement requires the configured Ed25519 signing identity"
                    .into(),
            );
        }
        if txt_size(&self.txt_properties()) > MAX_TXT_BYTES {
            return Err("local directory advertisement TXT data exceeds 512 bytes".into());
        }
        Ok(())
    }

    fn txt_properties(&self) -> Vec<(&'static str, String)> {
        vec![
            ("pv", "0".into()),
            ("path", DESCRIPTOR_PATH.into()),
            ("transport", "https".into()),
            ("did", self.did.clone()),
            ("role", self.role.clone()),
        ]
    }
}

pub(crate) struct LocalDirectoryAdvertiser {
    daemon: ServiceDaemon,
    fullname: String,
}

impl LocalDirectoryAdvertiser {
    pub(crate) fn start(config: LocalDirectoryAdvertisement) -> Result<Option<Self>, String> {
        if !config.enabled {
            return Ok(None);
        }
        let daemon = ServiceDaemon::new().map_err(|error| error.to_string())?;
        let properties = config.txt_properties();
        let property_refs: Vec<(&str, &str)> = properties
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &config.instance_name,
            &config.hostname,
            "",
            config.port,
            property_refs.as_slice(),
        )
        .map_err(|error| error.to_string())?
        .enable_addr_auto();
        let fullname = service.get_fullname().to_string();
        daemon
            .register(service)
            .map_err(|error| error.to_string())?;
        println!("local directory candidate advertised as {fullname}");
        Ok(Some(Self { daemon, fullname }))
    }
}

impl Drop for LocalDirectoryAdvertiser {
    fn drop(&mut self) {
        if let Ok(receiver) = self.daemon.unregister(&self.fullname) {
            let _ = receiver.recv_timeout(std::time::Duration::from_secs(2));
        }
        if let Ok(receiver) = self.daemon.shutdown() {
            let _ = receiver.recv_timeout(std::time::Duration::from_secs(2));
        }
    }
}

pub(crate) async fn directory_descriptor(
    State(state): State<AppState>,
) -> (StatusCode, Json<Value>) {
    let role = std::env::var("IICP_LOCAL_DIRECTORY_ROLE").unwrap_or_else(|_| {
        if state.replica_ready.is_some() {
            "replica".into()
        } else {
            "standalone".into()
        }
    });
    let Some(secret) = state.signing_key.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error":{"code":"local_directory_descriptor_unavailable","message":"Local directory descriptor signing is not configured"}}),
            ),
        );
    };
    match signed_descriptor(
        &state.directory_did,
        &state.directory_service_endpoint,
        &role,
        secret,
        chrono::Utc::now().timestamp(),
    ) {
        Ok(descriptor) => (StatusCode::OK, Json(descriptor)),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"error":{"code":"local_directory_descriptor_unavailable","message":"Local directory descriptor could not be produced"}}),
            ),
        ),
    }
}

fn signed_descriptor(
    did: &str,
    endpoint: &str,
    role: &str,
    secret: &str,
    now: i64,
) -> Result<Value, String> {
    if !matches!(role, "seed" | "replica" | "standalone") || !endpoint.starts_with("https://") {
        return Err("invalid descriptor inputs".into());
    }
    let mut descriptor = json!({
        "schema": "iicp.local-directory-descriptor.v0",
        "profile": PROFILE_ID,
        "profile_version": "0",
        "directory_id": did,
        "directory_did": did,
        "role": role,
        "api_endpoints": [endpoint],
        "issued_at": now,
        "expires_at": now + DESCRIPTOR_LIFETIME_SECONDS,
        "canonicalization": "RFC8785"
    });
    let canonical = serde_jcs::to_vec(&descriptor).map_err(|error| error.to_string())?;
    let mut message = SIGNATURE_DOMAIN.to_vec();
    message.extend_from_slice(&canonical);
    let signature = sign(secret, &message).ok_or("invalid signing key")?;
    descriptor["signature"] = json!({
        "algorithm": "Ed25519",
        "key_id": format!("{did}#key-1"),
        "value": signature
    });
    Ok(descriptor)
}

fn sign(secret: &str, message: &[u8]) -> Option<String> {
    let bytes = hex::decode(secret).ok()?;
    let seed: [u8; 32] = bytes.get(..32)?.try_into().ok()?;
    let keypair = KeyPair::from_seed(Seed::new(seed));
    Some(hex::encode(keypair.sk.sign(message, None).as_ref()))
}

fn valid_secret(secret: &str) -> bool {
    secret.len() == 128 && hex::decode(secret).is_ok_and(|bytes| bytes.len() == 64)
}

fn flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn txt_size(properties: &[(&str, String)]) -> usize {
    properties
        .iter()
        .map(|(key, value)| 1 + key.len() + 1 + value.len())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> String {
        let keypair = KeyPair::from_seed(Seed::new([7; 32]));
        hex::encode(keypair.sk.as_ref())
    }

    fn config() -> LocalDirectoryAdvertisement {
        LocalDirectoryAdvertisement {
            enabled: true,
            instance_name: "IICP Test Directory".into(),
            hostname: "iicp-test.local.".into(),
            port: 443,
            role: "standalone".into(),
            did: "did:web:iicp-test.local".into(),
            api_endpoint: "https://iicp-test.local/v1".into(),
            signing_key: Some(secret()),
        }
    }

    #[test]
    fn advertised_txt_is_bounded_and_contains_no_inventory() {
        let properties = config().txt_properties();
        assert!(txt_size(&properties) <= MAX_TXT_BYTES);
        assert_eq!(properties.len(), 5);
        assert!(properties
            .iter()
            .all(|(key, _)| { matches!(*key, "pv" | "path" | "transport" | "did" | "role") }));
    }

    #[test]
    fn enabled_advertisement_fails_closed_on_incomplete_inputs() {
        let mut value = config();
        value.hostname.clear();
        assert!(value.validate().is_err());
        let mut value = config();
        value.api_endpoint = "http://iicp-test.local/v1".into();
        assert!(value.validate().is_err());
        let mut value = config();
        value.signing_key = None;
        assert!(value.validate().is_err());
        let mut value = config();
        value.role = "unknown".into();
        assert!(value.validate().is_err());
    }

    #[test]
    fn descriptor_is_deterministic_signed_and_time_bounded() {
        let value = signed_descriptor(
            "did:web:iicp-test.local",
            "https://iicp-test.local/v1",
            "standalone",
            &secret(),
            1_000,
        )
        .unwrap();
        assert_eq!(value["issued_at"], 1_000);
        assert_eq!(value["expires_at"], 1_300);
        assert_eq!(value["signature"]["algorithm"], "Ed25519");
        assert_eq!(
            value["signature"]["key_id"],
            "did:web:iicp-test.local#key-1"
        );
        assert_eq!(value["signature"]["value"].as_str().unwrap().len(), 128);
    }

    #[test]
    fn disabled_advertisement_requires_no_local_network_configuration() {
        let mut value = config();
        value.enabled = false;
        value.hostname.clear();
        value.api_endpoint.clear();
        value.signing_key = None;
        assert!(value.validate().is_ok());
        assert!(LocalDirectoryAdvertiser::start(value).unwrap().is_none());
    }
}
