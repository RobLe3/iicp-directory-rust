//! Process configuration and production startup guards.

use crate::replica::ReplicaConfig;
use crate::validate::Env;

pub(crate) const DEFAULT_DIRECTORY_DID: &str = "did:web:iicp.network";

pub(crate) struct DirectoryIdentity {
    pub(crate) did: String,
    pub(crate) service_endpoint: String,
}

pub(crate) fn environment() -> Env {
    environment_from_value(std::env::var("APP_ENV").ok().as_deref())
}

pub(crate) fn directory_identity(
    replica: Option<&ReplicaConfig>,
) -> Result<DirectoryIdentity, String> {
    directory_identity_from_values(
        replica,
        std::env::var("IICP_DIRECTORY_DID").ok(),
        std::env::var("IICP_DIRECTORY_ENDPOINT").ok(),
    )
}

pub(crate) fn signing_key(env: Env) -> Result<Option<String>, String> {
    signing_key_from_value(env, std::env::var("IICP_GENESIS_ED25519_SECRET_KEY").ok())
}

pub(crate) fn strict_e050_secured() -> bool {
    env_flag("IICP_E050_STRICT_SECURED")
}

pub(crate) fn allow_insecure_tls(env: Env) -> bool {
    env != Env::Production && env_flag("IICP_DEV_ALLOW_INSECURE_TLS")
}

pub(crate) fn skip_liveness_check(env: Env) -> bool {
    matches!(env, Env::Local | Env::Testing) && env_flag("IICP_SKIP_LIVENESS_CHECK")
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| truthy(&value))
}

fn truthy(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn environment_from_value(value: Option<&str>) -> Env {
    match value {
        Some("local") => Env::Local,
        Some("testing") => Env::Testing,
        Some("staging") => Env::Staging,
        _ => Env::Production,
    }
}

fn directory_identity_from_values(
    replica: Option<&ReplicaConfig>,
    configured_did: Option<String>,
    configured_endpoint: Option<String>,
) -> Result<DirectoryIdentity, String> {
    if let Some(replica) = replica {
        let did = replica
            .replica_did
            .as_ref()
            .filter(|did| did.starts_with("did:web:"))
            .ok_or_else(|| "replica mode requires a valid IICP_REPLICA_DID".to_string())?;
        let endpoint = replica
            .replica_endpoint
            .as_ref()
            .filter(|url| url.starts_with("https://"))
            .ok_or_else(|| "replica mode requires an HTTPS IICP_REPLICA_ENDPOINT".to_string())?;
        if configured_did.is_some_and(|served| served != *did) {
            return Err(
                "IICP_DIRECTORY_DID must equal IICP_REPLICA_DID in replica mode".to_string(),
            );
        }
        return Ok(DirectoryIdentity {
            did: did.clone(),
            service_endpoint: endpoint.trim_end_matches('/').to_string(),
        });
    }

    Ok(DirectoryIdentity {
        did: configured_did.unwrap_or_else(|| DEFAULT_DIRECTORY_DID.to_string()),
        service_endpoint: configured_endpoint
            .unwrap_or_else(|| "https://iicp.network/v1".to_string()),
    })
}

fn signing_key_from_value(env: Env, value: Option<String>) -> Result<Option<String>, String> {
    let key = value.filter(|key| key.len() == 128 && hex::decode(key).is_ok());
    if env == Env::Production && key.is_none() {
        return Err(
            "IICP_GENESIS_ED25519_SECRET_KEY must be a valid 128-hex Ed25519 secret in production"
                .to_string(),
        );
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replica(did: Option<&str>, endpoint: Option<&str>) -> ReplicaConfig {
        ReplicaConfig {
            seed_url: "https://seed.example".to_string(),
            seed_did: "did:web:seed.example".to_string(),
            poll_interval_secs: 10,
            replica_did: did.map(str::to_string),
            replica_endpoint: endpoint.map(str::to_string),
            verification_required: true,
            status_path: std::path::PathBuf::from("/tmp/iicp-replica-test-status.json"),
        }
    }

    #[test]
    fn environment_defaults_to_production() {
        assert_eq!(environment_from_value(None), Env::Production);
        assert_eq!(environment_from_value(Some("unknown")), Env::Production);
        assert_eq!(environment_from_value(Some("local")), Env::Local);
        assert_eq!(environment_from_value(Some("testing")), Env::Testing);
        assert_eq!(environment_from_value(Some("staging")), Env::Staging);
    }

    #[test]
    fn truthy_values_match_existing_flag_contract() {
        for value in ["1", "true", "TRUE", "yes", "on"] {
            assert!(truthy(value));
        }
        for value in ["", "0", "false", "off"] {
            assert!(!truthy(value));
        }
    }

    #[test]
    fn standalone_identity_keeps_existing_defaults() {
        let identity = directory_identity_from_values(None, None, None).expect("identity");
        assert_eq!(identity.did, DEFAULT_DIRECTORY_DID);
        assert_eq!(identity.service_endpoint, "https://iicp.network/v1");
    }

    #[test]
    fn replica_identity_requires_did_endpoint_and_matching_served_did() {
        assert!(directory_identity_from_values(
            Some(&replica(None, Some("https://replica.example"))),
            None,
            None,
        )
        .is_err());
        assert!(directory_identity_from_values(
            Some(&replica(Some("did:web:replica.example"), None)),
            None,
            None,
        )
        .is_err());
        assert!(directory_identity_from_values(
            Some(&replica(
                Some("did:web:replica.example"),
                Some("https://replica.example/")
            )),
            Some("did:web:other.example".to_string()),
            None,
        )
        .is_err());

        let identity = directory_identity_from_values(
            Some(&replica(
                Some("did:web:replica.example"),
                Some("https://replica.example/"),
            )),
            Some("did:web:replica.example".to_string()),
            None,
        )
        .expect("replica identity");
        assert_eq!(identity.did, "did:web:replica.example");
        assert_eq!(identity.service_endpoint, "https://replica.example");
    }

    #[test]
    fn signing_key_is_required_only_in_production() {
        assert_eq!(signing_key_from_value(Env::Testing, None).unwrap(), None);
        assert!(signing_key_from_value(Env::Production, None).is_err());
        assert!(signing_key_from_value(Env::Production, Some("invalid".into())).is_err());
        let key = "ab".repeat(64);
        assert_eq!(
            signing_key_from_value(Env::Production, Some(key.clone())).unwrap(),
            Some(key)
        );
    }
}
