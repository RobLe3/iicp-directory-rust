//! Process configuration and production startup guards.

use crate::replica::ReplicaConfig;
use crate::validate::Env;

pub(crate) const DEFAULT_DIRECTORY_DID: &str = "did:web:iicp.network";

const DEFAULT_DATABASE_POOL_MAX_CONNECTIONS: u32 = 10;
const DEFAULT_DATABASE_POOL_MIN_CONNECTIONS: u32 = 0;
const DEFAULT_DATABASE_POOL_ACQUIRE_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_DATABASE_POOL_IDLE_TIMEOUT_MS: u64 = 600_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DatabasePoolConfig {
    pub(crate) max_connections: u32,
    pub(crate) min_connections: u32,
    pub(crate) acquire_timeout_ms: u64,
    pub(crate) idle_timeout_ms: u64,
}

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

pub(crate) fn database_pool_config() -> Result<DatabasePoolConfig, String> {
    database_pool_config_from_values(
        std::env::var("IICP_DB_POOL_MAX_CONNECTIONS").ok(),
        std::env::var("IICP_DB_POOL_MIN_CONNECTIONS").ok(),
        std::env::var("IICP_DB_POOL_ACQUIRE_TIMEOUT_MS").ok(),
        std::env::var("IICP_DB_POOL_IDLE_TIMEOUT_MS").ok(),
    )
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
            .filter(|url| {
                url.starts_with("https://")
                    || (replica.allow_http_did && url.starts_with("http://"))
            })
            .ok_or_else(|| {
                "replica mode requires HTTPS unless the explicit local/testing HTTP testbed flag is active"
                    .to_string()
            })?;
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

fn database_pool_config_from_values(
    max_connections: Option<String>,
    min_connections: Option<String>,
    acquire_timeout_ms: Option<String>,
    idle_timeout_ms: Option<String>,
) -> Result<DatabasePoolConfig, String> {
    fn parse_u32(name: &str, value: Option<String>, default: u32) -> Result<u32, String> {
        value.map_or(Ok(default), |raw| {
            raw.parse::<u32>()
                .map_err(|_| format!("{name} must be an unsigned integer"))
        })
    }

    fn parse_u64(name: &str, value: Option<String>, default: u64) -> Result<u64, String> {
        value.map_or(Ok(default), |raw| {
            raw.parse::<u64>()
                .map_err(|_| format!("{name} must be an unsigned integer"))
        })
    }

    let config = DatabasePoolConfig {
        max_connections: parse_u32(
            "IICP_DB_POOL_MAX_CONNECTIONS",
            max_connections,
            DEFAULT_DATABASE_POOL_MAX_CONNECTIONS,
        )?,
        min_connections: parse_u32(
            "IICP_DB_POOL_MIN_CONNECTIONS",
            min_connections,
            DEFAULT_DATABASE_POOL_MIN_CONNECTIONS,
        )?,
        acquire_timeout_ms: parse_u64(
            "IICP_DB_POOL_ACQUIRE_TIMEOUT_MS",
            acquire_timeout_ms,
            DEFAULT_DATABASE_POOL_ACQUIRE_TIMEOUT_MS,
        )?,
        idle_timeout_ms: parse_u64(
            "IICP_DB_POOL_IDLE_TIMEOUT_MS",
            idle_timeout_ms,
            DEFAULT_DATABASE_POOL_IDLE_TIMEOUT_MS,
        )?,
    };
    if !(1..=1024).contains(&config.max_connections) {
        return Err("IICP_DB_POOL_MAX_CONNECTIONS must be between 1 and 1024".to_string());
    }
    if config.min_connections > config.max_connections {
        return Err(
            "IICP_DB_POOL_MIN_CONNECTIONS must not exceed IICP_DB_POOL_MAX_CONNECTIONS".to_string(),
        );
    }
    if config.acquire_timeout_ms == 0 {
        return Err("IICP_DB_POOL_ACQUIRE_TIMEOUT_MS must be greater than zero".to_string());
    }
    if config.idle_timeout_ms == 0 {
        return Err("IICP_DB_POOL_IDLE_TIMEOUT_MS must be greater than zero".to_string());
    }
    Ok(config)
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
            allow_http_did: false,
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
    fn replica_identity_allows_http_only_for_explicit_testbed_config() {
        let mut testbed = replica(Some("did:web:replica%3A8090"), Some("http://replica:8090"));
        assert!(directory_identity_from_values(Some(&testbed), None, None).is_err());
        testbed.allow_http_did = true;
        let identity = directory_identity_from_values(Some(&testbed), None, None)
            .expect("explicit testbed HTTP endpoint");
        assert_eq!(identity.service_endpoint, "http://replica:8090");
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

    #[test]
    fn database_pool_defaults_preserve_the_existing_capacity() {
        assert_eq!(
            database_pool_config_from_values(None, None, None, None).unwrap(),
            DatabasePoolConfig {
                max_connections: 10,
                min_connections: 0,
                acquire_timeout_ms: 30_000,
                idle_timeout_ms: 600_000,
            }
        );
    }

    #[test]
    fn database_pool_configuration_is_bounded_and_consistent() {
        let configured = database_pool_config_from_values(
            Some("64".into()),
            Some("4".into()),
            Some("5000".into()),
            Some("120000".into()),
        )
        .unwrap();
        assert_eq!(configured.max_connections, 64);
        assert_eq!(configured.min_connections, 4);
        assert_eq!(configured.acquire_timeout_ms, 5000);
        assert_eq!(configured.idle_timeout_ms, 120000);

        assert!(database_pool_config_from_values(Some("0".into()), None, None, None).is_err());
        assert!(
            database_pool_config_from_values(Some("4".into()), Some("5".into()), None, None)
                .is_err()
        );
        assert!(database_pool_config_from_values(None, None, Some("0".into()), None).is_err());
    }
}
