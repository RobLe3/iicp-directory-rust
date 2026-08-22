//! Restricted trust-domain configuration, persistence and HTTP admission.

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use sha2::{Digest, Sha256};
use sqlx::{MySql, Pool, Row};
use std::collections::{HashMap, HashSet};

use crate::restricted_domain_membership::{self, MembershipEnvelope, MembershipInput};
use crate::state::AppState;

const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const ALLOWED_SCOPES: &[&str] = &[
    "*",
    "registration",
    "discovery",
    "bootstrap",
    "heartbeat",
    "peers",
    "consumer_token",
    "dispatch",
    "relay",
];

#[derive(Clone, Debug, serde::Serialize)]
struct RestrictedDirectoryDecision {
    schema: &'static str,
    profile: &'static str,
    decision: &'static str,
    operation: &'static str,
    domain_id: String,
    authority_id: String,
    subject_kind: String,
    membership_generation: u64,
    membership_expires_at: i64,
}

#[derive(Clone, Debug)]
struct AuthorizedMembership {
    subject_kind: String,
    generation: u64,
    expires_at: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct RestrictedDomainConfig {
    pub(crate) enabled: bool,
    pub(crate) domain_id: String,
    pub(crate) authority_id: String,
    pub(crate) authority_key_id: String,
    pub(crate) membership_epoch: u64,
    pub(crate) max_credential_ttl_seconds: u64,
}

impl RestrictedDomainConfig {
    pub(crate) fn from_env(replica_mode: bool) -> Result<Self, String> {
        let enabled = flag("IICP_RESTRICTED_DOMAIN_ENABLED");
        let config = Self {
            enabled,
            domain_id: std::env::var("IICP_TRUST_DOMAIN_ID").unwrap_or_default(),
            authority_id: std::env::var("IICP_TRUST_DOMAIN_AUTHORITY_ID").unwrap_or_default(),
            authority_key_id: std::env::var("IICP_TRUST_DOMAIN_AUTHORITY_KEY_ID")
                .unwrap_or_default(),
            membership_epoch: number("IICP_TRUST_DOMAIN_MEMBERSHIP_EPOCH", 1),
            max_credential_ttl_seconds: number("IICP_TRUST_DOMAIN_MAX_CREDENTIAL_TTL", 86_400),
        };
        config.validate(replica_mode)?;
        Ok(config)
    }

    fn validate(&self, replica_mode: bool) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.domain_id.trim().is_empty()
            || self.authority_id.trim().is_empty()
            || self.membership_epoch < 1
            || self.max_credential_ttl_seconds < 60
        {
            return Err("restricted trust-domain mode requires domain ID, authority ID, positive membership epoch and credential TTL of at least 60 seconds".into());
        }
        if replica_mode {
            return Err("restricted trust-domain federation is not implemented; replica mode cannot be combined with restricted-domain mode".into());
        }
        Ok(())
    }
}

fn flag(name: &str) -> bool {
    std::env::var(name)
        .is_ok_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}
fn number(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[derive(Clone)]
pub(crate) struct RestrictedDomainService {
    pub(crate) config: RestrictedDomainConfig,
    pool: Option<Pool<MySql>>,
}

impl RestrictedDomainService {
    #[cfg(test)]
    pub(crate) fn public() -> Self {
        Self {
            config: RestrictedDomainConfig {
                enabled: false,
                domain_id: String::new(),
                authority_id: String::new(),
                authority_key_id: String::new(),
                membership_epoch: 1,
                max_credential_ttl_seconds: 86_400,
            },
            pool: None,
        }
    }
    pub(crate) fn new(
        config: RestrictedDomainConfig,
        pool: Option<Pool<MySql>>,
    ) -> Result<Self, String> {
        if config.enabled && pool.is_none() {
            return Err(
                "restricted trust-domain mode requires DATABASE_URL-backed membership persistence"
                    .into(),
            );
        }
        Ok(Self { config, pool })
    }

    #[cfg(test)]
    async fn verify(&self, token: &str, subject_id: &str, operation: &str) -> bool {
        if !self.config.enabled {
            return true;
        }
        self.authorize(token, subject_id, operation).await.is_some()
    }

    async fn authorize(
        &self,
        token: &str,
        subject_id: &str,
        operation: &str,
    ) -> Option<AuthorizedMembership> {
        if !self.config.enabled {
            return None;
        }
        if token.is_empty() || subject_id.is_empty() {
            return None;
        }
        let Some(pool) = &self.pool else {
            return None;
        };
        let digest = hex::encode(Sha256::digest(token.as_bytes()));
        let row = sqlx::query(
            "SELECT subject_id, subject_kind, scopes, generation, expires_at FROM trust_domain_memberships \
             WHERE domain_id = ? AND token_hash = ? AND revoked_at IS NULL \
             AND expires_at > NOW() AND generation >= ? LIMIT 1",
        )
        .bind(&self.config.domain_id)
        .bind(digest)
        .bind(self.config.membership_epoch)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        let row = row?;
        let stored: String = row.get("subject_id");
        if stored.as_bytes() != subject_id.as_bytes() {
            return None;
        }
        let scopes: serde_json::Value = row.try_get("scopes").unwrap_or(serde_json::Value::Null);
        if !scopes.as_array().is_some_and(|values| {
            values
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s == "*" || s == operation))
        }) {
            return None;
        }
        let expires_at: chrono::NaiveDateTime = row.try_get("expires_at").ok()?;
        Some(AuthorizedMembership {
            subject_kind: row.try_get("subject_kind").ok()?,
            generation: row.try_get("generation").ok()?,
            expires_at: expires_at.and_utc().timestamp(),
        })
    }

    pub(crate) async fn issue(
        &self,
        kind: &str,
        subject: &str,
        scopes: &[String],
        ttl: u64,
    ) -> Result<String, String> {
        Ok(self.issue_record(kind, subject, scopes, ttl).await?.token)
    }

    async fn issue_with_assertion(
        &self,
        kind: &str,
        subject: &str,
        scopes: &[String],
        ttl: u64,
        keys: AssertionKeys<'_>,
    ) -> Result<(String, MembershipEnvelope), String> {
        if keys.subject_key_id.trim().is_empty() {
            return Err("subject key identifier is required".into());
        }
        let requested_peer_scopes: Vec<String> = scopes
            .iter()
            .filter(|scope| is_peer_scope(scope.as_str()))
            .cloned()
            .collect();
        restricted_domain_membership::validate_signing_inputs(
            keys.subject_public_key,
            keys.signing_key,
            &requested_peer_scopes,
        )?;
        let record = self.issue_record(kind, subject, scopes, ttl).await?;
        let authority_key_id = if self.config.authority_key_id.trim().is_empty() {
            format!("{}#key-1", self.config.authority_id)
        } else {
            self.config.authority_key_id.clone()
        };
        let assertion = restricted_domain_membership::sign(
            MembershipInput {
                domain_id: &self.config.domain_id,
                authority_id: &self.config.authority_id,
                authority_key_id: &authority_key_id,
                subject_kind: kind,
                subject_id: subject,
                subject_key_id: keys.subject_key_id,
                subject_public_key: keys.subject_public_key,
                generation: record.generation,
                issued_at: record.issued_at,
                expires_at: record.expires_at,
                scopes: record.peer_scopes,
            },
            keys.signing_key,
        )?;
        let pool = self
            .pool
            .as_ref()
            .ok_or("membership persistence unavailable")?;
        let serialized = serde_json::to_string(&assertion)
            .map_err(|_| "membership assertion serialization failed")?;
        sqlx::query(
            "UPDATE trust_domain_memberships SET membership_envelope=?, updated_at=NOW() \
             WHERE domain_id=? AND subject_kind=? AND subject_id=? AND generation=?",
        )
        .bind(serialized)
        .bind(&self.config.domain_id)
        .bind(kind)
        .bind(subject)
        .bind(record.generation)
        .execute(pool)
        .await
        .map_err(|_| "membership assertion persistence failed")?;
        Ok((record.token, assertion))
    }

    pub(crate) async fn bootstrap_memberships(
        &self,
        node_ids: &[String],
    ) -> HashMap<String, MembershipEnvelope> {
        if !self.config.enabled || node_ids.is_empty() {
            return HashMap::new();
        }
        let Some(pool) = &self.pool else {
            return HashMap::new();
        };
        let rows = sqlx::query(
            "SELECT subject_id, membership_envelope FROM trust_domain_memberships \
             WHERE domain_id=? AND subject_kind='node' AND revoked_at IS NULL \
             AND expires_at > NOW() AND generation >= ? AND membership_envelope IS NOT NULL",
        )
        .bind(&self.config.domain_id)
        .bind(self.config.membership_epoch)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .filter_map(|row| {
                let subject: String = row.try_get("subject_id").ok()?;
                if !node_ids.contains(&subject) {
                    return None;
                }
                let raw: serde_json::Value = row.try_get("membership_envelope").ok()?;
                let envelope: MembershipEnvelope = serde_json::from_value(raw).ok()?;
                let scoped = envelope
                    .assertion
                    .scopes
                    .iter()
                    .any(|scope| matches!(scope.as_str(), "bootstrap" | "peers"));
                (scoped && envelope.assertion.subject.id == subject).then_some((subject, envelope))
            })
            .collect()
    }

    /// Return only node identifiers whose domain membership is current at the
    /// time of this decision. Caller authentication does not establish that a
    /// provider registered earlier is still eligible after expiry, revocation
    /// or an epoch advance.
    pub(crate) async fn current_node_members(&self, node_ids: &[String]) -> HashSet<String> {
        if !self.config.enabled || node_ids.is_empty() {
            return HashSet::new();
        }
        let Some(pool) = &self.pool else {
            return HashSet::new();
        };
        let rows = sqlx::query(
            "SELECT subject_id FROM trust_domain_memberships \
             WHERE domain_id=? AND subject_kind='node' AND revoked_at IS NULL \
             AND expires_at > NOW() AND generation >= ?",
        )
        .bind(&self.config.domain_id)
        .bind(self.config.membership_epoch)
        .fetch_all(pool)
        .await
        .unwrap_or_default();
        rows.into_iter()
            .filter_map(|row| row.try_get::<String, _>("subject_id").ok())
            .filter(|subject| node_ids.contains(subject))
            .collect()
    }

    async fn issue_record(
        &self,
        kind: &str,
        subject: &str,
        scopes: &[String],
        ttl: u64,
    ) -> Result<IssuedMembership, String> {
        if !self.config.enabled {
            return Err("restricted trust-domain mode is not enabled".into());
        }
        if !matches!(kind, "node" | "client") || subject.trim().is_empty() {
            return Err(
                "subject kind must be node or client and subject ID must be non-empty".into(),
            );
        }
        let mut normalized: Vec<&str> = scopes
            .iter()
            .map(String::as_str)
            .filter(|s| ALLOWED_SCOPES.contains(s))
            .collect();
        normalized.sort_unstable();
        normalized.dedup();
        if normalized.is_empty() {
            return Err("at least one valid membership scope is required".into());
        }
        let pool = self
            .pool
            .as_ref()
            .ok_or("membership persistence unavailable")?;
        let token = format!(
            "iicp_mem_{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let digest = hex::encode(Sha256::digest(token.as_bytes()));
        let ttl = ttl.clamp(60, self.config.max_credential_ttl_seconds);
        let issued_at = chrono::Utc::now().timestamp();
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| "membership persistence failed")?;
        let existing: Option<(u64,)> = sqlx::query_as(
            "SELECT generation FROM trust_domain_memberships WHERE domain_id=? AND subject_kind=? AND subject_id=? FOR UPDATE"
        ).bind(&self.config.domain_id).bind(kind).bind(subject).fetch_optional(&mut *tx).await.map_err(|_| "membership persistence failed")?;
        let generation = existing.map_or(self.config.membership_epoch, |v| {
            (v.0 + 1).max(self.config.membership_epoch)
        });
        sqlx::query(
            "INSERT INTO trust_domain_memberships (id,domain_id,issuer_id,subject_kind,subject_id,token_hash,scopes,generation,expires_at,revoked_at,created_at,updated_at) \
             VALUES (?,?,?,?,?,?,?,?,DATE_ADD(NOW(), INTERVAL ? SECOND),NULL,NOW(),NOW()) \
             ON DUPLICATE KEY UPDATE issuer_id=VALUES(issuer_id),token_hash=VALUES(token_hash),scopes=VALUES(scopes),generation=VALUES(generation),expires_at=VALUES(expires_at),revoked_at=NULL,updated_at=NOW()"
        ).bind(uuid::Uuid::new_v4().to_string()).bind(&self.config.domain_id).bind(&self.config.authority_id).bind(kind).bind(subject).bind(digest)
         .bind(serde_json::to_string(&normalized).map_err(|_| "invalid scopes")?).bind(generation).bind(ttl)
         .execute(&mut *tx).await.map_err(|_| "membership persistence failed")?;
        tx.commit()
            .await
            .map_err(|_| "membership persistence failed")?;
        let peer_scopes = normalized
            .iter()
            .filter(|scope| is_peer_scope(scope))
            .map(|scope| (*scope).to_string())
            .collect();
        Ok(IssuedMembership {
            token,
            generation,
            issued_at,
            expires_at: issued_at + ttl as i64,
            peer_scopes,
        })
    }

    pub(crate) async fn revoke(&self, kind: &str, subject: &str) -> Result<bool, String> {
        let pool = self
            .pool
            .as_ref()
            .ok_or("membership persistence unavailable")?;
        let result = sqlx::query("UPDATE trust_domain_memberships SET revoked_at=NOW() WHERE domain_id=? AND subject_kind=? AND subject_id=? AND revoked_at IS NULL")
            .bind(&self.config.domain_id).bind(kind).bind(subject).execute(pool).await.map_err(|_| "membership persistence failed")?;
        Ok(result.rows_affected() == 1)
    }
}

fn is_peer_scope(scope: &str) -> bool {
    matches!(
        scope,
        "bootstrap" | "peers" | "relay" | "execution" | "cip" | "federation"
    )
}

struct IssuedMembership {
    token: String,
    generation: u64,
    issued_at: i64,
    expires_at: i64,
    peer_scopes: Vec<String>,
}

struct AssertionKeys<'a> {
    subject_key_id: &'a str,
    subject_public_key: &'a str,
    signing_key: &'a str,
}

pub(crate) async fn run_command(command: crate::cli::Command) -> Result<(), String> {
    let url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL is required for membership administration")?;
    let pool = crate::db::init_pool(&url)
        .await
        .map_err(|_| "membership database connection failed")?;
    crate::schema::verify_existing_schema(&pool)
        .await
        .map_err(|_| {
            "membership database schema is incompatible; apply the reviewed migration first"
        })?;
    let service =
        RestrictedDomainService::new(RestrictedDomainConfig::from_env(false)?, Some(pool))?;
    match command {
        crate::cli::Command::TrustDomainMembershipIssue {
            kind,
            subject,
            scopes,
            ttl_seconds,
            subject_key_id,
            subject_public_key,
        } => {
            if let (Some(key_id), Some(public_key)) = (subject_key_id, subject_public_key) {
                let signing_key = crate::config::signing_key(crate::config::environment())?
                    .ok_or("directory signing key is required for a peer-verifiable assertion")?;
                let (token, assertion) = service
                    .issue_with_assertion(
                        &kind,
                        &subject,
                        &scopes,
                        ttl_seconds,
                        AssertionKeys {
                            subject_key_id: &key_id,
                            subject_public_key: &public_key,
                            signing_key: &signing_key,
                        },
                    )
                    .await?;
                println!("{token}");
                println!(
                    "{}",
                    serde_json::to_string(&assertion)
                        .map_err(|_| "membership assertion serialization failed")?
                );
            } else {
                let token = service.issue(&kind, &subject, &scopes, ttl_seconds).await?;
                println!("{token}");
            }
        }
        crate::cli::Command::TrustDomainMembershipRevoke { kind, subject } => {
            if !service.revoke(&kind, &subject).await? {
                return Err("active membership not found".into());
            }
            println!("revoked");
        }
        _ => return Err("unsupported membership command".into()),
    }
    Ok(())
}

fn protected_operation(method: &Method, path: &str) -> Option<&'static str> {
    let path = path.strip_prefix("/api").unwrap_or(path);
    match (method, path) {
        (&Method::POST, "/v1/register") => Some("registration"),
        (&Method::GET, "/v1/discover") => Some("discovery"),
        (&Method::GET, "/v1/bootstrap") => Some("bootstrap"),
        (&Method::POST, "/v1/heartbeat") => Some("heartbeat"),
        (&Method::POST, "/v1/peers") => Some("peers"),
        (&Method::POST, "/v1/consumer-token") => Some("consumer_token"),
        (&Method::POST, "/v1/dispatch/ticket") => Some("dispatch"),
        (&Method::POST, "/v1/relay/ticket") => Some("relay"),
        _ => None,
    }
}

fn projected_operation(operation: &str) -> Option<&'static str> {
    match operation {
        "registration" => Some("registration"),
        "discovery" => Some("discovery"),
        "bootstrap" => Some("bootstrap"),
        "dispatch" => Some("dispatch_ticket"),
        "consumer_token" => Some("consumer_token"),
        _ => None,
    }
}

fn directory_decision(
    config: &RestrictedDomainConfig,
    operation: &str,
    membership: AuthorizedMembership,
) -> Option<RestrictedDirectoryDecision> {
    Some(RestrictedDirectoryDecision {
        schema: "iicp.restricted-trust-domain.directory-decision.v0",
        profile: "urn:iicp:profile:restricted-trust-domain:v1",
        decision: "eligible",
        operation: projected_operation(operation)?,
        domain_id: config.domain_id.clone(),
        authority_id: config.authority_id.clone(),
        subject_kind: membership.subject_kind,
        membership_generation: membership.generation,
        membership_expires_at: membership.expires_at,
    })
}

pub(crate) async fn restricted_domain_gate(
    State(st): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    if !st.restricted_domain.config.enabled {
        return next.run(req).await;
    }
    let Some(operation) = protected_operation(req.method(), req.uri().path()) else {
        return next.run(req).await;
    };
    let token = req
        .headers()
        .get("x-iicp-membership")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let claimed = req
        .headers()
        .get("x-iicp-subject-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let (parts, body) = req.into_parts();
    let bytes = match to_bytes(body, MAX_BODY_BYTES).await {
        Ok(v) => v,
        Err(_) => return denied(),
    };
    let body_subject = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.get("node_id")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    let subject = body_subject.as_deref().unwrap_or(&claimed);
    if !claimed.is_empty() && body_subject.as_deref().is_some_and(|v| v != claimed) {
        return denied();
    }
    let Some(membership) = st
        .restricted_domain
        .authorize(&token, subject, operation)
        .await
    else {
        return denied();
    };
    let response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    let Some(decision) = directory_decision(&st.restricted_domain.config, operation, membership)
    else {
        return response;
    };
    project_decision(response, decision).await
}

async fn project_decision(response: Response, decision: RestrictedDirectoryDecision) -> Response {
    if !response.status().is_success() {
        return response;
    }
    let (mut parts, body) = response.into_parts();
    let Ok(bytes) = to_bytes(body, MAX_BODY_BYTES).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error":{"code":"restricted_decision_projection_failed","message":"Restricted authorization evidence could not be produced"}})),
        ).into_response();
    };
    let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error":{"code":"restricted_decision_projection_failed","message":"Restricted authorization evidence could not be produced"}})),
        ).into_response();
    };
    let Some(object) = value.as_object_mut() else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error":{"code":"restricted_decision_projection_failed","message":"Restricted authorization evidence could not be produced"}})),
        ).into_response();
    };
    object.insert(
        "restricted_domain_decision".into(),
        serde_json::to_value(decision).expect("decision projection is serializable"),
    );
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    parts.headers.insert(
        header::VARY,
        HeaderValue::from_static("X-IICP-Membership, X-IICP-Subject-Id"),
    );
    Response::from_parts(
        parts,
        Body::from(serde_json::to_vec(&value).expect("JSON serialization")),
    )
}

fn denied() -> Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":{"code":"restricted_domain_denied","message":"Restricted trust-domain membership is required"}}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    const DIRECTORY_DECISION_FIXTURE: &str =
        include_str!("../parity/restricted-trust-domain-directory-decision-v0.json");

    #[test]
    fn directory_decision_matches_shared_positive_vectors() {
        let fixture: serde_json::Value = serde_json::from_str(DIRECTORY_DECISION_FIXTURE).unwrap();
        let config = RestrictedDomainConfig {
            enabled: true,
            domain_id: "domain-test-a".into(),
            authority_id: "did:iicp:test:directory-a".into(),
            authority_key_id: "did:iicp:test:directory-a#key-1".into(),
            membership_epoch: 1,
            max_credential_ttl_seconds: 86_400,
        };
        for vector in fixture["vectors"].as_array().unwrap() {
            if vector["expected"] != "eligible" {
                continue;
            }
            let expected = &vector["projection"];
            let wire_operation = match expected["operation"].as_str().unwrap() {
                "dispatch_ticket" => "dispatch",
                value => value,
            };
            let decision = directory_decision(
                &config,
                wire_operation,
                AuthorizedMembership {
                    subject_kind: expected["subject_kind"].as_str().unwrap().into(),
                    generation: expected["membership_generation"].as_u64().unwrap(),
                    expires_at: expected["membership_expires_at"].as_i64().unwrap(),
                },
            )
            .unwrap();
            assert_eq!(
                serde_json::to_value(decision).unwrap(),
                *expected,
                "{}",
                vector["id"]
            );
        }
        assert!(directory_decision(
            &config,
            "heartbeat",
            AuthorizedMembership {
                subject_kind: "node".into(),
                generation: 1,
                expires_at: 1
            }
        )
        .is_none());
    }

    #[tokio::test]
    async fn projection_rewrites_json_and_cache_headers_without_stale_length() {
        let mut response = Json(serde_json::json!({"nodes": []})).into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_LENGTH, HeaderValue::from_static("12"));
        let response = project_decision(
            response,
            RestrictedDirectoryDecision {
                schema: "iicp.restricted-trust-domain.directory-decision.v0",
                profile: "urn:iicp:profile:restricted-trust-domain:v1",
                decision: "eligible",
                operation: "discovery",
                domain_id: "domain-test-a".into(),
                authority_id: "did:iicp:test:directory-a".into(),
                subject_kind: "client".into(),
                membership_generation: 7,
                membership_expires_at: 1_800_000_300,
            },
        )
        .await;
        assert!(response.headers().get(header::CONTENT_LENGTH).is_none());
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        let body = to_bytes(response.into_body(), MAX_BODY_BYTES)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["restricted_domain_decision"]["operation"],
            "discovery"
        );
        assert!(value["restricted_domain_decision"]
            .get("subject_id")
            .is_none());
    }

    #[test]
    fn protected_route_inventory_is_explicit() {
        assert_eq!(
            protected_operation(&Method::GET, "/api/v1/discover"),
            Some("discovery")
        );
        assert_eq!(
            protected_operation(&Method::POST, "/v1/register"),
            Some("registration")
        );
        assert_eq!(protected_operation(&Method::GET, "/health"), None);
    }
    #[test]
    fn invalid_enabled_configuration_fails_closed() {
        let cfg = RestrictedDomainConfig {
            enabled: true,
            domain_id: "".into(),
            authority_id: "a".into(),
            authority_key_id: "a#key-1".into(),
            membership_epoch: 1,
            max_credential_ttl_seconds: 60,
        };
        assert!(cfg.validate(false).is_err());
        let cfg = RestrictedDomainConfig {
            enabled: true,
            domain_id: "d".into(),
            authority_id: "a".into(),
            authority_key_id: "a#key-1".into(),
            membership_epoch: 1,
            max_credential_ttl_seconds: 60,
        };
        assert!(cfg.validate(true).is_err());
    }

    #[tokio::test]
    #[ignore = "requires disposable MySQL in IICP_TEST_DATABASE_URL"]
    async fn membership_rotation_scope_epoch_and_revocation_fail_closed() {
        let url = std::env::var("IICP_TEST_DATABASE_URL").expect("disposable database URL");
        let pool = crate::db::init_pool(&url).await.expect("pool");
        sqlx::raw_sql(include_str!(
            "../migrations/023_create_trust_domain_memberships.sql"
        ))
        .execute(&pool)
        .await
        .expect("membership schema");
        let subject = format!("node-{}", uuid::Uuid::new_v4());
        let config = RestrictedDomainConfig {
            enabled: true,
            domain_id: "test.example".into(),
            authority_id: "did:web:directory.test".into(),
            authority_key_id: "did:web:directory.test#key-1".into(),
            membership_epoch: 1,
            max_credential_ttl_seconds: 3600,
        };
        let service = RestrictedDomainService::new(config.clone(), Some(pool.clone())).unwrap();
        let first = service
            .issue("node", &subject, &["heartbeat".into()], 600)
            .await
            .unwrap();
        assert!(service.verify(&first, &subject, "heartbeat").await);
        assert!(!service.verify(&first, &subject, "peers").await);

        let second = service
            .issue("node", &subject, &["*".into()], 600)
            .await
            .unwrap();
        assert!(!service.verify(&first, &subject, "heartbeat").await);
        assert!(service.verify(&second, &subject, "peers").await);
        assert!(service
            .current_node_members(std::slice::from_ref(&subject))
            .await
            .contains(&subject));

        let epoch_service = RestrictedDomainService::new(
            RestrictedDomainConfig {
                membership_epoch: 3,
                ..config
            },
            Some(pool),
        )
        .unwrap();
        assert!(!epoch_service.verify(&second, &subject, "peers").await);
        assert!(service.revoke("node", &subject).await.unwrap());
        assert!(!service.verify(&second, &subject, "peers").await);
        assert!(service
            .current_node_members(std::slice::from_ref(&subject))
            .await
            .is_empty());
    }
}
