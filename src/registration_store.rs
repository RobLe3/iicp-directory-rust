// SPDX-License-Identifier: Apache-2.0
//! Transactional MySQL registration persistence.

use sqlx::{MySql, Pool};

use crate::repo::{NodeRecord, RepoError};
use crate::reputation;

pub(crate) async fn hash_tokens(rec: &NodeRecord) -> Result<(String, String), RepoError> {
    let plain_token = rec.node_token.clone().unwrap_or_default();
    let plain_proxy = rec.proxy_token.clone().unwrap_or_default();
    let (token_hash, proxy_hash) = tokio::join!(
        tokio::task::spawn_blocking(move || bcrypt::hash(plain_token, 12)),
        tokio::task::spawn_blocking(move || bcrypt::hash(plain_proxy, 12)),
    );
    match (
        completed_bcrypt_hash(token_hash),
        completed_bcrypt_hash(proxy_hash),
    ) {
        (Ok(token_hash), Ok(proxy_hash)) => Ok((token_hash, proxy_hash)),
        _ => Err(RepoError::Persistence),
    }
}

fn completed_bcrypt_hash(
    task: Result<Result<String, bcrypt::BcryptError>, tokio::task::JoinError>,
) -> Result<String, RepoError> {
    match task {
        Ok(Ok(hash)) => Ok(hash),
        _ => Err(RepoError::Persistence),
    }
}

async fn upsert_node(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    rec: &NodeRecord,
    token_hash: &str,
    proxy_hash: &str,
) -> Result<(), RepoError> {
    sqlx::query(
        r#"INSERT INTO nodes
             (id, endpoint, region, available, relay_capable, node_token_hash, node_hmac_key,
              proxy_token_hash, max_concurrent, tokens_per_min, reputation_score,
              reputation_model, reputation_epoch, status,
              operator_pubkey, operator_verified, operator_trust_tier, backend,
              sdk_language, implementation_name, implementation_version, sdk_compatibility_version, sdk_version,
              supported_receipt_profiles, public_listing, operator_url, policy_manifest,
              cx_public_key, credit_cost_multiplier, pricing_model)
           VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, 0, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE
             endpoint = VALUES(endpoint), region = VALUES(region), available = 1,
             relay_capable = VALUES(relay_capable), status = 'active',
             node_token_hash = VALUES(node_token_hash),
             node_hmac_key = VALUES(node_hmac_key),
             proxy_token_hash = VALUES(proxy_token_hash),
             operator_pubkey = VALUES(operator_pubkey),
             operator_verified = VALUES(operator_verified),
             operator_trust_tier = VALUES(operator_trust_tier),
             backend = VALUES(backend),
             sdk_language = VALUES(sdk_language),
             implementation_name = VALUES(implementation_name),
             implementation_version = VALUES(implementation_version),
             sdk_compatibility_version = VALUES(sdk_compatibility_version),
             sdk_version = VALUES(sdk_version),
             supported_receipt_profiles = VALUES(supported_receipt_profiles),
             public_listing = VALUES(public_listing),
             operator_url = VALUES(operator_url),
             policy_manifest = VALUES(policy_manifest),
             cx_public_key = VALUES(cx_public_key),
             credit_cost_multiplier = VALUES(credit_cost_multiplier),
             pricing_model = VALUES(pricing_model)
             -- reputation_score intentionally NOT updated (ADR-026 anti-laundering)"#,
    )
    .bind(&rec.node.node_id)
    .bind(&rec.node.endpoint)
    .bind(&rec.node.region)
    .bind(rec.node.relay_capable.unwrap_or(false))
    .bind(token_hash)
    .bind(rec.node_hmac_key.clone().unwrap_or_default())
    .bind(proxy_hash)
    .bind(rec.node.max_concurrent)
    .bind(reputation::STARTING_SCORE as f32)
    .bind(&rec.node.reputation_model)
    .bind(&rec.node.reputation_epoch)
    .bind(&rec.node.operator_pubkey)
    .bind(rec.node.operator_verified)
    .bind(&rec.node.operator_trust_tier)
    .bind(&rec.node.backend)
    .bind(&rec.node.sdk_language)
    .bind(&rec.node.implementation_name)
    .bind(&rec.node.implementation_version)
    .bind(&rec.node.sdk_compatibility_version)
    .bind(&rec.node.sdk_version)
    .bind(
        rec.node
            .consumer_cosignature_ready
            .then_some("[\"consumer_cosignature_v1\"]"),
    )
    .bind(rec.node.public_listing)
    .bind(&rec.node.operator_url)
    .bind(
        rec.node
            .policy_manifest
            .as_ref()
            .map(serde_json::Value::to_string),
    )
    .bind(
        rec.node
            .public_key
            .as_ref()
            .map(serde_json::Value::to_string),
    )
    .bind(rec.node.credit_cost_multiplier)
    .bind(&rec.node.pricing_model)
    .execute(&mut **transaction)
    .await
    .map_err(|_| RepoError::Persistence)?;
    Ok(())
}

async fn replace_relations(
    transaction: &mut sqlx::Transaction<'_, MySql>,
    rec: &NodeRecord,
) -> Result<(), RepoError> {
    sqlx::query("DELETE FROM capabilities WHERE node_id = ?")
        .bind(&rec.node.node_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RepoError::Persistence)?;
    if !rec.capabilities.is_empty() {
        for capability in &rec.capabilities {
            let models =
                serde_json::to_string(&capability.models).map_err(|_| RepoError::Persistence)?;
            let input_modalities = serde_json::to_string(&capability.input_modalities)
                .map_err(|_| RepoError::Persistence)?;
            let output_modalities = serde_json::to_string(&capability.output_modalities)
                .map_err(|_| RepoError::Persistence)?;
            let features =
                serde_json::to_string(&capability.features).map_err(|_| RepoError::Persistence)?;
            let execution_capabilities = serde_json::to_string(&capability.execution_capabilities)
                .map_err(|_| RepoError::Persistence)?;
            let limits =
                serde_json::to_string(&capability.limits).map_err(|_| RepoError::Persistence)?;
            let supported_profiles = serde_json::to_string(&capability.supported_profiles)
                .map_err(|_| RepoError::Persistence)?;
            let claim_provenance = capability
                .claim_provenance
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|_| RepoError::Persistence)?;
            let extensions = serde_json::to_string(&capability.extensions)
                .map_err(|_| RepoError::Persistence)?;
            sqlx::query(
                "INSERT INTO capabilities (node_id, intent, capability_version, capability_phase, variant_id, models, max_tokens, input_modalities, output_modalities, features, execution_capabilities, capability_limits, supported_profiles, claim_provenance, extensions, quantization, inference_engine) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&rec.node.node_id)
            .bind(&capability.intent)
            .bind(&capability.version)
            .bind(capability.phase)
            .bind(&capability.variant_id)
            .bind(&models)
            .bind(capability.max_tokens.unwrap_or(0))
            .bind(&input_modalities)
            .bind(&output_modalities)
            .bind(&features)
            .bind(&execution_capabilities)
            .bind(&limits)
            .bind(&supported_profiles)
            .bind(&claim_provenance)
            .bind(&extensions)
            .bind(&capability.quantization)
            .bind(&capability.inference_engine)
            .execute(&mut **transaction)
            .await
            .map_err(|_| RepoError::Persistence)?;
        }
    } else {
        let models = serde_json::to_string(&rec.node.models).map_err(|_| RepoError::Persistence)?;
        for intent in &rec.intents {
            let supported_profiles = serde_json::to_string(
                rec.capability_profiles
                    .get(intent)
                    .map(Vec::as_slice)
                    .unwrap_or(&[]),
            )
            .map_err(|_| RepoError::Persistence)?;
            sqlx::query(
            "INSERT INTO capabilities (node_id, intent, models, max_tokens, supported_profiles) VALUES (?, ?, ?, 0, ?)",
        )
        .bind(&rec.node.node_id)
        .bind(intent)
        .bind(&models)
        .bind(&supported_profiles)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RepoError::Persistence)?;
        }
    }
    sqlx::query("DELETE FROM availability_windows WHERE node_id = ?")
        .bind(&rec.node.node_id)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RepoError::Persistence)?;
    for window in &rec.availability {
        sqlx::query(
            "INSERT INTO availability_windows (node_id, start_time, end_time, share) VALUES (?, ?, ?, ?)",
        )
        .bind(&rec.node.node_id)
        .bind(&window.start)
        .bind(&window.end)
        .bind(window.share)
        .execute(&mut **transaction)
        .await
        .map_err(|_| RepoError::Persistence)?;
    }
    Ok(())
}

pub(crate) async fn persist(
    pool: &Pool<MySql>,
    rec: &NodeRecord,
    token_hash: &str,
    proxy_hash: &str,
) -> Result<(), RepoError> {
    let mut transaction = pool.begin().await.map_err(|_| RepoError::Persistence)?;
    upsert_node(&mut transaction, rec, token_hash, proxy_hash).await?;
    replace_relations(&mut transaction, rec).await?;
    transaction
        .commit()
        .await
        .map_err(|_| RepoError::Persistence)
}
