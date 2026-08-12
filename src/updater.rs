// SPDX-License-Identifier: Apache-2.0
//! Read-only release discovery. Installation and rollback remain in the guarded script.

use serde::{Deserialize, Serialize};

use crate::cli::UpdateAction;

const CRATE_API: &str = "https://crates.io/api/v1/crates/iicp-directory-rs";

#[derive(Deserialize)]
struct CrateEnvelope {
    #[serde(rename = "crate")]
    package: CrateRecord,
}

#[derive(Deserialize)]
struct CrateRecord {
    max_stable_version: Option<String>,
    max_version: String,
}

#[derive(Serialize)]
struct UpdateStatus {
    package: &'static str,
    current: &'static str,
    published: Option<String>,
    update_available: bool,
    source: &'static str,
}

async fn check_at(url: &str) -> Result<UpdateStatus, String> {
    let response = reqwest::Client::new()
        .get(url)
        .header(
            reqwest::header::USER_AGENT,
            "iicp-directory-rs update-check",
        )
        .send()
        .await
        .map_err(|error| format!("crates.io lookup failed: {error}"))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(UpdateStatus {
            package: "iicp-directory-rs",
            current: env!("CARGO_PKG_VERSION"),
            published: None,
            update_available: false,
            source: "crates.io",
        });
    }
    if !response.status().is_success() {
        return Err(format!("crates.io lookup returned {}", response.status()));
    }
    let envelope: CrateEnvelope = response
        .json()
        .await
        .map_err(|error| format!("invalid crates.io response: {error}"))?;
    let published = envelope
        .package
        .max_stable_version
        .unwrap_or(envelope.package.max_version);
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("invalid local package version: {error}"))?;
    let remote = semver::Version::parse(&published)
        .map_err(|error| format!("invalid published package version: {error}"))?;
    Ok(UpdateStatus {
        package: "iicp-directory-rs",
        current: env!("CARGO_PKG_VERSION"),
        published: Some(published),
        update_available: remote > current,
        source: "crates.io",
    })
}

pub(crate) async fn run(action: UpdateAction) -> Result<(), String> {
    match action {
        UpdateAction::Check { json } => {
            let status = check_at(CRATE_API).await?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&status).map_err(|error| error.to_string())?
                );
            } else if let Some(published) = status.published {
                println!(
                    "iicp-directory-rs {} (published {published}; update available: {})",
                    status.current, status.update_available
                );
            } else {
                println!(
                    "iicp-directory-rs {} (not yet published on crates.io)",
                    status.current
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_status_is_content_free() {
        let value = serde_json::to_value(UpdateStatus {
            package: "iicp-directory-rs",
            current: "0.1.10",
            published: Some("0.1.11".into()),
            update_available: true,
            source: "crates.io",
        })
        .unwrap();
        assert_eq!(value["update_available"], true);
        assert!(value.get("database_url").is_none());
    }
}
