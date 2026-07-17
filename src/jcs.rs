// SPDX-License-Identifier: Apache-2.0
//! Isolated RFC 8785 support for opt-in signed receipt profiles.

use serde_json::Value;
use std::fmt::{Display, Formatter};

pub(crate) const JCS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug)]
pub(crate) enum JcsError {
    UnsafeInteger,
    Serialization(serde_json::Error),
}

impl Display for JcsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeInteger => write!(
                f,
                "JCS integer exceeds the interoperable IEEE-754 safe range; encode it as a string"
            ),
            Self::Serialization(error) => write!(f, "JCS serialization failed: {error}"),
        }
    }
}

impl std::error::Error for JcsError {}

fn validate(value: &Value) -> Result<(), JcsError> {
    match value {
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                if value.unsigned_abs() > JCS_MAX_SAFE_INTEGER {
                    return Err(JcsError::UnsafeInteger);
                }
            } else if let Some(value) = number.as_u64() {
                if value > JCS_MAX_SAFE_INTEGER {
                    return Err(JcsError::UnsafeInteger);
                }
            }
        }
        Value::Array(values) => {
            for value in values {
                validate(value)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                validate(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn canonicalize_jcs(value: &Value) -> Result<Vec<u8>, JcsError> {
    validate(value)?;
    serde_jcs::to_vec(value).map_err(JcsError::Serialization)
}

#[cfg(test)]
mod tests {
    use super::canonicalize_jcs;
    use serde_json::{json, Value};

    #[test]
    fn shared_vectors_and_unsafe_integer_boundary() {
        let fixture: Value =
            serde_json::from_str(include_str!("../parity/cip-consumer-cosignature-v1.json"))
                .unwrap();
        assert_eq!(
            String::from_utf8(canonicalize_jcs(&fixture["canonical_vector"]["receipt"]).unwrap())
                .unwrap(),
            fixture["canonical_vector"]["canonical_json_utf8"]
        );
        for vector in fixture["jcs_vectors"].as_array().unwrap() {
            assert_eq!(
                String::from_utf8(canonicalize_jcs(&vector["input"]).unwrap()).unwrap(),
                vector["canonical_json_utf8"]
            );
        }
        assert!(canonicalize_jcs(&json!({"invalid": 9_007_199_254_740_992_u64})).is_err());
    }
}
