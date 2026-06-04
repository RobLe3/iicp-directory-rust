// SPDX-License-Identifier: Apache-2.0
//! JWT issuance and verification — Phase 4 auth (JwtService parity).
//!
//! The PHP directory issues HS256 JWTs at registration (`JwtService::issue()`).
//! The signing secret is derived from APP_KEY (base64-stripped if prefixed `base64:`).
//! A valid JWT is the primary auth path; bcrypt bearer fallback is provided for
//! nodes that have not yet re-registered since the JWT upgrade was deployed.
//!
//! Sub-claim: the node_id. Issuer: "iicp.network". Expiry: 1 hour.
//! Re-registration issues a fresh JWT + re-hashes bcrypt, so clients always get a JWT.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims (HS256, sub = node_id, iss = iicp.network, exp = now+3600).
#[derive(Debug, Serialize, Deserialize)]
pub struct NodeClaims {
    pub sub: String, // node_id
    pub iss: String,
    pub iat: u64,
    pub exp: u64,
}

/// Derive the JWT signing secret from APP_KEY env var (matches PHP JwtService).
/// PHP stores APP_KEY as "base64:<base64-encoded bytes>". Strip the prefix and decode.
pub fn jwt_secret() -> Vec<u8> {
    let key = std::env::var("APP_KEY").unwrap_or_default();
    if let Some(b64) = key.strip_prefix("base64:") {
        base64_decode(b64).unwrap_or_else(|_| key.into_bytes())
    } else {
        key.into_bytes()
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [0u8; 256];
    for (i, &c) in alphabet.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let input: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut i = 0;
    while i + 3 < input.len() {
        let a = table[input[i] as usize] as u32;
        let b = table[input[i + 1] as usize] as u32;
        let c = table[input[i + 2] as usize] as u32;
        let d = table[input[i + 3] as usize] as u32;
        let n = (a << 18) | (b << 12) | (c << 6) | d;
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
        out.push(n as u8);
        i += 4;
    }
    if i + 2 < input.len() {
        let a = table[input[i] as usize] as u32;
        let b = table[input[i + 1] as usize] as u32;
        let c = table[input[i + 2] as usize] as u32;
        let n = (a << 18) | (b << 12) | (c << 6);
        out.push((n >> 16) as u8);
        out.push((n >> 8) as u8);
    } else if i + 1 < input.len() {
        let a = table[input[i] as usize] as u32;
        let b = table[input[i + 1] as usize] as u32;
        let n = (a << 18) | (b << 12);
        out.push((n >> 16) as u8);
    }
    if out.is_empty() {
        Err(())
    } else {
        Ok(out)
    }
}

/// Issue a JWT for `node_id` using `secret`, valid for 1 hour.
fn issue_jwt_with_secret(node_id: &str, secret: &[u8]) -> Option<String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let claims = NodeClaims {
        sub: node_id.to_string(),
        iss: "iicp.network".to_string(),
        iat: now,
        exp: now + 3600,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .ok()
}

/// Verify a JWT using `secret`, return the node_id from `sub`.
fn verify_jwt_with_secret(token: &str, secret: &[u8]) -> Option<String> {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_issuer(&["iicp.network"]);
    decode::<NodeClaims>(token, &DecodingKey::from_secret(secret), &v)
        .ok()
        .map(|t| t.claims.sub)
}

/// Issue a JWT for `node_id`, valid for 1 hour. Returns None if APP_KEY is empty.
pub fn issue_jwt(node_id: &str) -> Option<String> {
    let secret = jwt_secret();
    if secret.is_empty() {
        return None;
    }
    issue_jwt_with_secret(node_id, &secret)
}

/// Verify a JWT and extract the node_id from `sub`. Returns None on invalid/expired.
pub fn verify_jwt(token: &str) -> Option<String> {
    let secret = jwt_secret();
    if secret.is_empty() {
        return None;
    }
    verify_jwt_with_secret(token, &secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-secret-key-that-is-long-enough";

    #[test]
    fn round_trip_jwt() {
        let token = issue_jwt_with_secret("node-abc", TEST_SECRET).unwrap();
        let node_id = verify_jwt_with_secret(&token, TEST_SECRET).unwrap();
        assert_eq!(node_id, "node-abc");
    }

    #[test]
    fn invalid_token_returns_none() {
        assert!(verify_jwt_with_secret("not.a.valid.jwt", TEST_SECRET).is_none());
    }

    #[test]
    fn wrong_secret_returns_none() {
        let token = issue_jwt_with_secret("node-x", TEST_SECRET).unwrap();
        assert!(verify_jwt_with_secret(&token, b"wrong-secret").is_none());
    }
}
