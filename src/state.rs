//! Shared HTTP application state and process-local admission counters.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::repo::NodeRepository;
use crate::validate::Env;

pub(crate) type RegisterRateMap = Arc<Mutex<HashMap<String, (u32, u64)>>>;

pub(crate) fn new_register_rate() -> RegisterRateMap {
    Arc::new(Mutex::new(HashMap::new()))
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) repo: Arc<dyn NodeRepository>,
    pub(crate) env: Env,
    /// Ed25519 event-signing key. `None` retains the documented unsigned
    /// non-production behavior; production startup rejects that state.
    pub(crate) signing_key: Option<String>,
    /// Served identity and public endpoint. Replica mode binds these to the
    /// replica rather than impersonating the Genesis Seed.
    pub(crate) directory_did: String,
    pub(crate) directory_service_endpoint: String,
    /// IICP-E034 registration counter keyed by source IP.
    pub(crate) register_rate: RegisterRateMap,
    /// Adoption-gated E050 hardening; production activation remains external.
    pub(crate) strict_e050_secured: bool,
    /// TLS identity verification can be bypassed only in explicit testbeds.
    pub(crate) allow_insecure_tls: bool,
    /// Local tests may disable dial-back; production never does.
    pub(crate) skip_liveness_check: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_rate_map_starts_empty_and_is_shared() {
        let map = new_register_rate();
        map.lock()
            .expect("register rate lock")
            .insert("source".into(), (1, 2));
        assert_eq!(
            Arc::clone(&map).lock().expect("register rate lock").len(),
            1
        );
    }
}
