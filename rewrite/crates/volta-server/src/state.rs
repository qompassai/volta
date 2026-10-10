//! crates/volta-server/src/state.rs - shared application state.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use volta_core::config::{resolve_secret_ref, ServerConfig};
use volta_core::error::VoltaError;
use volta_core::sealed::TokenSealer;
use volta_core::store::Store;
use volta_crypto::signing::{IdentitySigner, IdentitySuite};

use crate::ephemeral::EphemeralStore;
use crate::webauthn::OperatorStore;

/// An A2A task record (SPEC 9.3). Tasks are node-local in the
/// single-node profile; the clustered profile shares them through
/// the state tier (SPEC 12.2).
#[derive(Clone, Debug)]
pub struct TaskRecord {
    /// Artifact objects produced so far.
    pub artifacts: Vec<serde_json::Value>,
    /// The A2A context id.
    pub context_id: String,
    /// Creation time (unix seconds).
    pub created_unix: u64,
    /// History events (status transitions).
    pub history: Vec<serde_json::Value>,
    /// The task id.
    pub id: String,
    /// Owning principal name, or `anonymous`.
    pub owner: String,
    /// The skill invoked.
    pub skill: String,
    /// Current state (SPEC 9.3 state vocabulary).
    pub state: String,
}

/// Token-bucket rate state, keyed by (class, key).
#[derive(Default)]
pub struct RateState {
    /// Buckets: key -> (tokens, last refill unix millis).
    pub buckets: BTreeMap<String, (f64, u64)>,
}

impl RateState {
    /// Take one token from a bucket; false when empty.
    pub fn take(&mut self, key: &str, capacity: f64, refill_per_sec: f64) -> bool {
        let now_ms = crate::http_util::unix_now() * 1000;
        let entry = self.buckets.entry(key.to_string()).or_insert((capacity, now_ms));
        let elapsed = (now_ms.saturating_sub(entry.1)) as f64 / 1000.0;
        entry.0 = (entry.0 + elapsed * refill_per_sec).min(capacity);
        entry.1 = now_ms;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Everything the handlers share.
pub struct AppState {
    /// Operator bootstrap token (first enrollment only).
    pub bootstrap_token: String,
    /// Loaded server configuration.
    pub config: Arc<ServerConfig>,
    /// Ephemeral-key store (metadata durable, secrets memory-only).
    pub ephemeral: Arc<EphemeralStore>,
    /// The server's own signing identity, when configured.
    pub identity: Option<Arc<IdentitySigner>>,
    /// Configured identity fingerprint (card `kid`).
    pub identity_fingerprint: Option<String>,
    /// Operator (WebAuthn) store.
    pub operator: Arc<OperatorStore>,
    /// Rate-limit buckets.
    pub rate: Arc<Mutex<RateState>>,
    /// Sealed-token sealer (links and manage tokens).
    pub sealer: Arc<TokenSealer>,
    /// Process start (unix seconds).
    pub started_unix: u64,
    /// The key store.
    pub store: Arc<Mutex<Store>>,
    /// A2A tasks by id.
    pub tasks: Arc<Mutex<BTreeMap<String, TaskRecord>>>,
}

impl AppState {
    /// Build state from a loaded configuration: opens the stores,
    /// resolves the token secret and the identity seed, and
    /// generates a one-time bootstrap token.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` for storage or secret failures.
    pub fn new(config: ServerConfig) -> Result<Self, VoltaError> {
        let data_dir = std::path::PathBuf::from(&config.data_dir);
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let store = Store::open(&data_dir)?;
        let token_secret = resolve_secret_ref(&config.token_secret_ref)?;
        let sealer = TokenSealer::new(&token_secret);
        let ephemeral = EphemeralStore::open(&data_dir)?;
        let operator = OperatorStore::open(&data_dir, &config)?;
        let (identity, identity_fingerprint) = match &config.identity {
            Some(identity_config) => {
                let seed = resolve_secret_ref(&identity_config.secret_ref)?;
                let suite = IdentitySuite::parse(&identity_config.suite)?;
                let signer = IdentitySigner::from_seed(suite, &seed)?;
                (Some(Arc::new(signer)), Some(identity_config.fingerprint.clone()))
            }
            None => (None, None),
        };
        // First-enrollment bootstrap: if no credentials and no
        // bootstrap on record, mint one, keep only its hash in
        // the operator store, and expose the plaintext once (the
        // server main prints it to the host console; `voltactl
        // operator bootstrap` does the same on demand).
        let bootstrap_token = if operator.any_credentials() || operator.has_bootstrap() {
            String::new()
        } else {
            let mut bootstrap_bytes = [0u8; 24];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bootstrap_bytes);
            let token = crate::http_util::b64u_encode(&bootstrap_bytes);
            operator.set_bootstrap_hash(&crate::http_util::sha256_hex(token.as_bytes()))?;
            token
        };
        Ok(Self {
            bootstrap_token,
            config: Arc::new(config),
            ephemeral: Arc::new(ephemeral),
            identity,
            identity_fingerprint,
            operator: Arc::new(operator),
            rate: Arc::new(Mutex::new(RateState::default())),
            sealer: Arc::new(sealer),
            started_unix: crate::http_util::unix_now(),
            store: Arc::new(Mutex::new(store)),
            tasks: Arc::new(Mutex::new(BTreeMap::new())),
        })
    }

    /// Rate-limit gate for the by-email class (SPEC 6.2.6 floors:
    /// at least 1 request/minute per source key is *allowed*;
    /// buckets here cap abuse above the floor).
    ///
    /// # Errors
    /// `E_RATE_LIMITED` when the bucket is empty.
    pub fn rate_check(&self, class: &str, key: &str) -> Result<(), VoltaError> {
        let (capacity, refill) = match class {
            "by-email" => (10.0, 10.0 / 60.0),
            "by-fingerprint" => (60.0, 5.0),
            _ => (60.0, 5.0),
        };
        let mut rate = self.rate.lock().map_err(|_| VoltaError::Forbidden("rate state".into()))?;
        if rate.take(&format!("{class}:{key}"), capacity, refill) {
            Ok(())
        } else {
            Err(VoltaError::RateLimited)
        }
    }
}
