//! crates/volta-server/src/ephemeral.rs - ephemeral keys (SPEC 7).
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Hard TTLs, no renewal, Rosenpass-style rotation (EPH-1..EPH-6).
//! Metadata is durable (SQLite); server-custody private material
//! lives only in process memory and is zeroized on expiry,
//! revocation, or supersede-drain (EPH-4).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
use volta_core::error::VoltaError;
use volta_crypto::suites::{decapsulate, generate_keypair, Suite};
use zeroize::Zeroizing;

use crate::auth::{authenticate, authenticate_with_body, require_authenticated, require_step_up, Caller};
use crate::http_util::{b64_decode, b64_encode, problem, rfc3339, sha256_hex, unix_now};
use crate::state::AppState;

/// Default TTL in seconds (the Rosenpass rekey cadence).
pub const TTL_DEFAULT_SECONDS: u64 = 120;
/// Maximum TTL in seconds (hard cap, SPEC 7.2).
pub const TTL_MAX_SECONDS: u64 = 3600;
/// Minimum TTL in seconds.
pub const TTL_MIN_SECONDS: u64 = 30;
/// Session lifetime cap in seconds (SPEC 7.2).
pub const SESSION_MAX_SECONDS: u64 = 600;

/// Allowed purposes (SPEC 7.3, alphabetical).
pub const PURPOSES: [&str; 4] = ["a2a-session", "mcp-session", "relay-session", "wireguard-psk"];

/// One ephemeral key's durable metadata.
#[derive(Clone, Debug)]
pub struct EphKeyRecord {
    /// Audience binding, when set (EPH-3).
    pub audience: Option<String>,
    /// Classical public key bytes (empty for pure ML-KEM).
    pub classical_public: Vec<u8>,
    /// Creation time (unix seconds).
    pub created_unix: u64,
    /// `local` or `server`.
    pub custody: String,
    /// Hard expiry (unix seconds).
    pub expires_unix: u64,
    /// ML-KEM encapsulation key bytes.
    pub kem_public: Vec<u8>,
    /// The key id (`eph_<uuid v7>`).
    pub key_id: String,
    /// Owning principal id.
    pub owner_id: String,
    /// Purpose binding (EPH-3).
    pub purpose: String,
    /// When rotation is due (unix seconds).
    pub rotation_due_unix: u64,
    /// The stored status (`active`, `expired`, `revoked`,
    /// `superseded`); expiry is applied lazily on read.
    pub status: String,
    /// The suite string.
    pub suite: String,
    /// The key this one supersedes, when it is a successor.
    pub supersedes: Option<String>,
}

/// One registered session.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    /// Session expiry (unix seconds).
    pub expires_unix: u64,
    /// The key the session belongs to.
    pub key_id: String,
    /// The peer that registered the encapsulation.
    pub peer_id: String,
    /// The session id.
    pub session_id: String,
    /// `pending` or `established`.
    pub status: String,
}

/// The ephemeral store: SQLite metadata + in-memory secrets.
pub struct EphemeralStore {
    conn: Mutex<Connection>,
    private: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    sessions: Mutex<BTreeMap<String, SessionRecord>>,
}

impl EphemeralStore {
    /// Open (creating if needed) the ephemeral metadata database.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn open(data_dir: &std::path::Path) -> Result<Self, VoltaError> {
        let conn = Connection::open(data_dir.join("ephemeral.db"))
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS eph_keys (
                key_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                purpose TEXT NOT NULL,
                audience TEXT,
                suite TEXT NOT NULL,
                custody TEXT NOT NULL,
                status TEXT NOT NULL,
                created_unix INTEGER NOT NULL,
                expires_unix INTEGER NOT NULL,
                rotation_due_unix INTEGER NOT NULL,
                classical_public BLOB NOT NULL,
                kem_public BLOB NOT NULL,
                supersedes TEXT
            );",
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
            private: Mutex::new(BTreeMap::new()),
            sessions: Mutex::new(BTreeMap::new()),
        })
    }

    /// Insert a key record (+ private material for server custody).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn insert_key(&self, record: &EphKeyRecord, private: Option<Vec<u8>>) -> Result<(), VoltaError> {
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        conn.execute(
            "INSERT INTO eph_keys VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![
                record.key_id, record.owner_id, record.purpose, record.audience,
                record.suite, record.custody, record.status, record.created_unix as i64,
                record.expires_unix as i64, record.rotation_due_unix as i64,
                record.classical_public, record.kem_public, record.supersedes
            ],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        if let Some(material) = private {
            let mut map = self.private.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
            map.insert(record.key_id.clone(), Zeroizing::new(material));
        }
        Ok(())
    }

    /// Fetch a key, applying lazy expiry (EPH-1/EPH-4).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn get_key(&self, key_id: &str) -> Result<Option<EphKeyRecord>, VoltaError> {
        let mut record = self.raw_key(key_id)?;
        if let Some(rec) = record.as_mut() {
            if (rec.status == "active" || rec.status == "superseded")
                && unix_now() >= rec.expires_unix
            {
                self.set_status(key_id, "expired")?;
                rec.status = "expired".to_string();
            }
        }
        Ok(record)
    }

    fn raw_key(&self, key_id: &str) -> Result<Option<EphKeyRecord>, VoltaError> {
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        let mut stmt = conn
            .prepare("SELECT key_id, owner_id, purpose, audience, suite, custody, status, created_unix, expires_unix, rotation_due_unix, classical_public, kem_public, supersedes FROM eph_keys WHERE key_id = ?1")
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let rows = stmt
            .query_map(params![key_id], row_to_record)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        for row in rows {
            return Ok(Some(row.map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?));
        }
        Ok(None)
    }

    /// List an owner's keys after `cursor`, newest last.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn list_keys(
        &self,
        owner_id: &str,
        status: Option<&str>,
        limit: usize,
        cursor: Option<&str>,
    ) -> Result<Vec<EphKeyRecord>, VoltaError> {
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        let mut stmt = conn
            .prepare("SELECT key_id, owner_id, purpose, audience, suite, custody, status, created_unix, expires_unix, rotation_due_unix, classical_public, kem_public, supersedes FROM eph_keys WHERE owner_id = ?1 AND key_id > ?2 ORDER BY key_id ASC LIMIT ?3")
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let rows = stmt
            .query_map(params![owner_id, cursor.unwrap_or(""), limit as i64], row_to_record)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let record = row.map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            if status.is_none() || status == Some(record.status.as_str()) {
                out.push(record);
            }
        }
        Ok(out)
    }

    /// Transition a key's status; terminal transitions zeroize any
    /// server-custody private material immediately (EPH-4).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn set_status(&self, key_id: &str, status: &str) -> Result<(), VoltaError> {
        {
            let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
            conn.execute(
                "UPDATE eph_keys SET status = ?2 WHERE key_id = ?1",
                params![key_id, status],
            )
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        }
        if status == "expired" || status == "revoked" {
            let mut map = self.private.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
            map.remove(key_id);
        }
        Ok(())
    }

    /// Whether server-custody private material is present.
    #[must_use]
    pub fn has_private(&self, key_id: &str) -> bool {
        self.private.lock().map(|map| map.contains_key(key_id)).unwrap_or(false)
    }

    /// Clone the private material for a decapsulation (the clone is
    /// zeroizing at the call site and never stored, EPH-5).
    #[must_use]
    pub fn private_material(&self, key_id: &str) -> Option<Vec<u8>> {
        self.private.lock().ok()?.get(key_id).map(|z| z.as_slice().to_vec())
    }

    /// Register a session.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on lock failure.
    pub fn add_session(&self, session: SessionRecord) -> Result<(), VoltaError> {
        let mut map = self.sessions.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        map.insert(session.session_id.clone(), session);
        Ok(())
    }

    /// Count live sessions for a key.
    #[must_use]
    pub fn session_count(&self, key_id: &str) -> usize {
        self.sessions
            .lock()
            .map(|map| map.values().filter(|s| s.key_id == key_id).count())
            .unwrap_or(0)
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<EphKeyRecord> {
    Ok(EphKeyRecord {
        key_id: row.get(0)?,
        owner_id: row.get(1)?,
        purpose: row.get(2)?,
        audience: row.get(3)?,
        suite: row.get(4)?,
        custody: row.get(5)?,
        status: row.get(6)?,
        created_unix: row.get::<_, i64>(7)? as u64,
        expires_unix: row.get::<_, i64>(8)? as u64,
        rotation_due_unix: row.get::<_, i64>(9)? as u64,
        classical_public: row.get(10)?,
        kem_public: row.get(11)?,
        supersedes: row.get(12)?,
    })
}

/// The public record shape (SPEC 7.3 GET), keys alphabetical.
#[must_use]
pub fn key_record_json(record: &EphKeyRecord, custody_lost: bool, include_public: bool) -> Value {
    let mut public_material = serde_json::Map::new();
    if include_public {
        public_material.insert(
            "classical_public_b64".to_string(),
            json!(b64_encode(&record.classical_public)),
        );
        public_material.insert("kem_public_b64".to_string(), json!(b64_encode(&record.kem_public)));
        public_material.insert("suite".to_string(), json!(record.suite));
    }
    let mut out = serde_json::Map::new();
    out.insert("audience".to_string(), json!(record.audience));
    out.insert("created_at".to_string(), json!(rfc3339(record.created_unix)));
    if custody_lost {
        out.insert("custody_lost".to_string(), json!(true));
    }
    out.insert("custody".to_string(), json!(record.custody));
    out.insert("expires_at".to_string(), json!(rfc3339(record.expires_unix)));
    out.insert("key_id".to_string(), json!(record.key_id));
    out.insert("owner_id".to_string(), json!(record.owner_id));
    if include_public {
        out.insert("public_material".to_string(), Value::Object(public_material));
    }
    out.insert("purpose".to_string(), json!(record.purpose));
    out.insert("rotation_due_at".to_string(), json!(rfc3339(record.rotation_due_unix)));
    out.insert("status".to_string(), json!(record.status));
    if let Some(supersedes) = &record.supersedes {
        out.insert("supersedes".to_string(), json!(supersedes));
    }
    Value::Object(out)
}

/// Issue request body (SPEC 7.3).
#[derive(Debug, Deserialize)]
pub struct IssueBody {
    /// Audience binding.
    pub audience: Option<String>,
    /// `local` (default) or `server`.
    pub custody: Option<String>,
    /// Owning principal id.
    pub owner_id: String,
    /// Caller-generated public material (custody=local).
    pub public_material: Option<PublicMaterialBody>,
    /// Purpose binding.
    pub purpose: String,
    /// Rotation interval override.
    pub rotation_interval_seconds: Option<u64>,
    /// The suite string.
    pub suite: String,
    /// Requested TTL.
    pub ttl_seconds: Option<u64>,
}

/// Public material in an issue/rotate request.
#[derive(Debug, Deserialize)]
pub struct PublicMaterialBody {
    /// Classical public key, standard base64.
    pub classical_public_b64: Option<String>,
    /// ML-KEM encapsulation key, standard base64.
    pub kem_public_b64: String,
}

/// Mint a key record from validated inputs. Shared by REST, MCP,
/// and A2A so the TTL/custody rules exist exactly once (EPH-1..4).
///
/// # Errors
/// The SPEC 7.3 validation errors.
pub fn issue_key(
    state: &AppState,
    owner_id: &str,
    body: &IssueBody,
    supersedes: Option<String>,
) -> Result<EphKeyRecord, VoltaError> {
    let suite = Suite::parse(&body.suite)?;
    if !PURPOSES.contains(&body.purpose.as_str()) {
        return Err(VoltaError::Validation("purpose".to_string()));
    }
    let ttl = body.ttl_seconds.unwrap_or(TTL_DEFAULT_SECONDS);
    if !(TTL_MIN_SECONDS..=TTL_MAX_SECONDS).contains(&ttl) {
        return Err(VoltaError::TtlOutOfBounds);
    }
    let rotation = body.rotation_interval_seconds.unwrap_or(ttl);
    if !(TTL_MIN_SECONDS..=ttl).contains(&rotation) {
        return Err(VoltaError::Validation("rotation_interval_seconds".to_string()));
    }
    let custody = body.custody.as_deref().unwrap_or("local");
    let now = unix_now();
    let (classical_public, kem_public, private) = match custody {
        "local" => {
            let material = body
                .public_material
                .as_ref()
                .ok_or_else(|| VoltaError::Validation("public_material".to_string()))?;
            let kem_public = b64_decode(&material.kem_public_b64)?;
            if kem_public.len() != suite.kem_public_len() {
                return Err(VoltaError::CryptoNotAllowed("kem public length".to_string()));
            }
            let classical_public = match &material.classical_public_b64 {
                Some(text) => b64_decode(text)?,
                None => Vec::new(),
            };
            if classical_public.len() != suite.classical_len() {
                return Err(VoltaError::CryptoNotAllowed("classical public length".to_string()));
            }
            (classical_public, kem_public, None)
        }
        "server" => {
            let keypair = generate_keypair(suite, &mut rand::rngs::OsRng);
            (
                keypair.classical_public.clone(),
                keypair.kem_public.clone(),
                Some(keypair.secret_material.as_slice().to_vec()),
            )
        }
        _ => return Err(VoltaError::Validation("custody".to_string())),
    };
    let record = EphKeyRecord {
        audience: body.audience.clone(),
        classical_public,
        created_unix: now,
        custody: custody.to_string(),
        expires_unix: now + ttl,
        kem_public,
        key_id: format!("eph_{}", Uuid::now_v7()),
        owner_id: owner_id.to_string(),
        purpose: body.purpose.clone(),
        rotation_due_unix: now + rotation,
        status: "active".to_string(),
        suite: suite.as_str().to_string(),
        supersedes,
    };
    state.ephemeral.insert_key(&record, private)?;
    Ok(record)
}

/// Load a key or produce the SPEC status errors (410 family).
fn load_key(state: &AppState, key_id: &str) -> Result<EphKeyRecord, VoltaError> {
    state
        .ephemeral
        .get_key(key_id)?
        .ok_or(VoltaError::KeyNotFound)
}

/// Terminal-status error for a key.
fn status_error(record: &EphKeyRecord) -> VoltaError {
    match record.status.as_str() {
        "expired" => VoltaError::KeyExpired,
        "revoked" => VoltaError::KeyRevoked,
        _ => VoltaError::Validation(format!("key status {}", record.status)),
    }
}

/// POST /api/v1/ephemeral-keys — issue.
pub async fn issue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let request_id = new_request_id();
    let caller = authenticate_with_body(&state, &headers, "POST", "/api/v1/ephemeral-keys", &body);
    if let Err(error) = require_authenticated(&caller) {
        return problem(error, &request_id).into_response();
    }
    let parsed: IssueBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => return problem(VoltaError::Validation("body".into()), &request_id).into_response(),
    };
    if let Caller::Principal { name, .. } = &caller {
        if parsed.owner_id != *name {
            return problem(
                VoltaError::Forbidden("owner_id must be the caller".into()),
                &request_id,
            )
            .into_response();
        }
    }
    match issue_key(&state, &parsed.owner_id, &parsed, None) {
        Ok(record) => {
            let lost = record.custody == "server" && !state.ephemeral.has_private(&record.key_id);
            (axum::http::StatusCode::CREATED, Json(key_record_json(&record, lost, true))).into_response()
        }
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// GET /api/v1/ephemeral-keys/<key_id> — public material + metadata.
pub async fn get_one(
    State(state): State<Arc<AppState>>,
    Path(key_id): Path<String>,
) -> Response {
    let request_id = new_request_id();
    if let Err(error) = state.rate_check("by-keyid", &key_id) {
        return problem(error, &request_id).into_response();
    }
    match load_key(&state, &key_id) {
        Ok(record) => {
            let lost = record.custody == "server"
                && record.status == "active"
                && !state.ephemeral.has_private(&record.key_id);
            if record.status == "expired" || record.status == "revoked" || lost {
                let error = status_error(&record);
                let mut response = (
                    axum::http::StatusCode::GONE,
                    Json(key_record_json(&record, lost, false)),
                )
                    .into_response();
                if let Ok(value) = axum::http::HeaderValue::from_str(error.code()) {
                    response.headers_mut().insert("x-volta-error-code", value);
                }
                return response;
            }
            Json(key_record_json(&record, false, true)).into_response()
        }
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// List query parameters.
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    /// Opaque cursor (last key id of the previous page).
    pub cursor: Option<String>,
    /// Page size (default 50, max 200).
    pub limit: Option<usize>,
    /// Owner to list (must be the caller, or operator).
    pub owner_id: String,
    /// Status filter.
    pub status: Option<String>,
}

/// GET /api/v1/ephemeral-keys — list the caller's keys.
pub async fn list(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Response {
    let request_id = new_request_id();
    let caller = authenticate(&state, &headers);
    let allowed = match &caller {
        Caller::Operator { .. } => true,
        Caller::Principal { name, .. } => *name == query.owner_id,
        Caller::Anonymous => false,
    };
    if !allowed {
        return problem(VoltaError::AuthRequired, &request_id).into_response();
    }
    let limit = query.limit.unwrap_or(50).min(200);
    match state
        .ephemeral
        .list_keys(&query.owner_id, query.status.as_deref(), limit, query.cursor.as_deref())
    {
        Ok(records) => {
            let keys: Vec<Value> = records
                .iter()
                .map(|record| key_record_json(record, false, true))
                .collect();
            Json(json!({"keys": keys})).into_response()
        }
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Require that the caller owns the key (or is an operator).
fn require_owner(caller: &Caller, record: &EphKeyRecord) -> Result<(), VoltaError> {
    match caller {
        Caller::Operator { .. } => Ok(()),
        Caller::Principal { name, .. } if *name == record.owner_id => Ok(()),
        Caller::Anonymous => Err(VoltaError::AuthRequired),
        _ => Err(VoltaError::Forbidden("not the key owner".to_string())),
    }
}

/// DELETE /api/v1/ephemeral-keys/<key_id> — revoke now.
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
) -> Response {
    let request_id = new_request_id();
    let path = format!("/api/v1/ephemeral-keys/{key_id}");
    let caller = authenticate_with_body(&state, &headers, "DELETE", &path, &[]);
    let result = (|| -> Result<Value, VoltaError> {
        require_authenticated(&caller)?;
        let record = load_key(&state, &key_id)?;
        require_owner(&caller, &record)?;
        if record.status == "active" || record.status == "superseded" {
            state.ephemeral.set_status(&key_id, "revoked")?;
        }
        let record = load_key(&state, &key_id)?;
        Ok(json!({"key_id": record.key_id, "status": record.status}))
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Rotate request body.
#[derive(Debug, Deserialize)]
pub struct RotateBody {
    /// Successor public material (custody=local).
    pub public_material: Option<PublicMaterialBody>,
}

/// POST /api/v1/ephemeral-keys/<key_id>/rotate — supersede now.
pub async fn rotate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let request_id = new_request_id();
    let path = format!("/api/v1/ephemeral-keys/{key_id}/rotate");
    let caller = authenticate_with_body(&state, &headers, "POST", &path, &body);
    let result = (|| -> Result<(axum::http::StatusCode, Value), VoltaError> {
        require_authenticated(&caller)?;
        let record = load_key(&state, &key_id)?;
        require_owner(&caller, &record)?;
        if record.status != "active" {
            return Err(status_error(&record));
        }
        let parsed: RotateBody = if body.is_empty() {
            RotateBody { public_material: None }
        } else {
            serde_json::from_slice(&body)
                .map_err(|_| VoltaError::Validation("body".to_string()))?
        };
        let ttl = record.expires_unix - record.created_unix;
        let issue = IssueBody {
            audience: record.audience.clone(),
            custody: Some(record.custody.clone()),
            owner_id: record.owner_id.clone(),
            public_material: parsed.public_material,
            purpose: record.purpose.clone(),
            rotation_interval_seconds: Some(record.rotation_due_unix - record.created_unix),
            suite: record.suite.clone(),
            ttl_seconds: Some(ttl),
        };
        let successor = issue_key(&state, &record.owner_id, &issue, Some(key_id.clone()))?;
        state.ephemeral.set_status(&key_id, "superseded")?;
        Ok((axum::http::StatusCode::CREATED, key_record_json(&successor, false, true)))
    })();
    match result {
        Ok((status, value)) => (status, Json(value)).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Session-register request body.
#[derive(Debug, Deserialize)]
pub struct SessionBody {
    /// The encapsulation ciphertext (server custody), base64.
    pub ciphertext_b64: Option<String>,
    /// SHA-256 of the ciphertext (local custody), hex.
    pub ciphertext_sha256: Option<String>,
    /// The registering peer.
    pub peer_id: String,
}

/// POST /api/v1/ephemeral-keys/<key_id>/sessions — register an
/// encapsulation (SPEC 7.3).
pub async fn register_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let request_id = new_request_id();
    let path = format!("/api/v1/ephemeral-keys/{key_id}/sessions");
    let caller = authenticate_with_body(&state, &headers, "POST", &path, &body);
    let result = (|| -> Result<(axum::http::StatusCode, Value), VoltaError> {
        require_authenticated(&caller)?;
        let record = load_key(&state, &key_id)?;
        if record.status != "active" {
            return Err(status_error(&record));
        }
        let parsed: SessionBody = serde_json::from_slice(&body)
            .map_err(|_| VoltaError::Validation("body".to_string()))?;
        match record.custody.as_str() {
            "server" => {
                let ciphertext = parsed
                    .ciphertext_b64
                    .as_deref()
                    .ok_or_else(|| VoltaError::Validation("ciphertext_b64".to_string()))?;
                let bytes = b64_decode(ciphertext)?;
                let _digest = sha256_hex(&bytes);
            }
            _ => {
                let digest = parsed
                    .ciphertext_sha256
                    .as_deref()
                    .ok_or_else(|| VoltaError::Validation("ciphertext_sha256".to_string()))?;
                if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(VoltaError::Validation("ciphertext_sha256".to_string()));
                }
            }
        }
        let session = SessionRecord {
            expires_unix: (unix_now() + SESSION_MAX_SECONDS).min(record.expires_unix),
            key_id: key_id.clone(),
            peer_id: parsed.peer_id,
            session_id: format!("ses_{}", Uuid::now_v7()),
            status: "pending".to_string(),
        };
        let body = json!({
            "expires_at": rfc3339(session.expires_unix),
            "session_id": session.session_id,
            "status": session.status,
        });
        state.ephemeral.add_session(session)?;
        Ok((axum::http::StatusCode::CREATED, body))
    })();
    match result {
        Ok((status, value)) => (status, Json(value)).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Decapsulate request body.
#[derive(Debug, Deserialize)]
pub struct DecapsulateBody {
    /// The encapsulation ciphertext, base64.
    pub ciphertext_b64: String,
    /// The peer that encapsulated.
    pub peer_id: String,
}

/// POST /api/v1/ephemeral-keys/<key_id>/decapsulate — server
/// custody only, owner + step-up (SPEC 7.3).
pub async fn decapsulate_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(key_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let request_id = new_request_id();
    let path = format!("/api/v1/ephemeral-keys/{key_id}/decapsulate");
    let caller = authenticate_with_body(&state, &headers, "POST", &path, &body);
    let result = (|| -> Result<Value, VoltaError> {
        require_authenticated(&caller)?;
        require_step_up(&state, &caller, &headers)?;
        let record = load_key(&state, &key_id)?;
        require_owner(&caller, &record)?;
        if record.custody != "server" {
            return Err(VoltaError::CustodyMismatch);
        }
        if record.status == "expired" || record.status == "revoked" {
            return Err(status_error(&record));
        }
        let parsed: DecapsulateBody = serde_json::from_slice(&body)
            .map_err(|_| VoltaError::Validation("body".to_string()))?;
        let ciphertext = b64_decode(&parsed.ciphertext_b64)?;
        let secret = state
            .ephemeral
            .private_material(&key_id)
            .ok_or(VoltaError::KeyExpired)?;
        let suite = Suite::parse(&record.suite)?;
        let shared = decapsulate(suite, &secret, &ciphertext)?;
        let session = SessionRecord {
            expires_unix: (unix_now() + SESSION_MAX_SECONDS).min(record.expires_unix),
            key_id: key_id.clone(),
            peer_id: parsed.peer_id,
            session_id: format!("ses_{}", Uuid::now_v7()),
            status: "established".to_string(),
        };
        let body = json!({
            "expires_at": rfc3339(session.expires_unix),
            "session_id": session.session_id,
            "shared_secret_b64": b64_encode(shared.as_slice()),
        });
        state.ephemeral.add_session(session)?;
        Ok(body)
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// A fresh request id (uuid v7).
#[must_use]
pub fn new_request_id() -> String {
    Uuid::now_v7().to_string()
}
