//! crates/volta-server/src/webauthn.rs - WebAuthn operators (SPEC 10).
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Passkeys are the only operator credential (WA-3). Biometric
//! data never leaves the authenticator; the server stores only
//! credential public keys, ids, and counters (WA-1). UV is
//! required on every ceremony (WA-2); a non-increasing sign
//! counter locks the credential (clone detection, SPEC 10.3).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::Json;
use rusqlite::{params, Connection};
use serde::Deserialize;
use serde_json::{json, Value};
use url::Url;
use uuid::Uuid;
use volta_core::config::ServerConfig;
use volta_core::error::VoltaError;
use webauthn_rs::prelude::{
    Passkey, PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential,
    RegisterPublicKeyCredential, Webauthn, WebauthnBuilder,
};

use crate::http_util::{b64u_encode, problem, unix_now};
use crate::state::AppState;

/// Challenge lifetime in seconds (SPEC 10.4).
pub const CHALLENGE_TTL_SECONDS: u64 = 300;
/// Operator session lifetime in seconds (SPEC 10.3).
pub const SESSION_TTL_SECONDS: u64 = 900;

/// A pending ceremony (single-use, expiring).
struct ChallengeRecord {
    expires_unix: u64,
    kind: String,
    operator_id: String,
    state_json: String,
    step_up_for: Option<String>,
}

/// A live operator session.
struct SessionRecord {
    created_unix: u64,
    operator_id: String,
    step_up_unix: u64,
}

/// The operator store: durable credentials, volatile challenges
/// and sessions.
pub struct OperatorStore {
    challenges: Mutex<BTreeMap<String, ChallengeRecord>>,
    conn: Mutex<Connection>,
    sessions: Mutex<BTreeMap<String, SessionRecord>>,
    webauthn: Arc<Webauthn>,
}

impl OperatorStore {
    /// Open the operator database and build the WebAuthn engine
    /// from the configured RP id and origin.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` for storage or RP configuration failure.
    pub fn open(data_dir: &std::path::Path, config: &ServerConfig) -> Result<Self, VoltaError> {
        let conn = Connection::open(data_dir.join("operator.db"))
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS bootstrap_tokens (
                token_hash TEXT PRIMARY KEY
            );
             CREATE TABLE IF NOT EXISTS wa_credentials (
                cred_id TEXT PRIMARY KEY,
                operator_id TEXT NOT NULL,
                nickname TEXT NOT NULL,
                passkey_json TEXT NOT NULL,
                counter INTEGER NOT NULL,
                locked INTEGER NOT NULL DEFAULT 0
            );",
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let origin = Url::parse(&config.origin)
            .map_err(|e| VoltaError::ConfigInvalid(format!("origin: {e}")))?;
        let webauthn = WebauthnBuilder::new(&config.rp_id, &origin)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?
            .rp_name("volta")
            .build()
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(Self {
            challenges: Mutex::new(BTreeMap::new()),
            conn: Mutex::new(conn),
            sessions: Mutex::new(BTreeMap::new()),
            webauthn: Arc::new(webauthn),
        })
    }

    /// Record the hash of an issued bootstrap token (the token
    /// itself is printed once by whoever issued it and never
    /// stored).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn set_bootstrap_hash(&self, token_hash: &str) -> Result<(), VoltaError> {
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        conn.execute(
            "INSERT OR REPLACE INTO bootstrap_tokens (token_hash) VALUES (?1)",
            params![token_hash],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(())
    }

    /// Whether a bootstrap token hash is on record.
    #[must_use]
    pub fn has_bootstrap(&self) -> bool {
        self.conn
            .lock()
            .ok()
            .and_then(|conn| {
                conn.query_row("SELECT COUNT(*) FROM bootstrap_tokens", [], |row| {
                    row.get::<_, i64>(0)
                })
                .ok()
            })
            .unwrap_or(0)
            > 0
    }

    /// Whether a presented bootstrap token matches the record.
    #[must_use]
    pub fn bootstrap_matches(&self, presented: &str) -> bool {
        let digest = crate::http_util::sha256_hex(presented.as_bytes());
        self.conn
            .lock()
            .ok()
            .and_then(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM bootstrap_tokens WHERE token_hash = ?1",
                    params![digest],
                    |row| row.get::<_, i64>(0),
                )
                .ok()
            })
            .unwrap_or(0)
            > 0
    }

    /// Clear any bootstrap record (after enrollment or a
    /// break-glass reset).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn clear_bootstrap(&self) -> Result<(), VoltaError> {
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        conn.execute("DELETE FROM bootstrap_tokens", [])
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(())
    }

    /// The WebAuthn engine.
    #[must_use]
    pub fn engine(&self) -> &Webauthn {
        &self.webauthn
    }

    /// Whether any credential exists (bootstrap gate).
    #[must_use]
    pub fn any_credentials(&self) -> bool {
        self.conn
            .lock()
            .ok()
            .and_then(|conn| {
                conn.query_row("SELECT COUNT(*) FROM wa_credentials", [], |row| {
                    row.get::<_, i64>(0)
                })
                .ok()
            })
            .unwrap_or(0)
            > 0
    }

    /// Store a registered passkey.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure; `E_FORBIDDEN` when
    /// the credential id already belongs to another operator.
    pub fn store_passkey(
        &self,
        operator_id: &str,
        nickname: &str,
        passkey: &Passkey,
    ) -> Result<String, VoltaError> {
        let cred_id = credential_id_string(passkey);
        let passkey_json = serde_json::to_string(passkey)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let counter = counter_of_json(&passkey_json);
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        if let Some(existing) = self.operator_of_cred(&conn, &cred_id) {
            if existing != operator_id {
                return Err(VoltaError::Forbidden(
                    "credential registered to another operator".to_string(),
                ));
            }
        }
        conn.execute(
            "INSERT OR REPLACE INTO wa_credentials (cred_id, operator_id, nickname, passkey_json, counter, locked)
             VALUES (?1, ?2, ?3, ?4, ?5, 0)",
            params![cred_id, operator_id, nickname, passkey_json, counter as i64],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(cred_id)
    }

    fn operator_of_cred(&self, conn: &Connection, cred_id: &str) -> Option<String> {
        conn.query_row(
            "SELECT operator_id FROM wa_credentials WHERE cred_id = ?1",
            params![cred_id],
            |row| row.get(0),
        )
        .ok()
    }

    /// All passkeys for an operator (locked included; callers
    /// filter for ceremonies).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn passkeys_of(&self, operator_id: &str) -> Result<Vec<Passkey>, VoltaError> {
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        let mut stmt = conn
            .prepare("SELECT passkey_json FROM wa_credentials WHERE operator_id = ?1 AND locked = 0")
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let rows = stmt
            .query_map(params![operator_id], |row| row.get::<_, String>(0))
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let text = row.map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            let passkey: Passkey = serde_json::from_str(&text)
                .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            out.push(passkey);
        }
        Ok(out)
    }

    /// Every registered passkey (discoverable auth flow).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn all_passkeys(&self) -> Result<Vec<Passkey>, VoltaError> {
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        let mut stmt = conn
            .prepare("SELECT passkey_json FROM wa_credentials WHERE locked = 0")
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let mut out = Vec::new();
        for row in rows {
            let text = row.map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
            out.push(
                serde_json::from_str(&text)
                    .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?,
            );
        }
        Ok(out)
    }

    /// Resolve a credential id to (operator id, passkey, counter,
    /// locked).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn credential_by_id(
        &self,
        cred_id: &str,
    ) -> Result<Option<(String, Passkey, u32, bool)>, VoltaError> {
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        let row = conn
            .query_row(
                "SELECT operator_id, passkey_json, counter, locked FROM wa_credentials WHERE cred_id = ?1",
                params![cred_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .ok();
        match row {
            None => Ok(None),
            Some((operator_id, passkey_json, counter, locked)) => {
                let passkey: Passkey = serde_json::from_str(&passkey_json)
                    .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
                Ok(Some((operator_id, passkey, counter as u32, locked != 0)))
            }
        }
    }

    /// Persist an updated passkey + counter after authentication.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn update_passkey(&self, passkey: &Passkey, counter: u32) -> Result<(), VoltaError> {
        let cred_id = credential_id_string(passkey);
        let passkey_json = serde_json::to_string(passkey)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        conn.execute(
            "UPDATE wa_credentials SET passkey_json = ?2, counter = ?3 WHERE cred_id = ?1",
            params![cred_id, passkey_json, counter as i64],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(())
    }

    /// Lock a credential (clone detection, SPEC 10.3).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on storage failure.
    pub fn lock_credential(&self, cred_id: &str) -> Result<(), VoltaError> {
        let conn = self.conn.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        conn.execute(
            "UPDATE wa_credentials SET locked = 1 WHERE cred_id = ?1",
            params![cred_id],
        )
        .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        Ok(())
    }

    /// Park a ceremony state under a fresh challenge id.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on lock failure.
    pub fn challenge_put(
        &self,
        kind: &str,
        operator_id: &str,
        state_json: String,
        step_up_for: Option<String>,
    ) -> Result<String, VoltaError> {
        let mut bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let id = format!("chg_{}", b64u_encode(&bytes));
        let mut map = self.challenges.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        map.insert(
            id.clone(),
            ChallengeRecord {
                expires_unix: unix_now() + CHALLENGE_TTL_SECONDS,
                kind: kind.to_string(),
                operator_id: operator_id.to_string(),
                state_json,
                step_up_for,
            },
        );
        Ok(id)
    }

    /// Take a ceremony state (single-use: SPEC 10.4).
    ///
    /// # Errors
    /// `E_WEBAUTHN_CHALLENGE_INVALID` when unknown, expired, or
    /// of the wrong kind.
    pub fn challenge_take(&self, id: &str, kind: &str) -> Result<(String, String, Option<String>), VoltaError> {
        let mut map = self
            .challenges
            .lock()
            .map_err(|_| VoltaError::WebauthnChallengeInvalid)?;
        let record = map.remove(id).ok_or(VoltaError::WebauthnChallengeInvalid)?;
        if record.kind != kind || unix_now() > record.expires_unix {
            return Err(VoltaError::WebauthnChallengeInvalid);
        }
        Ok((record.operator_id, record.state_json, record.step_up_for))
    }

    /// Mint an operator session; returns the opaque token.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on lock failure.
    pub fn session_create(&self, operator_id: &str, step_up: bool) -> Result<String, VoltaError> {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let token = b64u_encode(&bytes);
        let now = unix_now();
        let mut map = self.sessions.lock().map_err(|_| VoltaError::ConfigInvalid("lock".into()))?;
        map.insert(
            token.clone(),
            SessionRecord {
                created_unix: now,
                operator_id: operator_id.to_string(),
                step_up_unix: if step_up { now } else { 0 },
            },
        );
        Ok(token)
    }

    /// The operator behind a live session token.
    #[must_use]
    pub fn session_operator(&self, token: &str) -> Option<String> {
        let map = self.sessions.lock().ok()?;
        let record = map.get(token)?;
        if unix_now().saturating_sub(record.created_unix) > SESSION_TTL_SECONDS {
            return None;
        }
        Some(record.operator_id.clone())
    }

    /// The session's step-up instant, when fresh.
    #[must_use]
    pub fn session_step_up_unix(&self, token: &str) -> Option<u64> {
        let map = self.sessions.lock().ok()?;
        let record = map.get(token)?;
        if record.step_up_unix == 0 {
            return None;
        }
        Some(record.step_up_unix)
    }
}

/// The wire form of a credential id (base64url of the raw id).
#[must_use]
pub fn credential_id_string(passkey: &Passkey) -> String {
    b64u_encode(passkey.cred_id().as_slice())
}

/// Extract the stored counter from a serialized passkey (the
/// counter field of the wrapped credential).
#[must_use]
pub fn counter_of_json(passkey_json: &str) -> u32 {
    serde_json::from_str::<Value>(passkey_json)
        .ok()
        .and_then(|value| value.pointer("/cred/counter").and_then(Value::as_u64))
        .unwrap_or(0) as u32
}

/// The operator's deterministic user handle (uuid v5 of the id).
#[must_use]
pub fn operator_handle(operator_id: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_OID, operator_id.as_bytes())
}

/// Registration options request body.
#[derive(Debug, Deserialize)]
pub struct RegisterOptionsBody {
    /// Nickname for the credential.
    pub nickname: Option<String>,
    /// The operator id being enrolled.
    pub operator_id: String,
}

/// POST /api/v1/operator/webauthn/register/options.
pub async fn register_options(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let presented_bootstrap = headers
        .get("x-volta-bootstrap")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let authorized = crate::auth::operator_session(&state, &headers).is_some()
        || (!state.operator.any_credentials()
            && ((!state.bootstrap_token.is_empty() && presented_bootstrap == state.bootstrap_token)
                || state.operator.bootstrap_matches(presented_bootstrap)));
    if !authorized {
        return problem(VoltaError::AuthRequired, &request_id).into_response();
    }
    let parsed: RegisterOptionsBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return problem(VoltaError::Validation("body".into()), &request_id).into_response()
        }
    };
    let result = (|| -> Result<Value, VoltaError> {
        let existing = state.operator.passkeys_of(&parsed.operator_id)?;
        let exclude: Vec<webauthn_rs::prelude::CredentialID> =
            existing.iter().map(|passkey| passkey.cred_id().clone()).collect();
        let (options, registration) = state.operator.engine().start_passkey_registration(
            operator_handle(&parsed.operator_id),
            &parsed.operator_id,
            &parsed.operator_id,
            Some(exclude),
        ).map_err(|error| VoltaError::WebauthnAssertionInvalid(error.to_string()))?;
        let state_json = serde_json::to_string(&registration)
            .map_err(|error| VoltaError::ConfigInvalid(error.to_string()))?;
        let challenge_id = state.operator.challenge_put(
            "register",
            &parsed.operator_id,
            state_json,
            None,
        )?;
        Ok(json!({"challenge_id": challenge_id, "options": options}))
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Registration verify request body.
#[derive(Debug, Deserialize)]
pub struct RegisterVerifyBody {
    /// The challenge id from the options call.
    pub challenge_id: String,
    /// The authenticator's credential.
    pub credential: RegisterPublicKeyCredential,
    /// Nickname for the credential.
    pub nickname: Option<String>,
}

/// POST /api/v1/operator/webauthn/register/verify.
pub async fn register_verify(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let parsed: RegisterVerifyBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return problem(VoltaError::Validation("body".into()), &request_id).into_response()
        }
    };
    let result = (|| -> Result<(axum::http::StatusCode, Value), VoltaError> {
        let (operator_id, state_json, _) =
            state.operator.challenge_take(&parsed.challenge_id, "register")?;
        let registration: PasskeyRegistration = serde_json::from_str(&state_json)
            .map_err(|_| VoltaError::WebauthnChallengeInvalid)?;
        let passkey = state
            .operator
            .engine()
            .finish_passkey_registration(&parsed.credential, &registration)
            .map_err(|error| VoltaError::WebauthnAssertionInvalid(error.to_string()))?;
        let nickname = parsed.nickname.clone().unwrap_or_else(|| "passkey".to_string());
        let cred_id = state.operator.store_passkey(&operator_id, &nickname, &passkey)?;
        Ok((
            axum::http::StatusCode::CREATED,
            json!({"credential_id": cred_id, "nickname": nickname}),
        ))
    })();
    match result {
        Ok((status, value)) => (status, Json(value)).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Authentication options request body.
#[derive(Debug, Deserialize)]
pub struct AuthOptionsBody {
    /// Operator to authenticate (omit for the discoverable flow).
    pub operator_id: Option<String>,
    /// Action this assertion will step up for (WA-4).
    pub step_up_for: Option<String>,
}

/// POST /api/v1/operator/webauthn/auth/options.
pub async fn auth_options(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let parsed: AuthOptionsBody = if body.is_empty() {
        AuthOptionsBody { operator_id: None, step_up_for: None }
    } else {
        match serde_json::from_slice(&body) {
            Ok(parsed) => parsed,
            Err(_) => {
                return problem(VoltaError::Validation("body".into()), &request_id).into_response()
            }
        }
    };
    let result = (|| -> Result<Value, VoltaError> {
        let passkeys = match &parsed.operator_id {
            Some(operator_id) => state.operator.passkeys_of(operator_id)?,
            None => state.operator.all_passkeys()?,
        };
        if passkeys.is_empty() {
            return Err(VoltaError::WebauthnAssertionInvalid(
                "no credentials registered".to_string(),
            ));
        }
        let (options, authentication) = state
            .operator
            .engine()
            .start_passkey_authentication(&passkeys)
            .map_err(|error| VoltaError::WebauthnAssertionInvalid(error.to_string()))?;
        let state_json = serde_json::to_string(&authentication)
            .map_err(|error| VoltaError::ConfigInvalid(error.to_string()))?;
        let challenge_id = state.operator.challenge_put(
            "auth",
            parsed.operator_id.as_deref().unwrap_or(""),
            state_json,
            parsed.step_up_for.clone(),
        )?;
        Ok(json!({"challenge_id": challenge_id, "options": options}))
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// Authentication verify request body.
#[derive(Debug, Deserialize)]
pub struct AuthVerifyBody {
    /// The challenge id from the options call.
    pub challenge_id: String,
    /// The authenticator's assertion.
    pub credential: PublicKeyCredential,
}

/// POST /api/v1/operator/webauthn/auth/verify.
pub async fn auth_verify(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    let parsed: AuthVerifyBody = match serde_json::from_slice(&body) {
        Ok(parsed) => parsed,
        Err(_) => {
            return problem(VoltaError::Validation("body".into()), &request_id).into_response()
        }
    };
    let result = (|| -> Result<(Value, String), VoltaError> {
        let (_, state_json, _) = state.operator.challenge_take(&parsed.challenge_id, "auth")?;
        let authentication: PasskeyAuthentication = serde_json::from_str(&state_json)
            .map_err(|_| VoltaError::WebauthnChallengeInvalid)?;
        let result = state
            .operator
            .engine()
            .finish_passkey_authentication(&parsed.credential, &authentication)
            .map_err(|error| VoltaError::WebauthnAssertionInvalid(error.to_string()))?;
        if !result.user_verified() {
            return Err(VoltaError::WebauthnUvRequired);
        }
        let cred_id = b64u_encode(result.cred_id().as_slice());
        let (operator_id, mut passkey, stored_counter, locked) = state
            .operator
            .credential_by_id(&cred_id)?
            .ok_or_else(|| VoltaError::WebauthnAssertionInvalid("unknown credential".into()))?;
        if locked {
            return Err(VoltaError::WebauthnAssertionInvalid(
                "credential locked".to_string(),
            ));
        }
        let presented = result.counter();
        if stored_counter > 0 && presented <= stored_counter {
            state.operator.lock_credential(&cred_id)?;
            return Err(VoltaError::WebauthnCloneDetected);
        }
        passkey.update_credential(&result);
        state.operator.update_passkey(&passkey, presented)?;
        let token = state.operator.session_create(&operator_id, true)?;
        Ok((
            json!({
                "expires_at": crate::http_util::rfc3339(unix_now() + SESSION_TTL_SECONDS),
                "operator_id": operator_id,
                "session_token": token,
            }),
            token,
        ))
    })();
    match result {
        Ok((value, token)) => {
            let mut response = Json(value).into_response();
            if let Ok(cookie) = axum::http::HeaderValue::from_str(&format!(
                "volta_operator={token}; HttpOnly; Secure; SameSite=Strict; Path=/"
            )) {
                response.headers_mut().insert("set-cookie", cookie);
            }
            response
        }
        Err(error) => problem(error, &request_id).into_response(),
    }
}

/// GET /api/v1/operator/whoami — session introspection.
pub async fn whoami(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let request_id = crate::ephemeral::new_request_id();
    match crate::auth::operator_session(&state, &headers) {
        Some(operator_id) => Json(json!({"operator_id": operator_id, "role": "operator"})).into_response(),
        None => problem(VoltaError::AuthRequired, &request_id).into_response(),
    }
}
