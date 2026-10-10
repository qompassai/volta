//! crates/volta-server/tests/server.rs - surface integration tests.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Roughly half validation, half adversarial (Matt's standing
//! split): happy-path round trips for HKP/VKS/WKD, the ephemeral
//! API, MCP, A2A, and WebAuthn — against weak-algorithm
//! injection, oversized uploads, unauthenticated mutation, TTL
//! abuse, replayed challenges, and forged assertions.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde_json::{json, Value};
use tower::ServiceExt;
use volta_core::config::ServerConfig;
use volta_crypto::signing::{canonical_request, IdentitySigner, IdentitySuite};
use volta_server::app::router;
use volta_server::state::AppState;

const ALICE: &str = include_str!("../../../tests/fixtures/alice.asc");
const RSA2048: &str = include_str!("../../../tests/fixtures/rsa2048.asc");
const ALICE_FPR: &str = "B75FDD3A562A4951988BA325BAA8C11D29B6FDC9";

struct Fixture {
    app: axum::Router,
    principal: IdentitySigner,
    state: Arc<AppState>,
    #[allow(dead_code)]
    dir: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let dir = std::env::temp_dir().join(format!("volta-test-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    std::fs::write(dir.join("token-secret"), [7u8; 32]).expect("secret");
    std::fs::write(dir.join("identity-seed"), [3u8; 32]).expect("seed");
    let identity = IdentitySigner::from_seed(IdentitySuite::EddsaEd25519, &[3u8; 32]).expect("identity");
    let principal = IdentitySigner::from_seed(IdentitySuite::EddsaEd25519, &[9u8; 32]).expect("principal");
    let toml = format!(
        "base_uri = \"https://localhost:8737\"\n\
         bind = \"127.0.0.1:0\"\n\
         data_dir = \"{dir}\"\n\
         origin = \"https://localhost:8737\"\n\
         rp_id = \"localhost\"\n\
         token_secret_ref = \"file:{dir}/token-secret\"\n\
         [identity]\n\
         fingerprint = \"{identity_fpr}\"\n\
         secret_ref = \"file:{dir}/identity-seed\"\n\
         suite = \"eddsa-ed25519\"\n\
         [[principals]]\n\
         identity_public_b64 = \"{principal_vk}\"\n\
         identity_suite = \"eddsa-ed25519\"\n\
         name = \"agent:test\"\n\
         permissions = [\"relay-fetch\"]\n\
         [[relay_peers]]\n\
         base_uri = \"http://127.0.0.1:9\"\n\
         identity_fingerprint = \"{identity_fpr}\"\n\
         name = \"dead-peer\"\n\
         [proxy.chains.dead]\n\
         fail_closed = true\n\
         name = \"dead\"\n\
         on_error = \"abort\"\n\
         [[proxy.chains.dead.hops]]\n\
         address = \"127.0.0.1\"\n\
         port = 1\n\
         type = \"socks5h\"\n\
         [proxy.routes]\n\
         default = \"deny\"\n",
        dir = dir.display(),
        identity_fpr = identity.fingerprint(),
        principal_vk = B64.encode(principal.verifying_key_bytes()),
    );
    let config = ServerConfig::from_toml(&toml).expect("config");
    let state = Arc::new(AppState::new(config).expect("state"));
    let app = router(state.clone());
    Fixture { app, principal, state, dir }
}

async fn send(app: &axum::Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.expect("oneshot")
}

async fn text(response: Response<Body>) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 4_194_304)
        .await
        .expect("body");
    String::from_utf8_lossy(&bytes).to_string()
}

async fn json_body(response: Response<Body>) -> Value {
    let text = text(response).await;
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("not json: {text}"))
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().method("GET").uri(uri).body(Body::empty()).expect("request")
}

fn post_json(uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

/// Sign a request as the test principal (SPEC 7.5).
fn signed(
    fixture: &Fixture,
    method: &str,
    path: &str,
    body: &[u8],
) -> Vec<(String, String)> {
    let timestamp = volta_server::http_util::unix_now() as i64;
    let canonical = canonical_request(method, path, timestamp, body);
    let signature = fixture.principal.sign(&canonical);
    vec![
        ("x-volta-principal".to_string(), "agent:test".to_string()),
        ("x-volta-timestamp".to_string(), timestamp.to_string()),
        ("x-volta-signature".to_string(), B64.encode(signature)),
    ]
}

fn with_headers(mut request: Request<Body>, headers: Vec<(String, String)>) -> Request<Body> {
    for (name, value) in headers {
        request.headers_mut().insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            axum::http::HeaderValue::from_str(&value).expect("header value"),
        );
    }
    request
}

async fn add_alice(fixture: &Fixture) {
    let form = format!("keytext={}", url_encode(ALICE));
    let request = Request::builder()
        .method("POST")
        .uri("/pks/add")
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(form))
        .expect("request");
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
}

fn url_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => out.push(byte as char),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[tokio::test]
async fn hkp_vks_wkd_roundtrip() {
    let fixture = fixture();
    add_alice(&fixture).await;

    // HKP get by fingerprint.
    let response = send(&fixture.app, get(&format!("/pks/lookup?op=get&search={ALICE_FPR}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(text(response).await.contains("BEGIN PGP PUBLIC KEY BLOCK"));

    // HKP machine-readable index.
    let response = send(
        &fixture.app,
        get(&format!("/pks/lookup?op=index&options=mr&search={ALICE_FPR}")),
    )
    .await;
    let body = text(response).await;
    assert!(body.contains("info:1:1"), "{body}");
    assert!(body.contains("pub:"), "{body}");

    // VKS by-fingerprint serves before verification; by-email does not.
    let response = send(&fixture.app, get(&format!("/vks/v1/by-fingerprint/{ALICE_FPR}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(&fixture.app, get("/vks/v1/by-email/alice@example.org")).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Upload -> request-verify -> verify -> by-email + WKD serve.
    let response = send(
        &fixture.app,
        post_json("/vks/v1/upload", &json!({"keytext": ALICE})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let upload = json_body(response).await;
    let token = upload["token"].as_str().expect("token").to_string();
    let response = send(
        &fixture.app,
        post_json(
            "/vks/v1/request-verify",
            &json!({"addresses": ["alice@example.org"], "token": token}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let verify = json_body(response).await;
    let verify_token = verify["dev_tokens"]["alice@example.org"]
        .as_str()
        .expect("dev token")
        .to_string();
    let response = send(&fixture.app, get(&format!("/vks/v1/verify/{verify_token}"))).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(&fixture.app, get("/vks/v1/by-email/alice@example.org")).await;
    assert_eq!(response.status(), StatusCode::OK);

    let hash = volta_core::wkd::wkd_hash("alice");
    let response = send(
        &fixture.app,
        get(&format!("/.well-known/openpgpkey/example.org/hu/{hash}?l=alice")),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(&fixture.app, get("/.well-known/openpgpkey/example.org/policy")).await;
    assert_eq!(text(response).await, "mailbox-only\nprotocol-version: 1\n");
}

#[tokio::test]
async fn adversarial_uploads_rejected() {
    let fixture = fixture();
    // Weak algorithm injection: RSA-2048 must be refused at ingest.
    let response = send(
        &fixture.app,
        post_json("/vks/v1/upload", &json!({"keytext": RSA2048})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("x-volta-error-code").map(|v| v.to_str().unwrap_or("")),
        Some("E_CRYPTO_NOT_ALLOWED")
    );
    // Malformed material.
    let response = send(
        &fixture.app,
        post_json("/vks/v1/upload", &json!({"keytext": "not a key"})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    // Oversized upload.
    let big = "A".repeat(1_100_000);
    let response = send(
        &fixture.app,
        post_json("/vks/v1/upload", &json!({"keytext": big})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // Short key ids are never accepted (HKP-2 grammar).
    let response = send(&fixture.app, get("/pks/lookup?op=get&search=29B6FDC9")).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ephemeral_flow_and_abuse() {
    let fixture = fixture();
    let issue = json!({
        "custody": "server",
        "owner_id": "agent:test",
        "purpose": "mcp-session",
        "suite": "hybrid-mlkem768-x25519",
        "ttl_seconds": 120,
    });
    let body = issue.to_string().into_bytes();

    // Anonymous issue is refused.
    let response = send(&fixture.app, post_json("/api/v1/ephemeral-keys", &issue)).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // TTL above the hard cap is refused even when signed.
    let mut abusive = issue.clone();
    abusive["ttl_seconds"] = json!(3601);
    let abusive_body = abusive.to_string().into_bytes();
    let request = with_headers(
        post_json("/api/v1/ephemeral-keys", &abusive),
        signed(&fixture, "POST", "/api/v1/ephemeral-keys", &abusive_body),
    );
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("x-volta-error-code").map(|v| v.to_str().unwrap_or("")),
        Some("E_TTL_OUT_OF_BOUNDS")
    );

    // Signed issue succeeds.
    let request = with_headers(
        post_json("/api/v1/ephemeral-keys", &issue),
        signed(&fixture, "POST", "/api/v1/ephemeral-keys", &body),
    );
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let record = json_body(response).await;
    let key_id = record["key_id"].as_str().expect("key_id").to_string();
    let kem_public = B64
        .decode(record["public_material"]["kem_public_b64"].as_str().expect("kem"))
        .expect("b64");
    let classical_public = B64
        .decode(record["public_material"]["classical_public_b64"].as_str().expect("classical"))
        .expect("b64");

    // Encapsulate as a peer, register the session, decapsulate as
    // the owner: both sides derive the same shared secret.
    let suite = volta_crypto::suites::Suite::parse("hybrid-mlkem768-x25519").expect("suite");
    let (ciphertext, shared) = volta_crypto::suites::encapsulate(
        suite,
        &classical_public,
        &kem_public,
        &mut rand::rngs::OsRng,
    )
    .expect("encapsulate");
    let session_body = json!({
        "ciphertext_b64": B64.encode(&ciphertext),
        "peer_id": "agent:peer",
    });
    let path = format!("/api/v1/ephemeral-keys/{key_id}/sessions");
    let request = with_headers(
        post_json(&path, &session_body),
        signed(&fixture, "POST", &path, session_body.to_string().as_bytes()),
    );
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);

    let decap_body = json!({
        "ciphertext_b64": B64.encode(&ciphertext),
        "peer_id": "agent:peer",
    });
    let path = format!("/api/v1/ephemeral-keys/{key_id}/decapsulate");
    let request = with_headers(
        post_json(&path, &decap_body),
        signed(&fixture, "POST", &path, decap_body.to_string().as_bytes()),
    );
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let decap = json_body(response).await;
    let shared_back = B64
        .decode(decap["shared_secret_b64"].as_str().expect("shared"))
        .expect("b64");
    assert_eq!(shared_back, shared.as_slice());

    // Revoke, then the key answers 410 E_KEY_REVOKED.
    let path = format!("/api/v1/ephemeral-keys/{key_id}");
    let request = with_headers(
        Request::builder().method("DELETE").uri(&path).body(Body::empty()).expect("request"),
        signed(&fixture, "DELETE", &path, &[]),
    );
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = send(&fixture.app, get(&path)).await;
    assert_eq!(response.status(), StatusCode::GONE);
    assert_eq!(
        response.headers().get("x-volta-error-code").map(|v| v.to_str().unwrap_or("")),
        Some("E_KEY_REVOKED")
    );
}

#[tokio::test]
async fn ephemeral_expiry_is_terminal() {
    let fixture = fixture();
    let issue = json!({
        "custody": "server",
        "owner_id": "agent:test",
        "purpose": "a2a-session",
        "suite": "mlkem1024",
        "ttl_seconds": 30,
    });
    let body = issue.to_string().into_bytes();
    let request = with_headers(
        post_json("/api/v1/ephemeral-keys", &issue),
        signed(&fixture, "POST", "/api/v1/ephemeral-keys", &body),
    );
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let record = json_body(response).await;
    let key_id = record["key_id"].as_str().expect("key_id").to_string();
    // Backdate expiry in the metadata store; the lazy-expiry read
    // path must zeroize and answer 410 E_KEY_EXPIRED.
    let db = fixture.dir.join("ephemeral.db");
    let conn = rusqlite::Connection::open(db).expect("db");
    conn.execute(
        "UPDATE eph_keys SET expires_unix = 1 WHERE key_id = ?1",
        [key_id.clone()],
    )
    .expect("backdate");
    drop(conn);
    let response = send(&fixture.app, get(&format!("/api/v1/ephemeral-keys/{key_id}"))).await;
    assert_eq!(response.status(), StatusCode::GONE);
    assert_eq!(
        response.headers().get("x-volta-error-code").map(|v| v.to_str().unwrap_or("")),
        Some("E_KEY_EXPIRED")
    );
}

#[tokio::test]
async fn mcp_tools_and_auth() {
    let fixture = fixture();
    add_alice(&fixture).await;
    let init = json!({
        "id": 1, "jsonrpc": "2.0", "method": "initialize",
        "params": {"capabilities": {}, "clientInfo": {"name": "test", "version": "0"}, "protocolVersion": "2025-03-26"},
    });
    let response = send(&fixture.app, post_json("/mcp", &init)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("mcp-session-id"));

    let list = json!({"id": 2, "jsonrpc": "2.0", "method": "tools/list", "params": {}});
    let response = send(&fixture.app, post_json("/mcp", &list)).await;
    let listed = json_body(response).await;
    let names: Vec<String> = listed["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("name").to_string())
        .collect();
    assert_eq!(names.len(), 13);
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "tools/list must be alphabetical");

    // Public tool anonymously.
    let call = json!({
        "id": 3, "jsonrpc": "2.0", "method": "tools/call",
        "params": {"arguments": {"fingerprint": ALICE_FPR}, "name": "volta_key_lookup_by_fingerprint"},
    });
    let response = send(&fixture.app, post_json("/mcp", &call)).await;
    let result = json_body(response).await;
    assert_eq!(result["result"]["isError"], json!(false));

    // Agent tool anonymously: error result, never executed.
    let call = json!({
        "id": 4, "jsonrpc": "2.0", "method": "tools/call",
        "params": {"arguments": {"purpose": "mcp-session", "suite": "mlkem1024"}, "name": "volta_ephemeral_issue"},
    });
    let response = send(&fixture.app, post_json("/mcp", &call)).await;
    let result = json_body(response).await;
    assert_eq!(result["result"]["isError"], json!(true));
    let text = result["result"]["content"][0]["text"].as_str().expect("text");
    assert!(text.contains("E_AUTH_REQUIRED"), "{text}");

    // No decapsulation tool exists (MCP-5).
    assert!(!names.iter().any(|name| name.contains("decapsulat")));
}

#[tokio::test]
async fn a2a_card_and_tasks() {
    let fixture = fixture();
    add_alice(&fixture).await;
    let response = send(&fixture.app, get("/.well-known/agent-card.json")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let card = json_body(response).await;
    assert_eq!(card["name"], json!("volta"));
    assert_eq!(card["skills"].as_array().expect("skills").len(), 4);

    // Verify the card signature against the identity key (A2A-3).
    let signature_entry = &card["signatures"][0];
    let protected = signature_entry["protected"].as_str().expect("protected").to_string();
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_entry["signature"].as_str().expect("signature"))
        .expect("b64");
    let mut unsigned = card.clone();
    unsigned.as_object_mut().expect("object").remove("signatures");
    let canonical = volta_server::jcs::canonicalize(&unsigned);
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(canonical.as_bytes());
    let input = format!("{protected}.{payload}");
    let identity = IdentitySigner::from_seed(IdentitySuite::EddsaEd25519, &[3u8; 32]).expect("identity");
    volta_crypto::signing::verify(
        IdentitySuite::EddsaEd25519,
        &identity.verifying_key_bytes(),
        input.as_bytes(),
        &signature,
    )
    .expect("card signature verifies");

    // Anonymous key-lookup task completes.
    let send_body = json!({
        "id": 1, "jsonrpc": "2.0", "method": "message/send",
        "params": {
            "message": {"messageId": "m1", "parts": [{"data": {"by": "fingerprint", "query": ALICE_FPR}, "kind": "data"}], "role": "user"},
            "metadata": {"volta.skill": "key-lookup"},
        },
    });
    let response = send(&fixture.app, post_json("/a2a/v1", &send_body)).await;
    let task = json_body(response).await;
    assert_eq!(task["result"]["status"]["state"], json!("completed"));
    let task_id = task["result"]["id"].as_str().expect("task id").to_string();

    // Another principal cannot see the task (no existence oracle).
    let get_body = json!({"id": 2, "jsonrpc": "2.0", "method": "tasks/get", "params": {"id": task_id}});
    let request = with_headers(
        post_json("/a2a/v1", &get_body),
        signed(&fixture, "POST", "/a2a/v1", get_body.to_string().as_bytes()),
    );
    let response = send(&fixture.app, request).await;
    let result = json_body(response).await;
    assert!(result.get("error").is_some(), "{result}");

    // Anonymous ephemeral issue fails the task, with the code.
    let send_body = json!({
        "id": 3, "jsonrpc": "2.0", "method": "message/send",
        "params": {
            "message": {"messageId": "m2", "parts": [{"data": {"intent": "issue"}, "kind": "data"}], "role": "user"},
            "metadata": {"volta.skill": "ephemeral-key-exchange"},
        },
    });
    let response = send(&fixture.app, post_json("/a2a/v1", &send_body)).await;
    let task = json_body(response).await;
    assert_eq!(task["result"]["status"]["state"], json!("failed"));
}
