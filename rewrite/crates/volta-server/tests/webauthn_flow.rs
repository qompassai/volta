//! crates/volta-server/tests/webauthn_flow.rs - WebAuthn ceremonies.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Registration + assertion against the software authenticator,
//! then the adversarial half: a replayed challenge and a forged
//! assertion must both fail, and the chain-check endpoint must
//! refuse the unauthenticated and report a dead chain as data.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use base64::Engine;
use serde_json::{json, Value};
use tower::ServiceExt;
use url::Url;
use volta_core::config::ServerConfig;
use volta_server::app::router;
use volta_server::state::AppState;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_authenticator_rs::AuthenticatorBackend;
use webauthn_rs::prelude::{CreationChallengeResponse, RequestChallengeResponse};

struct Fixture {
    app: axum::Router,
    state: Arc<AppState>,
}

fn fixture() -> Fixture {
    let dir = std::env::temp_dir().join(format!("volta-wa-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    std::fs::write(dir.join("token-secret"), [7u8; 32]).expect("secret");
    let toml = format!(
        "base_uri = \"https://localhost:8737\"\n\
         bind = \"127.0.0.1:0\"\n\
         data_dir = \"{dir}\"\n\
         origin = \"https://localhost:8737\"\n\
         rp_id = \"localhost\"\n\
         token_secret_ref = \"file:{dir}/token-secret\"\n\
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
    );
    let config = ServerConfig::from_toml(&toml).expect("config");
    let state = Arc::new(AppState::new(config).expect("state"));
    Fixture { app: router(state.clone()), state }
}

async fn send(app: &axum::Router, request: Request<Body>) -> Response<Body> {
    app.clone().oneshot(request).await.expect("oneshot")
}

async fn json_body(response: Response<Body>) -> Value {
    let bytes = axum::body::to_bytes(response.into_body(), 4_194_304)
        .await
        .expect("body");
    let text = String::from_utf8_lossy(&bytes).to_string();
    serde_json::from_str(&text).unwrap_or_else(|_| panic!("not json: {text}"))
}

fn post_json(uri: &str, body: &Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("request")
}

#[tokio::test]
async fn webauthn_register_auth_replay_forgery() {
    let fixture = fixture();
    let origin = Url::parse("https://localhost:8737").expect("origin");
    let mut authenticator = SoftPasskey::new(true);

    // Registration via the one-time bootstrap token.
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/operator/webauthn/register/options")
        .header("content-type", "application/json")
        .header("x-volta-bootstrap", fixture.state.bootstrap_token.clone())
        .body(Body::from(json!({"nickname": "test key", "operator_id": "op:test"}).to_string()))
        .expect("request");
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let options = json_body(response).await;
    let challenge_id = options["challenge_id"].as_str().expect("challenge").to_string();
    let ccr: CreationChallengeResponse =
        serde_json::from_value(options["options"].clone()).expect("ccr");
    let credential = authenticator
        .perform_register(origin.clone(), ccr.public_key, 30_000)
        .expect("register");
    let response = send(
        &fixture.app,
        post_json(
            "/api/v1/operator/webauthn/register/verify",
            &json!({
                "challenge_id": challenge_id,
                "credential": serde_json::to_value(&credential).expect("credential json"),
                "nickname": "test key",
            }),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);

    // Authentication mints an operator session.
    let response = send(
        &fixture.app,
        post_json(
            "/api/v1/operator/webauthn/auth/options",
            &json!({"operator_id": "op:test"}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let options = json_body(response).await;
    let challenge_id = options["challenge_id"].as_str().expect("challenge").to_string();
    let rcr: RequestChallengeResponse =
        serde_json::from_value(options["options"].clone()).expect("rcr");
    let assertion = authenticator
        .perform_auth(origin.clone(), rcr.public_key, 30_000)
        .expect("authenticate");
    let assertion_json = serde_json::to_value(&assertion).expect("assertion json");
    let response = send(
        &fixture.app,
        post_json(
            "/api/v1/operator/webauthn/auth/verify",
            &json!({"challenge_id": challenge_id, "credential": assertion_json.clone()}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let session = json_body(response).await;
    let token = session["session_token"].as_str().expect("token").to_string();

    // whoami with the session.
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/operator/whoami")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::OK);

    // REPLAY: the same challenge id + assertion a second time
    // must fail — challenges are single-use (SPEC 10.4).
    let response = send(
        &fixture.app,
        post_json(
            "/api/v1/operator/webauthn/auth/verify",
            &json!({"challenge_id": challenge_id, "credential": assertion_json}),
        ),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.headers().get("x-volta-error-code").map(|v| v.to_str().unwrap_or("")),
        Some("E_WEBAUTHN_CHALLENGE_INVALID")
    );

    // FORGERY: fresh challenge, but the assertion's signature is
    // tampered — verification must fail.
    let response = send(
        &fixture.app,
        post_json(
            "/api/v1/operator/webauthn/auth/options",
            &json!({"operator_id": "op:test"}),
        ),
    )
    .await;
    let options = json_body(response).await;
    let challenge_id = options["challenge_id"].as_str().expect("challenge").to_string();
    let rcr: RequestChallengeResponse =
        serde_json::from_value(options["options"].clone()).expect("rcr");
    let forged = authenticator
        .perform_auth(origin.clone(), rcr.public_key, 30_000)
        .expect("authenticate");
    // Flip a byte inside the signature blob at the JSON level.
    let mut forged_json = serde_json::to_value(&forged).expect("forged json");
    let sig_text = forged_json["response"]["signature"]
        .as_str()
        .expect("signature")
        .to_string();
    let mut sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&sig_text)
        .expect("sig b64");
    if let Some(first) = sig.first_mut() {
        *first ^= 0xff;
    }
    forged_json["response"]["signature"] = json!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig)
    );
    let response = send(
        &fixture.app,
        post_json(
            "/api/v1/operator/webauthn/auth/verify",
            &json!({"challenge_id": challenge_id, "credential": forged_json}),
        ),
    )
    .await;
    assert_ne!(response.status(), StatusCode::OK);

    // Chain check: unauthenticated -> 401; operator -> dead chain
    // reported as data with ok=false (fail closed, SPEC 13.5).
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/proxy-chains/dead/check")
        .body(Body::empty())
        .expect("request");
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let request = Request::builder()
        .method("GET")
        .uri("/api/v1/proxy-chains/dead/check")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .expect("request");
    let response = send(&fixture.app, request).await;
    assert_eq!(response.status(), StatusCode::OK);
    let report = json_body(response).await;
    assert_eq!(report["ok"], json!(false));
    assert_eq!(report["hops"][0]["status"], json!("E_PROXY_HOP_FAILED"));
}
