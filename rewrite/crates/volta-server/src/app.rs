//! crates/volta-server/src/app.rs - router assembly.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! Routes are declared in alphabetical path order (ORD-1). Body
//! limits: 2 MiB global ceiling; the upload paths enforce the
//! 1 MiB SPEC cap at ingest (E_UPLOAD_TOO_LARGE).

use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};

use crate::state::AppState;
use crate::{a2a, ephemeral, hkp, mcp, relay, vks, web, webauthn, wkd_http};

/// The full volta router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(web::index))
        .route("/.well-known/agent-card.json", get(a2a::agent_card))
        .route("/.well-known/openpgpkey/hu/{hash}", get(wkd_http::hu))
        .route("/.well-known/openpgpkey/policy", get(wkd_http::policy))
        .route(
            "/.well-known/openpgpkey/{domain}/hu/{hash}",
            get(wkd_http::hu_advanced),
        )
        .route(
            "/.well-known/openpgpkey/{domain}/policy",
            get(wkd_http::policy),
        )
        .route("/a2a/v1", post(a2a::rpc))
        .route("/about", get(web::about))
        .route(
            "/api/v1/ephemeral-keys",
            get(ephemeral::list).post(ephemeral::issue),
        )
        .route(
            "/api/v1/ephemeral-keys/{key_id}",
            get(ephemeral::get_one).delete(ephemeral::revoke),
        )
        .route(
            "/api/v1/ephemeral-keys/{key_id}/decapsulate",
            post(ephemeral::decapsulate_key),
        )
        .route(
            "/api/v1/ephemeral-keys/{key_id}/rotate",
            post(ephemeral::rotate),
        )
        .route(
            "/api/v1/ephemeral-keys/{key_id}/sessions",
            post(ephemeral::register_session),
        )
        .route(
            "/api/v1/operator/webauthn/auth/options",
            post(webauthn::auth_options),
        )
        .route(
            "/api/v1/operator/webauthn/auth/verify",
            post(webauthn::auth_verify),
        )
        .route(
            "/api/v1/operator/webauthn/register/options",
            post(webauthn::register_options),
        )
        .route(
            "/api/v1/operator/webauthn/register/verify",
            post(webauthn::register_verify),
        )
        .route("/api/v1/operator/whoami", get(webauthn::whoami))
        .route("/api/v1/proxy-chains/{name}/check", get(relay::chain_check))
        .route("/healthz", get(web::healthz))
        .route("/manage/action", post(web::manage_action))
        .route("/manage/{token}", get(web::manage_page))
        .route("/mcp", post(mcp::handle))
        .route("/metrics", get(web::metrics))
        .route("/pks/add", post(hkp::add))
        .route(
            "/pks/internal/get-armor-by-fingerprint/{fingerprint}",
            get(hkp::internal_get_armor),
        )
        .route("/pks/lookup", get(hkp::lookup))
        .route("/readyz", get(web::readyz))
        .route("/relay/v1/changes", get(relay::changes))
        .route("/relay/v1/connect", post(relay::connect))
        .route("/relay/v1/root", get(relay::root))
        .route("/search", get(web::search))
        .route("/upload", get(web::upload_form).post(web::upload_submit))
        .route("/verify/{token}", get(web::verify_page))
        .route("/vks/v1/by-email/{email}", get(vks::by_email))
        .route(
            "/vks/v1/by-fingerprint/{fingerprint}",
            get(vks::by_fingerprint),
        )
        .route("/vks/v1/by-keyid/{key_id}", get(vks::by_keyid))
        .route("/vks/v1/request-manage", post(vks::request_manage))
        .route("/vks/v1/request-verify", post(vks::request_verify))
        .route("/vks/v1/upload", post(vks::upload))
        .route("/vks/v1/verify/{token}", get(vks::verify_token))
        .layer(DefaultBodyLimit::max(2 * 1_048_576))
        .with_state(state)
}
