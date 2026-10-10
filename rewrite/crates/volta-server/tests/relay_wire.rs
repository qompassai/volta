// #################################################################
// /qompassai/volta/rewrite/crates/volta-server/tests/relay_wire.rs
// Qompass AI — volta relay wire test
//
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Two real volta servers on real TCP listeners: the local node
// fetches a key from the peer through volta-proxy's dialer
// (SPEC 11), and a dead chain fails closed without touching the
// peer.

#![forbid(unsafe_code)]

use std::sync::Arc;

use volta_core::config::ServerConfig;
use volta_crypto::signing::{IdentitySigner, IdentitySuite};
use volta_server::app::router;
use volta_server::relay::relay_fetch_key;
use volta_server::state::AppState;

const ALICE: &str = include_str!("../../../tests/fixtures/alice.asc");
const ALICE_FPR: &str = "B75FDD3A562A4951988BA325BAA8C11D29B6FDC9";
const BOB_FPR: &str = "3E5F8A2C9D4B7E1F0A6C3D5B8E2F4A7C9D1B3E5F";

fn make_state(tag: &str, extra_toml: &str) -> (Arc<AppState>, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("volta-wire-{tag}-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    std::fs::write(dir.join("token-secret"), [7u8; 32]).expect("secret");
    std::fs::write(dir.join("identity-seed"), [3u8; 32]).expect("seed");
    let identity =
        IdentitySigner::from_seed(IdentitySuite::EddsaEd25519, &[3u8; 32]).expect("identity");
    let toml = format!(
        "base_uri = \"https://localhost:8737\"\n\
         bind = \"127.0.0.1:0\"\n\
         data_dir = \"{dir}\"\n\
         origin = \"https://localhost:8737\"\n\
         rp_id = \"localhost\"\n\
         token_secret_ref = \"file:{dir}/token-secret\"\n\
         [identity]\n\
         fingerprint = \"{fpr}\"\n\
         secret_ref = \"file:{dir}/identity-seed\"\n\
         suite = \"eddsa-ed25519\"\n\
         {extra}",
        dir = dir.display(),
        fpr = identity.fingerprint(),
        extra = extra_toml,
    );
    let config = ServerConfig::from_toml(&toml).expect("config");
    let state = Arc::new(AppState::new(config).expect("state"));
    (state, dir)
}

#[tokio::test]
async fn relay_fetch_over_real_sockets_and_fail_closed() {
    // Peer: a real server holding alice, published.
    let (peer, _peer_dir) = make_state("peer", "");
    {
        volta_server::hkp::ingest_armor(&peer, ALICE).expect("ingest alice");
        let mut store = peer.store.lock().expect("lock");
        let now = volta_server::http_util::unix_now() as i64;
        store
            .publish_address("alice@example.org", ALICE_FPR, now)
            .expect("publish");
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let peer_app = router(peer.clone());
    tokio::spawn(async move {
        axum::serve(listener, peer_app).await.expect("serve");
    });

    // Local node: direct route to the peer.
    let peer_toml = format!(
        "[[relay_peers]]\n\
         base_uri = \"http://127.0.0.1:{port}\"\n\
         identity_fingerprint = \"{fpr}\"\n\
         name = \"peer-a\"\n\
         [proxy.routes]\n\
         relay_fetch = \"direct\"\n",
        fpr = peer.identity_fingerprint.as_deref().unwrap_or(""),
    );
    let (local, _local_dir) = make_state("local", &peer_toml);
    let fetched = relay_fetch_key(&local, ALICE_FPR, "peer-a")
        .await
        .expect("relay fetch");
    assert_eq!(
        fetched.get("fingerprint").and_then(|v| v.as_str()),
        Some(ALICE_FPR)
    );
    assert!(
        fetched
            .get("armor")
            .and_then(|v| v.as_str())
            .is_some_and(|armor| armor.contains("BEGIN PGP PUBLIC KEY BLOCK")),
        "armor returned: {fetched}"
    );

    // Adversarial: a key the peer does not hold is an error, not
    // an empty success.
    let missing = relay_fetch_key(&local, BOB_FPR, "peer-a").await;
    assert!(missing.is_err(), "unknown key must fail: {missing:?}");

    // Adversarial: an unconfigured peer name is an error.
    let unknown = relay_fetch_key(&local, ALICE_FPR, "no-such-peer").await;
    assert!(unknown.is_err());

    // Adversarial: route the fetch through a dead chain — the
    // fetch fails closed with a proxy error (CHAIN-1).
    let dead_toml = format!(
        "[[relay_peers]]\n\
         base_uri = \"http://127.0.0.1:{port}\"\n\
         identity_fingerprint = \"{fpr}\"\n\
         name = \"peer-a\"\n\
         [proxy.chains.dead]\n\
         fail_closed = true\n\
         name = \"dead\"\n\
         on_error = \"abort\"\n\
         [[proxy.chains.dead.hops]]\n\
         address = \"127.0.0.1\"\n\
         port = 1\n\
         type = \"socks5h\"\n\
         [proxy.routes]\n\
         relay_fetch = \"dead\"\n",
        fpr = peer.identity_fingerprint.as_deref().unwrap_or(""),
    );
    let (blocked, _blocked_dir) = make_state("blocked", &dead_toml);
    let error = relay_fetch_key(&blocked, ALICE_FPR, "peer-a")
        .await
        .expect_err("dead chain must fail closed");
    assert!(
        error.code().starts_with("E_PROXY"),
        "proxy error expected, got {}",
        error.code()
    );
}
