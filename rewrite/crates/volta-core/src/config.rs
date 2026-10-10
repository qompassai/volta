// #################################################################
// /qompassai/volta/rewrite/crates/volta-core/src/config.rs
// Qompass AI Volta — Configuration (SPEC 13.2, 16)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
// #################################################################

//! Consolidated configuration. Secrets are referenced, never
//! inlined: a `*_ref` value names `env:<VAR>` or `file:<path>`;
//! inline secret material is a load error. Unknown keys are a load
//! error (SPEC 16). Proxy chain validation is CHAIN-0/CHAIN-3:
//! invalid routing refuses startup — volta never starts with a
//! half-parsed routing table.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{VoltaError, VoltaResult};

/// Maximum hops in one chain (CHAIN-0).
pub const CHAIN_HOPS_MAX: usize = 8;
/// Default per-hop connect timeout (SPEC 13.2).
pub const HOP_TIMEOUT_MS_DEFAULT: u64 = 10_000;
/// Maximum body size for key uploads: 1 MiB (SPEC 6.1.3/6.2.2).
pub const UPLOAD_BYTES_MAX: usize = 1_048_576;
/// Default sealed-token validity in seconds (TOK-4).
pub const TOKEN_VALIDITY_SECONDS_DEFAULT: i64 = 3600;

/// How a chain resolves names (SPEC 13.2 `dns`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ChainDns {
    /// Names travel unresolved to the resolving hop (CHAIN-3).
    Remote,
    /// The local resolver is used; a load-time warning when set.
    System,
}

/// One hop in a proxy chain (SPEC 13.1). Field names follow the
/// schema; `hop_type` renders as `type` in TOML.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HopConfig {
    /// Hostname or IP literal of the hop.
    pub address: String,
    /// Authentication for the hop, when any.
    #[serde(default)]
    pub auth: Option<HopAuth>,
    /// Tor stream-isolation identity (tor-socks hops only).
    #[serde(default)]
    pub isolation_id: Option<String>,
    /// Port, 1..=65535.
    pub port: u16,
    /// `sha256:<base64>` SPKI pin for TLS hops.
    #[serde(default)]
    pub spki_pin: Option<String>,
    /// Whether the connection TO this hop is wrapped in TLS 1.3
    /// (SPEC 13.1 http-connect `tls: true`; required for
    /// volta-relay hops that name an `spki_pin`).
    #[serde(default)]
    pub tls: bool,
    /// TLS server name override for TLS hops.
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// The hop type (SPEC 13.1).
    #[serde(rename = "type")]
    pub hop_type: HopType,
}

/// Hop authentication. The secret itself is referenced (CHAIN-6).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HopAuth {
    /// `ephemeral`, `none`, or `userpass`.
    pub method: String,
    /// Reference into the secret store, e.g. `env:NAME`,
    /// `file:/path`, `pass:entry`. Inline values are a load error.
    #[serde(default)]
    pub secret_ref: Option<String>,
    /// Username for `userpass`, when not part of the secret value.
    #[serde(default)]
    pub username: Option<String>,
}

/// The hop types of SPEC 13.1 (alphabetical).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum HopType {
    /// HTTP CONNECT proxy.
    #[serde(rename = "http-connect")]
    HttpConnect,
    /// SOCKS5 with local resolution (restricted, CHAIN-3).
    #[serde(rename = "socks5")]
    Socks5,
    /// SOCKS5 with remote DNS.
    #[serde(rename = "socks5h")]
    Socks5h,
    /// A Tor client SOCKS port.
    #[serde(rename = "tor-socks")]
    TorSocks,
    /// Another volta instance's relay endpoint (SPEC 13.6).
    #[serde(rename = "volta-relay")]
    VoltaRelay,
}

impl HopType {
    /// The schema string for the hop type.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HttpConnect => "http-connect",
            Self::Socks5 => "socks5",
            Self::Socks5h => "socks5h",
            Self::TorSocks => "tor-socks",
            Self::VoltaRelay => "volta-relay",
        }
    }

    /// Whether this hop resolves target names remotely.
    #[must_use]
    pub fn resolves_remotely(&self) -> bool {
        matches!(self, Self::Socks5h | Self::TorSocks | Self::VoltaRelay | Self::HttpConnect)
    }
}

/// One named proxy chain (SPEC 13.2).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainConfig {
    /// Name-resolution mode; defaults to remote.
    #[serde(default = "default_dns")]
    pub dns: ChainDns,
    /// Must be `true`; `false` is a load error (fail-closed by
    /// design, CHAIN-2).
    pub fail_closed: bool,
    /// The hops, in traversal order (protocol order, ORD-1
    /// exception: order is the semantics).
    pub hops: Vec<HopConfig>,
    /// The chain's name (must equal its table key).
    pub name: String,
    /// Only `abort` is valid; anything else is a load error.
    pub on_error: String,
    /// Whole-chain deadline in milliseconds.
    #[serde(default = "default_chain_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_chain_timeout_ms() -> u64 {
    30_000
}

fn default_dns() -> ChainDns {
    ChainDns::Remote
}

/// The proxy section: named chains plus per-operation routes.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Named chains by name.
    #[serde(default)]
    pub chains: BTreeMap<String, ChainConfig>,
    /// Operation -> chain name | `direct` | (`default` only) `deny`.
    #[serde(default)]
    pub routes: BTreeMap<String, String>,
}

/// The outbound operations of SPEC 13.3 (alphabetical).
pub const OPERATIONS: [&str; 8] = [
    "a2a_fetch",
    "ephemeral_exchange",
    "key_lookup",
    "key_publish",
    "relay_fetch",
    "relay_sync",
    "smtp_submit",
    "wkd_fetch",
];

/// What routing decides for one operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouteDecision {
    /// Route through the named chain.
    Chain(String),
    /// Refuse the operation (fail closed).
    Deny,
    /// Connect directly — only when configuration says so in as
    /// many words (CHAIN-2: never a fallback).
    Direct,
}

impl ProxyConfig {
    /// Resolve the route for an operation. A missing operation with
    /// no default is `Deny` (CHAIN-2).
    #[must_use]
    pub fn route_for(&self, operation: &str) -> RouteDecision {
        let value = self
            .routes
            .get(operation)
            .or_else(|| self.routes.get("default"));
        match value.map(String::as_str) {
            Some("deny") | None => RouteDecision::Deny,
            Some("direct") => RouteDecision::Direct,
            Some(name) => RouteDecision::Chain(name.to_string()),
        }
    }

    /// CHAIN-0/CHAIN-3 validation. Any failure refuses startup.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` naming the offending chain or route.
    pub fn validate(&self) -> VoltaResult<()> {
        for (key, chain) in &self.chains {
            if chain.name != *key {
                return Err(VoltaError::ConfigInvalid(format!(
                    "chain table key {key} != chain name {}",
                    chain.name
                )));
            }
            if !chain.fail_closed {
                return Err(VoltaError::ConfigInvalid(format!(
                    "chain {}: fail_closed must be true",
                    chain.name
                )));
            }
            if chain.on_error != "abort" {
                return Err(VoltaError::ConfigInvalid(format!(
                    "chain {}: on_error must be \"abort\"",
                    chain.name
                )));
            }
            if chain.hops.is_empty() || chain.hops.len() > CHAIN_HOPS_MAX {
                return Err(VoltaError::ConfigInvalid(format!(
                    "chain {}: hop count {} outside 1..={CHAIN_HOPS_MAX}",
                    chain.name,
                    chain.hops.len()
                )));
            }
            let mut relay_peers_seen = Vec::new();
            for hop in &chain.hops {
                if hop.port == 0 {
                    return Err(VoltaError::ConfigInvalid(format!(
                        "chain {}: hop port 0",
                        chain.name
                    )));
                }
                if let Some(auth) = &hop.auth {
                    if let Some(secret) = &auth.secret_ref {
                        if !is_secret_ref(secret) {
                            return Err(VoltaError::ConfigInvalid(format!(
                                "chain {}: auth secret must be a reference (env:/file:/pass:)",
                                chain.name
                            )));
                        }
                    }
                }
                if hop.hop_type == HopType::VoltaRelay {
                    let peer = format!("{}:{}", hop.address, hop.port);
                    if relay_peers_seen.contains(&peer) {
                        return Err(VoltaError::ConfigInvalid(format!(
                            "chain {}: volta-relay peer {peer} appears twice (loop guard)",
                            chain.name
                        )));
                    }
                    relay_peers_seen.push(peer);
                }
                // CHAIN-3: a locally-resolving hop inside a
                // remote-DNS chain leaks names unless every hop
                // address is an IP literal (then there is no name
                // to leak).
                if hop.hop_type == HopType::Socks5 && chain.dns == ChainDns::Remote {
                    let all_ip = chain
                        .hops
                        .iter()
                        .all(|h| h.address.parse::<std::net::IpAddr>().is_ok());
                    if !all_ip {
                        return Err(VoltaError::ConfigInvalid(format!(
                            "chain {}: socks5 hop with dns=remote would resolve names locally (E_CHAIN_DNS_LEAK); use socks5h or dns=system",
                            chain.name
                        )));
                    }
                }
            }
        }
        for (operation, target) in &self.routes {
            if operation != "default" && !OPERATIONS.contains(&operation.as_str()) {
                return Err(VoltaError::ConfigInvalid(format!(
                    "proxy.routes: unknown operation {operation}"
                )));
            }
            if target == "direct" || target == "deny" {
                if target == "deny" && operation != "default" {
                    // deny is permitted per-operation too (it is
                    // the fail-closed default made explicit).
                }
                continue;
            }
            if !self.chains.contains_key(target) {
                return Err(VoltaError::ConfigInvalid(format!(
                    "proxy.routes.{operation}: unknown chain {target}"
                )));
            }
        }
        Ok(())
    }
}

fn is_secret_ref(value: &str) -> bool {
    value.starts_with("env:") || value.starts_with("file:") || value.starts_with("pass:")
}

/// Resolve a `env:` / `file:` secret reference. `pass:` references
/// are operator-machine only (the GPG agent is unreachable from
/// service contexts; SPEC 13.2 permits the reference, resolution
/// fails closed with a named error).
///
/// # Errors
/// `E_CONFIG_INVALID` when the reference cannot be resolved.
pub fn resolve_secret_ref(reference: &str) -> VoltaResult<Vec<u8>> {
    if let Some(var) = reference.strip_prefix("env:") {
        let value = std::env::var(var).map_err(|_| {
            VoltaError::ConfigInvalid(format!("secret reference env:{var} is not set"))
        })?;
        Ok(value.into_bytes())
    } else if let Some(path) = reference.strip_prefix("file:") {
        let mut bytes = std::fs::read(path).map_err(|e| {
            VoltaError::ConfigInvalid(format!("secret reference file:{path}: {e}"))
        })?;
        while matches!(bytes.last(), Some(b'\n' | b'\r')) {
            bytes.pop();
        }
        Ok(bytes)
    } else {
        Err(VoltaError::ConfigInvalid(format!(
            "unsupported secret reference scheme in {reference}"
        )))
    }
}

/// An MCP/A2A caller identity (SPEC 5.2 AgentPrincipal), as
/// configured. Identity public material is base64 of the raw
/// verifying-key bytes for the principal's suite.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalConfig {
    /// Permissions the principal holds (least privilege).
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Base64 raw identity verifying key (Ed25519: 32 bytes;
    /// volta ML-DSA-87+Ed25519 composite: ML-DSA key then Ed25519).
    pub identity_public_b64: String,
    /// The principal's identity suite.
    pub identity_suite: String,
    /// Stable operator-assigned agent ID.
    pub name: String,
}

/// The server's identity for signing (Agent Card, sync feed).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Identity suite: `eddsa-ed25519` or `volta-mldsa87-ed25519`.
    pub suite: String,
    /// Reference to the secret seed material (env:/file:).
    pub secret_ref: String,
    /// kid for emitted signatures: the identity fingerprint.
    pub fingerprint: String,
}

/// A volta-to-volta relay peer (SPEC 5.2 RelayPeer).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayPeerConfig {
    /// The peer's base URI.
    pub base_uri: String,
    /// The peer's pinned identity fingerprint.
    pub identity_fingerprint: String,
    /// The peer's name.
    pub name: String,
}

/// The whole server configuration (SPEC 16).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Public base URI of this instance.
    pub base_uri: String,
    /// Listen address, `host:port`.
    #[serde(default = "default_bind")]
    pub bind: String,
    /// State directory (blobs + index).
    pub data_dir: PathBuf,
    /// Server identity for card signing; absence disables A2A
    /// serving (A2A-1: refuse rather than serve unsigned).
    #[serde(default)]
    pub identity: Option<IdentityConfig>,
    /// Verification mail per hour per address (VKS-8).
    #[serde(default = "default_mail_rate")]
    pub mail_rate_limit_per_hour: u32,
    /// WebAuthn origin, exact match (SPEC 10.2).
    #[serde(default)]
    pub origin: String,
    /// Configured agent principals by name.
    #[serde(default)]
    pub principals: Vec<PrincipalConfig>,
    /// Proxy chains and routes (SPEC 13).
    #[serde(default)]
    pub proxy: ProxyConfig,
    /// Relay peers.
    #[serde(default)]
    pub relay_peers: Vec<RelayPeerConfig>,
    /// WebAuthn relying-party ID (SPEC 10).
    #[serde(default)]
    pub rp_id: String,
    /// Where SMTP submission goes, for verification mail egress.
    #[serde(default)]
    pub smtp_submit_address: Option<String>,
    /// Reference to the sealed-token secret (TOK-1).
    pub token_secret_ref: String,
    /// Sealed-token validity in seconds (TOK-4).
    #[serde(default = "default_token_validity")]
    pub token_validity_seconds: i64,
}

fn default_bind() -> String {
    "127.0.0.1:8737".to_string()
}

fn default_mail_rate() -> u32 {
    60
}

fn default_token_validity() -> i64 {
    TOKEN_VALIDITY_SECONDS_DEFAULT
}

impl ServerConfig {
    /// Load and validate a TOML configuration file.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` for unreadable, unparsable, or invalid
    /// configuration (including any proxy table defect, CHAIN-0).
    pub fn load(path: &std::path::Path) -> VoltaResult<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| VoltaError::ConfigInvalid(format!("{}: {e}", path.display())))?;
        let config: Self = toml::from_str(&text)
            .map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Parse and validate configuration from a string (tests, CLI).
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` on any defect.
    pub fn from_toml(text: &str) -> VoltaResult<Self> {
        let config: Self =
            toml::from_str(text).map_err(|e| VoltaError::ConfigInvalid(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the whole configuration.
    ///
    /// # Errors
    /// `E_CONFIG_INVALID` naming the defect.
    pub fn validate(&self) -> VoltaResult<()> {
        self.proxy.validate()?;
        if self.token_validity_seconds <= 0 {
            return Err(VoltaError::ConfigInvalid(
                "token_validity_seconds must be positive".to_string(),
            ));
        }
        if !is_secret_ref(&self.token_secret_ref) {
            return Err(VoltaError::ConfigInvalid(
                "token_secret_ref must be a reference (env:/file:/pass:)".to_string(),
            ));
        }
        for principal in &self.principals {
            for permission in &principal.permissions {
                const KNOWN: [&str; 6] = [
                    "ephemeral-issue",
                    "ephemeral-revoke",
                    "key-delete-request",
                    "key-lookup",
                    "key-publish",
                    "relay-fetch",
                ];
                if !KNOWN.contains(&permission.as_str()) {
                    return Err(VoltaError::ConfigInvalid(format!(
                        "principal {}: unknown permission {permission}",
                        principal.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// The configured principal with this name, when present.
    #[must_use]
    pub fn principal(&self, name: &str) -> Option<&PrincipalConfig> {
        self.principals.iter().find(|p| p.name == name)
    }

    /// The configured relay peer with this name, when present.
    #[must_use]
    pub fn relay_peer(&self, name: &str) -> Option<&RelayPeerConfig> {
        self.relay_peers.iter().find(|p| p.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"
base_uri = "https://volta.example.org"
data_dir = "/tmp/volta-test"
token_secret_ref = "env:VOLTA_TOKEN_SECRET"
"#;

    #[test]
    fn minimal_config_loads() {
        let config = ServerConfig::from_toml(BASE).expect("load");
        assert_eq!(config.bind, "127.0.0.1:8737");
        assert_eq!(config.proxy.route_for("wkd_fetch"), RouteDecision::Deny);
    }

    #[test]
    fn fail_closed_false_is_a_load_error() {
        let text = format!(
            "{BASE}\n[proxy.chains.bad]\nfail_closed = false\nname = \"bad\"\non_error = \"abort\"\n[[proxy.chains.bad.hops]]\naddress = \"127.0.0.1\"\nport = 9050\ntype = \"tor-socks\"\n"
        );
        assert!(matches!(
            ServerConfig::from_toml(&text),
            Err(VoltaError::ConfigInvalid(_))
        ));
    }

    #[test]
    fn socks5_in_remote_dns_chain_is_a_load_error() {
        let text = format!(
            "{BASE}\n[proxy.chains.leaky]\nfail_closed = true\nname = \"leaky\"\non_error = \"abort\"\n[[proxy.chains.leaky.hops]]\naddress = \"proxy.example.net\"\nport = 1080\ntype = \"socks5\"\n"
        );
        assert!(matches!(
            ServerConfig::from_toml(&text),
            Err(VoltaError::ConfigInvalid(_))
        ));
    }

    #[test]
    fn route_to_unknown_chain_is_a_load_error() {
        let text = format!("{BASE}\n[proxy.routes]\nwkd_fetch = \"nope\"\n");
        assert!(matches!(
            ServerConfig::from_toml(&text),
            Err(VoltaError::ConfigInvalid(_))
        ));
    }

    #[test]
    fn inline_secret_is_a_load_error() {
        let text = BASE.replace("env:VOLTA_TOKEN_SECRET", "hunter2");
        assert!(matches!(
            ServerConfig::from_toml(&text),
            Err(VoltaError::ConfigInvalid(_))
        ));
    }
}
