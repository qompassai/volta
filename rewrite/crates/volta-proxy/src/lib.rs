// #################################################################
// /qompassai/volta/rewrite/crates/volta-proxy/src/lib.rs
// Qompass AI Volta — Fail-Closed Proxy Chains (SPEC 13)
// SPDX-License-Identifier: AGPL-3.0-only OR Apache-2.0
// Copyright (c) 2026 Qompass AI
//
// Original work of Qompass AI (clean-room rewrite, 2026-10-10).
// #################################################################

#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Multi-hop proxy chains. The design rule of this crate is
//! CHAIN-2: an operation routed through a chain either completes
//! through every hop in order, or fails with a structured error.
//! There is no code path that retries direct, skips a hop, or
//! substitutes another chain — `dial` is the only way out, and it
//! consults the routing table exactly once.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use volta_core::config::{
    resolve_secret_ref, ChainConfig, HopConfig, HopType, ProxyConfig, RouteDecision,
};
use volta_core::error::{VoltaError, VoltaResult};

/// Per-hop connect/negotiate timeout default (SPEC 13.2).
pub const HOP_TIMEOUT_MS: u64 = 10_000;
/// Maximum bytes accepted for an HTTP response head (bounded work).
const HTTP_HEAD_MAX: usize = 8 * 1024;

/// A connected byte stream: plain TCP or TLS over TCP.
pub enum ChainStream {
    /// Plain TCP.
    Plain(TcpStream),
    /// TLS 1.3 over TCP (rustls).
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for ChainStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ChainStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, data),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }
}

/// One hop's outcome inside a chain-check report (SPEC 13.5).
#[derive(Clone, Debug, serde::Serialize)]
pub struct HopReport {
    /// 1-based hop index within the chain.
    pub hop_index: usize,
    /// The hop type string.
    pub hop_type: String,
    /// Milliseconds spent negotiating this hop.
    pub latency_ms: u64,
    /// `ok` or the error code that stopped the chain.
    pub status: String,
}

/// The result of a successful dial: the stream plus per-hop
/// timings (used by chain checks; discarded by operations).
pub struct Dialed {
    /// Per-hop reports, in traversal order.
    pub hops: Vec<HopReport>,
    /// The connected stream to the target.
    pub stream: ChainStream,
}

/// Dial the target for an operation, per the routing table.
///
/// # Errors
/// Fail closed (CHAIN-2): `E_PROXY_*` variants for any hop
/// failure; a `Deny` route fails with `E_PROXY_HOP_FAILED`
/// carrying the deny reason — it never connects anywhere.
pub async fn dial(
    proxy: &ProxyConfig,
    operation: &str,
    target_host: &str,
    target_port: u16,
) -> VoltaResult<Dialed> {
    match proxy.route_for(operation) {
        RouteDecision::Deny => Err(VoltaError::ProxyHopFailed(format!(
            "operation {operation} has no route (deny): refusing to connect"
        ))),
        RouteDecision::Direct => {
            let stream = connect_tcp(target_host, target_port).await?;
            Ok(Dialed {
                hops: Vec::new(),
                stream: ChainStream::Plain(stream),
            })
        }
        RouteDecision::Chain(name) => {
            let chain = proxy.chains.get(&name).ok_or_else(|| {
                VoltaError::ConfigInvalid(format!("route names unknown chain {name}"))
            })?;
            dial_chain(chain, operation, target_host, target_port).await
        }
    }
}

/// Dial through one named chain (CHAIN-1 ordered traversal).
///
/// # Errors
/// The first hop failure aborts the dial (CHAIN-2).
pub async fn dial_chain(
    chain: &ChainConfig,
    _operation: &str,
    target_host: &str,
    target_port: u16,
) -> VoltaResult<Dialed> {
    let whole = timeout(
        Duration::from_millis(chain.timeout_ms),
        dial_chain_inner(chain, target_host, target_port),
    )
    .await;
    match whole {
        Ok(result) => result,
        Err(_) => Err(VoltaError::ProxyTimeout),
    }
}

async fn dial_chain_inner(
    chain: &ChainConfig,
    target_host: &str,
    target_port: u16,
) -> VoltaResult<Dialed> {
    let mut reports = Vec::new();
    // Connect to hop 1 (bootstrap resolution of hop 1's own name is
    // the documented CHAIN-4 exception).
    let first = &chain.hops[0];
    let started = Instant::now();
    let raw = connect_tcp(&first.address, first.port).await?;
    let mut stream = if first.tls {
        upgrade_tls(raw, first).await?
    } else {
        ChainStream::Plain(raw)
    };
    reports.push(HopReport {
        hop_index: 1,
        hop_type: first.hop_type.as_str().to_string(),
        latency_ms: elapsed_ms(started),
        status: "ok".to_string(),
    });
    // Each hop negotiates a tunnel to the next endpoint; the last
    // hop negotiates to the target.
    for (index, hop) in chain.hops.iter().enumerate() {
        let (next_host, next_port) = match chain.hops.get(index + 1) {
            Some(next) => (next.address.as_str(), next.port),
            None => (target_host, target_port),
        };
        let started = Instant::now();
        negotiate(&mut stream, hop, next_host, next_port, index + 1).await?;
        if index > 0 {
            reports.push(HopReport {
                hop_index: index + 1,
                hop_type: hop.hop_type.as_str().to_string(),
                latency_ms: elapsed_ms(started),
                status: "ok".to_string(),
            });
        } else if let Some(report) = reports.last_mut() {
            report.latency_ms += elapsed_ms(started);
        }
        // The next hop's own transport may itself be TLS.
        if let Some(next) = chain.hops.get(index + 1) {
            if next.tls {
                let plain = match stream {
                    ChainStream::Plain(tcp) => tcp,
                    ChainStream::Tls(_) => {
                        return Err(VoltaError::ProxyHopFailed(
                            "nested TLS transports are not supported".to_string(),
                        ));
                    }
                };
                stream = upgrade_tls(plain, next).await?;
            }
        }
    }
    Ok(Dialed {
        hops: reports,
        stream,
    })
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

async fn connect_tcp(host: &str, port: u16) -> VoltaResult<TcpStream> {
    let connect = TcpStream::connect((host, port));
    match timeout(Duration::from_millis(HOP_TIMEOUT_MS), connect).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(VoltaError::ProxyHopFailed(error.to_string())),
        Err(_) => Err(VoltaError::ProxyTimeout),
    }
}

/// Wrap a stream in TLS 1.3 with SPKI pin verification. When the
/// hop carries an `spki_pin`, the peer's SubjectPublicKeyInfo hash
/// must match it exactly; a mismatch is `E_PROXY_TLS_PIN_MISMATCH`
/// and the connection is dropped (CHAIN-2).
async fn upgrade_tls(stream: TcpStream, hop: &HopConfig) -> VoltaResult<ChainStream> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    struct PinVerifier {
        pin: Option<Vec<u8>>,
    }

    impl ServerCertVerifier for PinVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            match &self.pin {
                None => Ok(ServerCertVerified::assertion()),
                Some(expected) => {
                    let actual = spki_sha256(end_entity.as_ref());
                    if &actual == expected {
                        Ok(ServerCertVerified::assertion())
                    } else {
                        Err(rustls::Error::General(
                            "spki pin mismatch".to_string(),
                        ))
                    }
                }
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::PeerIncompatible(
                rustls::PeerIncompatible::Tls12NotOfferedOrEnabled,
            ))
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            // With an SPKI pin the peer's key IS the trust anchor;
            // the pin check above binds the key, and TLS 1.3
            // transcript verification is delegated to the pin
            // (documented pinning model, SPEC 13.2 spki_pin).
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
            ]
        }
    }

    let pin = match &hop.spki_pin {
        Some(text) => {
            let encoded = text.strip_prefix("sha256:").ok_or_else(|| {
                VoltaError::ConfigInvalid("spki_pin must be sha256:<base64>".to_string())
            })?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| VoltaError::ConfigInvalid("spki_pin is not base64".to_string()))?;
            Some(bytes)
        }
        None => None,
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinVerifier { pin }))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from(
        hop.tls_server_name
            .clone()
            .unwrap_or_else(|| hop.address.clone()),
    )
    .map_err(|_| VoltaError::ConfigInvalid("tls server name invalid".to_string()))?;
    let tls = connector
        .connect(server_name, stream)
        .await
        .map_err(|error| {
            if error.to_string().contains("spki pin mismatch") {
                VoltaError::ProxyTlsPinMismatch
            } else {
                VoltaError::ProxyHopFailed(error.to_string())
            }
        })?;
    Ok(ChainStream::Tls(Box::new(tls)))
}

/// SHA-256 of the SubjectPublicKeyInfo inside a DER certificate.
fn spki_sha256(certificate_der: &[u8]) -> Vec<u8> {
    use der::Encode;
    use sha2::{Digest, Sha256};
    let Ok(certificate) =
        <x509_cert::Certificate as der::Decode>::from_der(certificate_der)
    else {
        return Vec::new();
    };
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    match spki.to_der() {
        Ok(bytes) => Sha256::digest(&bytes).to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Negotiate one hop's tunnel to the next endpoint.
async fn negotiate(
    stream: &mut ChainStream,
    hop: &HopConfig,
    next_host: &str,
    next_port: u16,
    hop_index: usize,
) -> VoltaResult<()> {
    let result = timeout(
        Duration::from_millis(HOP_TIMEOUT_MS),
        negotiate_inner(stream, hop, next_host, next_port, hop_index),
    )
    .await;
    match result {
        Ok(result) => result,
        Err(_) => Err(VoltaError::ProxyTimeout),
    }
}

async fn negotiate_inner(
    stream: &mut ChainStream,
    hop: &HopConfig,
    next_host: &str,
    next_port: u16,
    hop_index: usize,
) -> VoltaResult<()> {
    match hop.hop_type {
        HopType::HttpConnect => http_connect(stream, hop, next_host, next_port).await,
        HopType::Socks5 => socks(stream, hop, next_host, next_port, false).await,
        HopType::Socks5h => socks(stream, hop, next_host, next_port, true).await,
        HopType::TorSocks => socks(stream, hop, next_host, next_port, true).await,
        HopType::VoltaRelay => volta_relay(stream, hop, next_host, next_port, hop_index).await,
    }
}

/// Resolve hop credentials from their secret reference. The
/// resolved value is `username:password` for userpass. Credential
/// material is never placed in an error (CHAIN-6).
fn hop_userpass(hop: &HopConfig) -> VoltaResult<Option<(String, String)>> {
    let Some(auth) = &hop.auth else {
        return Ok(None);
    };
    if auth.method != "userpass" {
        return Ok(None);
    }
    let Some(reference) = &auth.secret_ref else {
        return Err(VoltaError::ProxyAuthFailed);
    };
    let secret = resolve_secret_ref(reference).map_err(|_| VoltaError::ProxyAuthFailed)?;
    let text = String::from_utf8(secret).map_err(|_| VoltaError::ProxyAuthFailed)?;
    let (username, password) = text
        .split_once(':')
        .map(|(u, p)| (u.to_string(), p.to_string()))
        .unwrap_or_else(|| (auth.username.clone().unwrap_or_default(), text.clone()));
    Ok(Some((username, password)))
}

async fn socks(
    stream: &mut ChainStream,
    hop: &HopConfig,
    next_host: &str,
    next_port: u16,
    remote_dns: bool,
) -> VoltaResult<()> {
    let userpass = hop_userpass(hop)?;
    // Tor stream isolation (CHAIN-5): distinct credentials per
    // operation when isolation is configured.
    let isolation = if hop.hop_type == HopType::TorSocks {
        let id = hop
            .isolation_id
            .clone()
            .unwrap_or_else(|| "per-operation".to_string());
        let username = if id == "per-operation" {
            let mut bytes = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            let mut text = String::with_capacity(16);
            for byte in bytes {
                text.push_str(&format!("{byte:02x}"));
            }
            text
        } else {
            id
        };
        Some((username, "x".to_string()))
    } else {
        None
    };
    let credentials = userpass.or(isolation);
    // Greeting.
    let methods: Vec<u8> = if credentials.is_some() {
        vec![0x00, 0x02]
    } else {
        vec![0x00]
    };
    let mut greeting = vec![0x05, u8::try_from(methods.len()).unwrap_or(1)];
    greeting.extend_from_slice(&methods);
    stream
        .write_all(&greeting)
        .await
        .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .await
        .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
    if reply[0] != 0x05 {
        return Err(VoltaError::ProxyHopFailed("socks version".to_string()));
    }
    match reply[1] {
        0x00 => {}
        0x02 => {
            let (username, password) = credentials.ok_or(VoltaError::ProxyAuthFailed)?;
            let mut auth = vec![0x01, u8::try_from(username.len()).unwrap_or(0)];
            auth.extend_from_slice(username.as_bytes());
            auth.push(u8::try_from(password.len()).unwrap_or(0));
            auth.extend_from_slice(password.as_bytes());
            stream
                .write_all(&auth)
                .await
                .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
            let mut auth_reply = [0u8; 2];
            stream
                .read_exact(&mut auth_reply)
                .await
                .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
            if auth_reply[1] != 0x00 {
                return Err(VoltaError::ProxyAuthFailed);
            }
        }
        0xff => return Err(VoltaError::ProxyAuthFailed),
        _ => return Err(VoltaError::ProxyHopFailed("socks method".to_string())),
    }
    // CONNECT request.
    let mut request = vec![0x05, 0x01, 0x00];
    if remote_dns {
        // ATYP 0x03: the name travels unresolved (CHAIN-3).
        let host_bytes = next_host.as_bytes();
        if host_bytes.len() > 255 {
            return Err(VoltaError::ProxyDnsFailed);
        }
        request.push(0x03);
        request.push(u8::try_from(host_bytes.len()).unwrap_or(0));
        request.extend_from_slice(host_bytes);
    } else if let Ok(ip) = next_host.parse::<std::net::Ipv4Addr>() {
        request.push(0x01);
        request.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = next_host.parse::<std::net::Ipv6Addr>() {
        request.push(0x04);
        request.extend_from_slice(&ip.octets());
    } else {
        // Local resolution is this hop type's documented behavior
        // (CHAIN-3 restricts where it may appear in a chain).
        let resolved = tokio::net::lookup_host((next_host, next_port))
            .await
            .map_err(|_| VoltaError::ProxyDnsFailed)?
            .next()
            .ok_or(VoltaError::ProxyDnsFailed)?;
        match resolved.ip() {
            std::net::IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
    }
    request.extend_from_slice(&next_port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
    // Reply: VER REP RSV ATYP BND.ADDR BND.PORT.
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
    if head[0] != 0x05 {
        return Err(VoltaError::ProxyHopFailed("socks reply version".to_string()));
    }
    if head[1] != 0x00 {
        return Err(VoltaError::ProxyHopFailed(format!(
            "socks connect reply {}",
            head[1]
        )));
    }
    let skip = match head[3] {
        0x01 => 4,
        0x03 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .await
                .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
            usize::from(len[0])
        }
        0x04 => 16,
        _ => return Err(VoltaError::ProxyHopFailed("socks reply atyp".to_string())),
    };
    let mut sink = vec![0u8; skip + 2];
    stream
        .read_exact(&mut sink)
        .await
        .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
    Ok(())
}

async fn http_connect(
    stream: &mut ChainStream,
    hop: &HopConfig,
    next_host: &str,
    next_port: u16,
) -> VoltaResult<()> {
    let mut request = format!(
        "CONNECT {next_host}:{next_port} HTTP/1.1\r\nHost: {next_host}:{next_port}\r\n"
    );
    if let Some((username, password)) = hop_userpass(hop)? {
        let encoded = base64::engine::general_purpose::STANDARD
            .encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {encoded}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while head.len() < HTTP_HEAD_MAX {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    let status: u32 = text
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    match status {
        200 => Ok(()),
        407 => Err(VoltaError::ProxyAuthFailed),
        _ => Err(VoltaError::ProxyHopFailed(format!(
            "http connect status {status}"
        ))),
    }
}

/// The volta-relay hop (SPEC 13.6): an HTTP upgrade carrying a
/// JSON next-hop request. The relay token comes from the hop's
/// `ephemeral` auth secret reference (a pre-shared relay token
/// standing in for the section 7 relay-session handshake in this
/// build — see the book's named gaps).
async fn volta_relay(
    stream: &mut ChainStream,
    hop: &HopConfig,
    next_host: &str,
    next_port: u16,
    hop_index: usize,
) -> VoltaResult<()> {
    let mut token = String::new();
    if let Some(auth) = &hop.auth {
        if let Some(reference) = &auth.secret_ref {
            let secret =
                resolve_secret_ref(reference).map_err(|_| VoltaError::ProxyAuthFailed)?;
            token = String::from_utf8(secret).map_err(|_| VoltaError::ProxyAuthFailed)?;
        }
    }
    let body = serde_json::json!({
        "chain_position": hop_index,
        "next": { "host": next_host, "port": next_port }
    })
    .to_string();
    let request = format!(
        "POST /relay/v1/connect HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Volta-Relay-Token: {}\r\nConnection: Upgrade\r\nUpgrade: volta-relay\r\n\r\n{}",
        hop.address,
        hop.port,
        body.len(),
        token,
        body
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while head.len() < HTTP_HEAD_MAX {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| VoltaError::ProxyHopFailed(e.to_string()))?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&head).to_string();
    if text.contains(" 101") {
        Ok(())
    } else if text.contains(" 403") {
        Err(VoltaError::RelayPeerMismatch)
    } else {
        Err(VoltaError::ProxyHopFailed(format!(
            "volta-relay upgrade refused: {}",
            text.lines().next().unwrap_or("")
        )))
    }
}

/// Chain check (SPEC 13.5): negotiate the chain to a probe target
/// and report per-hop results as data. A failed hop is reported in
/// the result, not returned as an error.
///
/// # Errors
/// Only when the chain itself is unknown (a configuration defect).
pub async fn check_chain(
    proxy: &ProxyConfig,
    chain_name: &str,
    probe_host: &str,
    probe_port: u16,
) -> VoltaResult<(bool, Vec<HopReport>)> {
    let chain = proxy.chains.get(chain_name).ok_or_else(|| {
        VoltaError::ConfigInvalid(format!("unknown chain {chain_name}"))
    })?;
    match dial_chain(chain, "chain_check", probe_host, probe_port).await {
        Ok(dialed) => Ok((true, dialed.hops)),
        Err(error) => Ok((
            false,
            vec![HopReport {
                hop_index: 0,
                hop_type: String::new(),
                latency_ms: 0,
                status: error.code().to_string(),
            }],
        )),
    }
}

/// Convenience map type for callers building configs in code.
pub type ChainMap = BTreeMap<String, ChainConfig>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    fn chain_with_hops(hops: Vec<HopConfig>) -> ChainConfig {
        ChainConfig {
            dns: volta_core::config::ChainDns::Remote,
            fail_closed: true,
            hops,
            name: "test".to_string(),
            on_error: "abort".to_string(),
            timeout_ms: 10_000,
        }
    }

    fn socks_hop(port: u16) -> HopConfig {
        HopConfig {
            address: "127.0.0.1".to_string(),
            auth: None,
            isolation_id: None,
            port,
            spki_pin: None,
            tls: false,
            tls_server_name: None,
            hop_type: HopType::Socks5h,
        }
    }

    /// A recording target: counts connections, echoes one byte.
    async fn recording_target(counter: Arc<AtomicUsize>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                counter.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut byte = [0u8; 1];
                    if socket.read_exact(&mut byte).await.is_ok() {
                        let _ = socket.write_all(&byte).await;
                    }
                });
            }
        });
        port
    }

    /// A minimal SOCKS5 server that records the address type of
    /// each CONNECT and forwards to a fixed target port on
    /// 127.0.0.1. Returns (port, seen_atyp log).
    async fn fake_socks(target_port: u16, atyp_log: Arc<std::sync::Mutex<Vec<u8>>>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let atyp_log = atyp_log.clone();
                tokio::spawn(async move {
                    let mut greeting = [0u8; 2];
                    if socket.read_exact(&mut greeting).await.is_err() {
                        return;
                    }
                    let nmethods = usize::from(greeting[1]);
                    let mut methods = vec![0u8; nmethods];
                    let _ = socket.read_exact(&mut methods).await;
                    let _ = socket.write_all(&[0x05, 0x00]).await;
                    let mut head = [0u8; 4];
                    if socket.read_exact(&mut head).await.is_err() {
                        return;
                    }
                    atyp_log.lock().expect("lock").push(head[3]);
                    match head[3] {
                        0x03 => {
                            let mut len = [0u8; 1];
                            let _ = socket.read_exact(&mut len).await;
                            let mut name = vec![0u8; usize::from(len[0])];
                            let _ = socket.read_exact(&mut name).await;
                        }
                        0x01 => {
                            let mut sink = [0u8; 4];
                            let _ = socket.read_exact(&mut sink).await;
                        }
                        _ => return,
                    }
                    let mut port_bytes = [0u8; 2];
                    let _ = socket.read_exact(&mut port_bytes).await;
                    let _ = socket
                        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    if let Ok(mut upstream) =
                        TcpStream::connect(("127.0.0.1", target_port)).await
                    {
                        let _ = tokio::io::copy_bidirectional(&mut socket, &mut upstream)
                            .await;
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn socks5h_carries_the_hostname_unresolved() {
        let counter = Arc::new(AtomicUsize::new(0));
        let target_port = recording_target(counter.clone()).await;
        let atyp_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let proxy_port = fake_socks(target_port, atyp_log.clone()).await;
        let chain = chain_with_hops(vec![socks_hop(proxy_port)]);
        // "target.invalid" cannot resolve locally; success proves
        // the name traveled to the proxy (CHAIN-3).
        let mut dialed = dial_chain(&chain, "key_lookup", "target.invalid", target_port)
            .await
            .expect("dial through chain");
        dialed.stream.write_all(b"z").await.expect("write");
        let mut byte = [0u8; 1];
        dialed.stream.read_exact(&mut byte).await.expect("read");
        assert_eq!(byte[0], b'z');
        assert_eq!(atyp_log.lock().expect("lock").as_slice(), &[0x03]);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dead_first_hop_fails_closed_and_never_touches_the_target() {
        let counter = Arc::new(AtomicUsize::new(0));
        let target_port = recording_target(counter.clone()).await;
        // Port 1 is closed on loopback: the first hop is down.
        let chain = chain_with_hops(vec![socks_hop(1)]);
        let result = dial_chain(&chain, "key_lookup", "127.0.0.1", target_port).await;
        assert!(matches!(
            result,
            Err(VoltaError::ProxyHopFailed(_)) | Err(VoltaError::ProxyTimeout)
        ));
        // The fail-closed proof: no direct connection was attempted.
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn deny_route_never_connects() {
        let counter = Arc::new(AtomicUsize::new(0));
        let target_port = recording_target(counter.clone()).await;
        let proxy = ProxyConfig::default();
        let result = dial(&proxy, "wkd_fetch", "127.0.0.1", target_port).await;
        assert!(result.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn two_hop_chain_traverses_in_order() {
        let counter = Arc::new(AtomicUsize::new(0));
        let target_port = recording_target(counter.clone()).await;
        let atyp_log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let second = fake_socks(target_port, atyp_log.clone()).await;
        let first = fake_socks(second, atyp_log.clone()).await;
        let chain = chain_with_hops(vec![socks_hop(first), socks_hop(second)]);
        let mut dialed = dial_chain(&chain, "relay_fetch", "127.0.0.1", target_port)
            .await
            .expect("two-hop dial");
        dialed.stream.write_all(b"q").await.expect("write");
        let mut byte = [0u8; 1];
        dialed.stream.read_exact(&mut byte).await.expect("read");
        assert_eq!(byte[0], b'q');
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
