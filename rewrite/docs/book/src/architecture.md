# Architecture

Volta is a Cargo workspace of five crates, each with one job.
Dependencies point one way: surfaces depend on the core and the
crypto, never on each other.

| Crate | Responsibility |
|---|---|
| `volta-core` | Configuration (with chain validation), the error taxonomy, the key store, OpenPGP parsing + the algorithm allowlist, sealed tokens, the WKD hash |
| `volta-crypto` | KEM suites, identity signing (Ed25519 and the volta ML-DSA-87+Ed25519 composite), the machine-readable crypto policy |
| `volta-proxy` | Fail-closed proxy-chain dialing: SOCKS5/SOCKS5h, Tor SOCKS, HTTP CONNECT, TLS hops with SPKI pins, volta-relay hops |
| `volta-server` | The HTTP surfaces: HKP, VKS, WKD, ephemeral API, MCP, A2A, WebAuthn, relay, web |
| `volta-cli` | `voltactl` (operator CLI incl. the stdio MCP transport) and `volta-delete` |

<details>
<summary>Storage: content-addressed, index-derived</summary>

Certificates live as immutable blobs named by their SHA-256.
A SQLite index (bindings, certificates, subkey index, WKD index)
is derived **once at ingest** — the read path never parses,
cleans, or renders a key (that was a per-request cost in the
predecessor). A blob whose bytes do not match its content
address is never served. `voltactl regenerate` rebuilds every
derived row from the stored certificates and reports mismatches.

</details>

<details>
<summary>State: what is durable, what is deliberately not</summary>

- **Durable**: certificates, bindings, ephemeral-key *metadata*,
  WebAuthn credentials, bootstrap hashes.
- **Memory-only by design**: server-custody ephemeral *private
  material* (never written to disk; a restart answers those keys
  `410 E_KEY_EXPIRED` with `custody_lost: true`), operator
  sessions, WebAuthn challenges (single-use, 300 s), A2A tasks,
  shared secrets (never stored at all — there is no field for
  them).

</details>

<details>
<summary>Errors are a contract</summary>

Every failure on the new surfaces is RFC 9457 problem JSON with
a stable `E_*` code, mirrored in the `X-Volta-Error-Code`
header, plus a uuid-v7 request id. The taxonomy (~40 codes)
lives in `volta-core`'s error module and is the same vocabulary
MCP tool results and A2A task histories speak.

</details>
