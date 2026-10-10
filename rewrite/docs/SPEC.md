# Volta Rewrite — Behavior / Interface Specification

- **Status:** Clean-room behavior/interface spec, v1.0, 2026-10-10.
- **Scope:** Everything an implementer needs to build a wire-compatible,
  behavior-compatible successor to volta (the Hagrid-derived OpenPGP key
  server) plus the new agent-era surfaces mandated 2026-10-10: ephemeral
  Rosenpass-style keys for MCP and A2A, a PQC allowlist by design,
  WebAuthn/FIDO2 passkey authorization for operator actions, and
  configurable fail-closed proxy chains.
- **Non-scope:** Implementation structure, crate layout, language idioms.
  This spec constrains observable behavior, wire formats, data semantics,
  configuration schemas, and error behavior only.

<details>
<summary>How to read this spec</summary>

- The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and
  **MAY** are normative (RFC 2119 / RFC 8174 sense).
- Requirements carry stable IDs (`HKP-1`, `VKS-3`, `EPH-2`, …) so tests
  and conformance reports can cite them.
- Sections, endpoint tables, tool lists, configuration keys, error
  codes, and enumerations are listed in **alphabetical order** per the
  standing ordering rule (§3). Where an order is semantically load-
  bearing (OpenPGP packet order, JWS construction, proxy-chain hop
  traversal), the order is protocol order and §3 says so explicitly.
- Times are UTC, RFC 3339, seconds precision unless stated otherwise.
  Durations are integer seconds unless a field name ends in `_ms`.

</details>

---

## 1. Clean-room provenance

This spec was derived **only** from public surfaces. No implementation
source of the predecessor tree (no `.rs` file under `src/`, `database/`,
or `voltactl/`) was read at any point.

| # | Source (public surface) | What it grounded |
|---|---|---|
| S-1 | mdBook docs of the old tree: `docs/src/{SUMMARY,architecture,contracts,introduction,licensing,nix,operations,security,testing}.md`, `book.toml` | Route inventory, trust model, sealed-token contract and bounds, configuration key names, build/run behavior, documented limitations |
| S-2 | `README.md` of the old tree | Product identity (OpenPGP key server, Hagrid-derived), quickstart, crate names |
| S-3 | `Cargo.toml` metadata (root, `database/`, `voltactl/` manifests: names, versions, descriptions, licenses only) | Component inventory and version skew (conflict C-7) |
| S-4 | CLI help output, black-box, on primo: `voltactl --help`, `voltactl import --help`, `voltactl regenerate --help`, `volta-delete --help`, `--version` outputs; `volta --help` attempted | Operator CLI surface (§15); the `--help` panic finding (conflict C-8) |
| S-5 | Operator-facing deployment config shipped at the repo root (`Rocket.toml.dist`, `volta-routes.conf` — nginx edge configuration, not implementation source) | Public edge behavior: body-size cap, rate-limit zones, static-serve sharding shape, internal HKP rewrite shapes |
| S-6 | keys.openpgp.org public API page (`/about/api/`, the upstream VKS/HKP contract for Hagrid) | VKS request/response shapes, status vocabulary, rate-limit floors, HKP subset and its documented limitations |
| S-7 | HKP draft (draft-shaw-openpgp-hkp-00 lineage; current text draft-gallagher-openpgp-hkp) | `op` vocabulary, variables (`search`, `options`, `fingerprint`, `exact`), machine-readable index format |
| S-8 | WKD draft (draft-koch-openpgp-webkey-service) | Advanced/direct methods, `hu/` hash construction, `policy` file |
| S-9 | RFC 9580 (OpenPGP) and RFC 9980 (PQC in OpenPGP) | Certificate versions, fingerprint lengths, composite algorithm IDs and pairings |
| S-10 | FIPS 203 (ML-KEM), FIPS 204 (ML-DSA); Rosenpass whitepaper (public) | PQC parameter sets; ephemeral rekeying cadence and PSK-delivery semantics |
| S-11 | MCP specification (public, 2025-06-18 lineage: JSON-RPC 2.0, `initialize`, `tools/list`, `tools/call`, Streamable HTTP); A2A specification (public: Agent Card at `/.well-known/agent-card.json`, signed cards via JWS, task lifecycle); WebAuthn Level 2/3 (W3C) | New surfaces in §8, §9, §10 |

Where a fact could not be established from these surfaces, this spec
**decides** it and marks the decision `DECISION:` so a reviewer can
overrule it in one place instead of hunting through prose.

---

## 2. Premise conflicts found (resolve before building)

Each conflict lists the colliding sources and the resolution this spec
adopts. Resolutions are normative for the rewrite unless Matt overrules
them.

### C-1 — PQC composite pairings: requirement vs RFC 9980

- **Requirement (2026-10-10):** allowlist built on ML-KEM-1024,
  "hybrid X25519+ML-KEM", ML-DSA-87, and "Ed25519 as classical hybrid
  half".
- **RFC 9980 (S-9):** the standardized OpenPGP composites pair
  ML-KEM-768 with X25519 (algorithm 35, MUST) and ML-KEM-1024 with
  **X448** (algorithm 36, SHOULD); ML-DSA-65 with **Ed25519**
  (algorithm 30, MUST) and ML-DSA-87 with **Ed448** (algorithm 31,
  SHOULD). There is no RFC 9980 algorithm ID for X25519+ML-KEM-1024 or
  Ed25519+ML-DSA-87.
- **Resolution:** both are specified, in separate domains (§11):
  - OpenPGP certificate surfaces accept/serve exactly the RFC 9980
    pairings. An implementation MUST NOT encode a non-standard pairing
    under an RFC 9980 algorithm ID.
  - Volta-native surfaces (ephemeral keys, A2A card signatures, MCP
    session binding) additionally define the volta-native suites
    `hybrid-mlkem1024-x25519` and `hybrid-mldsa87-ed25519`, clearly
    named, never representable as OpenPGP certificates.
- **Consequence if ignored:** keys generated to the letter of the
  requirement would be unparseable by every conforming OpenPGP
  implementation.

### C-2 — WKD mandates SHA-1; the allowlist rejects SHA-1

- **WKD draft (S-8):** the `hu/` path segment is z-base-32(SHA-1(
  lowercased local-part)) — a fixed 32-character string. There is no
  alternative construction in the draft.
- **Requirement (2026-10-10):** SHA-1 is on the explicit rejected list.
- **Resolution:** SHA-1 survives in exactly one scoped exception
  (§11.4): as the WKD **address-naming hash**. It is not a security
  digest there — authenticity of a WKD result comes from the
  certificate's self-signatures and the HTTPS channel; a SHA-1
  collision lets an attacker shadow an address lookup (availability /
  misdirection), never forge a certificate. Any other SHA-1 use —
  signature digest, fingerprint (outside the inherent v4 fingerprint
  definition), token construction, file integrity — is rejected.

### C-3 — Fingerprint/KeyID textual form differs per surface

- **VKS (S-6):** hexadecimal MUST be uppercase, MUST NOT carry a `0x`
  prefix (by-fingerprint, by-keyid).
- **HKP (S-6, S-7):** `0x` prefix optional; KeyID/fingerprint may name
  a primary key or any subkey.
- **Old edge config (S-5):** internal rewrites accept `(?:0x)?` and
  uppercase the value before dispatch.
- **Resolution:** one canonical stored form (§5.1) and per-surface
  acceptance rules (§6.1, §6.2): VKS stays strict-canonical on output
  and normalizes on input; HKP accepts the draft's forms. Rejecting
  lowercase VKS input is **not** required and the rewrite does not —
  S-6 states what clients MUST send, not what servers MUST reject.

### C-4 — HKP completeness: the deployed subset vs the draft

- **Draft (S-7)** defines `op=vindex`, substring/exact search
  semantics, and a populated expiration field in index records.
- **Deployed Hagrid/volta behavior (S-1, S-6)** is a deliberate
  subset: no `vindex`; exact matches only (email, fingerprint, long
  KeyID); at most one result; expiration field left blank; parameters
  other than `op` and `search` ignored; output always machine-readable.
- **Resolution:** the rewrite keeps the subset (it is the privacy and
  abuse posture of a verifying keyserver — substring search is an
  enumeration oracle) and declares each deviation in §6.1 instead of
  inheriting them silently. Two subset behaviors are **fixed**, not
  kept: the index expiration field is populated when the key carries
  an expiration (blank only when none exists), and `op=stats` is
  implemented with the defined schema in §6.1.4.

### C-5 — VKS error-shape asymmetry in the upstream contract

- **S-6:** failed GETs return a plaintext message with a suitable
  status; failed POSTs return JSON `{"error": "…"}`.
- **Resolution:** preserved byte-for-byte on the legacy surfaces
  (§6.2.5), with the structured taxonomy of §13 added via content
  negotiation (`Accept: application/problem+json`) and an
  `X-Volta-Error-Code` header on every error response, so old clients
  are untouched and new clients get structure.

### C-6 — "Stateful on-disk tokens" vs "stateless sealed tokens"

- **S-1 architecture** describes "stateful on-disk tokens" (a
  `token_dir` exists in configuration, S-5) while **S-1 contracts**
  specify stateless sealed tokens in detail.
- **Resolution:** both existed. The rewrite standardizes: verify and
  manage links use **only** the stateless sealed construction of
  §5.4 (wire-compatible). Server-side single-use state exists only
  for WebAuthn challenges (§10) and ephemeral sessions (§7), held in
  the shared TTL store of §12 — never as node-local files, which is
  scaling gap G-7.

### C-7 — Version skew across the old tree

- **S-3/S-4:** server package `1.1.0`; `volta-delete --version` →
  `1.1.0`; `voltactl --version` → `Volta Control 0.1` while its
  manifest says `1.0.0`; database crate `0.1.0`.
- **Resolution:** the rewrite ships one workspace version; every
  binary's `--version` MUST print that version (§15, CLI-3).

### C-8 — The old server binary has no usable `--help`

- **Black-box probe (S-4):** `volta --help` panics on missing
  configuration (`keys_internal_dir`) instead of printing usage;
  `voltactl` with no arguments panics on a missing config file
  instead of printing usage.
- **Resolution:** CLI-1/CLI-2 (§15) make help/version config-free and
  panic-free. A missing-config invocation exits `2` with a structured
  error naming the missing key, never a panic backtrace.

### C-9 — WKD hosted form vs draft form

- **S-1** lists the volta WKD surface as
  `/.well-known/openpgpkey/<domain>/hu/<hash>` and `/policy` on the
  keyserver's own host (a multi-domain hosted form), while **S-8**
  defines the per-domain advanced form
  (`openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>`)
  and direct form (`<domain>/.well-known/openpgpkey/hu/<hash>`).
- **Resolution:** all three are served (§6.3). The hosted form is a
  keyserver adaptation, kept for compatibility; responses are
  identical in body and semantics.

### C-10 — "Rosenpass-style" is a semantics borrowing, not wire compatibility

- **S-10:** Rosenpass pairs a static Classic McEliece KEM with an
  ephemeral Kyber KEM and refreshes a WireGuard PSK roughly every two
  minutes. Classic McEliece and Kyber-as-draft are **not** in the
  2026-10-10 allowlist; FIPS 203 ML-KEM is.
- **Resolution:** §7 adopts Rosenpass **semantics** — static identity
  plus short-lived ephemeral KEM material, ~2-minute default
  rotation, derived symmetric key delivered as a PSK, forward
  secrecy from ephemeral destruction — over ML-KEM suites. The
  result is not wire-compatible with Rosenpass and MUST NOT be
  advertised as Rosenpass.

### C-11 — Two different "3600"s must not be conflated

- **S-5:** `token_validity = 3600` (seconds) bounds sealed verify/
  manage tokens (§5.4). **§7** independently sets the ephemeral-key
  hard TTL cap at 3600 s. They are different token classes with
  different stores and failure modes; configuration keys keep them
  in separate sections (§16) so neither can silently retune the other.

---

## 3. Global conventions

- **ORD-1 (alphabetical ordering, standing rule 2026-10-10):** every
  enumerable surface is alphabetical unless an external protocol
  mandates an order: configuration keys, endpoint listings, enum
  values in documentation, error codes, JSON keys in examples, MCP
  tool names, A2A skill IDs, file and directory names, and CLI
  subcommands. Protocol-mandated orders that win over ORD-1: OpenPGP
  packet order, HKP machine-readable record order (§6.1.3), JWS
  signing input construction, and proxy-chain hop traversal order
  (§13: hop order is the semantics, exactly the
  "dependency order wins" exception of the standing rule).
- **GLOB-1 (transport):** every HTTP surface is HTTPS with TLS 1.3
  only (§11). Plain HTTP is served only on loopback in development
  profiles. HKP's historical port 11371 MAY be listened on as an
  HKPS alias; there is no cleartext HKP listener in production
  profiles.
- **GLOB-2 (request IDs):** every response carries `X-Request-Id`
  (UUIDv7). Error bodies repeat it (§13).
- **GLOB-3 (no silent fallback):** no feature in this spec degrades
  silently — not proxy routing (§13), not
  crypto negotiation (§11), not verification state (§5). Any behavior
  a caller might not expect is either an error or an explicit field
  in the response.
- **GLOB-4 (no key-material logging):** request paths MUST NOT log
  token plaintexts, private key material, shared secrets, or
  verification-mail contents (carried over from S-1 security model).
  Logs carry fingerprints, key IDs, error codes, and request IDs only.
- **GLOB-5 (canonical encodings):** fingerprints are uppercase hex
  without `0x` (§5.1); email addresses are stored and indexed
  lowercased (§5.2); binary key material on JSON surfaces is
  base64 (standard alphabet, padded) unless a field is documented as
  ASCII armor.
- **GLOB-6 (time):** servers MUST run on synchronized UTC (NTP or
  equivalent). Token and TTL checks (§5.4, §7) assume skew ≤ 5 s
  between volta nodes; checks themselves grant **zero** skew
  allowance (fail closed, C-6/§5.4 future-dated rejection).

---

## 4. Surface map (all public surfaces, alphabetical by path)

| Path / surface | Kind | Auth | Section |
|---|---|---|---|
| `/.well-known/agent-card.json` | A2A discovery (signed) | public | §9 |
| `/.well-known/openpgpkey/<domain>/hu/<hash>` | WKD hosted | public | §6.3 |
| `/.well-known/openpgpkey/<domain>/policy` | WKD policy | public | §6.3 |
| `/.well-known/openpgpkey/hu/<hash>` | WKD direct (per-domain deployments) | public | §6.3 |
| `/.well-known/openpgpkey/policy` | WKD policy (direct) | public | §6.3 |
| `/a2a/v1` | A2A JSON-RPC + HTTP+JSON bindings | per-task (§9.4) | §9 |
| `/about`, `/about/*` | Web UI (informational) | public | §6.4 |
| `/api/v1/ephemeral-keys` (+`/<id>`…) | Ephemeral key API | mixed (§7.5) | §7 |
| `/api/v1/operator/webauthn/*` | WebAuthn ceremonies | operator | §10 |
| `/api/v1/proxy-chains/<name>/check` | Chain health probe | operator | §13 |
| `/debug` | Diagnostics | operator only (rewrite change) | §6.4 |
| `/manage`, `/manage/<token>`, `/manage/unpublish` | Web UI management | sealed token | §6.4 |
| `/mcp` | MCP Streamable HTTP | agent credential (§8.3) | §8 |
| `/metrics` | Prometheus | operator network only | §12.6 |
| `/pks/add` | HKP submission | public (rate-limited) | §6.1 |
| `/pks/internal/get/<query>`, `/pks/internal/index/<query>` | HKP internal (edge-rewrite targets) | internal only | §6.1.5 |
| `/pks/lookup` | HKP lookup | public (rate-limited) | §6.1 |
| `/relay/v1/changes`, `/relay/v1/connect`, `/relay/v1/root` | Volta-to-volta relay/sync | peer credential | §13.6, §12.4 |
| `/search` | Web UI search | public (rate-limited) | §6.4 |
| `/upload` | Web UI upload | public (rate-limited) | §6.4 |
| `/verify/<token>` | Web UI verification landing | sealed token | §6.4 |
| `/vks/v1/by-email/<email>` | VKS lookup | public (strict rate limit) | §6.2 |
| `/vks/v1/by-fingerprint/<fpr>` | VKS lookup | public (rate-limited) | §6.2 |
| `/vks/v1/by-keyid/<keyid>` | VKS lookup | public (rate-limited) | §6.2 |
| `/vks/v1/request-verify` | VKS verification request | upload token | §6.2 |
| `/vks/v1/upload` | VKS submission | public (rate-limited) | §6.2 |
| `voltactl` (CLI) | Operator CLI + MCP stdio | local host | §15 |

---

## 5. Data model

### 5.1 Identifiers

- **DM-1 (fingerprint):** v4 certificates (RFC 9580 §12.2 lineage):
  40 uppercase hex chars (SHA-1 over the key material — inherent to
  the v4 format; see exception §11.4). v6 certificates: 64 uppercase
  hex chars (SHA-256). Stored form is the full fingerprint; no
  truncation anywhere in storage, logs, or errors.
- **DM-2 (KeyID):** long KeyID = low 16 hex chars of the fingerprint.
  Short KeyIDs (8 hex) are **never** accepted as lookup keys on any
  surface (collision-prone; the HKP subset in S-6 already restricts
  to long KeyIDs).
- **DM-3 (WKD hash):** 32-char z-base-32 string per §6.3.
- **DM-4 (ephemeral key ID):** `eph_` + 26-char base32 of 128 random
  bits. **DECISION:** prefixed, sortable-agnostic, unguessable.
- **DM-5 (task/session IDs):** UUIDv7 strings.

### 5.2 Entities (alphabetical)

<details>
<summary>AddressBinding — one (address, certificate) publication state</summary>

| Field | Type | Notes |
|---|---|---|
| `address` | string | Lowercased, IDNA/punycode-normalized domain, RFC 5322 addr-spec only (no display name in the index) |
| `certificate_fingerprint` | string | DM-1 |
| `created_at`, `updated_at` | timestamp | |
| `status` | enum | `pending`, `published`, `revoked`, `unpublished` (the VKS vocabulary of S-6) |
| `verification_method` | enum | `email-token`, `operator`, `webauthn-operator`, `wkd-domain` |
| `verified_at` | timestamp \| null | Set exactly when status enters `published` |

Invariants: an address binds to **at most one** certificate as
`published` at a time (S-6 behavior: verifying an address for a new
key unpublishes it from the previous key). Unverified bindings are
stored but **never disclosed**: by-email lookup answers as if they
did not exist (§6.2), and served certificates omit their User IDs
(§5.3).

</details>

<details>
<summary>AgentPrincipal — an MCP/A2A caller identity</summary>

| Field | Type | Notes |
|---|---|---|
| `agent_id` | string | Stable operator-assigned ID |
| `display_name` | string | |
| `identity_fingerprint` | string | DM-1 of the agent's long-term OpenPGP identity certificate, or the SHA-256 fingerprint of its native-suite identity key |
| `identity_suite` | enum | §11 suites usable for identity: `eddsa-ed25519`, `ml-dsa-65-ed25519`, `ml-dsa-87-ed448`, `volta-mldsa87-ed25519` |
| `permissions` | set of enum | `ephemeral-issue`, `ephemeral-revoke`, `key-delete-request`, `key-lookup`, `key-publish`, `relay-fetch` (least privilege; a principal has only what is listed) |
| `status` | enum | `active`, `disabled`, `suspended` |

</details>

<details>
<summary>Certificate — a stored OpenPGP transferable public key</summary>

| Field | Type | Notes |
|---|---|---|
| `armor_cache` | text | Pre-rendered ASCII armor of the **served form** (computed at ingest, §12.3) |
| `canonical_bytes` | blob | Content-addressed (SHA-256) canonical binary of the served form |
| `created_at`, `modified_at` | timestamp | Ingest bookkeeping, not key timestamps |
| `fingerprint` | string | DM-1, primary key |
| `key_id` | string | DM-2 |
| `primary_algorithm` | enum | RFC 9580/9980 algorithm name (§11) |
| `primary_created_at`, `primary_expires_at` | timestamp \| null | From the direct-key/self signature |
| `revoked` | bool | A valid revocation for the primary key is on file |
| `subkeys[]` | list | `{algorithm, created_at, expires_at, fingerprint, key_flags, key_id, revoked}` |
| `user_ids[]` | list | `{binding_status (via AddressBinding or `non-email`), raw_user_id, verified}` — non-email User IDs are served only when `verified` by operator action; email User IDs follow their AddressBinding |

**Served form (cleaning policy), from S-1/S-6:** the served
certificate contains the primary key, subkeys, direct-key and
binding self-signatures, revocation signatures, and **verified**
User IDs with their self-signatures. Stripped at ingest: third-party
certifications (never distributed), User IDs that are neither
verified nor self-signed-valid, and any packet that is not a public
key, User ID/User Attribute, or signature packet. The full uploaded
form is retained in cold storage (`keys_internal` equivalent) for
re-derivation; only the served form is ever returned.

</details>

<details>
<summary>EphemeralKey — §7's short-lived KEM/signing material</summary>

| Field | Type | Notes |
|---|---|---|
| `audience` | string \| null | Intended peer/service; encapsulations for other audiences are rejected |
| `created_at`, `expires_at` | timestamp | `expires_at − created_at = ttl_seconds`, hard bounds §7.2 |
| `custody` | enum | `local` (volta never sees private material), `server` (private held in memory only, §7.6) |
| `key_id` | string | DM-4 |
| `owner_id` | string | AgentPrincipal ID or operator ID |
| `public_material` | object | `{classical_public_b64?, kem_public_b64, suite}` per suite |
| `purpose` | enum | `a2a-session`, `mcp-session`, `relay-session`, `wireguard-psk` |
| `rotation_due_at` | timestamp | ≤ `expires_at` |
| `status` | enum | `active`, `expired`, `revoked`, `superseded` |

</details>

<details>
<summary>EphemeralSession — one establishment against an EphemeralKey</summary>

| Field | Type | Notes |
|---|---|---|
| `ciphertext_b64` | string \| null | Registered encapsulation ciphertext (hash-only in `local` custody audits: `ciphertext_sha256`) |
| `created_at`, `expires_at` | timestamp | `expires_at` = min(key expiry, session creation + 600 s) |
| `key_id` | string | DM-4 |
| `peer_id` | string | Encapsulating principal |
| `session_id` | string | DM-5 |
| `status` | enum | `established`, `expired`, `failed`, `pending` |

The shared secret itself is **never** a stored field, on any node,
in any mode (§7.6).

</details>

<details>
<summary>OperatorAccount + WebAuthnCredential — §10</summary>

OperatorAccount: `{display_name, operator_id, status, created_at}`.
WebAuthnCredential: `{aaguid, backup_eligible, backup_state,
created_at, credential_id (base64url), last_used_at, nickname,
public_key_cose_b64, sign_count, transports[]}`. No biometric data
exists in either record — by construction (§10.1).

</details>

<details>
<summary>ProxyChain — §13 configuration object</summary>

Stored exactly as configured (§13.2 schema): `{dns, fail_closed,
hops[], name, on_error}` plus the per-operation binding table
`operation_routes{operation → chain_name | direct}`.

</details>

<details>
<summary>RelayPeer — a volta-to-volta sync/relay counterpart</summary>

`{base_uri, identity_fingerprint, last_cursor, permissions
(relay-connect, sync-read), status}`. Peer identity is pinned by
fingerprint; a peer presenting a different key for a known
`base_uri` is rejected (`E_RELAY_PEER_MISMATCH`, §13).

</details>

<details>
<summary>SealedToken — §5.4 wire object (not stored)</summary>

Defined by its wire format and payload schema in §5.4; the only
persisted artifact is the token secret, held in the secret store,
referenced — never inlined — by configuration (§15).

</details>

### 5.3 Publication rules (normative)

- **DM-PUB-1:** an email address becomes searchable (by-email, WKD,
  HKP email search) only when its AddressBinding is `published`.
- **DM-PUB-2:** by-fingerprint and by-keyid lookups succeed for any
  stored certificate, published or not, but return the served form
  (verified User IDs only). This asymmetry is inherited from the
  Hagrid model (S-1, S-6) and is deliberate: fingerprint lookup is
  how correspondents confirm a key they already know about;
  email lookup is the enumeration-sensitive path.
- **DM-PUB-3:** a revoked certificate is still served (revocation
  must propagate), with `revoked` visible in index/API metadata; an
  expired certificate is served and marked expired.
- **DM-PUB-4:** deletion removes the AddressBindings and, when no
  bindings remain and deletion is total (§15.2), the certificate; a
  deletion request is an operator/owner action (§10), never a public
  API call.

### 5.4 Sealed tokens (verify / manage links) — wire-compatible

Carried over exactly from S-1 contracts so links mailed by old builds
remain valid until expiry:

- **TOK-1 (construction):** AES-256-GCM seal; key = HKDF-SHA256 over
  the configured token secret, salt `b"volta"`, empty info, 32-byte
  output. Wire format: `nonce (12 B) ‖ ciphertext ‖ GCM tag (16 B)`,
  base64url-encoded when carried in a URL or JSON field.
- **TOK-2 (bounds):** plaintext input to sealing MUST NOT exceed
  `SEALED_LEN_MAX = 64 KiB`. Unsealing input shorter than a nonce,
  oversized, bit-flipped, or sealed under another secret fails with
  `E_TOKEN_INVALID` — never a panic, never partial plaintext.
- **TOK-3 (payload):** JSON object, keys alphabetical:
  `{"addresses": [..], "created_at": <unix s>, "fingerprint": "…",
  "type": "manage" | "verify"}`. A token presented to the wrong flow
  fails with `E_TOKEN_TYPE_MISMATCH`.
- **TOK-4 (lifetime):** `token_validity_seconds`, default **3600**.
  `check` rejects a token when `now − created_at > validity`
  (`E_TOKEN_EXPIRED`) **and** when `created_at > now`
  (`E_TOKEN_FUTURE_DATED`) — the two-sided check is the 2026 fix
  recorded in S-1 and is mandatory.
- **TOK-5 (single-purpose):** a `verify` token authorizes verification
  of exactly the addresses in its payload for exactly its
  fingerprint; a `manage` token authorizes publish/unpublish/delete
  operations for exactly its fingerprint. Tokens are bearer
  credentials: surfaces MUST NOT log them (GLOB-4) and MUST serve
  the landing pages over HTTPS only.

---

## 6. Legacy keyserver interfaces

### 6.1 HKP — `/pks/lookup`, `/pks/add`

The rewrite implements the HKP subset that the predecessor publicly
documented (S-6), with the C-4 fixes. Anything outside this section
is not HKP behavior and MUST NOT be inferred from the draft.

#### 6.1.1 `GET /pks/lookup`

Query parameters (alphabetical):

| Parameter | Values | Rewrite behavior |
|---|---|---|
| `exact` | `off`, `on` | Accepted; all searches are already exact (HKP-3), so `on` changes nothing and `off` does **not** widen the search |
| `fingerprint` | `off`, `on` | Accepted; index output always includes fingerprints (draft default) |
| `op` | `get`, `index`, `stats` | Required; any other value (incl. `vindex`) → `400`, `E_HKP_UNSUPPORTED_OP` |
| `options` | comma list, `mr` recognized | Accepted; output is always machine-readable (HKP-4), with or without `mr` |
| `search` | see HKP-2 | Required for `get`/`index` |
| `x-*` | any | Ignored (draft convention) |

- **HKP-1:** unknown non-`x-` parameters are ignored (predecessor
  behavior, S-6) — but see HKP-6: the response carries
  `X-Volta-Hkp-Subset: exact-only` so clients can detect the subset
  instead of discovering it from empty results.
- **HKP-2 (search grammar):** exactly one of —
  (a) an exact email address (`localpart@domain`, any `<…>` wrapping
  stripped, address lowercased before lookup);
  (b) a long KeyID: 16 hex chars, optional `0x`;
  (c) a fingerprint: 40 (v4) or 64 (v6) hex chars, optional `0x`.
  KeyIDs/fingerprints may name the primary key or any subkey; the
  **primary** certificate is what is returned. Anything else —
  including name/substring searches — is `400`, `E_HKP_BAD_SEARCH`
  (this is C-4: a deliberate deviation from the draft's substring
  semantics, kept as an anti-enumeration measure).
- **HKP-3 (cardinality):** `get` and `index` return at most one
  certificate — the single AddressBinding/fingerprint match.
- **HKP-4 (get response):** `200`, `Content-Type:
  application/pgp-keys`, `Access-Control-Allow-Origin: *`, body =
  ASCII armor of the served form, nothing else. Not found → `404`
  with a plaintext body that cannot be mistaken for key material.
- **HKP-5 (publication):** email searches obey DM-PUB-1; fingerprint/
  KeyID searches obey DM-PUB-2.

#### 6.1.2 Machine-readable index format (`op=index`)

Draft format (S-7), newline-separated, `text/plain`, 7-bit clean:

```
info:1:<count>
pub:<keyid>:<algorithm-id>:<key-length-bits>:<creation-unix>:<expiration-unix-or-empty>:<flags>
uid:<percent-escaped-user-id>:<creation-unix>:<expiration-unix-or-empty>:<flags>
sub:<keyid>:<algorithm-id>:<key-length-bits>:<creation-unix>:<expiration-unix-or-empty>:<flags>
```

- **HKP-7:** field order `info`, `pub`, `uid`*, `sub`* is protocol
  order (ORD-1 exception). `flags` uses the draft letters (`r`
  revoked, `e` expired, `d` disabled — disabled is never emitted).
- **HKP-8 (C-4 fix):** expiration fields are populated from the
  certificate whenever an expiration exists; empty means "no
  expiration", never "not computed".
- **HKP-9:** only verified User IDs appear as `uid` records
  (DM-PUB-2 applied to the index).

#### 6.1.3 `POST /pks/add`

- **HKP-10:** body `application/x-www-form-urlencoded`, field
  `keytext` = one or more ASCII-armored certificates. Limit
  **1 MiB** (S-5/S-6), enforced before parsing (`413`,
  `E_UPLOAD_TOO_LARGE`).
- **HKP-11:** HKP submission stores keys exactly like a VKS upload
  but returns no token: addresses start `unpublished`, and
  verification is only possible via `/vks/v1/upload` +
  `/vks/v1/request-verify` (S-6). Response `200` with a plaintext
  per-key summary line `OK <fingerprint>` per accepted key; any
  unparseable key in a multi-key body fails the whole request `400`
  `E_KEY_MALFORMED` and stores nothing (atomicity is a rewrite
  **DECISION:** the predecessor's behavior here is not documented in
  the allowed sources; all-or-nothing is the fail-closed choice).

#### 6.1.4 `op=stats` (C-4 addition)

`200`, `application/json`, keys alphabetical:
`{"certificates": <n>, "ephemeral_active": <n>,
"published_addresses": <n>, "revoked_certificates": <n>,
"server": "volta", "version": "<workspace version>"}`. Counts only —
never addresses, never per-address data.

#### 6.1.5 Internal HKP (`/pks/internal/…`)

`GET /pks/internal/get/<query>` and `GET /pks/internal/index/<query>`
(S-1: `index` documented; S-5: `get` used by edge rewrites) exist
solely as rewrite targets for the fronting proxy. They MUST refuse
any request that did not arrive through the local edge (loopback +
edge marker header), `403 E_INTERNAL_ONLY`. Query grammar = HKP-2.

### 6.2 VKS-style API — `/vks/v1/*`

The native JSON API. Frozen at `v1` semantics per S-6; volta
additions live under `/api/v1/*` (§7, §10, §13) so this surface can be
implemented by any Hagrid-compatible client unchanged.

#### 6.2.1 Lookups (GET)

| Endpoint | Path value | Success | Not found |
|---|---|---|---|
| `/vks/v1/by-email/<email>` | URI-encoded exact address | `200 application/pgp-keys`, armor of served form | `404` |
| `/vks/v1/by-fingerprint/<fpr>` | v4/v6 fingerprint; canonical form uppercase, no `0x` (C-3); lowercase/`0x` input is normalized | `200 application/pgp-keys` | `404` |
| `/vks/v1/by-keyid/<keyid>` | 16 hex long KeyID (primary or subkey) | `200 application/pgp-keys` | `404` |

- **VKS-1:** by-email returns a key only if the address is
  `published` for it (DM-PUB-1). A stored-but-unpublished address
  and a nonexistent address are indistinguishable (`404`, same body
  shape) — no existence oracle.
- **VKS-2:** all three return the primary certificate's served form
  even when the query named a subkey.
- **VKS-3:** headers on success: `Access-Control-Allow-Origin: *`,
  `Cache-Control: no-cache` (edge caching, where enabled, is a §12
  deployment behavior keyed on `ETag`, never on `Cache-Control`
  relaxation for by-email), `Content-Disposition: attachment;
  filename="<fingerprint>.asc"`, `ETag: "<fingerprint>-<revision>"`.

#### 6.2.2 `POST /vks/v1/upload`

Request: `application/json`, exactly `{"keytext": "<armor or
base64>"}`. One certificate per request. Body limit 1 MiB
(`E_UPLOAD_TOO_LARGE`).

Response `200`, keys alphabetical:

```json
{
  "key_fpr": "<FINGERPRINT>",
  "status": { "<address>": "unpublished" },
  "token": "<sealed verify/manage token, TOK-1>"
}
```

- **VKS-4:** `status` maps **every** email address in the key to one
  of `pending`, `published`, `revoked`, `unpublished` (S-6). An
  address already published for this same key reports `published`;
  publication to a *different* key is not transferred by upload —
  only by verification (DM-PUB-1 invariant).
- **VKS-5:** unparseable material → `400 E_KEY_MALFORMED`, nothing
  stored. A certificate whose primary algorithm is on the rejected
  list (§11) → `400 E_CRYPTO_NOT_ALLOWED`, nothing stored.
  Certificates using accept-serve-only legacy algorithms (§11.3) are
  stored but flagged, and their upload response adds
  `"warnings": ["legacy-algorithm:<name>"]`.

#### 6.2.3 `POST /vks/v1/request-verify`

Request: `{"addresses": ["<address>", …], "locale": ["de_DE", …],
"token": "<token from upload>"}` (`locale` optional, ordered by
preference; supported locales are those compiled in — S-1: en, plus
de/ja in full builds).

- **VKS-6:** for each requested address that (a) appears in the
  token's certificate and (b) is not already `published`, send one
  verification mail containing a `verify` sealed token link
  (`/verify/<token>`) and mark the address `pending`. Response =
  the upload response shape, reflecting the new statuses. The mail
  is sent via the configured mail egress (which is itself a
  proxy-chain operation, §13.3 `smtp-submit`).
- **VKS-7:** requesting verification for an address not in the key,
  or with another key's token, fails the whole request
  `400 E_VERIFICATION_ADDRESS_MISMATCH`. A forged/expired token →
  `E_TOKEN_INVALID` / `E_TOKEN_EXPIRED` (§5.4).
- **VKS-8 (mail rate limit):** verification mail is rate-limited per
  address and per requesting network (defaults §16: 60/hour debug
  profiles, 3600/hour-class production profile in the predecessor's
  units — rewrite normalizes to `mail_rate_limit_per_hour`,
  default 60). Exceeding → `429 E_RATE_LIMITED` with
  `Retry-After`.

#### 6.2.4 Verification and management completion

Clicking `/verify/<token>` (or the API client following the same
sealed token) transitions each address in the token to `published`
and unpublishes that address from any other certificate. Manage
tokens (§6.4) drive unpublish/delete.

#### 6.2.5 VKS errors (C-5)

- GET failure: suitable status + **plaintext** body naming the
  failure (e.g. the predecessor's `No key found for fingerprint …`
  shape), plus `X-Volta-Error-Code`.
- POST failure: suitable status + JSON `{"error": "<message>"}`.
- With `Accept: application/problem+json`, both return the §13
  problem object instead. During storage maintenance a POST MAY
  fail `503 E_MAINTENANCE` (S-6) — retryable; §12.4 (SCALE-7) narrows when
  this is allowed to happen at all.

#### 6.2.6 VKS rate limits (floors, S-6)

| Class | Sustained | Burst |
|---|---|---|
| by-fingerprint, by-keyid | 5 req/s per source network | 1000 |
| by-email | 1 req/min per source network | 50 |
| upload, request-verify | per §16 config, MUST be ≤ mail limits for request-verify | — |

Operators MAY raise lookup limits; by-email limits MUST NOT be
raised above these floors' strictness (privacy control, not a
performance knob).

### 6.3 WKD — `/.well-known/openpgpkey/…`

- **WKD-1 (hash):** `hash = z-base-32(SHA-1(lowercase(local-part)))`,
  32 chars (S-8; SHA-1 scoped exception §11.4). Local-part mapping:
  ASCII uppercase → lowercase; non-ASCII unchanged.
- **WKD-2 (served forms, C-9):**
  - advanced (per-domain host): `https://openpgpkey.<domain>/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local-part>`
  - direct (per-domain host): `https://<domain>/.well-known/openpgpkey/hu/<hash>?l=<local-part>`
  - hosted (volta host): `/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local-part>`
  The `l` parameter carries the unchanged local-part, percent-escaped;
  servers MUST verify that `hash` matches `l`'s hash when `l` is
  present and MUST resolve by hash regardless.
- **WKD-3 (response):** `200`, `application/octet-stream`, body =
  **binary** (never armored) served form; multiple certificates for
  one address, where policy permits, are concatenated key blocks
  (S-8) — volta policy permits at most one `published` binding per
  address (§5.2 AddressBinding invariant), plus a revoked predecessor during a
  30-day rotation grace (**DECISION**). `HEAD` MUST be supported.
  Only `published` addresses resolve (DM-PUB-1). Unknown hash → `404`.
- **WKD-4 (policy):** `GET …/policy` (hosted:
  `/.well-known/openpgpkey/<domain>/policy`; direct:
  `/.well-known/openpgpkey/policy`) returns `200 text/plain`, the
  draft policy-flags file. Volta emits exactly, each on its own line,
  alphabetical: `dane-only` is **not** emitted; emitted flags are
  `mailbox-only` and `protocol-version: 1` (**DECISION:** matches the
  predecessor's empty-body `200` policy at the edge (S-5) in spirit —
  a flags file with content is more informative and draft-conformant;
  clients treat unknown flags as ignorable per the draft).
- **WKD-5:** WKD generation is derived data, regenerated
  incrementally at ingest (§12.3) — never a whole-tree operator step
  on the request path.

### 6.4 Web UI and misc surfaces

Behavioral contract only (templates are presentation):

| Route | Behavior |
|---|---|
| `/` , `/about`, `/about/*` | Informational pages, `200`; cacheable |
| `/debug` | Packet-dump/diagnostic pages of the predecessor — rewrite: **operator-authenticated only** (§10 session), `404` for anonymous callers (do not confirm existence) |
| `/manage` | Landing explaining the tokenized manage flow |
| `/manage/<token>` | With a valid `manage` token: list the certificate's addresses with per-address publish state and unpublish/delete controls |
| `/manage/unpublish` | POST target of the manage form; effects per §5.3; requires the manage token **and**, for delete-total, a WebAuthn step-up (§10.3) — a rewrite strengthening, since a mailed bearer link alone no longer suffices for irreversible deletion |
| `/metrics` | Prometheus exposition; operator network only (§12.6) |
| `/search` | Human search form; same grammar and publication rules as HKP-2 |
| `/upload` | Human upload form; same pipeline as §6.2.2 |
| `/verify/<token>` | §6.2.4 completion landing; invalid/expired token → error page with the §13 code, `400`/`410` respectively |

---

## 7. Ephemeral key API (new) — `/api/v1/ephemeral-keys`

Volta as the secure key server **for agents**: long-term identity
stays in certificates (§5); everything session-like is ephemeral,
hybrid-PQC, and dies on a hard TTL. Design semantics follow
Rosenpass (S-10, C-10): static identity + ephemeral KEM material,
frequent rekeying, derived symmetric key usable as a PSK, forward
secrecy by destruction of ephemeral private material.

### 7.1 Suites for ephemeral keys (alphabetical; definitions in §11)

| Suite ID | Construction | Use |
|---|---|---|
| `hybrid-mlkem1024-x448` | ML-KEM-1024 (FIPS 203) + X448, X-Wing-style combiner | RFC 9980 alg 36 profile; high-assurance |
| `hybrid-mlkem768-x25519` | ML-KEM-768 + X25519, X-Wing-style combiner | RFC 9980 alg 35 profile; default |
| `mlkem1024` | ML-KEM-1024 alone | PSK derivation only (`wireguard-psk`), where the consuming protocol supplies its own classical layer (the Rosenpass composition) |
| `volta-hybrid-mlkem1024-x25519` | ML-KEM-1024 + X25519, same combiner | Volta-native profile mandated 2026-10-10 (C-1); **never** encoded as an OpenPGP algorithm |

Combiner (all hybrid suites): `shared = KDF(classical_ss ‖ pq_ss ‖
classical_ct ‖ pq_ct ‖ classical_pk ‖ pq_pk ‖ suite_id)` with
HKDF-SHA-512 — both component secrets and both transcripts are
bound in, so a session is valid only if **both** halves succeed
(RFC 9980 composite rule). A failed half is a failed session, never
a downgrade to the surviving half (GLOB-3).

### 7.2 TTL bounds (hard, non-configurable beyond these)

| Bound | Value |
|---|---|
| `ttl_seconds` minimum | 30 |
| `ttl_seconds` default | 120 (the Rosenpass rekey cadence, S-10) |
| `ttl_seconds` maximum | **3600 — hard cap**; requests above → `400 E_TTL_OUT_OF_BOUNDS`; configuration cannot raise it |
| `rotation_interval_seconds` | default = `ttl_seconds`; min 30; max = `ttl_seconds` |
| Session lifetime (§5.2 EphemeralSession) | ≤ 600 s and ≤ key remaining life |
| Post-expiry grace for in-flight encapsulation | **0 s** for new sessions; an encapsulation registered before expiry completes or fails on its own 600 s bound |

- **EPH-1 (hard TTL):** at `expires_at` the key's status becomes
  `expired` at every node within 5 s (GLOB-6 clock discipline).
  Expired private material in `server` custody is zeroized at
  expiry, not at next use. Expired public material answers
  `410 E_KEY_EXPIRED` — distinguishable from never-existed (`404`).
- **EPH-2 (no renewal):** TTLs are never extended. Rotation and
  re-issue always mint a **new** `key_id`; the old key enters
  `superseded` and runs out its original TTL. Any API or config that
  appears to "refresh" a TTL is non-conformant.
- **EPH-3 (purpose binding):** a key issued for purpose P MUST NOT
  be accepted for another purpose; audiences likewise (mismatch →
  `403 E_AUDIENCE_MISMATCH`).

### 7.3 Endpoints (alphabetical)

<details>
<summary>DELETE /api/v1/ephemeral-keys/&lt;key_id&gt; — revoke now</summary>

Auth: owner (§7.5). Effect: status → `revoked`; `server`-custody
private material zeroized immediately; sessions in `pending` →
`failed`. Response `200 {"key_id": "…", "status": "revoked"}`.
Revoking an already-terminal key is idempotent (`200`, current
status).

</details>

<details>
<summary>GET /api/v1/ephemeral-keys/&lt;key_id&gt; — public material + metadata</summary>

Auth: public (it is key *distribution*), rate-limited like
by-keyid (§6.2.6). Response `200`, keys alphabetical:

```json
{
  "audience": "a2a:peer-agent-id | null",
  "created_at": "2026-10-10T15:00:00Z",
  "expires_at": "2026-10-10T15:02:00Z",
  "key_id": "eph_…",
  "owner_id": "agent:…",
  "public_material": {
    "classical_public_b64": "…",
    "kem_public_b64": "…",
    "suite": "hybrid-mlkem768-x25519"
  },
  "purpose": "mcp-session",
  "rotation_due_at": "2026-10-10T15:02:00Z",
  "status": "active"
}
```

Private material, shared secrets, and session ciphertexts are
never in this response. Expired → `410 E_KEY_EXPIRED` with the same
metadata minus `public_material`. Revoked → `410 E_KEY_REVOKED`.
Unknown → `404 E_KEY_NOT_FOUND`.

</details>

<details>
<summary>GET /api/v1/ephemeral-keys?owner_id=&amp;status= — list</summary>

Auth: the listed owner, or an operator (§10 session). Returns the
caller's keys only (other owners' keys are not enumerable; their
public material is fetched one-by-one by `key_id`). Pagination:
`limit` (default 50, max 200) + opaque `cursor`. Expired keys are
listed for 24 h after expiry, then only by operators.

</details>

<details>
<summary>POST /api/v1/ephemeral-keys — issue</summary>

Auth: owner (§7.5). Request, keys alphabetical:

```json
{
  "audience": "mcp:host.example | null",
  "custody": "local | server",
  "owner_id": "agent:…",
  "public_material": { "…": "required iff custody=local" },
  "purpose": "a2a-session | mcp-session | relay-session | wireguard-psk",
  "rotation_interval_seconds": 120,
  "suite": "hybrid-mlkem768-x25519",
  "ttl_seconds": 120
}
```

- `custody=local` (**default, recommended**): the caller generates
  the keypair; volta stores public material + metadata only.
- `custody=server`: volta generates the keypair, returns
  `public_material` in the `201` response, and holds private
  material **in memory only** (§7.6).
Response `201` = the GET shape. Validation failures: suite not
allowlisted → `E_CRYPTO_NOT_ALLOWED`; TTL out of bounds →
`E_TTL_OUT_OF_BOUNDS`; purpose/audience malformed → `E_VALIDATION`.

</details>

<details>
<summary>POST /api/v1/ephemeral-keys/&lt;key_id&gt;/decapsulate — server custody only</summary>

Auth: owner, step-up (§7.5). Request:
`{"ciphertext_b64": "…", "peer_id": "…"}`. Response `200`:
`{"expires_at": "…", "session_id": "…", "shared_secret_b64": "…"}`.
Rules: callable only while the key is `active`; each call mints a
distinct session; the response is the **only** time the shared
secret crosses the API; volta MUST NOT persist it (EPH-6).
`custody=local` keys → `400 E_CUSTODY_MISMATCH` (decapsulation is
the owner's local operation by construction).

</details>

<details>
<summary>POST /api/v1/ephemeral-keys/&lt;key_id&gt;/rotate — supersede now</summary>

Auth: owner. Mints a successor key (new `key_id`, same owner/
purpose/audience/suite/TTL policy), marks the old key
`superseded` (it remains usable for decapsulation of in-flight
sessions until its original expiry, and unusable for new sessions
immediately). Response `201` = successor's GET shape plus
`"supersedes": "<old key_id>"`.

</details>

<details>
<summary>POST /api/v1/ephemeral-keys/&lt;key_id&gt;/sessions — register an encapsulation</summary>

Auth: any authenticated principal (§7.5) — this is how a *peer*
announces it encapsulated to the owner's key. Request:
`{"ciphertext_b64": "…", "peer_id": "…"}` for `server` custody, or
`{"ciphertext_sha256": "…", "peer_id": "…"}` for `local` custody
(audit registration without handing volta the ciphertext).
Response `201 {"expires_at": "…", "session_id": "…", "status":
"pending"}`. The owner (or volta, in `server` custody, on the
owner's decapsulate call) completes establishment. Sessions
against expired/revoked keys → `410`.

</details>

### 7.4 WireGuard PSK delivery (`purpose = wireguard-psk`)

For `suite = mlkem1024` (or a hybrid suite), the derived shared
secret is delivered exactly as Rosenpass delivers to WireGuard
(S-10): as a symmetric PSK consumed by the outer protocol. Volta's
part ends at §7.3 decapsulate/registration — volta does not run the
VPN, does not see WireGuard keys, and re-derivation follows the
rotation cadence: a consumer needing continuous coverage holds at
most two live keys (current + successor during rotation overlap).

### 7.5 Authentication for §7

- Owner operations (issue with `custody=local` naming oneself,
  list-own, revoke, rotate, decapsulate): the caller authenticates
  as the AgentPrincipal (§5.2) by **detached signature** over the
  canonical request (JCS-canonicalized JSON body + method + path +
  `X-Volta-Timestamp` within 300 s) using the principal's identity
  key (any `identity_suite`), **or** mTLS with a client certificate
  whose fingerprint is registered to the principal, **or** — for
  human operators — a §10 WebAuthn session.
- Peer operations (GET public material, register session): public
  GET; session registration requires any AgentPrincipal signature
  (accountability), or an operator session.
- Anonymous issue/revoke/decapsulate: never. Failure →
  `401 E_AUTH_REQUIRED` / `403 E_FORBIDDEN` per §13.

### 7.6 Custody and zeroization

- **EPH-4:** `server`-custody private material lives only in
  process memory of the issuing node, is never written to disk,
  swap-backed files, logs, or the sync feed, and is zeroized on
  expiry, revocation, rotation-supersede + in-flight drain, or
  process shutdown. Consequence, stated plainly: a node restart
  kills `server`-custody keys early (they answer `410
  E_KEY_EXPIRED` with metadata `"custody_lost": true`). Clients
  needing restart-survival use `local` custody.
- **EPH-5:** shared secrets are computed, returned once (§7.3
  decapsulate), and never stored (no field exists for them, §5.2).
- **EPH-6:** audit logs record issue/rotate/revoke/session-register
  events with key ID, owner, peer, suite, timestamps — never
  material.

---

## 8. MCP surface (new) — `POST /mcp`, stdio via `voltactl mcp`

Volta is an MCP server (S-11): JSON-RPC 2.0, `initialize` handshake
with capability negotiation, Streamable HTTP transport at `/mcp`
(single endpoint; POST carries requests, responses are JSON or
SSE streams), plus a stdio transport for local hosts launched as
`voltactl mcp --stdio` (§15). Protocol version is negotiated per
the MCP lifecycle; volta advertises `tools` capability with
`listChanged: true` (the tool list changes when agent permissions
change) and no `prompts`; `resources` per §8.4.

### 8.1 Session and transport rules

- **MCP-1:** `initialize` MUST precede all other methods; volta
  answers with `serverInfo {name: "volta", version: <workspace
  version>}` and its capabilities; `notifications/initialized`
  completes the handshake.
- **MCP-2:** HTTP transport validates `Origin` (DNS-rebinding
  defense per S-11), requires `MCP-Protocol-Version` on
  post-initialize requests, and issues `Mcp-Session-Id` on
  initialize. Sessions are bound to the authenticated principal
  (§8.3) and die with it.
- **MCP-3:** stdio transport is local-host only and inherits the
  invoking user's operator rights only when launched with
  `--operator` **and** a live §10 session token file is presented;
  otherwise it runs as a read-only lookup principal.

### 8.2 Tools (`tools/list` returns exactly these, alphabetical)

Every tool's `inputSchema` is a closed JSON Schema object
(`additionalProperties: false`). `Auth` column: `public` (rate-
limited), `agent` (§7.5 principal signature / session credential),
`owner` (principal must own the target), `operator` (§10 session).

| Tool | Purpose (one line) | Auth | Key inputs → outputs |
|---|---|---|---|
| `volta_ephemeral_issue` | Issue an ephemeral key (§7.3 POST) | agent | `{audience?, custody?, purpose, suite, ttl_seconds?}` → key record |
| `volta_ephemeral_revoke` | Revoke an ephemeral key | owner | `{key_id}` → `{status}` |
| `volta_ephemeral_rotate` | Rotate an ephemeral key | owner | `{key_id}` → successor record |
| `volta_ephemeral_status` | Fetch public material + metadata (§7.3 GET) | public | `{key_id}` → key record |
| `volta_key_delete_request` | Open a deletion/unpublish request for a certificate (completes only via §10 step-up or manage token) | agent + operator completion | `{fingerprint, scope: addresses\|bindings\|total}` → `{request_id, status: "awaiting-operator"}` |
| `volta_key_lookup_by_email` | VKS by-email (§6.2.1) | public | `{email}` → `{armor, fingerprint}` |
| `volta_key_lookup_by_fingerprint` | VKS by-fingerprint | public | `{fingerprint}` → `{armor, fingerprint}` |
| `volta_key_lookup_by_keyid` | VKS by-keyid | public | `{keyid}` → `{armor, fingerprint}` |
| `volta_key_publish` | VKS upload (§6.2.2) | public | `{keytext}` → `{key_fpr, status, token}` |
| `volta_key_request_verify` | VKS request-verify (§6.2.3) | public + token | `{addresses[], locale?, token}` → status map |
| `volta_proxy_chain_check` | Per-hop probe of a named chain (§13.5) — never touches the target, never falls back | operator | `{chain}` → `{hops: [{hop, status, latency_ms}], ok}` |
| `volta_relay_fetch_key` | Fetch a certificate from a RelayPeer **through the configured chain** for `relay-fetch` | agent (`relay-fetch` permission) | `{fingerprint, peer}` → `{armor, fingerprint, via_chain}` |
| `volta_wkd_lookup` | WKD lookup (§6.3) against a domain's or volta's own WKD | public | `{email}` → `{key_binary_b64, fingerprint}` |

- **MCP-4:** tool results use the MCP result shape (`content[]`
  with a JSON text block carrying the object above, `isError`
  flag). Volta errors inside tools carry the §13 code in
  `content[0].text`'s parsed object under `"error_code"` plus the
  JSON-RPC error object for protocol-level failures.
- **MCP-5:** no tool returns private key material, shared secrets,
  or sealed token plaintexts beyond the VKS upload token the caller
  itself just created (that token is the caller's credential).
  `volta_ephemeral_issue` with `custody=server` returns public
  material only; decapsulation is **not** an MCP tool (it is the
  §7.3 REST call, owner step-up) — deliberately, so an MCP host's
  tool-approval UI is never the sole guard on secret release.

### 8.3 MCP authentication

HTTP transport requires `Authorization: Bearer <credential>` where
the credential is either (a) an ephemeral session token minted
against an active `mcp-session` ephemeral key (the §7 handshake:
client proves possession by signature at session open), or (b) an
operator session token (§10). Tool-level auth (§8.2) is enforced
per call, not just at connect. Unauthenticated `tools/list` MAY be
served (discovery), but `tools/call` without a credential answers
only the `public` tools and rate-limits as anonymous.

### 8.4 Resources

| URI | Content |
|---|---|
| `volta://agent-card` | The current signed A2A Agent Card (§9) as JSON |
| `volta://crypto-policy` | The §11 allowlist/rejected tables as JSON (machine-readable policy) |
| `volta://keys/<fingerprint>` | Served-form armor for the fingerprint (same rules as VKS by-fingerprint) |

---

## 9. A2A surface (new) — Agent Card + tasks

### 9.1 Agent Card — `GET /.well-known/agent-card.json`

Served `200 application/json`, cacheable for ≤ 300 s, keys
alphabetical in the emitted document:

```json
{
  "capabilities": {"pushNotifications": false, "stateTransitionHistory": true, "streaming": true},
  "defaultInputModes": ["application/json", "text/plain"],
  "defaultOutputModes": ["application/json", "text/plain"],
  "description": "OpenPGP key server for humans and agents: verified key publication, ephemeral hybrid-PQC session keys, chained-proxy relay.",
  "name": "volta",
  "provider": {"organization": "Qompass AI", "url": "<base-URI>"},
  "securitySchemes": {
    "agentSignature": {"type": "apiKey", "in": "header", "name": "X-Volta-Agent-Signature"},
    "ephemeralSession": {"type": "http", "scheme": "bearer"}
  },
  "signatures": [ "<JWS objects, §9.2>" ],
  "skills": [
    {"id": "ephemeral-key-exchange", "name": "Ephemeral key exchange", "description": "Issue, fetch, rotate, revoke hard-TTL hybrid-PQC ephemeral keys (§7).", "tags": ["ephemeral", "ml-kem", "pqc"], "inputModes": ["application/json"], "outputModes": ["application/json"]},
    {"id": "key-lookup", "name": "Key lookup", "description": "Exact lookup by email, fingerprint, or long KeyID under the publication rules (§6).", "tags": ["hkp", "openpgp", "vks", "wkd"], "inputModes": ["application/json", "text/plain"], "outputModes": ["application/json", "text/plain"]},
    {"id": "key-publication", "name": "Key publication", "description": "Upload a certificate and run email verification (§6.2).", "tags": ["openpgp", "publication", "verification"], "inputModes": ["application/json"], "outputModes": ["application/json"]},
    {"id": "relay-fetch", "name": "Relay fetch", "description": "Fetch certificates from peer volta instances through configured proxy chains (§13).", "tags": ["proxy-chain", "relay"], "inputModes": ["application/json"], "outputModes": ["application/json"]}
  ],
  "supportedInterfaces": [
    {"protocolBinding": "JSONRPC", "protocolVersion": "1.0", "url": "<base-URI>/a2a/v1"},
    {"protocolBinding": "HTTP+JSON", "protocolVersion": "1.0", "url": "<base-URI>/a2a/v1"}
  ],
  "url": "<base-URI>/a2a/v1",
  "version": "<workspace version>"
}
```

### 9.2 Card signing (mandatory)

- **A2A-1:** the card MUST be signed; an unsigned card is a build/
  deploy error, and volta refuses to serve §9 endpoints in that
  state (`503 E_CARD_UNSIGNED` at readiness, not per request).
- **A2A-2:** signatures are JWS (RFC 7515) objects in the card's
  `signatures[]`, each `{protected, signature}` over the
  RFC 8785 (JCS) canonicalization of the card with `signatures`
  removed. Two signatures are emitted, in this order:
  1. `alg: "EdDSA"` (Ed25519) — the A2A-interop signature, keyed by
     volta's long-term identity certificate signing key;
     `kid` = that certificate's fingerprint.
  2. `alg: "ML-DSA-87+Ed448"` composite profile per RFC 9980
     algorithm 31, **or**, where the deployment identity is the
     volta-native suite, `alg: "VOLTA-MLDSA87-ED25519"` (C-1) —
     `kid` likewise the identity fingerprint. Header carries
     `"typ": "agent-card+jws"`.
- **A2A-3:** consumers MUST verify at least one signature against a
  pinned identity fingerprint before sending tasks; a card whose
  signatures all fail verification is refused — fail closed, no
  "unsigned mode" (GLOB-3). Volta's own client behavior (§9.5)
  follows the same rule.
- **A2A-4:** card rotation: when the identity key rotates, the new
  card is dual-signed (old + new identity) for one card TTL window
  (≤ 300 s cache + 24 h grace, **DECISION**) so pinned consumers can
  re-pin deliberately rather than silently.

### 9.3 Task endpoint — `POST /a2a/v1`

JSON-RPC 2.0 binding (methods alphabetical) and the HTTP+JSON
binding equivalents:

| Method | Effect |
|---|---|
| `message/send` | Submit a message (skill invocation); returns a Task |
| `message/stream` | Submit and stream status/artifact events (SSE) |
| `tasks/cancel` | Cancel a non-terminal task the caller owns |
| `tasks/get` | Fetch a task by ID (caller must own it, or operator) |
| `tasks/list` | List the caller's tasks (cursor pagination) |
| `tasks/resubscribe` | Re-attach an SSE stream to a live task |

Message shape: `{contextId?, id, message: {messageId, parts: […],
role: "user"}, metadata: {"volta.skill": "<skill id>"}}`. Parts:
`{kind: "text", text}`, `{kind: "data", data: {…}}`,
`{kind: "file", file: {bytes: "<base64 armor>", mimeType:
"application/pgp-keys"}}` for publication.

Task object: `{artifacts: […], contextId, history: […], id,
kind: "task", metadata, status: {state, timestamp}}` with `state`
one of (alphabetical) `auth-required`, `canceled`, `completed`,
`failed`, `input-required`, `rejected`, `submitted`, `working`.
Terminal states: `canceled`, `completed`, `failed`, `rejected`.

Skill → task semantics:

| Skill | Synchronous result (artifact) | Async behavior |
|---|---|---|
| `ephemeral-key-exchange` | Key record (§7.3 GET shape) for issue/fetch/rotate intents in the data part | Session establishment streams `pending → established` as task status + artifact on completion |
| `key-lookup` | `{armor, fingerprint}` or a `failed` task with §13 code (a miss is `failed`/`E_KEY_NOT_FOUND`, not an empty success) | Always completes in the `message/send` response |
| `key-publication` | Upload result `{key_fpr, status, token}` | Verification stays `working` until the mailed link completes, then `completed`; 7-day task ceiling → `failed`/`E_TOKEN_EXPIRED` |
| `relay-fetch` | `{armor, fingerprint, via_chain}` | Chain traversal (§13) streams per-hop status as history events; any hop failure → `failed` with the §13 proxy code, never a direct-fetch retry |

### 9.4 A2A authentication and authorization

- Every `message/send` carries either the `agentSignature` scheme
  (detached JWS over the canonical request, identity per §5.2) or
  an `ephemeralSession` bearer minted from an active `a2a-session`
  ephemeral key. Anonymous callers may invoke **only** `key-lookup`
  (rate-limited as by-email class where applicable).
- `tasks/get`/`tasks/cancel`/`tasks/list` are scoped to the owning
  principal: another principal's task ID answers `404` (no existence
  oracle), mirroring VKS-1.
- A task that needs an operator-only completion (e.g. publication
  of an operator domain) parks in `auth-required` until §10
  step-up completes it or it hits the task ceiling.

### 9.5 Volta as A2A client

When volta fetches a **peer** card (relay peers, §5.2), it MUST
verify the card signature against the peer's pinned fingerprint
(A2A-3), MUST fetch through the chain configured for `a2a-fetch`
(§13), and MUST refuse on any failure of either — there is no
direct-fetch fallback path in the code's behavior, configured or
otherwise.

---

## 10. WebAuthn / FIDO2 operator authentication (new)

Operator power is passkey power. Passwords, TOTP, and emailed codes
are **not** operator credentials in the rewrite.

### 10.1 Principles

- **WA-1 (biometrics never leave the authenticator):** user
  verification (biometric or PIN) happens inside the authenticator.
  Volta receives and stores only the credential **public key**,
  credential ID, counters, and attestation data (§5.2). The server
  MUST NOT request, receive, log, or store biometric samples or
  templates; no API field exists for them. Attestation is used to
  learn the authenticator model (AAGUID) at registration, never as
  a biometric channel.
- **WA-2 (UV required):** every ceremony sets
  `userVerification: "required"`. An assertion with the UV flag
  unset is rejected (`E_WEBAUTHN_UV_REQUIRED`) even if the
  signature verifies.
- **WA-3 (no fallback):** there is no password/OTP fallback for a
  lost passkey. Recovery is (a) a second pre-registered passkey, or
  (b) the break-glass ceremony of §10.5. This is deliberate and is
  stated to operators at enrollment.

### 10.2 Registration ceremony

1. `POST /api/v1/operator/webauthn/register/options` (authenticated
   by an existing operator session, or — for the very first
   operator — by the one-time bootstrap token printed by
   `voltactl operator bootstrap` on the host console, §15).
   Response `PublicKeyCredentialCreationOptions`:
   ```json
   {
     "attestation": "direct",
     "authenticatorSelection": {"residentKey": "required", "userVerification": "required"},
     "challenge": "<32 random bytes, base64url>",
     "excludeCredentials": [ "<the operator's existing credentials>" ],
     "pubKeyCredParams": [{"alg": -8, "type": "public-key"}, {"alg": -7, "type": "public-key"}],
     "rp": {"id": "<volta host domain>", "name": "volta"},
     "timeout": 60000,
     "user": {"displayName": "…", "id": "<opaque 32-byte operator handle>", "name": "…"}
   }
   ```
   `pubKeyCredParams` is exactly the §11 WebAuthn allowlist:
   EdDSA (-8) preferred, ES256 (-7) accepted. **RS256 (-257) and
   all others are absent — a credential offered with an unlisted
   algorithm fails registration** (`E_CRYPTO_NOT_ALLOWED`).
   `attestation: "direct"` lets the operator record the AAGUID;
   deployments MAY set `"none"` (privacy profile) via §16 config —
   the credential is accepted either way; enterprise attestation
   chains are not required.
2. `POST /api/v1/operator/webauthn/register/verify` with the
   authenticator's `{id, rawId, response: {attestationObject,
   clientDataJSON}, transports}`. Server checks: challenge match
   (single-use, §10.4), `clientDataJSON.origin` == the configured
   origin exactly, `rpIdHash` == SHA-256(rp.id), UP+UV flags set,
   signature over attestation valid, credential ID not already
   registered to another operator. Success stores §5.2
   WebAuthnCredential and returns `201 {"credential_id": "…",
   "nickname": "…"}`.

### 10.3 Authentication ceremony + step-up

1. `POST /api/v1/operator/webauthn/auth/options` →
   `PublicKeyCredentialRequestOptions`:
   `{"allowCredentials": […], "challenge": "<32 random bytes>",
   "rpId": "<domain>", "timeout": 60000, "userVerification":
   "required"}`. `allowCredentials` is populated for non-discoverable
   flows and empty (discoverable/passkey flow) when the caller does
   not name an operator first.
2. `POST /api/v1/operator/webauthn/auth/verify` with
   `{id, rawId, response: {authenticatorData, clientDataJSON,
   signature, userHandle}}`. Checks: challenge, origin, rpIdHash,
   UP+UV, signature against the stored public key, and
   **`sign_count` strictly greater than stored** — a non-increasing
   counter (authenticators with counter support) locks the
   credential and returns `E_WEBAUTHN_CLONE_DETECTED`; counter-less
   authenticators (stored count 0, presented 0) are accepted per
   WebAuthn spec and noted `"counterless": true` at registration.
3. Success mints an **operator session**: opaque 256-bit token,
   `Set-Cookie: volta_operator=…; HttpOnly; Secure; SameSite=Strict;
   Path=/`, lifetime **900 s** (15 min), bound to the TLS channel
   and, when the operator surface is reached through a §13 chain, to
   the chain profile name. Session use is audited (§12.6).

**Step-up (WA-4):** the following actions require an assertion
completed within the last **300 s**, regardless of session age —
the server demands a fresh `auth/*` ceremony scoped with
`"step_up_for": "<action>"` and the action's target fingerprint:

| Action | Where |
|---|---|
| Delete certificate / bindings (total) | §6.4 manage, §8.2 delete-request completion, §15 `voltactl delete` remote mode |
| Unpublish a published address | §6.4 |
| Decapsulate a `server`-custody ephemeral key | §7.3 |
| Change proxy-chain configuration | §13.7 |
| Toggle maintenance mode | §12.4 (SCALE-7) |
| Bulk import via API (operator upload) | §6.2.2 with operator session |
| Rotate the sealed-token secret | §16 |
| Register/remove another operator's credential | §10.2 |

### 10.4 Challenges

Challenge state is the **only** server-side WebAuthn state besides
credentials: 32 random bytes, stored hashed, single-use, TTL
**300 s**, bound to (ceremony type, operator, origin). Reuse,
expiry, or cross-ceremony presentation → `E_WEBAUTHN_CHALLENGE_INVALID`.
Challenges live in the shared TTL store (§12.2) — any node can
verify any ceremony (no sticky sessions).

### 10.5 Break-glass

If all passkeys are lost: on-host `voltactl operator recover
--operator <id>` (§15) requires local root, prints a one-time
recovery challenge to the console, waits for a **second** operator's
existing passkey assertion over a local prompt **or** a 24-hour
timedelay with audit alarms (config, §16), then permits registering
a new credential. Every break-glass step writes to the append-only
audit log before it takes effect. There is no remote break-glass.

---

## 11. Cryptography: allowlist by design

Two domains (C-1): **OpenPGP domain** — what certificates volta
accepts, serves, and (for its own identity) uses; and **native
domain** — volta's own session/token/agent cryptography. An
algorithm's presence in one domain implies nothing about the other.

### 11.1 Allowlist — OpenPGP domain (accept + serve + generate-for-self)

| Algorithm | Role | Level |
|---|---|---|
| AES-256 (symmetric, incl. SEIPDv2 AEAD-OCB/GCM per RFC 9580) | Message/key encryption in served material | MUST accept |
| Argon2id S2K (RFC 9580) | Secret-key protection in stored material | MUST accept |
| Ed25519 (RFC 9580 legacy EdDSA form and RFC 9580 Ed25519) | Sign / hybrid half | MUST |
| Ed448 | Sign / hybrid half | SHOULD |
| HKDF-SHA-256 / HKDF-SHA-512 | Derivation (tokens, combiners) | MUST |
| ML-DSA-65+Ed25519 (RFC 9980 alg 30) | Composite sign | MUST |
| ML-DSA-87+Ed448 (RFC 9980 alg 31) | Composite sign | SHOULD |
| ML-KEM-1024+X448 (RFC 9980 alg 36) | Composite encrypt | SHOULD |
| ML-KEM-768+X25519 (RFC 9980 alg 35; also permitted on v4 encryption subkeys per RFC 9980) | Composite encrypt | MUST |
| NIST P-256 / P-384 / P-521 (ECDH + ECDSA) | Interop accept | MUST accept; volta's own keys SHOULD NOT be generated on NIST curves when a composite suite fits |
| SHA-256 / SHA-384 / SHA-512, SHA3-256 / SHA3-512 | Digests | MUST |
| SLH-DSA-SHAKE-128f / 128s / 256s (RFC 9980 algs 33/32/34) | Standalone hash-based sign (the only standalone PQ signature RFC 9980 permits) | MAY accept |
| X25519 / X448 (ECDH) | Encrypt / hybrid half | MUST / SHOULD |

### 11.2 Allowlist — native domain

| Algorithm / construction | Use in volta |
|---|---|
| AES-256-GCM + HKDF-SHA-256, salt `b"volta"` | Sealed tokens (§5.4) — construction frozen for compatibility |
| ChaCha20-Poly1305 | TLS 1.3 suite; relay transport (§13.6) option |
| Ed25519 | A2A card signature #1, agent identity, MCP session binding |
| HKDF-SHA-512 combiner (§7.1) | Hybrid ephemeral sessions |
| ML-DSA-87 (FIPS 204, standalone) | Native signing where no OpenPGP encoding is required (audit-log checkpoints, sync-feed entries, §12.4) |
| ML-KEM-1024 (FIPS 203, standalone) | Ephemeral suite `mlkem1024`; relay peer exchange |
| ML-KEM-768 / ML-KEM-1024 in §7.1 hybrids | Ephemeral suites |
| TLS 1.3, groups `X25519MLKEM768`, `x25519`, `secp384r1`, `x448` (preference order as listed); suites `TLS_AES_256_GCM_SHA384`, `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256` | All volta-served TLS and all volta-initiated TLS (§13 hops included) |
| WebAuthn COSE: EdDSA (-8), ES256 (-7) | §10 only |
| X25519+ML-KEM-1024 hybrid; Ed25519+ML-DSA-87 hybrid (`volta-*` suites, §7.1/§9.2) | Volta-native profiles per C-1 — labeled non-standard wherever they appear |

### 11.3 Accept-serve-only (legacy interop; never generated, never in volta's own keys)

| Algorithm | Rule |
|---|---|
| RSA 3072–8192 (sign/encrypt) | Served; upload response carries `legacy-algorithm` warning if < 4096 (**DECISION** threshold for the warning only) |
| ECDSA/ECDH on secp256k1 | Served (OpenPGP interop); not generated |
| SHA-224, RIPEMD-160 in existing self-signatures | Verified for serving decisions on pre-existing certificates; never used in new signatures |
| AES-128, Camellia-256 in existing material | Accepted in served material |

### 11.4 Rejected list (hard rejects; `E_CRYPTO_NOT_ALLOWED` on upload/issue/use)

| Rejected | Scope / note |
|---|---|
| 3DES, Blowfish, CAST5, IDEA, SEIPDv0 (no integrity) | Symmetric/material |
| DSA (any size) | Signature/encryption |
| ECDSA/ECDH on curves < 224-bit security class (incl. NIST P-192, P-224 for new material) | Curves |
| ElGamal (encrypt-only or sign) | Public-key |
| MD5 (digest ID 1) in any signature relied on for a serving decision | Digests. A certificate whose *only* self-signature uses MD5 is `E_CRYPTO_NOT_ALLOWED` at upload |
| RSA < 3072 | **Where controllable** (requirement wording): new uploads with RSA primary or subkeys < 3072 are rejected. Pre-existing grandfathered material, if an operator imports it out-of-band, is served with the legacy warning — the server never *generates* or *endorses* it |
| RS256/RS384/RS512 and all non-listed COSE algorithms | WebAuthn (§10.2) |
| SHA-1 as a signature digest or integrity hash | Digests — **except** the two scoped exceptions below |
| TLS < 1.3, SSL any version, TLS compression, static-RSA/DH key transport, export ciphers | Volta's own surfaces and volta-initiated connections, including inside §13 chains |
| v3 keys (PGP 2.x format) | Upload reject |
| v5/LibrePGP-format keys | Upload reject (not RFC 9580; accepting them would fork the format base) |
| Weak S2K (simple, salted-only with trivial iteration) on secret material volta itself stores | Native domain |

**Scoped SHA-1 exceptions (C-2), the only ones:**
1. WKD `hu/` naming hash (§6.3) — availability-grade, not authenticity.
2. Computing/comparing v4 fingerprints — the fingerprint *is* SHA-1
   by format definition (RFC 9580 §12.2); volta treats a fingerprint
   as an identifier, and binding decisions additionally require the
   full certificate bytes to hash-match the content address (§12.3),
   which is SHA-256.

### 11.5 Negotiation and downgrade rules

- **CRYPTO-1:** there is no negotiation on volta's own surfaces
  below §11.1/§11.2. A peer offering only rejected primitives gets
  a handshake/validation failure, not a weaker session.
- **CRYPTO-2:** unknown algorithm IDs in uploaded material →
  reject at upload (`E_CRYPTO_NOT_ALLOWED` if the unknown ID is in
  a position volta must rely on) — never "store now, understand
  later".
- **CRYPTO-3:** suite identifiers in APIs are the exact strings of
  §7.1/§11.2. Aliases (`kyber1024`, `pqc`, …) are not accepted.

---

## 12. Scaling design — the Hagrid gaps, named, and the answers

### 12.1 Gap list (evidence from the allowed public surfaces only)

| ID | Gap | Evidence (public surface) |
|---|---|---|
| G-1 | **Non-synchronizing, single-node.** Hagrid instances do not sync with each other; the deployment model is one server process with a local state root | Public keyserver comparison tables list keys.openpgp.org (Hagrid) as "Synchronizing: No" while synchronizing servers (Hockeypuck pools) say Yes (S-6-adjacent public record); S-1 describes one Rocket app with local `state/` dirs and a maintenance *file* |
| G-2 | **Filesystem keystore + derived symlink tree.** Keys live as files keyed by fingerprint/KeyID/email, and a parallel *symlink* layout is what the edge actually serves; keeping it true is an operator batch job | S-4: `voltactl regenerate` — "Regenerate symlink directory"; S-5: edge `try_files /keys/links/by-fpr/$1/$2/$3`, `/keys/links/by-keyid/…`, `/keys/links/wkd/…` (two-level 2+2-hex sharding) |
| G-3 | **Asymmetric fast path.** Fingerprint/KeyID/WKD reads can be served as static files by the edge; email reads cannot — they always pay full application cost | S-5 carries the operator comment, in substance: URI-encoding trouble on the by-email location means it is "route[d] through volta, for now" |
| G-4 | **Request-path parsing and cleaning.** Uploads are parsed and cleaned in the request; lookups re-derive the cleaned, served form from stored material through the database crate (parse → clean → render per request in the documented architecture) | S-1 architecture/contracts: parsing, cleaning (stripping per policy), and WKD hashing all live in the request-serving database crate; S-6: uploads capped at 1 MiB, non-key packets filtered — work done on the serving path |
| G-5 | **Whole-service maintenance windows.** Writes can fail wholesale during "database maintenance"; maintenance is a single file flag for the whole service | S-6: "A POST request may fail with a HTTP 503 error at any time if the server is undergoing database maintenance"; S-1/S-5: `maintenance_file`, `/maintenance/*` |
| G-6 | **Edge-only, coarse rate limiting.** Protection lives in the fronting proxy's limit zones; the application's own documented limits are mail counters | S-5 limit zones (email burst 50 / loose 200; fingerprint burst 1000); S-6: 5 req/s fingerprint/KeyID, 1 req/min email — one global class each, no per-principal quotas |
| G-7 | **Node-local token state.** Part of the token system is stateful files in a local `token_dir` | S-1 architecture ("stateful on-disk tokens"), S-5 `token_dir = "state/tokens"` (conflict C-6) |
| G-8 | **Protocol-surface narrowing that pushes cost to clients.** Exact-match-only, single-result, no `vindex`, blank index expiry: clients retry, scrape, or multi-home against several keyservers | S-6 "Limitations" list (verbatim the deployed contract); public client reports of `400`s for name searches against Hagrid |

### 12.2 Design answer — shape

Stateless application nodes over shared state, in three tiers:

1. **Edge tier** — TLS 1.3 termination, §12.5 limit zones, static
   cache for immutable public reads (by-fingerprint, by-keyid, WKD)
   keyed by content address + `ETag` (§6.2.1). By-email and all
   writes always pass through.
2. **Application tier** — N identical volta nodes; **no node-local
   state**: sealed tokens are stateless (§5.4); challenges and
   sessions live in the shared TTL store (below); nodes hold only
   `server`-custody ephemeral private keys (with the EPH-4 semantics
   that already price in node loss).
3. **State tier** —
   - **Blob store:** content-addressed by SHA-256 of canonical
     served-form bytes (§12.3); S3-compatible or shared filesystem.
   - **Index store:** relational (SQLite-WAL for single-node
     deployments, PostgreSQL for clustered — one schema, §5.2
     entities, indexes on `fingerprint`, `key_id`, `address`,
     `wkd_hash`, `key_id` of subkeys). Single-node SQLite remains a
     fully supported profile (volta must still run on one box); the
     schema and queries are identical so the profile is a config
     choice, not a fork.
   - **TTL store:** shared key-value with per-key expiry (Redis-
     compatible or the index store's TTL tables in the single-node
     profile) holding WebAuthn challenges (§10.4), MCP sessions,
     ephemeral session registrations, and rate-limit counters.

### 12.3 Design answer — request path (fixes G-2, G-3, G-4)

- **SCALE-1 (ingest-time derivation):** parsing, policy cleaning,
  armoring, WKD blob rendering, and index-row extraction happen
  **once**, in the ingest pipeline (§12.4). The read path is:
  index lookup → blob fetch by content address → stream out. No
  OpenPGP parsing, no cleaning, no rendering on any read path.
- **SCALE-2 (no symlink tree):** the derived layout is data
  (index rows + blob addresses), not filesystem links. There is no
  `regenerate` batch step in normal operation; §15 keeps the
  subcommand as an index **rebuild/verify** tool for disaster
  recovery, and its output is a verification report, not a serving
  prerequisite.
- **SCALE-3 (email path parity):** by-email is an index lookup like
  every other read (the G-3 encoding problem disappears when the
  address is a normalized index key, §5.2, instead of a filename).
- **SCALE-4 (cacheability):** by-fingerprint/by-keyid/WKD responses
  are immutable per revision: a certificate update mints a new
  content address and bumps `revision`, so edges/CDNs cache safely
  and revocation propagation = new revision + purge signal on the
  §12.4 feed.

### 12.4 Design answer — ingest pipeline and federation (fixes G-1, G-5)

- **SCALE-5 (queued ingest):** upload request path performs only:
  size check → parse-lite (extract primary fingerprint, reject
  malformed, §11 screening of the primary) → durable enqueue →
  `200` with token (§6.2.2 shape is unchanged; the token flow is
  what gates publication anyway). Cleaning/derivation (§12.3) runs
  in the pipeline; a certificate becomes *servable* when its
  pipeline stage completes (target < 5 s, §12.7) and *searchable*
  only per DM-PUB-1 as before. Pipeline failure → the upload's
  status endpoint behavior: the token's status map reports the
  addresses as `unpublished` and a retry of request-verify after
  the failure surfaces `E_INGEST_FAILED` with the reason code.
- **SCALE-6 (volta-to-volta sync):** peers (§5.2 RelayPeer) pull a
  signed change feed:
  - `GET /relay/v1/changes?since=<cursor>` → entries
    `{blob_sha256, cursor, fingerprint, kind:
    upsert|revocation|deletion-tombstone, revision, signature}`
    signed with the origin node's ML-DSA-87 native key (§11.2);
  - `GET /relay/v1/root` → `{cursor, merkle_root}` over
    `(fingerprint, revision, blob_sha256)` for anti-entropy
    comparison; mismatches trigger targeted re-pull, never bulk
    trust.
  - **Verification state does not transfer as fact:** an address
    `published` at a peer arrives as a *signed attestation claim*
    by that peer; the local node applies its own policy (default:
    accept attestations from configured peers for addresses, since
    the peer ran the same email proof — the claim and its signer
    are recorded on the AddressBinding as
    `verification_method: "relay-attestation"` (**DECISION** — the
    alternative, re-verifying every synced address by mail, makes
    sync useless; the risk is bounded by peer pinning, §5.2).
  - Deletions propagate as tombstones carrying the §10-authorized
    deletion's audit reference; tombstones are honored for
    bindings, and certificate bytes are dropped when the last
    binding tombstones (DM-PUB-4).
- **SCALE-7 (no global maintenance):** schema migrations and index
  rebuilds run per-shard/per-index online (additive-first). The
  `503 E_MAINTENANCE` of §6.2.5 survives only for the single-node
  profile's storage compaction and MUST be scoped (per-operation
  `Retry-After` + code), never a whole-service file flag.

### 12.5 Design answer — limits and backpressure (fixes G-6)

Layered, all layers active simultaneously: edge limit zones
(§6.2.6 floors) → application token buckets per
(principal-or-network, operation class) in the TTL store → ingest
queue depth bound (over-depth upload → `503 E_INGEST_BUSY`,
`Retry-After`) → mail egress quota (VKS-8). Every rejection is
`429 E_RATE_LIMITED` (or the noted 503s) with `Retry-After`; no
layer silently drops.

### 12.6 Observability

- `/metrics` (Prometheus) exposes, names alphabetical:
  `volta_chain_hop_failures_total`, `volta_ephemeral_active`,
  `volta_ephemeral_expired_total`, `volta_http_requests_total`,
  `volta_ingest_duration_seconds`, `volta_ingest_queue_depth`,
  `volta_lookup_duration_seconds`, `volta_sync_cursor_lag`,
  `volta_token_rejections_total`, `volta_webauthn_ceremonies_total`
  — each labeled by operation/error code only (GLOB-4: no
  addresses, no fingerprints beyond aggregate counts).
- **Audit log:** append-only, hash-chained, periodic ML-DSA-87
  checkpoint signatures (§11.2); records operator actions (§10),
  deletions, chain config changes, break-glass steps, sync peer
  changes. Audit entries are operator-readable via §15, never via
  public API.

### 12.7 Performance targets (design targets, to be proven by load test — not measurements)

| Operation | Target (per node, warm) |
|---|---|
| by-fingerprint / by-keyid (blob hit) | p95 ≤ 25 ms at 1,000 rps |
| by-email | p95 ≤ 50 ms at 100 rps |
| WKD `hu/` | p95 ≤ 25 ms at 500 rps |
| Upload accept (parse-lite + enqueue) | p95 ≤ 150 ms at 20 rps |
| Ingest → servable | p95 ≤ 5 s |
| Ephemeral issue (local custody) | p95 ≤ 20 ms at 200 rps |
| Sync feed application | ≥ 500 entries/s per peer stream |

Targets scale ~linearly with application nodes until the index
store saturates; sharding the index by fingerprint prefix
(first byte → 256 logical shards) is the documented next step and
the schema's `fingerprint` leading-byte index exists from day one
so it is a migration, not a redesign.

---

## 13. Proxy chains (new) — configuration schema and semantics

Volta originates network connections for: fetching peer cards and
keys, relay/sync, WKD fetches for foreign domains, and verification
**mail egress**. Every one of those egress paths can be routed
through an operator-configured, ordered, multi-hop proxy chain —
or explicitly direct — and failure is always closed.

### 13.1 Hop types (alphabetical)

| Type | Meaning | DNS behavior |
|---|---|---|
| `http-connect` | HTTP CONNECT proxy; `tls: true` wraps the proxy connection itself in TLS 1.3 (pin via `spki_pin`) | Hostname passed to proxy in CONNECT (remote resolution) |
| `socks5` | SOCKS5, addresses resolved **locally** — see CHAIN-3: local resolution is a leak on this hop type and volta therefore restricts it | Local (restricted) |
| `socks5h` | SOCKS5 with remote DNS (the `h` semantics): hostnames travel unresolved to the proxy/exit | Remote |
| `tor-socks` | A Tor client SOCKS port (default `127.0.0.1:9050`); behaves as `socks5h` plus per-operation stream isolation | Remote (Tor) |
| `volta-relay` | Another volta instance's relay endpoint (§13.6); mutually authenticated, carries byte streams to the next hop/target | Remote (relay resolves the next hop) |

### 13.2 Configuration schema (TOML rendering; JSON equivalent field-for-field)

```toml
# One named chain. Keys alphabetical within every table (ORD-1).
[proxy.chains.tor-only]
dns = "remote"                 # remote | system — see CHAIN-3
fail_closed = true             # MUST be true; false is a config error
name = "tor-only"
on_error = "abort"             # only value; anything else is a config error

[[proxy.chains.tor-only.hops]]
address = "127.0.0.1"
isolation_id = "per-operation"   # tor-socks only
port = 9050
type = "tor-socks"

[[proxy.chains.relay-via-peer]]
fail_closed = true
name = "relay-via-peer"
on_error = "abort"

[[proxy.chains.relay-via-peer.hops]]
address = "proxy.example.net"
auth = { method = "userpass", secret_ref = "pass:proxy/example" }
port = 1080
type = "socks5h"

[[proxy.chains.relay-via-peer.hops]]
address = "peer-volta.example.org"
port = 8443
spki_pin = "sha256:<base64>"
tls_server_name = "peer-volta.example.org"
type = "volta-relay"

# Per-operation routing. Keys alphabetical. A missing operation
# means DIRECT IS FORBIDDEN for it (CHAIN-2) unless a default is set.
[proxy.routes]
a2a_fetch = "tor-only"
default = "deny"               # deny | direct | <chain name>
ephemeral_exchange = "relay-via-peer"
key_lookup = "relay-via-peer"
key_publish = "direct"
relay_fetch = "relay-via-peer"
relay_sync = "relay-via-peer"
smtp_submit = "direct"
wkd_fetch = "tor-only"
```

Field reference (alphabetical per table):

| Field | Where | Rules |
|---|---|---|
| `address` | hop | Hostname or IP literal. A hostname for hop 1 is resolved by the bootstrap rule CHAIN-4; hostnames for later hops are resolved by the preceding hop |
| `auth.method` | hop | `none`, `userpass` (SOCKS5/HTTP), `ephemeral` (volta-relay: peer session via §7 `relay-session` keys) |
| `auth.secret_ref` | hop | Reference into the secret store (e.g. `pass:…`, `env:…`, `file:…`). Inline secrets in config are a **load error** |
| `dns` | chain | `remote` (default and required unless every target is an IP literal or every hop provably resolves remotely) |
| `fail_closed` | chain | MUST be `true`; `false` → config load fails with `E_CONFIG_INVALID` |
| `isolation_id` | tor hop | `per-operation` (fresh circuit credentials per operation) or a static string |
| `port` | hop | 1–65535 |
| `spki_pin` | hop (TLS hops, volta-relay) | `sha256:<base64 SPKI hash>`; mismatch → `E_PROXY_TLS_PIN_MISMATCH` |
| `timeout_ms` | chain/hop | Per-hop connect timeout (default 10,000), whole-chain deadline (default 30,000) |
| `type` | hop | §13.1 enum; unknown → load error |

Validation at load (**CHAIN-0**): chain length 1–8 hops; no chain
may contain the same `volta-relay` peer twice (loop guard); every
`proxy.routes` value names an existing chain, `direct`, or (for
`default` only) `deny`; invalid configuration refuses startup —
volta never starts with a half-parsed routing table.

### 13.3 Operation inventory (alphabetical)

`a2a_fetch` (peer Agent Card), `ephemeral_exchange` (§7 traffic to
peers), `key_lookup` (outbound lookups to peers/other keyservers),
`key_publish` (outbound submission), `relay_fetch` (§8.2/§9 skill),
`relay_sync` (§12.4 feed), `smtp_submit` (verification/management
mail egress — a chain that ends at an SMTP submission endpoint is
expressed as hops ending in `direct-to-target` semantics: the last
hop connects to the configured MX/submission host), `wkd_fetch`
(foreign-domain WKD). Inbound serving is never proxied by this
section.

### 13.4 Semantics (normative)

- **CHAIN-1 (ordered traversal):** hops are negotiated strictly in
  configuration order — hop *n* is reached only through hops
  1…*n*−1, and the target only through the full chain. Negotiation
  means: for `socks5*`, the SOCKS handshake + auth with the target
  (or next hop) address; for `http-connect`, CONNECT to the next
  hop/target; for `tor-socks`, SOCKS5h via the Tor port with the
  isolation credential; for `volta-relay`, §13.6.
- **CHAIN-2 (fail closed, never silent direct):** if routing names
  a chain for an operation, **any** failure — DNS, connect,
  handshake, auth, pin mismatch, timeout, mid-chain close — aborts
  the operation with the §14 taxonomy error
  (`E_PROXY_HOP_FAILED` etc., carrying `chain`, `hop_index`,
  `hop_type`, and `operation`; never target-internal details the
  operator didn't configure). There is **no** code path that retries
  direct, skips a hop, reorders hops, or substitutes another chain.
  Retries, when the operation itself is retryable, re-run the
  **same** chain, ≤ 2 attempts, exponential backoff ≥ 1 s.
- **CHAIN-3 (DNS through the chain):** with `dns = "remote"`, the
  volta resolver is never consulted for hop-2+ addresses or target
  hostnames: they are handed unresolved to the resolving hop
  (`socks5h` semantics). `socks5` (local resolution) inside a chain
  that also carries a hostname target makes the chain **invalid at
  load** (`E_CONFIG_INVALID`, reason `dns-leak`) unless
  `dns = "system"` is set explicitly — and `dns = "system"` is
  itself a load-time warning surfaced in the readiness output,
  never silent. Plain `socks5` remains available for IP-literal
  targets and single-hop-to-IP uses where no name exists to leak.
- **CHAIN-4 (bootstrap exception, stated honestly):** resolving
  hop 1's own hostname, if it is a name, necessarily uses the
  system/bootstrap resolver (or a configured `bootstrap_resolver`).
  That single lookup is the documented exception to CHAIN-3; it
  reveals only that volta talks to its first hop — which the first
  hop already knows. Operators avoiding even this use IP literals
  or `hosts`-pinned names for hop 1.
- **CHAIN-5 (Tor isolation):** `tor-socks` hops present distinct
  SOCKS credentials per operation when `isolation_id =
  "per-operation"`, so operations do not share circuits by default.
- **CHAIN-6 (credential hygiene):** hop credentials are read from
  `secret_ref` at chain-build time, held in memory only, never
  logged, never echoed in `check` output (§13.5) or errors.
- **CHAIN-7 (TLS inside chains):** the operation's own TLS (§11.2)
  is end-to-end to the final target, inside whatever tunnel the
  chain built — hops see ciphertext (for `volta-relay`, §13.6
  states exactly what the relay can see: connection metadata only).

### 13.5 Chain check

`GET /api/v1/proxy-chains/<name>/check` (operator session) and the
MCP tool `volta_proxy_chain_check` (§8.2) negotiate the chain to a
synthetic echo target at the chain's end (the last hop is asked to
connect to a volta-operated discard endpoint, or, for
`volta-relay`-terminated chains, the relay's own health endpoint),
reporting per-hop `{hop_index, hop_type, latency_ms, status}`
without touching any real operation target and — per CHAIN-2 —
reporting failure as data in the check result while returning a
§14 error only if the check itself could not run.

### 13.6 Volta-relay hop protocol

`POST /relay/v1/connect` on the peer, authenticated with the
`ephemeral` method (a `relay-session` §7 handshake pins both
identities to their §5.2 RelayPeer fingerprints): request
`{"next": {"host": "…", "port": …}, "chain_position": <n>}` →
`101`-style upgraded byte stream (or HTTP/2 CONNECT equivalent in
the HTTP+JSON binding). The relay opens the onward connection —
through **its own** configured chain for `relay_fetch` if the
request so chains (§13.4 applies recursively, with a chain-depth
budget of 16 hops total across instances, carried in a
`Volta-Chain-Depth` header; exceeding → `E_PROXY_CHAIN_TOO_DEEP`) —
and pipes bytes. The relay MUST NOT terminate the inner TLS
(CHAIN-7) and MUST NOT log payloads (GLOB-4). A relay that cannot
reach `next` answers with the §14 proxy error set, which the
originator surfaces unchanged (hop indices are local to each
instance; the originator re-anchors them by prefixing its own).

### 13.7 Changing chains

Chain configuration changes are operator actions requiring §10
step-up (WA-4), are applied atomically (a broken new table never
displaces the working one), and are audit-logged with the full old
and new chain names + hop types (never credentials, CHAIN-6).

---

## 14. Error taxonomy

### 14.1 Shape

New surfaces (`/api/v1/*`, `/mcp`, `/a2a/v1`, `/relay/v1/*`) return
RFC 9457 problem JSON, `Content-Type: application/problem+json`:

```json
{
  "code": "E_PROXY_HOP_FAILED",
  "detail": "hop 2 (socks5h) refused the connection",
  "request_id": "<uuidv7>",
  "retryable": false,
  "status": 502,
  "title": "Proxy hop failed",
  "type": "https://volta.qompass.ai/errors/proxy-hop-failed",
  "volta": {"chain": "relay-via-peer", "hop_index": 2, "hop_type": "socks5h", "operation": "relay_fetch"}
}
```

`volta` carries machine-readable context specific to the code
(chain data for proxy errors, `key_id`/`expires_at` for ephemeral
errors, `field` for validation errors). Legacy surfaces keep their
legacy bodies (§6.2.5) and add `X-Volta-Error-Code: <code>` +
`X-Request-Id` headers. HKP errors stay plaintext per §6.1 with the
same header.

### 14.2 Codes (alphabetical)

| Code | HTTP | Retryable | Meaning |
|---|---|---|---|
| `E_AUDIENCE_MISMATCH` | 403 | no | Ephemeral key used outside its audience/purpose (EPH-3) |
| `E_AUTH_REQUIRED` | 401 | no | No/insufficient credential for the operation |
| `E_CARD_UNSIGNED` | 503 | yes | A2A card signing unavailable; §9 endpoints refuse (A2A-1) |
| `E_CHAIN_DNS_LEAK` | 500 (config-time: startup refusal) | no | Surfaced as load error `E_CONFIG_INVALID` with this reason when a chain would resolve target names locally against CHAIN-3 |
| `E_CONFIG_INVALID` | — (startup) / 400 (API config write) | no | Configuration fails §13.2/§16 validation; server refuses to start or refuses the write |
| `E_CRYPTO_NOT_ALLOWED` | 400 | no | Algorithm/suite on the §11.4 rejected list, or not on the allowlist |
| `E_CUSTODY_MISMATCH` | 400 | no | Operation incompatible with the key's custody mode (§7.3) |
| `E_FORBIDDEN` | 403 | no | Authenticated, but the principal lacks the permission |
| `E_HKP_BAD_SEARCH` | 400 | no | HKP search outside the HKP-2 grammar |
| `E_HKP_UNSUPPORTED_OP` | 400 | no | HKP `op` outside `get`/`index`/`stats` (incl. `vindex`) |
| `E_INGEST_BUSY` | 503 | yes | Ingest queue over depth (§12.5); `Retry-After` present |
| `E_INGEST_FAILED` | 409 | yes | Async ingest pipeline rejected the queued certificate; detail carries the stage reason |
| `E_INTERNAL_ONLY` | 403 | no | `/pks/internal/*` reached without the edge path (§6.1.5) |
| `E_KEY_EXPIRED` | 410 | no | Ephemeral key past hard TTL (EPH-1); also used for expired-certificate distinctions where a surface needs them |
| `E_KEY_MALFORMED` | 400 | no | Unparseable OpenPGP material |
| `E_KEY_NOT_FOUND` | 404 | no | No (visible) key for the query — visibility per VKS-1/§9.4 |
| `E_KEY_REVOKED` | 410 | no | Ephemeral key revoked (distinct from a revoked *certificate*, which is served, DM-PUB-3) |
| `E_MAINTENANCE` | 503 | yes | Scoped maintenance (§12.4 SCALE-7); `Retry-After` present |
| `E_NOT_FOUND` | 404 | no | Unknown route on a new surface (ERR-4) |
| `E_PROXY_AUTH_FAILED` | 502 | no | Hop authentication rejected |
| `E_PROXY_CHAIN_TOO_DEEP` | 502 | no | Cross-instance chain depth budget exceeded (§13.6) |
| `E_PROXY_DNS_FAILED` | 502 | no | Name resolution inside the chain failed (remote resolver error) |
| `E_PROXY_HOP_FAILED` | 502 | yes (same chain only) | Hop refused/reset/closed mid-negotiation |
| `E_PROXY_TIMEOUT` | 504 | yes (same chain only) | Per-hop or whole-chain deadline exceeded |
| `E_PROXY_TLS_PIN_MISMATCH` | 502 | no | SPKI pin mismatch on a TLS hop — possible MITM; also audit-logged at warning level |
| `E_RATE_LIMITED` | 429 | yes | Any §12.5 layer; `Retry-After` present |
| `E_RELAY_PEER_MISMATCH` | 403 | no | Peer presented an identity ≠ its pinned fingerprint (§5.2) |
| `E_TOKEN_EXPIRED` | 410 | no | Sealed token past `token_validity_seconds` (TOK-4) |
| `E_TOKEN_FUTURE_DATED` | 400 | no | Sealed token created in the future (TOK-4) |
| `E_TOKEN_INVALID` | 400 | no | Sealed token fails unsealing for any other reason (TOK-2) |
| `E_TOKEN_TYPE_MISMATCH` | 400 | no | `verify` token used in a manage flow or vice versa (TOK-3) |
| `E_TTL_OUT_OF_BOUNDS` | 400 | no | `ttl_seconds` outside §7.2 bounds |
| `E_UPLOAD_TOO_LARGE` | 413 | no | Body over the 1 MiB cap (§6.1.3/§6.2.2) |
| `E_VALIDATION` | 400 | no | Request schema violation; `volta.field` names the first offending field |
| `E_VERIFICATION_ADDRESS_MISMATCH` | 400 | no | request-verify names an address not in the token's key (VKS-7) |
| `E_VERIFICATION_REQUIRED` | 403 | no | Operation needs a `published` binding the caller does not have (DM-PUB-1) |
| `E_WEBAUTHN_ASSERTION_INVALID` | 401 | no | Signature/flags/origin/rpId check failed (§10.3) |
| `E_WEBAUTHN_CHALLENGE_INVALID` | 400 | no | Challenge unknown, reused, expired, or cross-ceremony (§10.4) |
| `E_WEBAUTHN_CLONE_DETECTED` | 401 | no | Sign counter did not increase; credential locked (§10.3) |
| `E_WEBAUTHN_ORIGIN_MISMATCH` | 401 | no | `clientDataJSON.origin` ≠ configured origin (also an `E_WEBAUTHN_ASSERTION_INVALID` detail case; separate code because it is the phishing signal) |
| `E_WEBAUTHN_UV_REQUIRED` | 401 | no | Assertion lacks the UV flag (WA-2) |

### 14.3 Rules

- **ERR-1:** a response carries exactly one primary `code`. Warnings
  (e.g. legacy algorithms, VKS-5) travel in a separate `warnings[]`
  array and never change the status.
- **ERR-2:** `retryable: true` is a promise that retrying the
  *identical* request can succeed (modulo the stated `Retry-After`);
  for proxy errors it additionally promises the retry uses the
  same chain (CHAIN-2).
- **ERR-3:** no error body contains secret material, token
  plaintexts, hop credentials, target data beyond what the caller
  itself supplied, or another principal's identifiers (GLOB-4,
  VKS-1).
- **ERR-4:** unknown routes on new surfaces return `404` with
  code `E_NOT_FOUND` in the §14.1 shape (routing, not domain
  behavior, but drawn from the same taxonomy so implementers never
  invent ad-hoc codes).

---

## 15. Operator CLI — `voltactl`, `volta`, `volta-delete`

Behavior preserved from black-box help output (S-4), with the C-8
fixes.

- **CLI-1:** `--help` and `--version` work with **no configuration
  present**, exit `0`, and print to stdout. Help/version never touch
  the database, the network, or the proxy configuration.
- **CLI-2:** a run that needs configuration and lacks it exits `2`,
  prints one structured line to stderr naming the missing key(s),
  and never panics.
- **CLI-3:** one workspace version: `volta`, `volta-delete`, and
  `voltactl` all print it (C-7).

### 15.1 `voltactl` (global flags preserved)

```
voltactl [-c|--config <FILE>] [-e|--env <dev|stage|prod>] <subcommand>
```

Subcommands (alphabetical):

| Subcommand | Behavior |
|---|---|
| `audit` | Read the §12.6 audit log (`--since`, `--operator`, `--verify-chain` to check hash-chain + checkpoint signatures) |
| `delete` | The `volta-delete` semantics (§15.2) as a subcommand |
| `import` | `voltactl import [-n|--dry-run] <keyring files>…` — bulk import through the §12.4 pipeline; `--dry-run` parses and reports, stores nothing (S-4 shape preserved) |
| `mcp` | MCP server over stdio: `voltactl mcp --stdio [--operator]` (§8.1 MCP-3) |
| `operator` | `operator bootstrap` (print one-time first-operator token), `operator recover` (§10.5), `operator list`, `operator revoke-credential` |
| `regenerate` | **Kept name, changed meaning (SCALE-2):** rebuild + verify the derived indexes/WKD blobs from stored certificates; prints a verification report (counts, mismatches fixed, mismatches remaining); serving never depends on it. The predecessor's "Regenerate symlink directory" behavior is explicitly gone |
| `relay-sync` | Drive §12.4 sync manually (`--peer <name>`, `--dry-run` shows the change-feed diff from the Merkle root) |
| `stats` | Print the §6.1.4 stats object for the local store |

### 15.2 `volta-delete` (binary kept; also `voltactl delete`)

```
volta-delete [--all] [--all-bindings] <base> <query>
```

`<query>` = email address, fingerprint, or KeyID. Semantics from
S-4, made explicit: an address query deletes that (address, key)
binding; `--all-bindings` deletes all bindings for the queried
key; `--all` deletes all bindings **and** the key; a fingerprint
or KeyID query implies `--all`. Remote/API-triggered deletion
additionally requires §10 step-up; local on-host invocation writes
the §12.6 audit entry before acting.

### 15.3 `volta` (server)

Starts the server with configuration per §16. Readiness endpoint
behavior: the process reports ready only when storage, token
secret, A2A card signing (A2A-1), and proxy table validation
(CHAIN-0) have all passed; any failure is a startup refusal with
the §14 code on stderr, never a half-up server.

---

## 16. Configuration schema (consolidated)

One configuration document (Rocket-style TOML in the predecessor;
the rewrite keeps TOML + `VOLTA_*` environment overrides with the
same names where a predecessor key exists, S-1/S-5). Keys
alphabetical within sections. Predecessor keys retained:
`assets_dir`, `base-URI`, `base-URI-Onion`, `email_template_dir`,
`from`, `keys_external_dir`, `keys_internal_dir` (now blob-store
roots), `maintenance_file` (single-node profile only, SCALE-7),
`root`, `template_dir`, `tmp_dir`, `token_dir` (legacy verify-flow
compat only; new state never lands there, C-6), `token_secret`
(reference form below), `token_validity` (→
`tokens.validity_seconds`), `x-accel-redirect` (edge serving hint).

```toml
[a2a]
card_signing_key_ref = "pass:volta/a2a-identity"   # secret reference, never inline
enabled = true

[crypto]
policy = "strict"               # only value in v1; a placeholder for future profiles is NOT shipped (no speculative config)

[ephemeral]
default_ttl_seconds = 120
max_ttl_seconds = 3600          # values above the §7.2 hard cap are load errors, not clamps
min_ttl_seconds = 30
server_custody_enabled = true

[mail]
rate_limit_per_hour = 60
transport = "smtp"              # smtp | file-spool (development only)

[mcp]
enabled = true
stdio_enabled = true

[operator.webauthn]
attestation = "direct"          # direct | none (§10.2)
origin = "https://keys.example.org"
rp_id = "keys.example.org"
rp_name = "volta"
session_seconds = 900
step_up_freshness_seconds = 300

[proxy]                          # chains/routes per §13.2
# [proxy.chains.<name>] … [[proxy.chains.<name>.hops]] … [proxy.routes] …

[relay]
enabled = false
# [[relay.peers]] base_uri / identity_fingerprint / name …

[server]
address = "0.0.0.0"
base_URI = "https://keys.example.org"
base_URI_onion = ""
port = 8080

[storage]
blob_root = "state/blobs"
index_url = "sqlite://state/volta.db"   # or postgres://… (§12.2)
profile = "single-node"                  # single-node | clustered
ttl_store_url = "sqlite://state/volta.db"

[tokens]
secret_ref = "pass:volta/token-secret"  # the §5.4 secret, by reference only
validity_seconds = 3600
```

- **CFG-1:** any secret-valued setting is a `*_ref` into the secret
  store (`pass:`, `env:`, `file:` schemes). A literal secret in the
  configuration file is a load error (`E_CONFIG_INVALID`).
- **CFG-2:** unknown keys are load errors, not warnings — silent
  misconfiguration in a security product is a defect (fail closed).
- **CFG-3:** the sealed-token secret (`tokens.secret_ref`) is the
  one setting whose rotation is a §10 step-up action; rotation
  keeps the previous secret readable for `validity_seconds` so
  in-flight mailed links don't die ( dual-read window), then drops
  it.

---

## 17. Conformance checklist (summary of normative requirements)

An implementation claims conformance when, at minimum:

1. HKP subset behaves per §6.1 including HKP-2 grammar, HKP-4/7/8
   formats, and the declared C-4 deviations.
2. VKS endpoints reproduce §6.2 shapes byte-for-byte on success and
   legacy error bodies (§6.2.5), with §6.2.6 floors enforced.
3. WKD serves §6.3 forms with binary bodies and the policy file.
4. Publication invariants DM-PUB-1…4 hold under concurrent upload/
   verify/delete races (the one-published-binding invariant is
   transactional).
5. Sealed tokens round-trip with predecessor builds (TOK-1…5),
   including the two-sided lifetime check.
6. Ephemeral keys enforce §7.2 TTL bounds with zero grace (EPH-1/2),
   custody semantics EPH-4/5, and per-purpose binding (EPH-3).
7. MCP `tools/list` returns exactly the §8.2 tools with closed
   schemas; decapsulation is absent from the tool list (MCP-5).
8. The A2A card is served signed (A2A-1…4) and tasks honor §9.3/9.4
   ownership scoping.
9. Operator actions in the WA-4 table are impossible without a
   fresh UV assertion; no biometric data exists server-side (WA-1).
10. Every §13-routed operation fails closed per CHAIN-2 under
    fault injection at **each** hop (kill hop *n* ⇒ error names
    hop *n*, no direct connection attempt is observable on the
    wire — this is testable with a packet capture and MUST be in
    the adversarial half of the test suite).
11. §11.4 rejects fire on upload/issue/use; the two SHA-1
    exceptions are the only SHA-1 computations in the system.
12. Read paths perform no OpenPGP parsing (SCALE-1) — measurable
    via §12.7 targets under load test.
13. All errors carry §14 codes; legacy surfaces additionally keep
    their legacy bodies.
14. `--help`/`--version` pass CLI-1…3 on a machine with no
    configuration and no database.
15. Ordering rule ORD-1 holds for every enumerable the
    implementation emits or documents.

*End of spec v1.0.*
