# Ephemeral keys

Agents need session keys the way Rosenpass taught WireGuard to
want them: minted fresh, bound to a purpose, dead on schedule.
Volta's ephemeral API (`/api/v1/ephemeral-keys`) issues hybrid
post-quantum keypairs under a **hard TTL**: minimum 30 s, default
120 s (the Rosenpass re-key cadence), maximum 3600 s — and TTLs
are **never extended**. Rotation mints a successor with a new key
id; the old key runs out its original clock.

<details>
<summary>Custody: local by default</summary>

- `custody=local` (default, recommended): the caller generates
  the keypair; volta stores public material and metadata only.
- `custody=server`: volta generates the keypair and holds the
  private half **in process memory only** — never on disk, never
  in logs, zeroized at expiry, revocation, or drain. The honest
  consequence, stated in the API itself: a restart kills
  server-custody keys early (`410 E_KEY_EXPIRED`,
  `custody_lost: true`). Clients needing restart survival use
  local custody.

</details>

<details>
<summary>Sessions and decapsulation</summary>

A peer registers an encapsulation (`POST .../sessions`); the
owner decapsulates (`POST .../decapsulate`, server custody only,
step-up required). Each decapsulation mints a distinct session
(≤ 600 s, ≤ the key's remaining life), and the shared secret
crosses the API exactly once — volta stores no field for it.
Decapsulation is deliberately **not** an MCP tool: a tool-host's
approval prompt is not the sole guard on secret release.

</details>

<details>
<summary>Purpose and audience binding</summary>

A key issued for purpose P is refused for any other purpose, and
likewise for audiences (`E_AUDIENCE_MISMATCH`). Purposes:
`a2a-session`, `mcp-session`, `relay-session`, `wireguard-psk`.
For the last, volta's part ends at delivery of the derived
secret as a WireGuard PSK, exactly as Rosenpass delivers to
WireGuard; volta does not run the VPN.

</details>

<details>
<summary>Premise conflict C-10: Rosenpass semantics, not wire format</summary>

Real Rosenpass uses Classic McEliece and Kyber — ciphers outside
volta's allowlist. What volta adopts is Rosenpass's *exchange
discipline* (ephemeral KEM keypairs, periodic re-keying, forward
secrecy, PSK delivery) re-instantiated over ML-KEM. It is not
wire-compatible with Rosenpass, and does not claim to be.

</details>
