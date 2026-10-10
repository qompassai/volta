# Introduction

Volta is an OpenPGP key server built for two kinds of clients at
once: the humans and tools that have always used key servers
(GnuPG, Sequoia, email clients), and the software agents that now
need key material on short deadlines and shorter lifetimes.

It publishes and serves certificates under **verified email
bindings**, speaks the three public key-server protocols (HKP,
VKS, WKD), and adds three things its Hagrid-derived predecessor
did not have:

- **Ephemeral hybrid post-quantum session keys** with hard TTLs,
  minted for MCP and A2A agents in the spirit of Rosenpass's
  re-keying discipline.
- **First-class agent surfaces**: an MCP server (13 tools) and an
  A2A participant with a *signed* Agent Card.
- **Fail-closed proxy chains** for its own egress, so a hostile
  local network sees at most the first hop.

Operator power is passkey power: WebAuthn with user verification
required, no passwords, no fallback. Cryptography is allowlisted
in code — what is not on the list in
[Cryptography](crypto.md) is rejected at parse time with a
structured error, not negotiated down.

<details>
<summary>What volta is not</summary>

- Not a certificate authority: volta attests that an email
  address's owner approved publication of a certificate, nothing
  more. Trust in a key still comes from OpenPGP's own mechanisms.
- Not a VPN: the WireGuard-PSK ephemeral purpose ends at key
  delivery; volta never sees WireGuard keys.
- Not a general proxy: chains exist for volta's own operations
  (relay fetch, peer sync, verification mail), each routed by
  name in configuration.
- Not a cluster (yet): the single-node profile is what ships;
  the scaling chapter describes the clustered profile the data
  model was designed for.

</details>

<details>
<summary>Lineage and licensing</summary>

This tree is a clean-room rewrite (2026-10-10), written from a
behavioral specification derived from public protocol documents
and black-box observation — not from the predecessor's source.
First-party code is dual licensed AGPL-3.0-only OR Apache-2.0;
see `rewrite/NOTICE`. The predecessor tree remains in git
history with its own licensing story intact.

</details>
