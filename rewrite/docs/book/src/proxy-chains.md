# Proxy chains

Volta routes its *own* egress — relay fetch, peer sync,
verification mail — through configurable multi-hop chains:
SOCKS5, SOCKS5h, Tor SOCKS, HTTP CONNECT, TLS-wrapped hops with
SPKI pins, and volta-to-volta relay hops. Routing is
per-operation in configuration (`publish`, `relay-fetch`,
`relay-sync`, `wkd-fetch`, …), resolved once at connection time.

<details>
<summary>Fail closed, always</summary>

If any hop in a configured chain is unavailable, the operation
fails with a structured error (`E_PROXY_HOP_FAILED`,
`E_PROXY_TIMEOUT`, `E_PROXY_TLS_PIN_MISMATCH`, …). There is **no
silent direct fallback** — a direct connection happens only when
the routing table says `direct` in so many words. Tests prove
this with connection counters: a dead first hop means the target
saw zero connection attempts.

</details>

<details>
<summary>No DNS leaks</summary>

Hostname resolution happens *through* the chain (SOCKS5h
semantics, ATYP `0x03`). Configuration validation rejects the
leaky combination at startup: a local-resolving SOCKS5 hop plus
a hostname anywhere downstream is a load-time error
(`E_CHAIN_DNS_LEAK` class), not a runtime surprise. All-IP-literal
chains are exempt — there is nothing to leak.

</details>

<details>
<summary>What chains do — and do not — protect</summary>

A chain protects **metadata and local-network exposure**: an
evil-twin access point or a hostile LAN sees a connection to the
first hop and nothing else — not the destination, not the DNS
names, not (past the first hop) the content. It frustrates
traffic correlation against volta's clients and against the
server's own egress patterns.

A chain does **not** provide end-to-end integrity or
authenticity. A malicious exit hop can tamper with bytes; what
stops it is not the chain but the cryptography: OpenPGP
self-signatures on certificates, hybrid-PQC session keys on
ephemeral flows, pinned identity fingerprints on relay peers
(a fingerprint mismatch is `E_RELAY_PEER_MISMATCH`, full stop).
Chains hide *where* volta talks; signatures prove *what* it
received. Neither substitutes for the other, and this book does
not pretend otherwise.

One boundary is stated plainly: the very first connection of a
fresh deployment (fetching a peer's card before any pin exists)
cannot be bootstrapped from nothing — pins come from
configuration, and configuration is the trust root (CHAIN-4).

</details>

<details>
<summary>Credentials and depth</summary>

Hop credentials come from secret references (`env:`, `file:`,
`pass:`) resolved at dial time; they never appear in config
files, logs, or error messages. Tor hops get per-operation
stream isolation by default. Cross-instance relay depth is
budgeted at 16; beyond it, `E_PROXY_CHAIN_TOO_DEEP`. The relay
endpoint itself (`POST /relay/v1/connect`) is token
authenticated and upgrades to a raw pipe only after the next
hop is validated.

</details>
