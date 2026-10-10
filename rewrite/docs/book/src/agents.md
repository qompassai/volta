# Agents: MCP and A2A

Volta's primary clients are agents, so the agent surfaces are
not a bolt-on: they are the same operations as the REST API,
behind protocol-shaped doors, with authorization checked **per
call**, before anything executes.

<details>
<summary>MCP — 13 tools, no more</summary>

Streamable HTTP at `POST /mcp` (plus stdio via `voltactl mcp
--stdio`), JSON-RPC 2.0 with the initialize handshake, an
`Mcp-Session-Id` per session, and Origin validation against DNS
rebinding. `tools/list` returns exactly the 13 tools of the
specification — lookups, publication, ephemeral
issue/status/rotate/revoke, a delete *request* tool (completion
needs an operator), the operator-only chain check, relay fetch,
and WKD lookup. Resources: `volta://agent-card`,
`volta://crypto-policy`, `volta://keys/<fingerprint>`.

Auth classes are per tool: `public` (rate-limited), `agent`
(detached signature over the canonical request, 300 s window),
`owner`, `operator`. Anonymous callers reach the public tools
only. The stdio transport runs as a read-only lookup principal
unless launched `--operator` with a live session token file.

</details>

<details>
<summary>A2A — a signed card or nothing</summary>

`GET /.well-known/agent-card.json` serves the Agent Card with
JWS signatures over its RFC 8785 (JCS) canonicalization — EdDSA
for a classical identity, the `VOLTA-MLDSA87-ED25519` profile
for the composite identity. **An unsigned card is a deployment
error**: without a configured identity the endpoint answers
`503 E_CARD_UNSIGNED` rather than serving an unsigned card.
Four skills (`ephemeral-key-exchange`, `key-lookup`,
`key-publication`, `relay-fetch`) run as tasks over
`POST /a2a/v1` (`message/send`, `message/stream`, `tasks/get`,
`tasks/list`, `tasks/cancel`, `tasks/resubscribe`). Tasks are
ownership-scoped: another principal's task id is a 404, never an
existence oracle. A lookup miss is a *failed* task carrying the
error code, not an empty success.

</details>

<details>
<summary>Agent identity</summary>

An agent principal is a name, an identity suite, a verifying
key, and a permission list, all from configuration. Requests are
signed over `method \n path \n timestamp \n sha256(body)`.
Permissions are least-privilege and checked by name (e.g.
`relay-fetch` is a separate grant). There is no anonymous
mutation on either surface; there is no "unsigned mode".

</details>
