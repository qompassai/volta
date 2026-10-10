# Scaling model

The specification began by naming the predecessor's scaling gaps
(G-1..G-8) and answering each. This chapter is the short form.

<details>
<summary>The gaps, answered</summary>

| Gap in the predecessor | Volta's answer |
|---|---|
| Single node, non-synchronizing (G-1) | Content-addressed blobs + a relay change feed with Merkle roots (`/relay/v1/root`, `/relay/v1/changes`); sync is a designed surface, not an afterthought |
| Filesystem keystore + derived symlink tree needing manual regeneration (G-2) | Blobs + SQLite index derived at ingest; `voltactl regenerate` is a *verification* tool, serving never depends on it (SCALE-1/2) |
| Static fast path for some lookups, app path for others (G-3) | One read path for all lookup classes; the served form is pre-rendered at ingest |
| Parse/clean/render on the request path (G-4) | All derivation happens once, at ingest (SCALE-1) |
| Whole-service maintenance file (G-5) | Dropped: readiness is per-surface (`/readyz` reports identity/signing state) instead of a global 503 switch |
| Coarse edge-only rate limits (G-6) | In-process token buckets per lookup class with spec floors, in addition to any edge limits |
| Node-local on-disk token state (G-7) | Link tokens are stateless sealed tokens; only challenges/sessions are node-local, and both are short-lived by design |
| Protocol narrowing by accident (G-8) | Narrowing by *decision*, documented in the spec: exact lookups only, no vindex, explicit grammar |

</details>

<details>
<summary>Profiles</summary>

**Single-node (what ships):** SQLite-WAL index, content-addressed
blob directory, in-memory ephemeral/session/task state. Honest
limits: server-custody ephemeral keys and A2A tasks are
node-local (a restart ends them — for ephemeral keys this is a
designed, documented behavior, EPH-4).

**Clustered (the design):** the same data model over shared
tiers — Postgres for the index, object storage for blobs, Redis
for the TTL stores — with relay sync between nodes. The store
boundary in `volta-core` is where this lands; no surface changes
shape.

</details>

<details>
<summary>Bounded everything</summary>

Uploads capped at 1 MiB, chain hops at 8 per chain and depth 16
across instances, sealed tokens at 64 KiB, list pages at 200,
session lifetimes at 600 s, TTLs at 3600 s. Every bound is a
named constant with a structured error on the other side of it.

</details>
