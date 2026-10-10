# Protocols: HKP, VKS, WKD

Volta serves the three public key-server protocols, with the
narrowing the specification chose deliberately: **exact lookups
only** — no substring search, no short key ids, no `vindex`.

<details>
<summary>HKP — compatibility for existing clients</summary>

`GET /pks/lookup` with `op=get|index|stats`. The machine-readable
(`options=mr`) index keeps the protocol's field order. `POST
/pks/add` ingests multiple certificates **atomically**: every
block is parsed and policy-checked before any is stored.
`/pks/internal/*` endpoints answer only to the edge's attestation
header; from anywhere else they are `E_INTERNAL_ONLY`.

</details>

<details>
<summary>VKS — verified publication</summary>

`POST /vks/v1/upload` stores a certificate *unpublished* and
returns a sealed manage token. `POST /vks/v1/request-verify`
marks addresses pending and issues per-address verify tokens;
following one publishes exactly that address. Lookups keep the
VKS error asymmetry: by-email reveals nothing about unpublished
bindings (404 either way), while by-fingerprint and by-keyid
serve any stored certificate — possession of the fingerprint is
the capability. Rate floors are enforced in-process with token
buckets rather than left to the edge alone.

Sealed tokens are stateless AES-256-GCM (HKDF-SHA256, salt
`volta`), capped at 64 KiB, with a two-sided lifetime check:
expired and future-dated tokens fail with distinct codes.

</details>

<details>
<summary>WKD — hashed discovery</summary>

`/.well-known/openpgpkey/<domain>/hu/<hash>?l=<local>` serves the
cleaned *binary* form, published bindings only. The policy file
is exactly two lines: `mailbox-only` and `protocol-version: 1`.
The `hu/` hash is SHA-1 of the lowercased local part in z-base-32
— a naming hash the WKD draft mandates (see the scoped exception
in [Cryptography](crypto.md)); it carries no authenticity.

</details>

<details>
<summary>The served form</summary>

What volta serves is derived at ingest: self-issued signatures
only, third-party certifications stripped, user ids kept when
verified or self-signed. Serving is therefore a lookup, never a
computation — and the bytes served are the bytes whose SHA-256
names the blob.

</details>
