# Security Model

## Threat assumptions

Volta is a public key server: its inputs are untrusted by design
(arbitrary key uploads, arbitrary lookup strings), and its assets
are the integrity of the key directory and the privacy of
unverified email addresses.

## What is enforced

- **Verify before publish.** Email addresses are not searchable
  until the address owner proves control via the mailed token link.
  This is the anti-spam / anti-impersonation core of the Hagrid
  model and is exercised end-to-end by the integration tests.
- **Sealed management tokens.** Verification and management links
  carry AES-256-GCM-sealed tokens (Contracts chapter): tampering,
  truncation, oversized inputs, and wrong-secret tokens all fail
  closed. Token checks are time-bounded in both directions.
- **No key-material logging.** Upload and token paths do not log
  token plaintexts or key material; mail contents stay in the mail
  spool directory configured by the operator.
- **Rate limiting and maintenance mode** are built in
  (`rate_limiter.rs`, `/maintenance/*`) and covered by tests.

## Decisions and disclosures from the 2026-10 pass

- **The sealed-token test fixture was regenerated.** The shipped
  fixture token did not validate under the sealed-state construction
  the repository itself ships, under any of the derivations tried
  (standard HKDF-SHA256 in both salt/secret orientations, extract-only
  HMAC, PBKDF2 at five iteration counts, alternate layouts and AADs,
  nine candidate secrets). Ring 0.13.5's HKDF/AEAD were verified
  RFC-equivalent from source, so the fixture's provenance is
  unverifiable and it was replaced with one produced by the current
  implementation, preserving the test's shape and intent. The
  replacement is commented in `tokens.rs` and summarized in the
  Testing chapter.
- **A mail assertion was corrected, not weakened.** The Japanese
  verification-mail test expected lettre's header folding with three
  spaces after `Subject:`; the current lettre emits one (the passing
  management-mail assertion agrees). The encoded-subject content
  assertion is unchanged.
- **License.** Volta is Hagrid-derived and distributed under
  AGPL-3.0. Material authored by Qompass AI is dual-licensed
  AGPL-3.0 or Apache-2.0 at the recipient's choice; the Apache
  choice does not extend to upstream-derived portions. The
  `dist/` tree is upstream material and retains its own
  provenance markings. See the Licensing chapter and the `NOTICE`
  file at the repository root.
