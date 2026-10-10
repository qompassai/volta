# Dependabot fixes: bump-now set + multipart narrowing — 2026-10-10

From the 2026-10-10 triage of volta's 56 open Dependabot alerts
(`~/workspace/security/volta-dependabot-triage.md`, sandbox copy);
Matt approved both fix sets the same day.

## Bump-now set (wkd-domain-checker/requirements.txt)

- gunicorn 20.0.4 -> 22.0.0 — clears #45 and #60 (Transfer-Encoding
  request smuggling in the checker's front-door parser; the one
  REACHABLE finding in the triage).
- certifi 2019.11.28 -> 2026.7.22 (current) — clears #34 and #39
  (2019 CA bundle still carrying the TrustCor and e-Tugra roots on
  the checker's outbound TLS path). Data-only change.

Both pins verified to install and run standalone. The rest of the
checker's 2019 stack (Flask/Werkzeug/urllib3/requests/Jinja2/idna)
is the separate bump-with-care modernization — not touched here,
and the `flask.escape` code fix stays with it.

## Multipart feature narrowing (legacy root workspace)

multipart 0.18 was declared as `multipart = "0"` (default features)
in Cargo.toml, database/Cargo.toml, and voltactl/Cargo.toml. The
defaults compile multipart's hyper/iron/nickel/tiny_http adapters,
which no first-party code uses — the only call site is
`multipart::server::Multipart` over Rocket Data in
src/web/vks_web.rs. All three declarations are now
`default-features = false, features = ["server"]` (the narrowing
must be in every manifest: cargo feature unification would
otherwise keep the defaults alive).

24 packages left the root Cargo.lock, none added — including
traitobject (#8 CRITICAL), typemap (#9 CRITICAL), hyper 0.10.16
(#1, #2, #6), tiny_http 0.6.4 (#3), and ascii 0.8.7 (#77): all seven multipart-family alerts. Gates: root
workspace `cargo test` in the flake dev shell = 63 passed
(34 server + 29 database), matching the Oct 9 finish-up baseline.
The rewrite/ workspace is untouched.
