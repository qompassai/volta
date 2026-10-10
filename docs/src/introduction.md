# Introduction

**Volta is an OpenPGP key server.** It is derived from Hagrid, the
software behind keys.openpgp.org. (The repository's GitHub
description long claimed it was a reverse proxy; that was wrong —
the code has never contained proxying. The description and this book
now say what the code does.)

What it serves, from the route tables in `src/web/`:

- **HKP** — `/pks/lookup`, `/pks/add`, `/pks/internal/index/<query>`
  (`hkp.rs`): the classic keyserver protocol.
- **VKS API** — `/vks/v1/upload`, `/vks/v1/request-verify`,
  `/vks/v1/by-fingerprint/<fpr>`, `/vks/v1/by-email/<email>`,
  `/vks/v1/by-keyid/<kid>` (`vks_api.rs`): the verifying keyserver
  API, JSON in and out.
- **Web Key Directory** — `/.well-known/openpgpkey/<domain>/hu/<hash>`
  and `/policy` (`wkd.rs`).
- **Web UI** — `/upload`, `/search`, `/verify/<token>`, `/manage`,
  `/manage/<token>`, `/manage/unpublish` (`vks_web.rs`, `manage.rs`),
  plus `/about` pages, `/debug`, `/maintenance/*`, and a Prometheus
  `/metrics` endpoint.

The trust model is Hagrid's: anyone may upload a key, but an email
address is only published as searchable after its owner clicks a
verification link mailed to that address; owners can manage and
delete their addresses through tokenized links. Keys are stored on
the filesystem by the `volta-database` crate; `voltactl` is the
operator CLI for bulk import and database regeneration.

Volta is not related to the bunker Nix-cache server beyond theme
(both handle keys and signatures in the same estate); they share no
code.
