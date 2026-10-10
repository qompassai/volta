# OpenShell reconciliation — 2026-10-10

Matt ruled (2026-10-10): reconcile both clean-room rewrites'
`.openshell/` directories against the estate pattern the rewrite
agents missed — the OpenShell gateway configuration reference in
the diver configuration (`agents/openshell/CONFIGURATION.md`)
and the operator's active config (`~/.config/openshell/
gateway.toml`, schema version 2).

Delta found in volta: the originated `.openshell/` already
pointed at the machine gateway, but `gateway.toml.example` used
an invented shape — `[gateway]`/`[sandbox]` sections with
`address`, `driver`, and `mtls` fields that exist nowhere in the
gateway schema.

Changes:

- `gateway.toml.example` rewritten in the real schema:
  `[openshell] version = 2`, `[openshell.drivers.podman]` with
  the machine gateway's driver values, `[openshell.gateway]`
  with `bind_address = "127.0.0.1:17670"` and
  `compute_driver = "podman"`; mTLS stays the default
  (`disable_tls` present only as a commented warning).
- The originated `sandbox.name = "volta-dev"` has no counterpart
  in the gateway schema (sandbox naming is a CLI concern); the
  intent is preserved as a comment in the example and in the
  README, and the fake field is dropped.
- `.openshell/README.md` no longer claims the directory is
  originated; it names the estate pattern as the source and
  records the reconciliation.

Validation: the example parses as TOML and carries the schema's
required shape (version 2, podman driver pin, loopback bind).
Local commits only; landing is Matt's separate word.
