# OpenAPPA worker policy for volta

This directory is volta's OpenAPPA (APPA) policy profile: the
deterministic, second gate for a dispatched Claude worker doing
work in this repository, under the harness's own permissions. It is
the estate's OpenAPPA adaptation — proven as a pilot on primo in
October 2026 — propagated to this repo per Matt's direction.

- `appa.toml` — the policy. It includes the upstream claude-code
  battery unchanged and adds volta's root rules: the repo's own
  build/test/lint workflows, hard denies for network egress and
  destructive operations, labels for volta's secret classes,
  staging zones a labeled session cannot write to, and tiers for
  volta's MCP tools (read-only allowed, mutating ask-first,
  decapsulation hard-denied — volta ships no such tool, by design).
- `replay/` — replay scenarios in the pilot's `.appa` format.
  Roughly half validate the allowed workflows; half are adversarial
  (exfiltration, label confusion, sink spoofing, the destructive
  set). Every expectation is checked by the pinned engine.

## Pinned engine

The profile validates against the pilot's pinned upstream build —
never upstream main:

- appa **0.30.0**, upstream commit
  `5060566a0d9fed034a5e68ec782a1b00714c7014`
- binary: `~/openappa-pilot/src/target/debug/appa`
- battery (by relative include from `appa.toml`):
  `~/openappa-pilot/src/marketplace/batteries/claude-code/appa.toml`

The include is relative because the engine requires it; the
configuration therefore loads on primo, where the pilot tree sits
at `~/openappa-pilot`, and fails closed anywhere else.

## Validation

Run from the repo root:

```sh
APPA=~/openappa-pilot/src/target/debug/appa
$APPA describe --config policy/appa.toml --check   # exit 0
$APPA replay --config policy/appa.toml policy/replay/
```

Expected: describe reports the configuration loadable, and replay
reports every scenario file ok (13 files, 25 expectations at
authoring time). One describe caveat: without an installed battery
beside the config, the session-tool inventory cross-check is
unavailable ("415 unknown") — tool names rest on replay and on the
adapter's identity mapping instead. That is an inventory gap, not a
load failure.

## Changing this policy

Policy changes are proposals, never worker self-widening: propose
the change, run both gates above with the replay expectations
updated to state the intent, and land it only with Matt's
approval. A scenario that fails is the policy or the expectation
being wrong — fix whichever is, and say which in the commit.

## Status and known gaps

This profile is checked in and gated; it is not wired into
dispatch. Runtime enforcement (launching a worker under `clappa`
with this profile) is a separate step, as it was for the pilot,
and is Matt's call.

Honest expressiveness gaps, in the pinned engine's own terms:

- Bash selectors are substring matches with no full-recall
  guarantee. The allow rules are command prefixes, so a compound
  command (`cd rewrite && cargo build`) does not take the allow
  path and falls through to the battery's annotator; the deny
  rules are substrings and are ordered first, so a denied
  operation inside a compound command is still blocked.
- Path selectors match the path as written, not the resolved
  path: a read through a symlink or alias is labeled by its
  written name. The live runtime's content tracking is the
  backstop (the pilot's live gate proved read-derived content
  cannot land in a later write).
- APPA tool identities admit no wildcards. Decapsulation is
  therefore denied by enumerating its plausible names; any other
  spelling is an undeclared tool, which the covered registry
  refuses before it runs.
- The flow rules name the staging zones (the tmp family and
  lookalike repo directories). A secret-labeled session writing
  to an unenumerated outside path is governed by the battery's
  bare Write rule and the live content check, not by a root rule.
