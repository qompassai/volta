# Licensing

<details>
<summary>The scheme in one paragraph</summary>

Volta is dual-licensed **where Qompass AI holds the copyright**:
material authored by Qompass AI in this repository is available
under AGPL-3.0 (`LICENSE-AGPL`) **or** Apache-2.0 (`LICENSE`), at
the recipient's choice. Volta is derived from Hagrid, and the
upstream-derived portions remain AGPL-3.0 only — so Volta as a
combined work is distributed under AGPL-3.0.

</details>

<details>
<summary>Why the boundary is where it is</summary>

Qompass AI can offer its own contributions under any terms it
likes, including the dual grant above. It cannot relicense code it
did not write: Hagrid is AGPL-3.0 software, and no Apache-2.0 grant
can be extended over upstream-derived portions of the server, the
database crate, or the command-line crate. Those crates therefore
declare `AGPL-3.0-only` in their manifests, which is the accurate
expression for the code as it stands.

The practical consequences:

- Running, modifying, or redistributing Volta as a whole is
  governed by AGPL-3.0, exactly as with upstream Hagrid.
- A Qompass-authored component extracted on its own — the
  documentation, the Nix packaging, a module written for this
  fork — may be taken under Apache-2.0 instead, under the dual
  grant recorded in `NOTICE` at the repository root.
- The `dist/` tree is upstream material with its own provenance
  markings and is not relicensed by anything in this repository.

Individual files carry headers stating which side of the boundary
they sit on: `AGPL-3.0-only OR Apache-2.0` for Qompass-authored
files, `AGPL-3.0-only` for upstream-derived material.

</details>

<details>
<summary>History of the scheme</summary>

The repository previously shipped a sole Apache-2.0 `LICENSE`
alongside (before that) an AGPL/Q-CDA pairing. The Q-CDA scheme no
longer applies and its text is not shipped. The current scheme was
adopted 2026-10-10 to state the dual grant for Qompass material
honestly, without claiming Apache terms over upstream code.

</details>
