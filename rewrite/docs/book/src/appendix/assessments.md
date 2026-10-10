# Appendix: Homa and Mojo assessments

Both were assessed with evidence during the rewrite; both
verdicts are "not now", for different reasons. Full texts:
`rewrite/docs/ASSESSMENTS.md`.

<details>
<summary>Homa — conditional, no-build</summary>

Homa (the receiver-driven datacenter transport) cannot run on
the development host today: the kernel (7.2.9-zen) is beyond the
upstream supported head (6.17.8; 7.0.14 is compile-only and
disclaimed), no module is packaged for Arch or nixpkgs, the
host's Realtek 2.5 GbE NIC is not among the known-good devices
(ConnectX-4/5/6, Intel E810 are), and there are no Rust
bindings (C/C++ and Go only, moving ABI). Homa also has no
built-in cryptography; it would have to compose with volta's
ML-KEM-established session keys.

The deeper mismatch: Homa's win is tail latency on controlled
datacenter fabrics; volta's costs are verification, parsing,
and database work on internet-facing requests, and its public
clients will never load a kernel module. Estimated cost of a
gated skeleton: 4–6 engineer-weeks for something that cannot be
validated on the target hardware. Verdict: **do not build**;
revisit if volta ever runs ≥ 2 dedicated nodes on a supported
kernel/NIC, or if Homa reaches mainline.

</details>

<details>
<summary>Mojo — negative, no-build</summary>

In-house evidence (the phlow trainer work) shows Mojo earning
its keep in exactly one shape: small, offline, numeric kernels
behind a Rust reference implementation — parity well inside its
bar, ~1.3–1.9× against PyTorch eager — while walling on serving
(missing entry points, undeclared dependencies, numeric drift).
Volta's bar is Rust, not Python, and no volta workload has that
kernel shape. The exclusions are harder still: nothing touching
key material (Mojo has no audited PQC/AEAD/OpenPGP stack and no
constant-time story), nothing serving online, nothing stateful.
The weakest-but-best candidate was benchmark harnesses, which
Rust already covers. Verdict: **do not build**; revisit only if
a measured offline numeric workload appears in volta's profile.

</details>
