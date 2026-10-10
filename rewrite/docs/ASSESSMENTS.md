# Volta clean-room rewrite — two assessments

Date: 2026-10-10. Scope: volta is the Hagrid-derived OpenPGP key server
(Rust / Rocket / sequoia-openpgp, HKP + VKS + WKD) being rewritten
clean-room. Both assessments are evidence-based: web sources are linked
in-line, and machine evidence was gathered read-only on primo via
`~/workspace/bin/primo-ssh` on 2026-10-10. No kernel module was loaded,
built, or attempted on primo — evidence gathering only.

**Verdicts up front**

- **A. Homa transport — CONDITIONAL, default NO.** Do not build it now,
  and never as a default. A feature-gated, non-default skeleton becomes
  defensible only when the conditions in §A.7 are all met (supported
  kernel on ≥2 peer nodes, known-good NIC / segment, AEAD layer on top).
  On primo today it cannot run: the module is absent and primo's kernel
  is two major versions past upstream's tested head.
- **B. Mojo — NEGATIVE, NO-BUILD.** Mojo earns nothing in volta today.
  The one narrow pattern that worked in phlow (a small, offline,
  numerically-shaped kernel behind a hashed receipt, with a Rust
  reference implementation as the authority) has no volta workload
  waiting for it. Revisit triggers are listed in §B.5; until one fires,
  Rust does every candidate job at least as well with an audited stack.

---

<details>
<summary>A. Homa feasibility — optional, feature-gated, non-default transport for volta peer sync / internal RPC</summary>

## A.1 What Homa is, and what the linked paper actually is

Matt linked arXiv:2210.00714v2, *It's Time to Replace TCP in the
Datacenter* (Ousterhout, v1 Oct 2022, v2 19 Jan 2023,
https://arxiv.org/abs/2210.00714). That is a **position paper**, not the
implementation paper. The implementation evidence lives in *A Linux
Kernel Implementation of the Homa Transport Protocol* (USENIX ATC '21)
and in the code at https://github.com/PlatformLab/HomaModule. The
original protocol design is Montazeri et al., SIGCOMM 2018.

Homa in one paragraph (paraphrased from those sources): a
message-oriented, connectionless transport for datacenters. There are
no streams and no connections — the unit is an RPC message (capped at
1,000,000 bytes, `HOMA_MAX_MESSAGE_LENGTH`). Receivers drive congestion
control by issuing *grants* for incoming bytes, and messages are
scheduled shortest-remaining-processing-time-first using multiple
priority queues (carried in the DSCP / Traffic-Class field), which is
what removes downlink congestion and head-of-line blocking in the
authors' benchmarks. Semantics are at-most-once (since Nov 2021).
Reported wins are large but specific: P99 tail latency for *short
messages under high load* on 25–100 GbE datacenter fabrics, in the
ATC '21 cluster benchmarks and in the 2022 position paper's numbers
(e.g. ~92 µs P99 vs ~1.2 ms for TCP at 80% load on 100 GbE in recent
2026 talks). IANA assigned Homa IP protocol number **146** in Oct 2024.

Fit check against volta's actual workload, before any engineering:
peer sync for a key server is bulk reconciliation of public-key
material — kilobytes-to-megabytes, latency-insensitive, bottlenecked
by parsing, signature verification, and the database, not by
short-message tail latency on a saturated fabric. Homa's demonstrated
win does not map onto volta's bottleneck. That mismatch, not
implementability, is the main reason for the verdict.

## A.2 State of the kernel module and its kernel-version requirements

The module is alive and actively developed — this is not abandonware:

- Repo head (checked 2026-10-10): *"The head is known to work under
  Linux 6.17.8; this is where current development occurs"*, plus
  compile support for Linux 7.0.14 that upstream explicitly says is
  *not actively supported* and may bit-rot. Branches `rhel8` and
  `rhel9.5` (Mar 2026) are the only other supported targets. Older
  kernels live on stale per-version branches. There are **no releases**
  (5 tags, 0 GitHub releases); you build from a pinned commit.
- The wire protocol and API are **still moving**: Sep 2026 changed the
  granting mechanism (new `START_MSG` packet type, messages fully
  scheduled); Jan 2026 added a `homa_qdisc` qdisc for Homa/TCP
  coexistence; Mar 2025 changed `homa_sendmsg_args` for private RPCs;
  Oct 2025 added the `HOMAIOCINFO` ioctl. Any binding volta writes is
  bound to a pinned module commit, not to a stable ABI.
- **Upstreaming began Oct 2024 and is explicitly expected to change
  the API.** Upstream's own README warns the first in-tree version will
  be neither functionally complete nor performant, and the sources
  carry `#ifndef STRIP` markers separating upstreamed from
  non-upstreamed parts. As of this check Homa is **not in mainline**:
  it is an out-of-tree module you compile and `insmod` yourself
  (`make`, then `sudo insmod homa.ko`; see the repo's `INSTALL.md`).
- Kernel-version discipline is strict: one supported head version at a
  time, historically advancing in jumps (6.1.38 → 6.10.6 → 6.13.9 →
  6.17.8). Running Homa means either pinning your kernel to upstream's
  cadence or carrying forward-port patches yourself — upstream says
  version bumps have usually been hours of work, but that is for jumps
  *they* chose to make, on unpatched mainline kernels.

## A.3 Primo evidence — can it run here? No (checked 2026-10-10, read-only)

| Check (primo, via `primo-ssh`) | Result |
|---|---|
| `uname -r` | `7.2.9-zen1-1-zen` (also installed: `7.2.9-arch1-1`) |
| `lsmod \| grep homa` | nothing loaded |
| `modinfo homa` / `modinfo homa_net` | `ERROR: Module homa not found.` (both) |
| `find /lib/modules/$(uname -r) -iname "*homa*"` | no files |
| `pacman -Qs homa` / AUR search (`paru -Ss homa`) | no Homa transport package (only unrelated hits) |
| Kernel headers | present: `linux-zen-headers 7.2.9.zen1-1`, build dir exists |
| Secure Boot / lockdown | SecureBoot **disabled**; lockdown `[none]` |
| Module signing | `CONFIG_MODULE_SIG=y`, `CONFIG_MODULE_SIG_FORCE` **not set** |
| `/etc/protocols` | already lists `homa 146` — that is the IANA assignment arriving via iana-etc, **not** module presence |
| NIC | Realtek Killer E3000 **2.5 GbE** (`enp45s0`, LAN `192.168.0.0/24` via `192.168.0.1`); Intel CNVi Wi-Fi down |
| DKMS status | only unrelated modules (acpi_call, akvcam); no Homa DKMS entry |

Reading of that table:

1. **Version gap is the blocker.** Primo runs 7.2.9-zen. Upstream's
   supported head is 6.17.8; 7.0.14 is compile-only and disclaimed.
   7.2 is untested territory, and the zen patchset adds a second
   variable. Expect a forward-port, not a build.
2. **Nothing else blocks loading in principle.** Headers exist, Secure
   Boot is off, module signing is not forced — *if* a port built, the
   machine would likely accept it. This assessment did not test that;
   loading was explicitly out of scope.
3. **The hardware/fabric case is absent anyway.** Upstream's known-good
   NIC list is Mellanox ConnectX-4/5/6 and Intel E810. Primo's Realtek
   2.5 GbE is unlisted, the "fabric" is a home LAN behind a consumer
   gateway with no DSCP priority-queue configuration and no jumbo
   frames, and there is exactly **one** node — Homa needs the module on
   both ends of every RPC. Even a successful port on primo would have
   nothing meaningful to talk to and no priority fabric to win on.

**Documented finding: Homa cannot run on primo as it stands, and
primo is not the kind of node Homa's benefits require.**

## A.4 Userspace access and Rust bindings

Correcting a common assumption (and the task brief's guess): the
modern API is **not ioctl-based**. Since v2.0 (Dec 2022) Homa uses the
ordinary `sendmsg`/`recvmsg` syscalls on a
`socket(AF_INET|AF_INET6, SOCK_DGRAM, IPPROTO_HOMA)` socket, with
Homa-specific argument structs (`homa_sendmsg_args`,
`homa_recvmsg_args`, defined in the repo's `homa.h`) passed as control
/ ancillary data, a pre-registered receive buffer pool via
`setsockopt`, configuration via `sysctl`, and metrics via
`/proc/net/homa_metrics`. The old `homa_api.c` helper library was
**removed in May 2025**. Ioctls survive only at the edges: abort, and
`HOMAIOCINFO` (Oct 2025) for socket status.

Binding state by language (searched 2026-10-10):

- **C/C++:** the repo itself, plus `PlatformLab/grpc_homa` (preliminary
  gRPC-over-Homa). This is the only first-class path.
- **Go:** one community client, `github.com/dpeckett/go-homa`
  (https://pkg.go.dev/github.com/dpeckett/go-homa) — useful as a
  worked example of the sendmsg/recvmsg + buffer-pool dance.
- **Rust: nothing found.** No crate on crates.io and no Rust binding in
  or around the upstream repo surfaced in search. Volta would write
  its own: a thin crate over `libc`/`socket2`-style raw syscalls —
  one contained `unsafe` module owning socket creation, the two args
  structs (layout-matched to a pinned `homa.h`), buffer-pool
  registration, and `sendmsg`/`recvmsg`. This is very doable — the
  syscall surface is small — but it is a *tracking* obligation, not a
  one-off: the structs changed incompatibly in Dec 2022 and Mar 2025,
  and the upstreaming process promises more changes. The crate must
  probe the module at startup (version/feature check via
  `HOMAIOCINFO` or a capability RPC) and **fail closed to TCP** on any
  mismatch. Budget for re-validation on every module bump.
- **Netlink:** not part of the API. Configuration is sysctl + the man
  pages (`homa.7`); do not design around netlink.

## A.5 Packaging state — Arch, NixOS, general

- **Arch:** no package in the official repos and none in the AUR
  (verified on primo, §A.3). No DKMS package exists upstream.
- **NixOS / nixpkgs:** no Homa package or module found in search
  (2026-10-10; stated as "none found", not "proven absent"). Volta's
  flake would need a custom `boot.extraModulePackages`-style
  derivation rebuilt per kernel — the worst-case packaging shape for a
  module whose supported kernel moves in jumps.
- **Elsewhere:** RHEL 8 / 9.5 are the only distro targets upstream
  maintains branches for. Everyone else builds from source per
  `INSTALL.md` and loads with `insmod`; upstream's cluster tooling
  assumes CloudLab-style homogeneous nodes.

Operational consequence: adopting Homa is adopting a per-kernel,
per-node build-and-load pipeline (plus rollback story) for every volta
peer. That treadmill, not the Rust code, is the dominant lifetime cost.

## A.6 Security composition — Homa brings no security; volta must bring all of it

Red-team framing (Matt's standard): Homa provides **no encryption, no
authentication, and no peer identity**. It is a datacenter transport
that assumes a trusted fabric. On the wire, any host that can emit IP
protocol 146 packets to a volta node can send it RPCs, spoof grants,
and probe the module. Two distinct exposures follow:

1. **Payload exposure / injection** — addressed by composition, below.
2. **Kernel attack surface** — an out-of-tree, network-facing parser
   running in kernel context, on every peer. Upstream is actively
   hardening it (e.g. Sep 2026 fixes for signed/unsigned confusion on
   grant and segment offsets in the incoming path) — good maintenance,
   and also evidence the surface is still yielding bugs. This surface
   is categorically larger than the battle-tested TCP stack's, and it
   lands on a machine whose job is key material. It must never be
   reachable from an untrusted segment.

Composition that would be acceptable for volta peer sync (all of it
mandatory, none optional):

- **Treat Homa exactly like raw UDP: an untrusted wire.** No sync
  payload is accepted on Homa's say-so.
- **Key establishment off-Homa:** peers authenticate and establish
  session keys over the default TCP/TLS path (or a direct ML-KEM
  handshake): ML-KEM (FIPS 203) encapsulation to the peer's pinned
  identity key, HKDF over the shared secret → per-direction session
  keys, peer identity = key fingerprint from volta's pinned peer list,
  never an IP address.
- **Every Homa message is an AEAD ciphertext** (ChaCha20-Poly1305 or
  AES-256-GCM, from volta's existing audited Rust crypto — *not* a new
  implementation): nonce derived from session id ‖ direction ‖ RPC id
  ‖ counter, associated data covering peer id, message type, and
  length; replay window per session; sessions re-keyed on counter
  exhaustion, peer restart, or a time bound. Cost notes: this forfeits
  Homa's zero-copy buffer-pool elegance on receive (you authenticate,
  then copy out — fine at volta's message sizes) and shrinks usable
  payload by the AEAD/header overhead under the 1 MB message cap.
- **Network containment as defence in depth, not as the control:**
  dedicated VLAN / direct link for peer sync, host firewall admitting
  IP protocol 146 only from peer addresses, Homa sysctls and
  `SO_HOMA_SERVER` bind discipline set so unbound sockets reject
  requests (upstream's Feb 2025 default). Public client traffic
  (HKP/VKS/WKD) stays on TCP/TLS, full stop — per the task scope.
- **Fail closed:** module missing, version mismatch, handshake
  failure, or AEAD failure ⇒ peer sync falls back to TCP/TLS or does
  not happen. Homa failure must never degrade authentication.

One more honest note: encrypting payloads does not hide message sizes
or timing. For public-key sync between federated key servers that
leakage is low-value; it would matter more for private RPCs, which is
another reason internal RPC over Homa stays cluster-only.

## A.7 Cost estimate — feature-gated skeleton (estimates, labelled as such)

Assuming the clean-room rewrite already has the TCP/TLS transport, the
ML-KEM handshake, and AEAD framing (reused, not rebuilt):

| Piece | Estimate |
|---|---|
| Forward-port / build the module for one chosen supported kernel; DKMS or Nix derivation; load/rollback runbook | 3–5 days, **plus** per-kernel-release treadmill (~0.5–1 day per bump, forever) |
| Rust binding crate (`homa-sys`-style): pinned-header structs, buffer pool, send/recv, capability probe, adversarial FFI tests | 1–2 weeks |
| Transport behind the existing transport trait, feature-gated off by default, probe-and-fallback to TCP at startup and per-peer | 1 week |
| AEAD session framing over Homa (handshake reuse, nonce/replay discipline, negative tests: tamper, replay, wrong peer, downgrade) | ~1 week |
| Two-node test rig (second node on the supported kernel + known-good NIC), sync smoke + fallback tests, 50/50 validation/adversarial | 1–2 weeks |

**Skeleton total: ≈4–6 engineer-weeks** to "gated, encrypted echo-RPC
between two suitable nodes, default off, falls back cleanly".
**Trustworthy production peer sync on top of it: roughly double**,
dominated by ops (kernel treadmill, peer upgrades in lockstep) rather
than code. If the ML-KEM/AEAD layer does not already exist in the
rewrite, add 2–3 weeks and re-price — do not build it *for* Homa.

## A.8 Verdict A — CONDITIONAL (default: no-build)

**Negative for primo, negative for production now, conditional for a
gated experiment.** Reasons, in order of weight:

1. Volta's sync workload doesn't need what Homa sells (§A.1); the
   bottleneck is verify/parse/DB, not short-message tail latency.
2. It cannot run on the hardware/kernel at hand (§A.3): kernel 7.2.9-zen
   vs supported 6.17.8, module absent, unlisted 2.5 GbE NIC, one node,
   no priority fabric.
3. No Rust bindings, a still-moving ABI, staged upstreaming that
   promises more ABI change, and zero distro packaging (§A.2, A.4,
   A.5) — volta would own the binding, the packaging, and the kernel
   treadmill.
4. Security is entirely volta's to add (§A.6), and the module widens
   kernel attack surface on a key-material host.

**Conditions that flip this to a buildable experiment** (all required):
(a) ≥2 dedicated peer nodes pinned to a kernel upstream supports
(6.17.8 line or RHEL 9.5), with a listed NIC and a segment where DSCP
priorities are actually honoured; (b) the ML-KEM + AEAD composition
of §A.6 specified and reviewed *before* any transport code; (c) the
transport lands feature-gated, default-off, probe-and-fallback, with
public traffic permanently excluded; (d) a named owner for the
per-kernel module treadmill. If those are ever met, the §A.7 skeleton
is a reasonable, bounded experiment. Until then: **documented
no-build, revisit on upstream mainline acceptance** — an in-tree Homa
with a stable ABI would remove reasons 3 and most of 2 at a stroke.

</details>

---

<details>
<summary>B. Mojo assessment — where Mojo honestly fits volta, and where it does not</summary>

## B.1 Local evidence — what phlow's Mojo track actually proved

Source: `trainer-mojo-findings.md` in primo's
`~/workspace/repos/phlow-trainlab-mojo/` (branch
`pax/trainlab-mojo-20261008`), read 2026-10-10; runs on primo
(RTX 4070 Laptop, 8 GB). This was an experimental *fourth* trainer
backend for phlow-trainlab, deliberately scoped to **kernels, not a
trainer**: per-token logprob over the vocabulary and RLOO advantage
computation, compiled to a shared library and called from Rust over a
C ABI. Toolchain: MAX 26.5.0 / Mojo 1.0.0 in a pixi env (a later probe
used pip `modular` 26.6.0 / Mojo 1.1.0).

What it proved, with the findings' own numbers:

- **Parity:** scoring kernel vs the PyTorch reference on identical
  logits — worst per-token |Δ| 1.35e-04, ~500× inside the 0.05
  nats/token contract bar; RLOO advantages near-exact (max |Δ|
  8.51e-09 over 128 completions).
- **Speed, kernel-shaped work only:** resident-batch scoring
  538–779 µs/launch (Mojo) vs 1005–1316 µs (PyTorch `log_softmax` +
  gather) — **≈1.3–1.9×**; the sampling kernel landed at ~1.8×
  (4811 µs vs 8959 µs). Every Mojo run beat every torch run despite
  torch getting the freer GPU. These are *kernel-vs-eager-framework*
  numbers on identical resident data — not end-to-end wins, and never
  compared against the full training step.
- **Integration shape that worked:** `build.rs` compiles the `.mojo`
  kernel to a `.so`; the Rust crate's `ffi.rs` is the *only* unsafe,
  with all shapes validated before any FFI call; the productised pass
  added a hashed scoring receipt tying outputs to the run, a vendored
  runtime (six MAX runtime libraries, `$ORIGIN` rpath — the shipped
  binary must not depend on the pixi env), and a fail-closed GPU
  policy with a pure-Rust reference fallback. Final gates: 38 tests
  in the Mojo crate, clippy/fmt clean.

Where it **walled**, precisely (the findings' word, and the pattern
matters for volta):

- **The framework/serving path.** MAX's own Qwen2 forward pipeline
  exists in the library but could not be assembled from the conda
  distribution in the time box: six undeclared PyPI dependencies,
  a serving-factory layer required before the model class is usable,
  and `max.entrypoints` absent from the conda package entirely.
- **The pip distribution probe (26.6) walled on accuracy:** `max serve`
  ran, but tail logprobs on a 73-token prompt deviated up to ~2.6 nats
  from the reference — ~50× outside the parity bar — and served
  logprobs were capped at 7. Verdict in the findings: not wired.
- **No trainer ecosystem:** no PEFT/QLoRA in Mojo; the PyTorch sidecar
  stayed the logits producer and the production trainer. Mojo was
  additive acceleration behind an existing contract, never the system.
- **Toolchain friction, itemised in the findings:** eight documented
  docs-vs-toolchain discrepancies in a single small project (GPU APIs
  living in different modules than the docs claim, a reserved keyword
  surprise, lockfile/pixi version traps including two pixis on primo
  where the stale one breaks the build, `mojo format` unable to find
  its formatter, plain executables failing to link while
  `--emit shared-lib` works). None fatal; all taxed a *two-kernel*
  project.

Language/ecosystem state (web, Oct 2026): Mojo 1.0 shipped
11 Aug 2026 and the compiler was open-sourced (Apache-2.0 with LLVM
exceptions) on 18 Aug 2026, after Qualcomm's acquisition of Modular —
a real improvement in auditability, with two caveats the coverage
itself flags: prebuilt wheels still carry Modular's MAX platform
licence identifier rather than the repo's Apache terms, and external
compiler contributions were not yet open. The ecosystem remains
numerics/ML-centred; general data-processing, web, and serving
libraries are sparse compared to Rust's.

## B.2 Where Mojo does NOT fit volta — hard exclusions first

1. **Anything touching key material — excluded, no exceptions.**
   Volta's core is OpenPGP key handling (sequoia-openpgp over nettle)
   and, in the rewrite, ML-KEM session establishment. There is **no
   audited PQC implementation in Mojo** — no ML-KEM, no ML-DSA, no
   audited AEAD, no OpenPGP — and no constant-time / side-channel
   story a reviewer could sign. Writing clean-room PQC in Mojo would
   mean volta shipping *un-audited cryptography it wrote itself in a
   young language*: exactly the failure mode a clean-room rewrite
   exists to avoid. The audited path stays in Rust (sequoia/nettle,
   RustCrypto-class crates) where constant-time discipline, fuzzing
   history, and reviewers exist.
2. **The FFI boundary is a cost, not a bridge.** Phlow's integration
   worked *because* the surface was tiny: one `.so`, a handful of
   exported functions, one unsafe Rust module, every shape checked
   before the call. Mojo↔Rust is a C ABI — no shared types, no shared
   error model, manual ownership on both sides, and Mojo-side export
   syntax and stdlib layout already churned between the 26.5 and 26.6
   toolchains in phlow's own findings. Every volta use wider than a
   single pure function pays this tax continuously, and each crossing
   is a place key material or unvalidated shapes must never be.
3. **Online / serving paths — excluded.** Volta serves HTTP
   (HKP/VKS/WKD) from Rocket. Mojo has no production HTTP stack to
   offer, and phlow's direct evidence is that Modular's *serving*
   layer is the part that walls (factory assembly, missing entry
   points, accuracy caps). A Mojo sidecar in the request path would
   add a process, a runtime to vendor, and a failure domain, for
   workloads that are I/O- and verification-bound.
4. **Stateful core logic — excluded.** Database, reconciliation,
   email-verification tokens, rate limiting: stateful, I/O-bound,
   correctness-dominated code where Mojo's strengths (SIMD/GPU numeric
   kernels) are irrelevant and Rust is already native-speed with the
   full ecosystem. No case.

## B.3 Where Mojo could honestly fit — candidates, graded

All three candidates share the phlow shape that worked: **offline,
batch, pure-function, no key material, Rust reference as authority,
outputs verified before use.**

| Candidate | Fit | Honest assessment |
|---|---|---|
| Benchmark harnesses | **Best fit — and still weak** | Mojo is genuinely good at tight numeric loops, and a harness is throwaway by definition, so toolchain churn costs little. But volta's harnesses need to benchmark *volta's* Rust paths (parse, verify, DB), which Criterion already does in-process. Mojo would benchmark reimplementations of the hot loop, not the hot loop. Useful only for exploring an algorithmic variant before porting it to Rust. |
| Offline audit-log processing | **Plausible, unproven** | Batch-shaped and offline, and log records carry no private keys — but they do carry email addresses and IPs (PII; "offline" is not "safe to hand around"). The work is text parsing, joins, and aggregation — string/regex territory where Mojo's stdlib is thinnest and its phlow-proven strength (dense numeric reductions) barely applies. Rust with `memchr`/`aho-corasick`-class tooling is the incumbent and is fast. Mojo would have to *win a measurement* here, not assume one. |
| Log / throughput analytics sidecar | **Plausible, narrow** | The closest analogue to phlow's win: histograms, percentile and rate computations over exported metrics are numeric reductions over resident arrays — the kernel shape Mojo demonstrably accelerates (1.3–1.9× vs a *framework*, note — phlow never measured Mojo vs hand-written Rust SIMD, which is the real bar here). If a volta analytics job ever becomes a measured bottleneck, this is the first place to prototype. Today no such bottleneck is measured. |

Note the asymmetry the phlow numbers impose: Mojo's proven margin is
over **PyTorch eager**, a low bar. Volta's incumbent is **Rust**, a
high bar. No local evidence shows Mojo beating competent Rust at
anything, because phlow never ran that comparison — the Rust side
there was the *reference*, not the competitor.

## B.4 Cost / risk if built anyway

A second language toolchain in CI and in every dev environment
(pixi/conda or pip pin, per phlow), a vendored runtime to ship and
patch (six libraries in phlow's small case), a young language whose
stdlib layout and export syntax moved between the two versions phlow
touched within weeks, and — for a solo-maintained, security-postured
project — a second language every future reviewer must audit at the
FFI seam. Against zero measured volta need. Tiger-style simplicity
says no.

## B.5 Verdict B — NEGATIVE: no-build (default stands)

**Do not build Mojo into volta.** Reasons:

1. The only place Mojo is *proven* (locally, on this hardware, by
   Matt's own program) is small offline numeric kernels behind a
   verified receipt — and volta has no measured workload of that
   shape waiting.
2. Its proven walls — serving/framework assembly, ecosystem gaps,
   toolchain churn — sit exactly on volta's centre of mass (HTTP
   serving, stateful logic, text processing).
3. Key material is a hard exclusion: no audited PQC/crypto in Mojo,
   and the FFI seam must never widen toward it (§B.2).
4. The performance bar in volta is Rust, not PyTorch; Mojo's
   1.3–1.9× local evidence does not transfer.

**Revisit triggers** (any one reopens this, as a time-boxed prototype
in the phlow shape — offline, hashed inputs, Rust reference checking
every output): (a) a volta batch job is *measured* to be a bottleneck
and profiled as a pure numeric reduction; (b) that prototype beats the
Rust implementation end-to-end (not kernel-only) by ≥2×; (c) the job
provably touches no key material and no PII beyond what the job already
handles in Rust. Until then, the correct volta Mojo artefact is this
assessment.

</details>

---

<details>
<summary>Evidence and sources</summary>

- Homa position paper (Matt's link): arXiv:2210.00714v2,
  https://arxiv.org/abs/2210.00714 (v2, 19 Jan 2023).
- Homa kernel implementation paper: *A Linux Kernel Implementation of
  the Homa Transport Protocol*, USENIX ATC '21 —
  https://www.usenix.org/system/files/atc21-ousterhout.pdf
- Module source, README (supported-kernel statement, significant
  changes 2022–2026, upstreaming note, IANA 146), and `INSTALL.md`:
  https://github.com/PlatformLab/HomaModule (head checked 2026-10-10:
  known to work on Linux 6.17.8; 7.0.14 compile-only).
- Go client (API shape reference): https://pkg.go.dev/github.com/dpeckett/go-homa
- Recent adoption/upstreaming coverage: *The Register*, 2026-10-01,
  https://www.theregister.com/networks/2026/10/01/stanford-prof-is-beating-the-drum-for-a-new-protocol-to-replace-tcp/5300629
- Primo machine evidence: read-only `primo-ssh` session, 2026-10-10 —
  `uname -r` → `7.2.9-zen1-1-zen`; `modinfo homa` / `modinfo homa_net`
  → not found; `lsmod`, `/lib/modules` search, `pacman -Qs`,
  `paru -Ss homa`, header/Secure Boot/module-sig probes, `lspci` /
  `ip -br link` — full results summarised in §A.3. No module load was
  attempted.
- Mojo local evidence: `trainer-mojo-findings.md`, primo
  `~/workspace/repos/phlow-trainlab-mojo/` (2026-10-08 findings +
  2026-10-09 productisation pass), read 2026-10-10. All Mojo numbers
  in §B.1 are from that file.
- Mojo 1.0 / open-sourcing dates and licence caveats:
  https://en.wikipedia.org/wiki/Mojo_(programming_language) and
  https://www.thesoftwarefrontier.com/p/how-mojo-actually-compiles
  (wheel licence identifiers vs repo Apache-2.0 terms).
- Absence claims ("no Rust crate found", "no nixpkgs/AUR package
  found") are search results as of 2026-10-10, phrased as *none found*,
  not proof of non-existence.
- Volta context: primo `~/workspace/repos/volta-cleanroom/README.md`
  and `Cargo.toml` (Hagrid-derived OpenPGP key server; Rust nightly
  2026-09-25, edition 2024; sequoia-openpgp/crypto-nettle; Nix flake
  present).

</details>
