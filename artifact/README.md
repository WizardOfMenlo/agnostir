# ERA codes: ASIACRYPT 2026 artifact

Artifact for **Field-Agnostic SNARKs with Small Proofs via Encode-Repeat-Accumulate (ERA) Codes**.

**AI disclosure:** GPT-6 Astra, accessed through OpenAI Codex, generated or
substantially revised nearly all final project-specific code and original
repository content, implementing algorithms from the human-written descriptions
and details in the paper under human direction. See the
[detailed disclosure, including scope, prompts, and revisions](../AI_DISCLOSURE.md).
The human authors retain responsibility for the implementation and scientific claims.

This is the reviewer entry point for two experiments: a common interleaved
argument comparing ERA, BaseFold-code, Brakedown and EA; and the optimized ERA
codeswitching IOPP compared with the local recursive BaseFold IOPP. The latter
uses the sparse zero-padding Brakedown base, uncheckpointed batched GKR,
compact verifier weight evaluations, and a switch to recursive BaseFold.

## Submission contents and status

The prepared main source archive is **`era-codes-artifact-20261016-final.tar.gz`**.
It contains source, tests, fixed parameters, compact raw reference measurements,
the supplied paper PDF, dependency/license records, the AI disclosure, a pinned
Docker build recipe, and scripts for both experiments. The
[submission metadata](submission.json) and `artifact/submission-form.txt`
identify the prepared submission. **Prepared locally; not uploaded.** No
committee badge or completed cryptographic soundness proof is claimed.

The optional `era-codes-dependencies-20261016.tar.gz` contains pinned Cargo
sources and Linux Python wheels. The optional `era-codes-evidence-20261016.tar.gz`
contains ten full reference proofs, original source snapshots and measured
binaries. Neither is required to regenerate proofs. The main archive contains
compact evidence and proof hashes; it does not contain build caches, prior
release archives, superseded experiment payloads, or the private AWS backup.

Paths in commands are relative to the repository or unpacked distribution root.
The few layout differences are:

| Item | Repository checkout | Unpacked source distribution |
| --- | --- | --- |
| This guide | `artifact/README.md` | `README.md` (also `artifact/README.md`) |
| Supplied paper | `artifact/paper.pdf` | `paper/paper.pdf` |
| Reference measurements | `artifact_results/<campaign>/` | `evidence/{paper22,interleaved28,codeswitch28,container-validation}/` |
| Release integrity | Local release record and archive checksums | `SHA256SUMS` and `SOURCE_VERSION.json` |

The Git base revision alone does not identify the release: the source snapshot
includes uncommitted work, and the packaged checksums identify its exact files.

## Quick start

Commands below assume an unpacked source distribution. In a repository checkout,
build and benchmark modes also work; the `evidence` checksum command is for the
packaged distribution. Docker on Linux x86-64 is the tested container platform. Building needs Internet
access for the pinned official Rust/Debian base and OS packages. The optional
`era-codes-dependencies-20261016.tar.gz` supplies exact Cargo sources and Python
wheels: extract it at this directory before building to avoid Cargo/PyPI downloads.
Without it, Cargo.lock and requirements-analysis.txt pin those downloads.

```sh
# First validate the distribution and inspect saved results (Python >=3.11 only; no extra packages).
python3 -B artifact/validate.py evidence .
python3 -B artifact/summarize.py evidence

# Portable build; allow 8 GiB RAM and several minutes for compilation.
docker build -t era-codes-artifact .
mkdir -p results
docker run --rm --network none --cpus 8 --memory 8g \
  -v "$PWD/results:/results" era-codes-artifact smoke /results/smoke
```

The smoke run checks all library tests (parallel and serial), distance/model
unit tests and calibration, then generates and verifies four
interleaved proofs and both IOPP proofs. It has reduced input sizes and query
counts and is a functional check, not a security-calibrated performance result.
Choose a fresh output path for every run; existing output is never overwritten.

Native alternative: Rust/Cargo **1.92.0**, Python **3.11+**, a C/C++ toolchain,
NumPy **2.4.1**, and SciPy **1.17.0**. Cargo.lock records every transitive Rust
version and the exact Plonky3 git revision. On Debian/Ubuntu install
`build-essential python3 python3-venv pkg-config`, install Rust 1.92.0 with rustup,
then run:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-analysis.txt
rustup override set 1.92.0
cargo +1.92.0 build --locked --release --bin interleaved_iopp --bin compare_iopps
bash artifact/run.sh smoke results/native-smoke
```

For the dependency archive, copy `dependencies/cargo-config.toml` to
`.cargo/config.toml` before native compilation, and install Python requirements
with `--no-index --find-links dependencies/wheels`. The supplied wheels are for
Linux x86-64 / CPython 3.11; other platforms can resolve the same pinned versions.
Rust/Debian OS installation is not made offline by this dependency archive.
The toolchain override above also selects Rust 1.92.0 for the runner's test commands.

## Experiments and resource requirements

All new benchmark modes default to **one warmup and one measured sample**.
They use seed 2025, canonical 32-byte secp256k1 scalar encodings, BLAKE3,
Fiat-Shamir, and exact serialized proof lengths. No command benchmarks 2^29.

| Mode | What it does | Memory / expected time on reference hardware |
| --- | --- | --- |
| `evidence` | Check bundle hashes and summarize retained measurements | <1 GiB; seconds |
| `check` | Library, distance, model tests and calibration | 8 GiB including compilation; minutes |
| `smoke` | Checks plus reduced-size versions of both experiments | 8 GiB; typically under 2 minutes after build |
| `paper22` | Four interleaved encoders at 2^22, eta=6 | 8 GiB; roughly 1-3 minutes |
| `interleaved28` | Four encoders with saved proof-size-selected interleaving | 128 GiB machine; budget about 45 minutes |
| `codeswitch28` | ERA codeswitching and local recursive BaseFold at 2^28 | 128 GiB machine; budget about 10 minutes |
| `full28` | All six full-size cases sequentially | 128 GiB machine; budget about one hour |

Timing ranges are planning allowances, not measurements of every container mode.
The historical paper table is the median of three samples on an Apple M2;
`paper22` defaults to one sample. `SAMPLES=3` is available
if a reviewer wishes to repeat that aggregation, but is not needed for smoke.
The full-size modes fix 16 threads and one sample.

```sh
# Reproduce the paper's encoder configuration.
docker run --rm --network none --cpus 8 --memory 8g \
  -v "$PWD/results:/results" era-codes-artifact paper22 /results/paper22

# On a 128 GiB Linux x86-64 host, compile for that host and run sequentially.
# A native image must not be moved to a CPU without its instruction set.
docker build --build-arg RUSTFLAGS='-C target-cpu=native' -t era-codes-native .
docker run --rm --network none --cpus 16 --memory 120g \
  -v "$PWD/results:/results" \
  era-codes-native full28 /results/full28
```

Use `codeswitch28` or `interleaved28` in place of `full28` for one experiment.
The 112 GiB preflight model retains headroom. It is an estimate; actual peaks
are retained in memory.json. Keep other large jobs off the benchmark machine.
No AWS credentials, public IP, remote service, or SSH access is needed to run.
`INSTANCE_TYPE` is optional provenance metadata; set it to the actual instance
type if using AWS. The generic command leaves it unspecified.

## Paper mapping and reference results

See [paper map and deviations](paper-map.md), [reference measurements](results.md), [parameters](parameters.md),
[implementation changes and limitations](changes.md), and [submission metadata](submission.json).
The supplied paper is in `paper/paper.pdf` at the package root.
Its Table 3 / Appendix D.1 is the original 2^22 common-interleaved comparison.
The 2^28 AWS measurements and the optimized code-switching implementation are
explicitly additional results. Appendix D.2/Table 4/Figure 7 use an older proof
size model and are not claimed to be reproduced by the measured proof bytes.

Both full-size comparisons use an on-demand AWS r7a.4xlarge, 16 physical AMD EPYC
9R14 cores and 128 GiB advertised RAM, Rust 1.92.0 with target-cpu=native.
The common interleaved results are from October 15; the optimized IOPP results
are from October 16, 2026 (America/New_York). Each uses one warmup and one sample.
The snapshots and campaigns are recorded separately, not pooled.

| Comparison / protocol | Commit (s) | Evaluation prove (s) | Total prover (s) | Verify (ms) | Proof (bytes) | Peak RSS (GiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Interleaved ERA | 29.575 | 18.132 | 47.707 | 1,046.157 | 40,541,384 | 58.817 |
| Interleaved BaseFold-code | 17.193 | 18.089 | 35.282 | 232.447 | 33,989,320 | 40.154 |
| Interleaved Brakedown | 86.297 | 18.200 | 104.496 | 1,367.456 | 49,624,040 | 41.149 |
| Interleaved EA | 937.552 | 18.172 | 955.723 | 10,610.487 | 49,622,792 | 48.560 |
| ERA codeswitching IOPP | 25.987 | 57.531 | 83.518 | 38.495 | 3,622,568 | 87.246 |
| Local recursive BaseFold IOPP | 18.767 | 18.579 | 37.346 | 56.703 | 6,004,040 | 44.277 |

The four interleaved rows form one comparison; the final two form another.
The interleaved experiment retains its original base encoders. The sparse
Brakedown base applies to the final ERA codeswitching IOPP only. All six cases
run sequentially under `full28`, with their distinct saved interleaving choices
and query counts from `artifact/evaluation-plan.json`.

Distances are conditional numerical estimates, EA retains the conjectured 0.1
distance, and the compact ERA verifier retains an `O(n log k')` tensor-weight
calculation. See [implementation limits](changes.md). The full-size baseline
is a local recursive BaseFold implementation using Plonky3 dependencies.

Expected proof SHA-256 values are in `artifact/expected-proofs.json`.
Benchmark programs cryptographically verify every generated proof before
writing an accepted row. The Python checker additionally matches lengths and
known hashes; checking a stored hash by itself is not cryptographic verification.
CPU flags and thread counts can change time but should not change proof bytes.
There are no confidence intervals from the single measured full-size samples.

## Outputs and interpretation

Each benchmark run saves accepted raw CSVs, logs, environment information,
exact source snapshots, proofs, proof-validation records, and checksums.
The `check` mode saves test/calibration records without generating benchmark proofs.
Large runs additionally save per-case commands and peak RSS. The full IOPP
cases have nested prover profiles; ERA also has a separate verifier profile. Setup and input
creation are excluded from commit/prove/verify timings. The public 32-byte root
is not part of proof_bytes. Total prover time is commitment plus evaluation
proof time; the summarizer aggregates that total per sample before taking medians.
Profile file writes are outside the timers. Peak RSS covers the whole process.
Sum only disjoint/exclusive profile times, never nested inclusive times.

```sh
python3 -B artifact/summarize.py results/full28 > results/full28-summary.json
python3 -B artifact/validate.py run results/full28
```

`evidence/` contains compact raw reference measurements, environments, selected
plans and proof hashes. The optional `era-codes-evidence-20261016.tar.gz` archive contains the full proof
files, original source snapshots and measured binaries. They are preserved for
inspection; rerunning the artifact generates fresh proofs without that archive.
`SHA256SUMS` covers the packaged source, documentation, paper, and compact evidence.

## Source layout and licenses

- `src/commit/codes/`: encoders; `src/interleaved_iopp/fs.rs`: common argument.
- `src/era_iopp.rs`: ERA codeswitching; `src/basefold_iopp.rs`: local recursive BaseFold.
- `src/proof/`: transcript, Merkle proofs, sumcheck, fractional GKR, compact weights.
- `src/bin/{interleaved_iopp,compare_iopps}.rs`: timing and serialization harnesses.
- `distance-analysis/`: BaseFold, ERA and Habock-Brakedown numerical calculations.
- `scripts/`: parameter planning and full-size runner; `artifact/`: reviewer entry points.

The baseline is a local implementation using pinned Plonky3 dependencies,
not a modified upstream Plonky3 BaseFold implementation. Dependencies are used
unmodified and retain their own licenses; see [third-party notices](THIRD_PARTY.md)
and dependency records.
See [container validation](validation.md) for the checks performed on this distribution.
See the [MIT license](../LICENSE) for the authors' code and the [AI disclosure](../AI_DISCLOSURE.md)
for the extent of generation and revision by GPT-6 Astra through OpenAI Codex.
The supplied paper is provided for evaluation and is not relicensed under MIT.

## Maintainer packaging

In the repository checkout, `python3 -B artifact/package.py results/new-package`
assembles a fresh source distribution using the bundled `artifact/paper.pdf`
and retained evidence. The reviewer archive itself needs no sibling paper
checkout, historical development runs, or AWS access. The packaging helper is
only in the development repository; it is not needed to execute the archive.
The proof-size audit includes its sparse-base input next to its reproduction
script, at `evidence/proof-size-audit/` in the distribution.

## Naming and proof compatibility

The Cargo package is `era-codes` (Rust import `era_codes`). The optional tuning
variables are `ERA_CHUNK_LEN` and `ERA_PROFILE_ENCODE_NAIVE`.
The historical transcript/setup domain labels remain fixed because they are
part of the existing proof format. Original logs, recorded paths and source
snapshots retain their original identifiers as provenance; they are not project
names or titles for the paper. Renaming the crate does not change proof bytes.
