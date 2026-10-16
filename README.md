# ERA codes and IOPP experiments

**AI disclosure:** GPT-6 Astra, accessed through OpenAI Codex, generated or
substantially revised nearly all final project-specific code and original
repository content, implementing algorithms from the human-written descriptions
and details in the paper under human direction. See the
[detailed disclosure, including scope, prompts, and revisions](AI_DISCLOSURE.md).
The human authors retain responsibility for the implementation and scientific claims.

Artifact for **Field-Agnostic SNARKs with Small Proofs via
Encode-Repeat-Accumulate (ERA) Codes**. The repository contains two experiments:

- A common interleaved evaluation argument comparing ERA, BaseFold-code,
  Brakedown, and Expand-Accumulate (EA), at the paper's `2^22` configuration
  and an additional `2^28` configuration.
- The optimized ERA codeswitching IOPP, using the sparse Brakedown base,
  uncheckpointed batched GKR and a switch to recursive BaseFold, compared
  with the local recursive BaseFold IOPP at `2^28`.

Start with the [artifact reproduction guide](artifact/README.md) for Docker,
resources, and all run modes. [Parameters](artifact/parameters.md),
[reference results](artifact/results.md), and the
[paper-to-artifact map](artifact/paper-map.md) describe the final comparison.
The supplied paper's Tables 3, 4, and 6 report the AWS measurements;
Table 5/Figure 7 retain the analytical estimates, separately from measured proof sizes. The artifact
implements encoders and evaluation arguments, not a complete zero-knowledge SNARK.

## Prepared submission

The current main archive is `era-codes-artifact-20261016-submission-llncs.tar.gz`, recorded
with its exact size and checksum in the [submission record](docs/artifact-submission.md).
It contains source, tests, fixed parameters, compact raw reference evidence,
reproduction scripts, Dockerfile, paper PDF, license notices, and the AI disclosure.
The [submission form](artifact/submission-form.txt) and
[metadata](artifact/submission.json) are prepared locally; no upload is claimed.

The archive's root README is generated from `artifact/README.md`. Its evidence
is under `evidence/`, whereas this checkout retains campaign records under
`artifact_results/`. Full reference proof files and pinned dependency sources
are separate optional archives. Local builds, old releases and private campaign
backups under `target/` and `results/` are excluded from the main submission;
see the [retention index](docs/repository-layout.md).

## Interleaved IOPP experiment

This experiment compares **ERA, BaseFold, Brakedown, and Expand-Accumulate (EA)** as encoders inside
the same interleaved evaluation argument. All four use the **secp256k1 scalar
field**, BLAKE3-256, Fiat–Shamir, and the same serializer and verifier. Proof
sizes are actual serialized lengths; every timed proof is verified.

The field is the prime field of order

```text
0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
```

Elements have canonical 32-byte encodings. This is the scalar field used by the
earlier experiment. The main comparison excludes both Bolt variants.

Query counts use `ceil(-300 / log2(1 - delta))`. **This is a conditional
100-bit query model, not a certified end-to-end 100-bit Fiat–Shamir security
claim.** The current presets apply the [distance-audit corrections](docs/distance-audit.md).
See [current calibration details](docs/prime-experiment.md) for the setup
budgets and remaining numerical qualifications.

## Paper-sized interleaved setup: 2^22

| Setting | Value |
| --- | --- |
| Message | `2^22 = 4,194,304` field elements |
| Interleaving | `eta = 6`: 64 contiguous rows of 65,536 elements |
| Field | secp256k1 scalar field, via `ark_secp256k1::Fr` |
| Commitment and transcript | BLAKE3, 32-byte digests, separate domains |
| Protocol | `interleaved-fs-v1`, setup recipe v3 |
| Benchmark seed | `2025` |
| Paper sampling | AWS Docker; 8 Rayon workers; 1 sample after 1 warmup |
| New reproduction default | 8 Rayon workers; 1 sample after 1 warmup |

The prover commits to the row encodings and proves the message's multilinear
evaluation at a public point. An initial sumcheck produces a transcript-derived
random row fold, including when the public point is Boolean. The prover sends
the folded message and a Merkle multiproof for sampled columns. The verifier
replays the transcript, checks the sumcheck, re-encodes the folded message, and
authenticates and checks the sampled columns.

The transcript binds the statement, root, setup ID, dimensions, query count,
and version. Queries are uniform with replacement; repeated columns and shared
authentication siblings are deduplicated on the wire. Noncanonical field
encodings, invalid headers, truncation, inconsistent proofs, and trailing
bytes are rejected.

### Encoder presets

These presets are calibrated only for row message length `2^16`. Without an
explicit distance/query override, the CLI requires `message-log - eta = 16`.
The full-size plan supplies separately calibrated parameters.

| CLI name | Parameters | Encoded row length | Distance used | Queries |
| --- | --- | ---: | ---: | ---: |
| `era` | Brakedown base `(alpha, inverse_rate, cn, dn)=(0.04,1.05,5,42)`; repetition 4 | 275,248 | 0.22037 | 836 |
| `basefold` | Symmetric random foldable code; inverse rate 2 | 131,072 | 0.20106 | 927 |
| `brakedown` | Inverse rate 2; `alpha=0.3`, `cn=14`, `dn=28` | 131,072 | 0.1 | 1,974 |
| `ea` | Inverse rate 2; `prob_multiplier=18` | 131,072 | 0.1 (conjectured) | 1,974 |

BaseFold's distance allocates a 102-bit total setup budget across 16 random
levels, giving per-level `lambda=106`. Brakedown's parameters pass Haböck's
numerical sufficient bound at every recursive level with the same total
setup budget. ERA uses base distance 0.0009 and a 102-bit CalcDist parameter;
its numerical distance candidate is rounded down to 0.22037. EA retains the
paper's conjectured distance 0.1 and multiplier 18; no new finite-length EA
setup certificate is supplied.

The [calibration report](distance-analysis/current-results.json) records these
calculations. Setup and inputs retain the earlier deterministic `SmallRng`
benchmark streams; these are reproducibility devices, not cryptographic setup
randomness or fixed-instance distance certificates. Fiat–Shamir challenges
come from the BLAKE3 transcript.

## Paper-sized interleaved results: 2^22

Measured on **16 October 2026** on an **AWS r7a.4xlarge**, AMD EPYC 9R14,
Linux x86-64, Rust 1.92.0 with `target-cpu=native`, inside Docker with an
8-CPU quota, 8 GiB memory cap, and 8 Rayon workers. Each row is one measured
sample after one warmup. Proofs exclude the public 32-byte initial root.
These are the updated paper's Table 3 measurements.

| Encoder | Commit (ms) | Prove (ms) | Verify (ms) | Proof (bytes) | Queries |
| --- | ---: | ---: | ---: | ---: | ---: |
| ERA | 547.936 | 404.666 | 61.858 | 4,010,824 | 836 |
| BaseFold | 432.036 | 410.508 | 30.499 | 4,177,416 | 927 |
| Brakedown | 1,012.292 | 421.097 | 147.110 | 6,438,728 | 1,974 |
| EA | 6,696.191 | 409.794 | 811.055 | 6,443,944 | 1,974 |

All four measured proofs verified and matched the earlier reference proofs
byte-for-byte. ERA has the smallest proof; BaseFold has the lowest commitment
and verification times. One sample does not establish timing variance.

The [AWS Docker run directory](artifact_results/2026-10-16-submission-validation/validation/paper22/)
contains the raw CSVs, logs and proof-validation record. The earlier Apple M2
three-sample measurements remain in
[the historical run directory](artifact_results/2026-10-14-prime-four/).
The 2^28 runs below used 16 workers, so the two sizes are not a fixed-worker
scaling experiment.

### Timing and proof-size definitions

| CSV field | What is measured |
| --- | --- |
| `setup_ms` | Graphs, coefficients, permutations, and code tables; once per process. |
| `commit_ms` | All row encodings, column hashing, and the retained Merkle tree. |
| `prove_ms` | Claimed evaluation, initial sumcheck, row folding, Fiat–Shamir, multiproof construction, and serialization. |
| `verify_ms` | Parsing, Fiat–Shamir, sumcheck checks, folded-message encoding, and all authentication/consistency checks. |
| `proof_bytes` | Exact byte-vector length, including header, claim, sumcheck messages, folded message, and authentication data. |
| `commitment_bytes` | Public initial root: 32 bytes, reported separately. |

Setup and input generation are outside the online timings. The public point,
setup, and initial root are outside the proof; the claimed value is included.
Add commit and prove times to compare total online prover work; a sum of stage
medians is not a measured total median. Samples repeat the same setup and
input. Warmups are omitted from CSV; verification failure aborts the run.

## Final full-size comparisons: 2^28

These are two separate comparisons, both on an on-demand AWS r7a.4xlarge
with 16 physical AMD EPYC 9R14 cores, 128 GiB advertised RAM, 16 Rayon workers,
Rust 1.92.0 and `target-cpu=native`. Each row is one measured sample after
one warmup. The common interleaved campaign is from October 15, 2026; the
optimized IOPP pair is from October 16. Measurements retain their original
source snapshots; later naming and documentation changes are recorded in
[validation](artifact/validation.md).

| Comparison / protocol | Commit (s) | Evaluation prove (s) | Total prover (s) | Verify (ms) | Proof (bytes) | Peak RSS (GiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Interleaved ERA | 29.575 | 18.132 | 47.707 | 1,046.157 | 40,541,384 | 58.817 |
| Interleaved BaseFold-code | 17.193 | 18.089 | 35.282 | 232.447 | 33,989,320 | 40.154 |
| Interleaved Brakedown | 86.297 | 18.200 | 104.496 | 1,367.456 | 49,624,040 | 41.149 |
| Interleaved EA | 937.552 | 18.172 | 955.723 | 10,610.487 | 49,622,792 | 48.560 |
| ERA codeswitching IOPP | 25.987 | 57.531 | 83.518 | 38.495 | 3,622,568 | 87.246 |
| Local recursive BaseFold IOPP | 18.767 | 18.579 | 37.346 | 56.703 | 6,004,040 | 44.277 |

The interleaved cases use `eta=8` for ERA and `eta=9` for the other codes;
they retain their original base encoders. The final ERA codeswitching case
instead uses `eta=6`, a tensor of `[2109,2048]` Brakedown codes with a
zero-padding terminal base, 888 initial queries, and a rate-1/8 BaseFold tail.
It has no RS base invocation. Its GKR has 25 layers and no intermediate
checkpoint commitments. The standalone BaseFold IOPP uses `eta=4`, rate 1/2,
and 1,290 queries. See the [full parameters](artifact/parameters.md) and
[executable plan](artifact/evaluation-plan.json).

The baseline is the local recursive implementation using Plonky3 dependencies;
it is not an optimized upstream BaseFold fork. Distance estimates remain
conditional, EA's distance is conjectured, and the compact verifier still
has an `O(n log k')` non-power-of-two tensor calculation. These and other
[scientific qualifications](artifact/changes.md) are part of the submission.

## Build, validate, and reproduce from the repository

The original interactive [exponent notebook](distance-analysis/exponent-behavior.ipynb)
is retained alongside the distance scripts. See its
[installation and launch instructions](distance-analysis/README.md); it uses
Python 3 and optional Jupyter/plotting dependencies.

Use Rust/Cargo **1.92.0** to match the local run (crate minimum 1.91), retain
`Cargo.lock`, and run from the repository root. Python 3.11+ with the pinned
NumPy/SciPy dependencies is required for distance calibration:

```bash
python3 -m venv /tmp/era-codes-analysis
source /tmp/era-codes-analysis/bin/activate
python3 -m pip install -r requirements-analysis.txt
rustup override set 1.92.0
cargo build --locked --release --bin interleaved_iopp --bin compare_iopps
cargo test --locked --lib
cargo test --locked --lib --no-default-features
python3 -B -m unittest discover -s distance-analysis -v
python3 -B -m unittest discover -s scripts -p test_large_iopp_plan.py -v
python3 -B scripts/calibrate_interleaved.py
cargo fmt --all --check
cargo clippy --locked --all-targets
```

The final container validation passed 204 default-feature and 203 serial library tests. Checks
cover encoder linearity and dense-matrix equivalence, RS interpolation,
honest proofs, wrong claims, tampering, and thread consistency. The distance
suite contains 18 tests; the proof-size model has two further tests. Existing repository Clippy warnings remain.

For the reduced-size functional checks (not security-calibrated timings):

```bash
THREADS=8 bash artifact/run.sh smoke results/smoke
```

For all four encoders with the paper's `2^22` / `eta=6` configuration:

```bash
THREADS=8 SAMPLES=1 bash artifact/run.sh paper22 results/paper22
```

Every new run defaults to one warmup and one measured sample. The table above uses the AWS Docker measured sample. Outputs include
raw CSVs, proofs, logs, environment information, proof checks and checksums;
choose a fresh output directory each time.

### Full-size reproduction on a 128 GiB Linux machine

The final AWS measurements used an on-demand r7a.4xlarge with 16 physical
AMD cores. The saved plan fixes 16 workers and runs only `2^28`, sequentially,
with one warmup and one sample per protocol:

```bash
RUSTFLAGS='-C target-cpu=native' cargo +1.92.0 build --locked --release \
  --bin interleaved_iopp --bin compare_iopps
RUSTFLAGS='-C target-cpu=native' bash artifact/run.sh full28 results/full28
```

See the [current full-size configuration](artifact/parameters.md),
[reference measurements](artifact/results.md), and
[Docker instructions](artifact/README.md). `full28` runs all six cases;
`interleaved28` runs the four common-interleaved cases and `codeswitch28`
runs the final ERA/BaseFold IOPP pair. These commands do not
require AWS or an SSH connection. The saved 112 GiB preflight allowance requires
a 128 GiB host; do not run them on a 16 GiB laptop.

Row encoding, column hashing, Merkle levels, sumcheck, and large vector
operations use Rayon. Inner encoders run sequentially when there are enough
outer rows to occupy the workers. `ERA_CHUNK_LEN` controls ERA's
prefix-scan chunks and defaults to 8192. RS base setup uses batch inversion
to avoid an inversion for every interpolation coefficient.

All four encoders produced byte-identical proofs with 1 and 32 workers at
`2^18` elements, `eta=2`, and 32 queries; see the
[functional check record](artifact_results/2026-10-14-prime-four/thread-checks.json).
These are functional checks on the local 8-core host, not 32-core performance
measurements.

## Implementation and historical notes

| File | Role |
| --- | --- |
| [`src/iopp_experiment.rs`](src/iopp_experiment.rs) | Shared encoder presets, setup IDs, and query counts. |
| [`src/commit/codes/`](src/commit/codes/) | Encoder implementations. |
| [`src/interleaved_iopp/fs.rs`](src/interleaved_iopp/fs.rs) | Serialized Fiat–Shamir argument. |
| [`src/bin/interleaved_iopp.rs`](src/bin/interleaved_iopp.rs) | Timing boundaries and proof output. |
| [`src/era_iopp.rs`](src/era_iopp.rs), [`src/basefold_iopp.rs`](src/basefold_iopp.rs) | Final codeswitching and recursive BaseFold IOPPs. |
| [`src/bin/compare_iopps.rs`](src/bin/compare_iopps.rs) | Full IOPP timing, proof output and profiling. |
| [`scripts/calibrate_interleaved.py`](scripts/calibrate_interleaved.py) | Current distance/setup recalibration. |
| [`artifact/run.sh`](artifact/run.sh) | Maintained validation and reproduction entry point. |

The [protocol audit](docs/artifact-audit.md) records earlier repairs to graph
orientation, linearity, transcript binding, randomization, and proof transport.
Superseded Bolt comparisons, development runs and duplicate payloads have
been removed from the active tree; see the [retention index](docs/repository-layout.md). Build output stays in the ignored `target/` directory.

Original project code is [MIT licensed](LICENSE); dependencies retain their
own licenses. The supplied paper is provided for evaluation and is not
relicensed under MIT. See [third-party notices](artifact/THIRD_PARTY.md).
