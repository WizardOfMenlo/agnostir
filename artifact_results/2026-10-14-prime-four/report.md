# agnostir: interleaved IOPP experiment

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

## Experiment setup

| Setting | Value |
| --- | --- |
| Message | `2^22 = 4,194,304` field elements |
| Interleaving | `eta = 6`: 64 contiguous rows of 65,536 elements |
| Field | secp256k1 scalar field, via `ark_secp256k1::Fr` |
| Commitment and transcript | BLAKE3, 32-byte digests, separate domains |
| Protocol | `interleaved-fs-v1`, setup recipe v3 |
| Benchmark seed | `2025` |
| Local sampling | 8 Rayon workers; 3 samples after 1 warmup |

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

These presets are calibrated only for row message length `2^16`; the CLI
requires `message-log - eta = 16`.

| CLI name | Parameters | Encoded row length | Distance used | Queries |
| --- | --- | ---: | ---: | ---: |
| `era` | Brakedown base `(alpha, inverse_rate, cn, dn)=(0.04,1.05,5,42)`; repetition 4 | 275,248 | 0.22037 | 836 |
| `basefold` | Symmetric random foldable code; inverse rate 2 | 131,072 | 0.20106 | 927 |
| `brakedown` | Inverse rate 2; `alpha=0.3`, `cn=14`, `dn=28` | 131,072 | 0.1 | 1,974 |
| `ea` | Inverse rate 2; `prob_multiplier=18` | 131,072 | 0.1 (inherited assumption) | 1,974 |

BaseFold's distance allocates a 102-bit total setup budget across 16 random
levels, giving per-level `lambda=106`. Brakedown's parameters pass Haböck's
numerical sufficient bound at every recursive level with the same total
setup budget. ERA uses base distance 0.0009 and a 102-bit CalcDist parameter;
its numerical distance candidate is rounded down to 0.22037. EA retains the
earlier distance assumption 0.1 and multiplier 18; no new finite-length EA
setup certificate is supplied.

The [calibration report](distance-analysis/current-results.json) records these
calculations. Setup and inputs retain the earlier deterministic `SmallRng`
benchmark streams; these are reproducibility devices, not cryptographic setup
randomness or fixed-instance distance certificates. Fiat–Shamir challenges
come from the BLAKE3 transcript.

## Measured results

Measured on **14 October 2026** (local time), on an **Apple M2, 8 cores
(4 performance + 4 efficiency), 16 GiB RAM**, macOS arm64, Rust/Cargo 1.92.0,
release profile, no explicit CPU flags, and 8 Rayon workers. Entries are
stage medians of three runs after one warmup. Proofs exclude the public
32-byte initial root.

| Encoder | Commit (ms) | Prove (ms) | Verify (ms) | Proof (bytes) | Queries |
| --- | ---: | ---: | ---: | ---: | ---: |
| ERA | 731.398 | 713.131 | 52.291 | 4,010,824 | 836 |
| BaseFold | 544.411 | 702.622 | 36.226 | 4,177,416 | 927 |
| Brakedown | 1,179.932 | 711.054 | 122.155 | 6,438,728 | 1,974 |
| EA | 8,524.394 | 763.297 | 617.407 | 6,443,944 | 1,974 |

All twelve measured proofs verified. ERA has the smallest proof in this
comparison; BaseFold has the lowest commitment and verification times.
These small local samples are not an AWS scaling study.

The [run directory](artifact_results/2026-10-14-prime-four/) contains
[unrounded summaries](artifact_results/2026-10-14-prime-four/summary.json),
raw CSVs, proofs, logs, metadata, calibration, source snapshot, and checksums.
All four rows were measured together using the same source and parameters.
The source archive includes uncommitted files. Older measurements used
different graph/distance presets and should not be mixed with these results.

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

## Build, validate, and reproduce

Use Rust/Cargo **1.92.0** to match the local run (crate minimum 1.91), retain
`Cargo.lock`, and run from the repository root. Python 3 with the pinned
NumPy/SciPy dependencies is required for distance calibration:

```bash
python3 -m venv /tmp/agnostir-analysis
source /tmp/agnostir-analysis/bin/activate
python3 -m pip install -r requirements-analysis.txt
cargo build --locked --release --bin interleaved_iopp
cargo test --locked --lib
cargo test --locked --lib --no-default-features
python3 -B -m unittest discover -s distance-analysis -v
python3 -B scripts/calibrate_interleaved.py
cargo fmt --all --check
cargo clippy --locked --all-targets
```

The rerun passed 189 default-feature and 188 serial library tests. Checks
cover encoder linearity and dense-matrix equivalence, RS interpolation,
honest proofs, wrong claims, tampering, and thread consistency. The distance
suite contains 16 tests. Existing repository Clippy warnings remain.

For a quick functional check (the query override is not security calibrated):

```bash
target/release/interleaved_iopp --code era --message-log 18 --eta 2 \
  --queries 32 --threads 8 --samples 1 --warmups 0 --csv
```

For the full four-row comparison, with a fresh output directory:

```bash
RAYON_NUM_THREADS=8 SAMPLES=3 \
  bash scripts/reproduce_artifact.sh results/interleaved-local full
```

This builds, runs checks and calibration, benchmarks the four encoders at
`2^22` elements / `eta=6`, verifies every proof, and saves the last proof per
encoder. The directory includes raw CSVs, logs, environment metadata,
`summary.json`, calibration output, a source snapshot containing uncommitted
and untracked files, and `SHA256SUMS`. A run refuses to reuse its output
directory. `--proof-out` also refuses to overwrite an existing file.

### Rerun on a 32-core AWS machine

```bash
RUSTFLAGS='-C target-cpu=native' RAYON_NUM_THREADS=32 SAMPLES=5 \
  bash scripts/reproduce_artifact.sh results/interleaved-aws32 full
```

Record the AWS instance type with the output. Check `lscpu`: 32 vCPUs need not
be 32 physical cores. Compare 1, 8, 16, and 32 workers in fresh directories,
keeping source, seed, flags, and parameters fixed. No AWS timing is reported
here.

Row encoding, column hashing, Merkle levels, sumcheck, and large vector
operations use Rayon. Inner encoders run sequentially when there are enough
outer rows to occupy the workers. `AGNOSTIR_CHUNK_LEN` controls ERA's
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
| [`src/iopp_experiment.rs`](src/iopp_experiment.rs) | Three shared presets, setup IDs, and query counts. |
| [`src/commit/codes/`](src/commit/codes/) | Encoder implementations. |
| [`src/interleaved_iopp/fs.rs`](src/interleaved_iopp/fs.rs) | Serialized Fiat–Shamir argument. |
| [`src/bin/interleaved_iopp.rs`](src/bin/interleaved_iopp.rs) | Timing boundaries and proof output. |
| [`scripts/calibrate_interleaved.py`](scripts/calibrate_interleaved.py) | Current distance/setup recalibration. |

The [protocol audit](docs/artifact-audit.md) records earlier repairs to graph
orientation, linearity, transcript binding, randomization, and proof transport.
Older six-encoder tables and Bolt reports are historical and do not describe
the current comparison. Build output stays in the ignored `target/` directory.

Substantial implementation and documentation used Codex assistance; see
[AI_DISCLOSURE.md](AI_DISCLOSURE.md). No public artifact submission is claimed.
