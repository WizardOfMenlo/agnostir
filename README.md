# agnostir: interleaved IOPP experiment

This experiment compares **Brakedown, Expand-Accumulate (EA), BaseFold, ERA,
Bolt-min, and Bolt-max as encoders inside the same interleaved evaluation
argument**. All rows use the secp256k1 scalar field, BLAKE3-256, Fiat–Shamir,
and the same proof serializer and verifier. Proof sizes are measured from the
actual serialized proofs, and every timed proof is verified.

The results below replace the historical interactive timings and analytical
proof-size estimates. **The query counts are conditional on distance and setup
assumptions; this is not yet a certified equal-security, 100-bit comparison.**
In particular, adapted Bolt-max has an unproved prime-field distance assumption.

## Experiment setup

The prover commits to a message and proves its multilinear evaluation at a
public point. For the reported instance:

| Setting | Value |
| --- | --- |
| Message | `2^22 = 4,194,304` field elements |
| Interleaving | `eta = 6`: 64 contiguous rows |
| Message per row | `2^16 = 65,536` elements |
| Field | secp256k1 **scalar** field; canonical 32-byte elements |
| Commitment and transcript hash | BLAKE3, 32-byte digests, separate domains |
| Benchmark seed | `2025` |
| Query model | `q = ceil(-300 / log2(1 - delta))` |
| Local workers | 8 Rayon workers |
| Sampling | Median of 3 runs after 1 warmup, for each stage |

The experiment has three measured stages:

1. **Commit:** encode each row, hash columns, and build the retained Merkle tree.
2. **Prove:** compute the claimed evaluation, run an initial sumcheck to obtain
   a transcript-derived random evaluation point, fold the message rows, and
   serialize the folded message and Merkle multiproof for sampled columns.
3. **Verify:** parse the proof, replay Fiat–Shamir, check the sumcheck, encode
   the folded message, authenticate the sampled columns, and check consistency.

The initial sumcheck is included so the row fold is randomized even when the
public evaluation point is Boolean. The transcript binds the statement,
commitment, setup identifier, dimensions, query count, and protocol version.
The verifier rejects malformed field elements, truncated proofs, and trailing
bytes. Column queries are sampled uniformly with replacement using rejection
sampling. Repeated query columns and shared Merkle siblings are deduplicated
by the serializer.

### Encoder presets

These are the settings at row message length `2^16`. Encoded row lengths are
exact; target inverse rates can be affected by integer rounding.

| CLI name | Encoder parameters | Encoded row length | Assumed full-code distance | Queries |
| --- | --- | ---: | ---: | ---: |
| `brakedown` | Target inverse rate 2; `alpha=0.3`, `cn=10`, `dn=20` | 131,072 | 0.1 | 1,974 |
| `ea` | Inverse rate 2; `prob_multiplier=18` | 131,072 | 0.1 | 1,974 |
| `basefold` | Inverse rate 2 (`log_rate=1`) | 131,072 | 0.213 | 869 |
| `era` | Brakedown base: target inverse rate 1.05, `alpha=0.04`, `cn=5`, `dn=42`; repetition 4 | 275,248 | 0.228 | 804 |
| `bolt-min` | Degree-16 weighted sketch; compression 8; rate-1/2 BaseFold syndrome code | 81,920 | 0.0448 | 4,537 |
| `bolt-max` | Degree-8 all-one sketch; compression 8; rate-1/2 BaseFold syndrome code | 81,920 | 0.0104 (additional assumption) | 19,891 |

ERA uses two independently sampled nonzero multiplier families and two
permutations. Both Bolt variants encode `x || BaseFold(Hx)`, with 8,192 syndrome
symbols and 16,384 parity symbols per row. They adapt Bolt's sketched-code
construction to this field: BaseFold replaces the binary-field additive
Reed–Solomon syndrome code. Bolt-max uses ordinary field addition, not XOR.
These rows measure the adapted encoders within our interleaved argument.

For Bolt-min, the conditional outer distance 0.224 is divided by 5 because
parity occupies one fifth of the complete word. For Bolt-max, the assumed
kernel distance 0.013 is divided by the inverse rate 1.25, giving 0.0104.
The binary LDPC analysis does not establish that prime-field kernel bound.
See the [Bolt-min analysis](docs/bolt-adaptation.md) and
[Bolt-max assumptions](docs/bolt-max-adaptation.md) for the derivations and limits.

The deterministic seed reproduces code setup, message, and public point.
Fiat–Shamir challenges come from the transcript, not the seeded RNG. A fixed
benchmark seed does not certify the random-setup distribution or its failure
probability. The inherited code distances, their applicability to the corrected
encoders, and the composed protocol security still require review.

## Measured results

Measured on **14 October 2026**, on an **Apple M2 with 8 cores and 16 GiB RAM**,
macOS arm64, Rust/Cargo **1.92.0**, release profile, **no explicit CPU flags**,
and 8 Rayon workers. All rows use the setup above. Times are stage medians in
milliseconds; proof sizes are exact bytes, excluding the public 32-byte root.

| Encoder | Commit (ms) | Prove (ms) | Verify (ms) | Serialized proof (bytes) | Queries |
| --- | ---: | ---: | ---: | ---: | ---: |
| Brakedown | 813.373 | 690.072 | 96.272 | 6,429,096 | 1,974 |
| EA | 7,473.722 | 690.544 | 593.401 | 6,441,704 | 1,974 |
| BaseFold | 526.392 | 677.768 | 32.901 | 4,046,664 | 869 |
| ERA | 677.600 | 689.640 | 50.081 | 3,936,296 | 804 |
| Bolt-min (adapted) | 695.659 | 902.238 | 85.948 | 11,621,288 | 4,537 |
| Bolt-max (adapted; assumed distance) | 182.287 | 927.059 | 255.222 | 39,119,368 | 19,891 |

The Bolt rows were added in separate runs on the same host with the same
field, hash, dimensions, seed, and timing boundaries. These small local samples
are not a controlled AWS scaling study. For example, Bolt-min commitment
samples ranged from 630.132 to 891.950 ms. No AWS measurements are reported here.

Raw CSVs, logs, environment metadata, source snapshots, and checksums are saved in:

- [Original four encoder runs](artifact_results/2026-10-14/) (`interleaved-*.csv`).
- [Bolt-min run](artifact_results/2026-10-14-bolt-adapted/), including its saved proof.
- [Bolt-max run](artifact_results/2026-10-14-bolt-max/), including its saved proof.

Use the CSVs for unrounded timings and the source archives to recover the
measured implementation, including changes not captured by a Git commit.
Historical root-level reports and `bench_logs/` are not these serialized results.
The conjectured-ERA variant is available through `--code conjectured-era`, but
has no proven distance guarantee and is not included in this results table.

### Timing and proof-size definitions

| CSV output | What is measured |
| --- | --- |
| `setup_ms` | Code generation, including graphs, permutations, and coefficients; measured once per process. |
| `commit_ms` | Row encoding, column hashing, and the complete retained Merkle tree. |
| `prove_ms` | Claimed evaluation, sumcheck, row folding, Fiat–Shamir, multiproof construction, and serialization. |
| `verify_ms` | Parsing, Fiat–Shamir replay, sumcheck checks, folded-message encoding, and all column/authentication checks. |
| `proof_bytes` | Exact emitted byte-vector length: header, claimed value, sumcheck messages, folded message, and authentication data. |
| `commitment_bytes` | Public initial Merkle root: 32 bytes, reported separately. |

Setup and message/point generation are outside commit/prove/verify. The public
setup, evaluation point, and initial root are outside the proof. The claimed
value is transmitted in the proof and checked against the public claim. Query
indices are derived from the transcript and need no wire bytes. Divide
`proof_bytes` by 1024 for KiB. Add commitment and proving times when comparing
total online prover work; a sum of stage medians is not a measured total median.
Warmups are omitted from CSV. Verification failure aborts the run.

## Build and check

Run all commands from the repository root. Use Rust/Cargo **1.92.0** to match
the measurements (edition 2024; crate minimum 1.91). Keep `Cargo.lock` and use
`--locked`: several Plonky3 dependencies are pinned to a Git revision. The first
build needs network access to fetch dependencies; cached builds can add
`--offline`. Python 3 is needed for the summary script; it uses only the standard
library. The commands below assume Bash.

```bash
cargo build --locked --release --bin interleaved_iopp
cargo test --locked --lib
cargo test --locked --lib --no-default-features
cargo fmt --all --check
cargo clippy --locked --all-targets
```

Default features `parallel` and `cli` are required by the experiment binary.
The latest validation passed 189 default-feature and 188 serial library tests.
Existing repository Clippy warnings remain. Encoder checks include linearity,
systematic coordinates and dense-matrix equivalence; protocol checks include
honest proofs, tampering, wrong public claims, and thread consistency.

## Reproduce the interleaved comparison

### Quick functional check

```bash
target/release/interleaved_iopp \
  --code era --message-log 14 --eta 2 --seed 2025 \
  --queries 32 --threads 8 --samples 1 --warmups 0 --csv
```

Expect one CSV row with `accepted=true`. This small query override checks
execution only and has no security calibration. Substitute any of the six code
names above to check another encoder. `--help` lists all options.

### Full table, raw CSVs, and saved proofs

Leave `RUSTFLAGS` unset to match the local build. The following runs only the
six interleaved encoder configurations, with 8 workers and 3 samples by default.
It creates a fresh timestamped directory and saves the last proof for each code.

```bash
set -euo pipefail
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-8}"
export AGNOSTIR_CHUNK_LEN="${AGNOSTIR_CHUNK_LEN:-8192}"
samples="${SAMPLES:-3}"
run_dir="results/interleaved-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p results
mkdir "$run_dir"

{
  date -u
  git rev-parse HEAD
  git status --short
  rustc -vV
  cargo -V
  uname -a
  if command -v lscpu >/dev/null; then lscpu; fi
  if command -v sw_vers >/dev/null; then sw_vers; fi
  if [[ "$(uname -s)" == Darwin ]]; then
    sysctl machdep.cpu.brand_string hw.physicalcpu hw.logicalcpu hw.memsize || true
  fi
  printf 'threads=%s\nsamples=%s\nwarmups=1\nseed=2025\nRUSTFLAGS=%s\nchunk_len=%s\n' \
    "$RAYON_NUM_THREADS" "$samples" "${RUSTFLAGS-}" "$AGNOSTIR_CHUNK_LEN"
} > "$run_dir/metadata.txt" 2>&1

git diff --binary HEAD > "$run_dir/source.patch"
tar --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' \
  -czf "$run_dir/source.tar.gz" \
  Cargo.toml Cargo.lock src benches scripts distance-analysis docs README.md AI_DISCLOSURE.md

cargo build --locked --release --bin interleaved_iopp > "$run_dir/build.log" 2>&1
for code in brakedown ea basefold era bolt-min bolt-max; do
  target/release/interleaved_iopp \
    --code "$code" --message-log 22 --eta 6 --seed 2025 \
    --threads "$RAYON_NUM_THREADS" --samples "$samples" --warmups 1 \
    --proof-out "$run_dir/$code.proof" --csv \
    > "$run_dir/interleaved-$code.csv" 2> "$run_dir/interleaved-$code.log"
done
python3 scripts/summarize_artifact.py "$run_dir"/interleaved-*.csv \
  > "$run_dir/summary.json"
printf 'Results: %s\n' "$run_dir"
```

`summary.json` reports each stage's median, minimum, and maximum, along with
proof bytes and acceptance. The summary script rejects failed verification or
inconsistent proof lengths within a configuration. `.log` files record the
assumed distance and security qualifications. `--proof-out` refuses to overwrite
an existing file. Samples repeat the same deterministic instance, rather than
sampling new code setups. For the same source, seed, and parameters, proof bytes
are deterministic; timing will vary with the machine and system load.

### Rerun on a 32-core AWS machine

Before executing the full-table block above on the AWS host, set:

```bash
export RUSTFLAGS='-C target-cpu=native'
export RAYON_NUM_THREADS=32
export SAMPLES=5
```

The block rebuilds on that host and applies the same flags to all six rows.
Record the instance type and CPU topology with the results. Use `lscpu` to
check physical cores versus logical CPUs/vCPUs: 32 Rayon workers do not
necessarily mean 32 physical cores. The local run fit on a 16 GiB machine;
that is not a peak-memory bound or a measured AWS requirement.

Repeat into fresh directories with 1, 8, 16, and 32 workers to measure scaling.
Keep source, seed, dimensions, query counts, CPU flags, and chunk length fixed,
and avoid competing heavy workloads. Encoding parallelizes across message
rows and uses sequential inner encoders when there are enough rows to occupy
the workers. Column hashing, Merkle levels, and sufficiently large arithmetic
operations also use Rayon; small operations use sequential cutoffs.
`AGNOSTIR_CHUNK_LEN` controls ERA's parallel prefix scans and defaults to 8192.

Full-size Bolt-min and Bolt-max proofs matched between 8 and 32 workers;
Bolt-max also matched with one worker. The 32-worker runs used the local
8-core host. Those are functional checks, not evidence of performance on
32 physical cores.

## Implementation map and further notes

| File | Role in this experiment |
| --- | --- |
| [`src/bin/interleaved_iopp.rs`](src/bin/interleaved_iopp.rs) | CLI, timing boundaries, verification, CSV and proof output. |
| [`src/iopp_experiment.rs`](src/iopp_experiment.rs) | Shared encoder presets, deterministic setup, distance assumptions, and query counts. |
| [`src/interleaved_iopp/fs.rs`](src/interleaved_iopp/fs.rs) | Fiat–Shamir evaluation argument and initial randomizing sumcheck. |
| [`src/proof.rs`](src/proof.rs) and [`src/proof/`](src/proof/) | Canonical transport, transcript, sumcheck, and Merkle multiproofs. |
| [`src/commit/codes/`](src/commit/codes/) | Encoder implementations, including both Bolt adaptations. |
| [`benches/iopp_bench.rs`](benches/iopp_bench.rs) | Optional Criterion measurements of the same serialized protocol. |
| [`scripts/summarize_artifact.py`](scripts/summarize_artifact.py) | CSV validation and stage summaries. |
| [`scripts/calibrate_bolt.py`](scripts/calibrate_bolt.py) | Bolt-min ideal-ensemble calculation and separate Bolt-max assumptions. |

The historical interleaved experiment needed corrections to Brakedown's graph
orientation and linearity, randomization at arbitrary evaluation points,
Fiat–Shamir binding, hash domain separation, and actual proof transport.
The [audit](docs/artifact-audit.md#findings-and-implemented-repairs) records the
findings; the successful implementation tests do not establish the remaining
code-distance or composed soundness claims.

Substantial code and documentation were produced with Codex assistance; see
[AI_DISCLOSURE.md](AI_DISCLOSURE.md). The repository's archival license has not
yet been selected. No public artifact submission or AWS run is claimed here.
