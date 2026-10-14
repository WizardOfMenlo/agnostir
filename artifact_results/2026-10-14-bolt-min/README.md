# Bolt-min comparison

The artifact now includes the reference implementation's degree-16 `bolt32`
configuration as **bolt-min**, using an independent adapter in
[`comparisons/bolt-min`](../comparisons/bolt-min/). It pins
[`bcc-research/bolt-rs`](https://github.com/bcc-research/bolt-rs/tree/3832e47b24e7b3e10525c9c5bcfc1cfe66d525f2)
at `3832e47b24e7b3e10525c9c5bcfc1cfe66d525f2`. Upstream is MIT OR Apache-2.0;
the dependency retains its license files and is not copied or modified here.
The paper is [Gurkan, Novakovic, Rothblum, 2026/310](https://eprint.iacr.org/2026/310).

## Scope and parameters

This is a **commitment-only, different-field baseline**. The upstream Bolt
benchmark implements the encoder and Merkle commitment. Its recursive proof
benchmark is Ligerito, and cannot be reported as a serialized Bolt evaluation
proof. We therefore report no Bolt proving time, verifier time, query budget,
or proof size. The JSON summary writes these as `null`, not zero. No 100-bit
soundness claim is attached to this commitment benchmark.

The adjacent Canopy implementation was also inspected: it implements a modified
Bolt-max/public-H construction over GF(2^256). It is not used for this Bolt-min
row. A complete Bolt evaluation argument remains separate implementation work.

Parameters follow upstream `bench_bolt32`: nonzero GF(2^32) coefficients,
left degree 16, right degree 128, compression 8, rate-1/2 additive RS on the
syndrome. The graph is the upstream biregular configuration model, including
parallel edges. The systematic message is concatenated with the encoded
syndrome, giving inverse rate 1.25. Setup and input RNGs are deterministic
benchmark fixtures, not a security-certified setup distribution.

For comparison with the local experiment, we change the reference's hardcoded
`2^30`, width-128 geometry to `2^22`, width 64: 65536 message positions,
8192 syndrome positions, 16384 parity positions, and 81920 committed leaves.
Each leaf contains 64 four-byte elements. This input is 16 MiB, versus 128 MiB
for the same number of secp256k1 scalars. These are neither the authors'
published M4 CPU/GPU timings nor a same-field speed comparison.

The adapter invokes upstream's optimized deferred-reduction sparse multiply,
paired RS FFT, and zero-copy Merkle construction. SHA-256 is the upstream
default; BLAKE3 is an additional supported upstream hash selection. No GPU
feature is enabled. Rayon workers are configured explicitly. The upstream
checkout's native-CPU Cargo configuration is not inherited by a dependency;
set `RUSTFLAGS` explicitly to request native compilation on the measurement
host. Host endianness is checked because upstream hashes in-memory bytes.

## Local measurements

Apple M2, 8 physical/logical cores, 16 GiB RAM; Rust 1.92.0 release, no explicit
CPU flags, 8 Rayon workers, seed 2025, three samples after one warmup. The Cargo
lockfile records all dependency versions. Raw records and the exact measured
adapter source are in [`artifact_results/2026-10-14-bolt-min`](../artifact_results/2026-10-14-bolt-min/).

| Variant | Commit median (ms) | Min–max (ms) | Full evaluation proof |
| --- | ---: | ---: | --- |
| bolt-min / SHA-256 | 13.505 | 13.334–14.035 | Unavailable |
| bolt-min / BLAKE3 | 17.256 | 16.570–19.417 | Unavailable |

Commit includes output allocation and input copy, sparse encoding, RS encoding,
and all retained Merkle levels. Setup and input generation are outside timing.
This differs slightly from upstream's quick benchmark, which allocates and
initializes its matrix before starting the timer. Each commitment is checked
outside the timed interval, with two complete parity vectors recomputed using
scalar sparse arithmetic and single-vector RS, plus authenticated openings from
the systematic and parity regions and rejection of a modified opening.

Unit validation compares every encoded element at small dimensions for widths
2, 16, and 64 with 1 and 4 workers, and checks both hashes. This checks the
adapter and optimized encoding path; it does not prove the LDPC ensemble's
minimum distance or Bolt protocol soundness. The 32-worker execution check runs
on the same 8-core host and is not an AWS scaling result.

## Reproduction

```sh
# First build requires network access to the pinned Git revision and crates.
RAYON_NUM_THREADS=32 SAMPLES=5 \
  bash scripts/reproduce_bolt.sh results/bolt-aws-32

# Request native compilation explicitly, just as for the other experiments.
RUSTFLAGS='-C target-cpu=native' RAYON_NUM_THREADS=32 SAMPLES=5 \
  bash scripts/reproduce_bolt.sh results/bolt-aws-native-32

# Small execution check; not security calibrated.
MESSAGE_LOG=14 ETA=2 RAYON_NUM_THREADS=32 SAMPLES=1 \
  bash scripts/reproduce_bolt.sh results/bolt-smoke-32
```

`MESSAGE_LOG`, `ETA`, `SEED`, `WARMUPS`, `SAMPLES`, and `RAYON_NUM_THREADS`
are configurable. The script creates a new output directory, runs tests,
builds once, runs the two hashes sequentially, and records metadata, source,
raw CSVs, and JSON medians/min/max. It never substitutes modeled proof sizes.
The main `reproduce_artifact.sh` now includes this separate result directory by
default; `INCLUDE_BOLT=0` skips it when reproducing the earlier experiment alone.

The paper table is updated with the corrected interleaved results and a separate
Bolt-min commitment panel. Its dashes explicitly mean unmeasured evaluation
metrics. The historical October 14 interleaved source snapshots/results remain
unchanged; this addition has its own result directory.
