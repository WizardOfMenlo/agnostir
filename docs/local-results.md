# Local measurements — 14 October 2026

These are measurements of the corrected implementations, not a reproduction of
the paper's historical tables or a certified 100-bit comparison. Read
[artifact-audit.md](artifact-audit.md) for the construction changes, parameter
assumptions, and unresolved security and implementation questions.

Host: Apple M2, 8 physical/logical cores, 16 GiB RAM, macOS arm64. Rust/Cargo
1.92.0, release profile, no `target-cpu` override, 8 Rayon workers, seed 2025.
Each entry is the median of three measured runs after one warmup. Every proof
was verified. Times are milliseconds. Setup is measured once separately.

## Complete protocols at 2^22 elements

| Protocol | Setup | Commit | Prove | Verify | Serialized proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Corrected ERA IOPP | 833.952 | 1,471.067 | 3,226.041 | 269.528 | 2,893,224 |
| Local recursive BaseFold | 42.235 | 538.031 | 764.937 | 24.850 | 2,965,224 |

ERA's proof is 2.43% smaller here. Its evaluation prover is 4.22 times slower;
the sum of median commitment and evaluation-prover times is 4.697 seconds
versus 1.303 seconds. This does not demonstrate a prover-time improvement.
The local BaseFold implementation includes interleaving and early termination,
but is not the requested modified upstream Plonky3 implementation. ERA uses
the documented finite-size adaptation in the audit, including two independent
multiplier families and the exact finite RS base-code distance.

## Local thread scaling

The same final binary was also run with one worker, three samples, and one
warmup. No other Codex compute jobs ran during the final scaling measurement.

| Protocol | 1-worker commit | 8-worker commit | 1-worker prove | 8-worker prove | Prover speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| Corrected ERA | 8,002.882 | 1,471.067 | 12,413.587 | 3,226.041 | 3.85x |
| Local BaseFold | 2,943.303 | 538.031 | 2,441.351 | 764.937 | 3.19x |

One-worker verification medians were 318.429 ms for ERA and 23.897 ms for
BaseFold. Eight workers do not improve every component. A separate 32-worker
smoke test verified both protocols and the interleaved argument on this same
8-core host; its saved 145,000-byte interleaved proof exactly matches the CSV
size. It is not evidence of scaling to 32 physical cores. The excluded preliminary
scaling run and its exclusion reason are retained in the raw bundle.

The scaling investigation identified parallel reductions over tiny Merkle
columns as unnecessary overhead. With a sequential cutoff for small dot
products and folds, eight-worker verification improved from about 307 to 270 ms
for ERA and 66 to 25 ms for local BaseFold, with unchanged proof sizes. These
cutoffs are practical defaults, not an exhaustive optimization search.

## Interleaved experiment at 2^22 elements, interleaving 64

| Encoder | Queries | Commit | Prove | Verify | Serialized proof bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| Brakedown | 1,974 | 813.373 | 690.072 | 96.272 | 6,429,096 |
| EA | 1,974 | 7,473.722 | 690.544 | 593.401 | 6,441,704 |
| BaseFold | 869 | 526.392 | 677.768 | 32.901 | 4,046,664 |
| ERA | 804 | 677.600 | 689.640 | 50.081 | 3,936,296 |
| Bolt-min (adapted) | 4,537 | 695.659 | 902.238 | 85.948 | 11,621,288 |
| Bolt-max (adapted; assumed distance) | 19,891 | 182.287 | 927.059 | 255.222 | 39,119,368 |

These are encoders within the same interleaved argument. The BaseFold row is
different from the recursive protocol above. Query counts use the CLI's
inherited, conditional distance tables; those tables still require validation
against the corrected encoders. Do not cite the rows as proven equal-security
performance results.

The Bolt-min row was added in a separate run using the same field, hash,
serialized protocol, dimensions, and timing definitions. Its sketched code
uses BaseFold for the syndrome in place of binary-field RS; see the
[adaptation, calibration, and scaling results](bolt-adaptation.md). Its raw
records are in `artifact_results/2026-10-14-bolt-adapted/`, separately from the
original four-row snapshot.

Bolt-max was measured separately on the same host with the same field,
protocol, dimensions, seed, and timing definitions. Its unproved prime-field
kernel-distance assumption 0.013 becomes 0.0104 after normalizing to the full
codeword, giving 19,891 queries. See the [construction, limitations, and worker
checks](bolt-max-adaptation.md) and raw records in
`artifact_results/2026-10-14-bolt-max/`.

## Reproduction and measurement boundaries

```sh
RAYON_NUM_THREADS=8 SAMPLES=3 \
  bash scripts/reproduce_artifact.sh results/local-new full
```

The byte count is the actual proof vector length. Proving includes computation
of the evaluation, Fiat–Shamir, intermediate commitments, Merkle multiproofs,
and canonical serialization. Verification includes parsing and all checks.
Initial and preprocessing commitment roots and the evaluation point are public
inputs outside the proof. Setup and input generation are outside the reported
commit/prove/verify intervals. Setup includes ERA's indexer commitment.

Raw CSVs, calibration, environment, logs, source snapshots, and checksums are
under `artifact_results/2026-10-14/`. `source.tar.gz` is the source snapshot
captured by the measured run; `source-final.tar.gz` additionally includes the
final documentation and packaging updates. The Rust implementation is identical
in these two snapshots. `paper.patch` records edits to the sibling paper; it is
not a revised final paper or an archival paper PDF.

No AWS run or Docker execution is represented by these measurements.
