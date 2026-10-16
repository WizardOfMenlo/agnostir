# ERA proof size: paper estimate versus AWS serialization

The large discrepancy is principally a parameter mismatch. The paper estimator
also needs corrections to represent the implemented virtual-oracle protocol.
The current AWS wire-size model closely predicts the actual serialized proof.

| Quantity | Paper's worked example | New AWS smaller-proof case |
| --- | ---: | ---: |
| Total input elements | 2^32 | 2^28 |
| Initial interleaving rows | 64 | 256 |
| ERA row message length | 2^26 | 2^20 |
| Codeswitch output message length k' | 2^25 | 2^15 |
| Output inverse rate | 8 | 8 |
| Terminal message length | 2^12 | 2^12 |
| Initial ERA queries | 830 | 887 |
| Terminal BaseFold queries | 154 | 147 |
| Index / online stack heights | 33 / 25 | 647 / 377 |
| Proof bytes | 4,013,728 estimated | 17,668,488 measured |

In the paper eta denotes the number of interleaved rows; the CLI's `--eta`
denotes its base-two logarithm. The table uses row counts to avoid ambiguity.

The saved `iopp_k_sweep_summary.csv` also has a 2^28 row: 3,300,576 estimated
bytes, 32 initial rows, and message exponents `(23,23)` for the ERA and output
codes. Thus the saved sweep at the actual AWS input size also used much larger
output messages and fewer interleaved rows. This is an older estimator result,
not a freshly calibrated feasible preset: the current square-tensor setup
requires an even row-message exponent and a strictly smaller output exponent,
which that `(23,23)` tuple does not satisfy. It also differs from the paper's
worked 2^32 tuple `(26,25)`; the sweep and worked example should not be treated
as a single checked parameter record.

## Why the AWS parameter choice produces more bytes

The paper optimizes interleaving, k', output rate and termination together.
The AWS planner inherited output_log = 15, output_log_rate = 3 and
terminal_log = 12 from the small local preset, and optimized interleaving under
those fixed settings. The later sparse-base search also varied the base-code
parameters, but retained the same fixed output settings. These were restricted
searches, not joint optimization of the parameters in the paper.

Each auxiliary vector is split into chunks of k' field elements. Smaller k'
therefore makes taller stacks, all of whose entries must be opened at every
queried source coordinate. For the measured 2^28, eta = 8 configuration, the
expected serialized breakdown is:

| Component | Expected bytes |
| --- | ---: |
| Initial ERA column field elements | 7,265,658 |
| Initial ERA authentication hashes | 328,427 |
| First BaseFold source-pair field elements | 9,628,428 |
| First BaseFold source authentication hashes | 83,890 |
| Remaining BaseFold proof | 220,018 |
| Other messages and framing | 132,968 |
| **Total expectation** | **17,659,389** |
| **Actual serialized proof** | **17,668,488** |

The expectation differs from the measured proof by 0.0515%; distinct query
counts and shared authentication nodes depend on the transcript. Opened field
values dominate the result.

Holding the current ERA code, interleaving, output rate and termination fixed,
and recalibrating terminal queries for each k', gives:

| k' | Index / online rows | Terminal queries | Expected proof (decimal MB) | Modeled peak with margin (GiB) |
| --- | ---: | ---: | ---: | ---: |
| 2^15 | 647 / 377 | 147 | 17.659 | 78.887 |
| 2^16 | 326 / 190 | 148 | 12.939 | 78.974 |
| 2^17 | 165 / 96 | 150 | 10.608 | 79.126 |
| 2^18 | 85 / 49 | 151 | 9.461 | 79.472 |
| 2^19 | 43 / 25 | 153 | **8.909** | **79.841** |

These alternatives have not been benchmarked. Their memory figures use the
existing conservative allocation model, including a 15% margin, rather than
measured RSS. The table already shows that the previous 17.668 MB proof was
not the smallest predicted proof within the broader parameter space.

## Issues in the old estimator

The checked-in `proof-size-estimate.py` reproduces the paper's 4,013,728 bytes
exactly for its worked example: 72,418 field elements plus 53,011 hashes,
32 bytes each. There is no arithmetic error in that final addition.

However, `compute_codeswitch_proof_size` charges q times the combined source
stack height, while `compute_basefold_contribution` charges two scalar values
per query in every round, including the first. The implemented BaseFold
protocol starts from a virtual linear combination of committed stacks.
Its first fold opens both coordinates of each pair from every source row.
If H is the combined source height, the first source values cost 2qH field
elements before deduplication, rather than qH + 2q.

At the paper's H = 33 + 25 = 58 and q = 154, this misses 8,624 field elements,
or 275,968 bytes. The virtual oracle also has no independent Merkle tree, so
its first-round authentication cannot be counted as an ordinary additional
scalar-oracle tree. If a separately committed combined oracle was intended,
its commitment, consistency test and security budget must be specified; that
is not the current virtual-oracle backend.

There is also a protocol difference: the paper counts one multiplier family,
whereas the implementation uses two independent multiplier vectors. Thus the
index height is g + 4*ell rather than g + 3*ell. At the worked example's
dimensions this means 43 index rows instead of 33. This needs reconciliation
with the paper's construction and analysis, rather than silently removing the
extra family from the implementation.

Finally, the paper uses a heuristic Merkle hash count and older query-budget
choices. Its hash approximation overestimates parts of the current batched
multiproof and offsets some of the omitted field values. At its worked-example
dimensions, using the current protocol's two multiplier families and wire model
but retaining its 830/154 query counts, the expected proof is about **4.089 MB**.
This is a byte-count counterfactual, not a new measured result or security
calibration. The proximity of 4.089 MB and 4.014 MB does not validate the old
component accounting.

Conversely, feeding the actual AWS dimensions, distances and 104-bit query
budget into the old estimator gives **12.329 MB**, versus **17.659 MB** in the
validated model. The errors do not cancel consistently across parameter choices.

## Consequence

Use the current serialized-size accounting for a joint search over
interleaving, k', output rate and termination under the memory budget before
claiming an optimized paper comparison. Reconcile the multiplier-family and
first-fold accounting differences before updating the paper's estimate or plot.
This audit does not edit the paper or change the benchmark implementation.

The relevant sources are the paper's `sections/evaluation.tex`, its
`figures/CodeswitchOracles.tex`, `proof-size-estimate.py`,
`scripts/plan_large_iopp.py`, and `src/basefold_iopp.rs`.
The [audit evidence](../artifact_results/2026-10-15-proof-size-audit/) records
the calculations and source hashes. Reproduce the model calculations with
`python3 -B artifact_results/2026-10-15-proof-size-audit/reproduce.py`.
