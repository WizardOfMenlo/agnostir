# ERA codeswitching with a sparse Brakedown tensor base

The previous 2^28 configuration used a dense systematic RS encoder as its entire
inner code: its Brakedown recursion stopped immediately. The tensor encoding
therefore performed 28,744,089,600 field multiplications across the input,
before ERA's outer permutations and accumulators. This was quadratic work in
the inner message length, even though the code was constructed through the
Brakedown API.

This experiment uses sparse Brakedown recursion and **no Reed–Solomon calls**.
It applies to the codeswitching IOPP. The common interleaved experiment and the
historical measurements in [the original AWS report](aws-r7a4x-n28.md) are unchanged.

## Parameters and distance

The field is the secp256k1 scalar field; the hash is BLAKE3. GKR has no checkpoints.
There are 2^28 input elements, interleaved into 256 rows of 2^20 elements each
(eta = 8). Each row uses the tensor square of the following inner code:

| Parameter | Value |
| --- | ---: |
| Inner message / block length | 1,024 / 1,116 |
| Brakedown alpha | 0.058 |
| Nominal inverse rate | 1.09 |
| A degree / B degree | 7 / 16 |
| A dimensions | 1,024 by 60 |
| Recursive terminal code | [65, 60, 1], zero-padded identity |
| B dimensions | 65 by 27 |
| Conservative inner relative distance | > 0.00754 |
| Tensor relative distance used | 0.0000568516 |
| Tensor message / block length | 1,048,576 / 1,245,456 |
| ERA repetition | 4 |
| ERA block length / actual rate | 4,981,824 / approximately 0.21048 |
| ERA numerical relative distance | 0.2164162427, rounded down to 0.216416 |
| ERA proximity queries | 887 |

The terminal code is simply `x -> (x, 0, 0, 0, 0, 0)`. Its exact absolute distance
is one, and its relative distance 1/65 exceeds 0.00754. Haböck's
[Section 3, Proposition 1](https://eprint.iacr.org/2023/769) allows an arbitrary
terminal linear code of sufficient relative distance. It does not require RS.
The implementation and analysis explicitly distinguish this distance from the
RS distance of `N-k+1`.

For this ERA block length, reversing the field-size and gamma constraints gives
a tensor-distance feasibility threshold of about 0.0000515471, or inner distance
about 0.0071796. The search adds a 5% margin to the inner distance and rounds up
to 0.00754, then checks the final ERA distance explicitly. This is a feasible
choice, not a claim of the globally minimum inner distance.

The Brakedown check covers every required support size at every actual rounded
recursive level. The selected code has one recursive level; A and B each need
support sizes 1 through 8. Graph and nonzero-coefficient failure bounds are
allocated 104 bits each, and 107 bits per support size, giving a combined
ideal-sampling setup failure bound at most 2^-102. The selected inequalities
also pass an independent check using exact rational arithmetic.

The outer ERA analysis retains the existing numerical CalcDist qualification:
the distance above is a numerical sufficient-bound candidate, not an interval
or all-roots certificate. A separate numerical maximization of the exponent
finds maximum -0.000220194, below the required -0.0000509100. This is an extra
falsification check. The setup analysis concerns ideal independent sampling;
the deterministic benchmark seed is not a certificate for the realized code,
and these checks do not constitute a complete Fiat–Shamir soundness proof.

The output code remains BaseFold with message length 2^15 and rate 1/8;
terminal message length is 2^12, with 147 terminal queries. The new index has
647 rows and the online proof has 377 rows. The public index commitment binds
the actual inner generator matrix. No new transcript format is needed.

## Selection and implementation

The finite search checks row logs 16, 18, 20, 22 and 24, 18 inverse rates, and
alpha from 0.004 through 0.120 in increments of 0.001. It chooses minimum root
degrees and then checks the whole recursion, including the terminal distance.
Of 4,973 passing candidates, it chooses the least multiplication count at each
row size among candidates fitting a 112 GiB memory budget, then the smallest
estimated serialized proof among those choices. This is a runtime-oriented
parameter search followed by interleaving optimization, not a global joint
optimum over every degree, rate, distance and interleaving.

For the chosen configuration, the tensor part takes 4,496,670,720 field
multiplications across the full input. Including ERA's two weighted accumulator
passes, the total falls from 31,340,699,648 to 7,047,364,608, about 4.45 times fewer.
These are operation counts, not measured time fractions or a predicted speedup.
The expected proof is 17,659,389 bytes; the allocation model with a 15% margin
predicts 78.887 GiB peak memory.

`BrakedownBaseCase::ZeroPadding` and `Setup::new_with_base_code` are explicit
options. The old constructors and default CLI configuration retain their old
parameters for reproducibility. Both default proofs remain byte-for-byte equal
to the pre-optimization references. The new parameterization changes the code
and index and therefore intentionally produces a different proof.

## Alternative at the previous interleaving

To separate the encoder change from the interleaving tradeoff, a third fresh
case keeps eta = 10 (1,024 rows of 2^18 inputs). Its fast base uses alpha 0.026,
inverse rate 1.075, A degree 9 and B degree 16, giving an inner [550,512] code.
The terminal [15,14,1] code appends one zero. The checked inner distance is
0.01477, tensor distance 0.0002181529, and numerical ERA distance 0.2183078472
(rounded down to 0.218307). This needs 879 ERA queries; the output code and
terminal queries are unchanged. Its bounds pass the same exact Brakedown and
numerical ERA checks as the eta = 8 case.

The eta = 8 configuration was selected for its smaller expected proof. The
eta = 10 comparison keeps the original row input size while changing the base
code and recalibrating distance and queries. Thus it isolates most of the
encoding benefit, while still allowing the block length and query count to change.

## Reproduction

Use Rust 1.92.0 with the locked dependencies on the 16-core r7a.4xlarge, or a
Linux machine with enough memory. The saved plan runs only codeswitching ERA
and the local recursive BaseFold IOPP, once each after one warmup.

```sh
python3 -m pip install -r requirements-analysis.txt
export RUSTFLAGS='-C target-cpu=native'
cargo +1.92.0 build --release --locked --bin compare_iopps
python3 -B scripts/run_large_iopp_plan.py \
  artifact_results/2026-10-15-era-sparse-base/plan.json results/era-sparse-base-reproduction \
  --experiment codeswitching --logs 28 --threads 16 --warmups 1 --samples 1 \
  --memory-budget-gib 112
```

The result directory must be fresh. To reproduce the search and additional
distance validation:

```sh
python3 -B scripts/search_era_base.py results/era-search.json \
  --message-log 28 --threads 16 --memory-budget-gib 112
python3 -B scripts/check_era_sparse_base.py results/era-search.json
python3 -B distance-analysis/brakedown.py 0.058 0.0082186 1.09 \
  -n 10 -s 102 --cn 7 --dn 16 --base-case zero-pad
```

To reproduce the additional eta = 10 case, using the same built binary:

```sh
python3 -B scripts/run_large_iopp_plan.py \
  artifact_results/2026-10-15-era-sparse-base/fixed-eta-plan.json \
  results/era-sparse-base-eta10 \
  --experiment codeswitching --logs 28 --threads 16 --warmups 1 --samples 1 \
  --memory-budget-gib 112 --instance-type r7a.4xlarge
python3 -B scripts/check_era_sparse_base.py \
  artifact_results/2026-10-15-era-sparse-base/search-summary.json --eta 10
```

The Brakedown CLI uses `beta = inverse_rate * relative_distance`, hence
0.0082186 in that last command. Compact parameters and distance evidence are
in [the evidence bundle](../artifact_results/2026-10-15-era-sparse-base/).
The measured source snapshot is retained separately from this later report.

## Measured results

All three fresh measured proofs verified on the same on-demand r7a.4xlarge,
with 16 Rayon workers, one warmup and one measured sample per case. The old
RS row below is the preserved measurement from the earlier campaign on this
same machine. Setup and input generation are excluded from prover totals.

| Configuration | eta | Commit (s) | Evaluation prove (s) | Total prover (s) | Verify (s) | Exact proof bytes | Peak RSS (GiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Previous ERA, dense RS base | 10 | 69.690 | 18.960 | 88.650 | 0.499 | 30,348,584 | 65.848 |
| Sparse ERA, previous interleaving | 10 | 23.736 | 18.825 | **42.561** | 0.504 | 31,785,384 | 63.649 |
| Sparse ERA, smaller-proof choice | 8 | 24.785 | 34.317 | **59.103** | 1.258 | 17,668,488 | 71.403 |
| Local recursive BaseFold IOPP, fresh | 4 | 18.834 | 18.688 | **37.521** | 0.0565 | 6,004,040 | 44.230 |

Keeping the previous interleaving reduces ERA commitment time by 2.94 times
and total prover time by 2.08 times. Its exact proof grows 4.73% because of the
recalibrated parameters and query count. At eta = 8, larger rows reduce the
proof by 41.78% versus the old configuration, while increasing the size of
the row computation and online witness. Evaluation and verifier time therefore
increase. The eta = 8 total still improves by 1.50 times versus the old result.
The faster eta = 10 ERA total is 13.43% above the fresh BaseFold measurement.
These are single samples, not distributions or uncertainty estimates.

Setup takes 1.765 s for eta = 10 ERA, 7.626 s for eta = 8 ERA, and 9.799 s for
BaseFold. Proof sizes are exact serialized bytes, excluding separately supplied
public commitments and the preprocessed index. Peak RSS covers the entire
process, including setup and warmup.

The 200 Rust library tests, 18 distance tests and two proof-size model tests
passed on AWS. Both small default proofs matched the historical reference
bytes, and the full BaseFold proof matched the previous AWS campaign exactly.
All three new proof files, source archives and every entry in both result
checksum manifests were retrieved and verified locally. Both measured source
archives match all 52 current Rust source/manifest files checked by the
finalizer. Source archives, complete proofs and remote control logs remain
in the [retained campaign archives](repository-layout.md); compact results,
checksums and proof hashes are retained in the evidence bundle. The instance
and original campaign files are left intact.
