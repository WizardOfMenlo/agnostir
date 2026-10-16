# Compact ERA verifier weights and prover optimization

This experiment preserves the transcript and parameters of the
[3.62 MB ERA-to-BaseFold experiment](../../docs/era-joint-parameters.md). It uses the
secp256k1 scalar field, BLAKE3, 2^28 input elements, 64 interleaved ERA rows,
a 2^21-element codeswitch output at BaseFold rate 1/8, terminal size 2^11,
888 ERA queries, 156 BaseFold queries, and seed 2025. GKR is uncheckpointed.
The inner Brakedown code is [2109,2048], with alpha 0.017, inverse rate 1.03,
cn=9, dn=20, and the zero-padding terminal code. Numerical distance and
soundness qualifications are unchanged; see the parameter report.

## What changed

The verifier previously built full equality tables, accumulator suffixes,
packed tensor weight arrays, and weighted combinations of those arrays.
These arrays were public, but their construction made verification linear
in the oracle width. The new `proof::weights` module represents each weight
vector by its challenges, length, and slice placement. Only the prover
materializes the dense arrays needed for sumcheck.

For a Boolean index i, let chi_p(i) be its multilinear equality weight at p.
The compact evaluators compute the exact same multilinear extensions:

- A shifted, truncated slice evaluates as
  sum over 0 <= t < length of chi_p(a+t) chi_r(b+t). A binary dynamic program
  tracks two addition carries and one comparison borrow: eight states and
  logarithmically many steps.
- An accumulator suffix evaluates as the sum of chi_p(j) chi_r(b+t) over
  0 <= t < length and a+t <= j < end. Its dynamic program has 32 states.
- Fourfold repetition sums four shifted evaluations. The affine permutation
  label's truncated first moment is computed in logarithmic time.
- Query accumulator weights sum truncated equality masses at the sampled
  query indices. Duplicate indices retain every coefficient.
- A tensor with a power-of-two column stride is a concatenated equality
  point. A non-power-of-two stride is evaluated one touched tensor row at
  a time using shifted equality products.

No field divisions are used in these evaluators, so zero and one challenge
coordinates need no special probabilistic assumption. All original split
claim scalars, batching coefficients, transcript challenges, and ordering
are retained, including checkpointed proofs.

**This is not a claim of a fully polylogarithmic verifier.** The current
tightly packed [2109 x 2109] tensor has a non-power-of-two stride. Its compact
evaluation costs O(n log(width)) for inner block length n, rather than
expanding n^2 entries. The overall code also uses preprocessed setup objects;
setup construction/storage is excluded from online verification timing.
Changing tensor packing or adding a proof of this public evaluation would
be a separate protocol change and would change the proof bytes.

Prover changes:

- Construct permutation denominators and label inner products in parallel.
- Build fractional GKR trees and split layer tables in parallel; consume
  each layer after its last use. Remove the intermediate array of pairs
  followed by a sequential unzip.
- Share dense weight backing arrays across split claims. Borrow index and
  online message rows instead of cloning their entire stack.
- Build grouped sumcheck weight tables in parallel, move them into sumcheck,
  then release dense source weights. Check endpoints with compact evaluators.
- Use parallel block suffix scans and parallel tensor contractions.

The GKR circuit, number of layers, sumcheck polynomials, and Fiat–Shamir
schedule are unchanged. These are table construction, evaluation, and
memory-lifetime changes, not new protocol parameters.

## Validation and reproduction

Tests compare compact evaluations with independent dense evaluations over
truncated intervals, unaligned slices, non-power-of-two tensors, repetitions,
duplicate queries, and Boolean challenge coordinates. Golden hashes captured
from the unchanged executable cover both uncheckpointed and checkpointed
proofs. Existing malformed-proof and context-tampering tests remain enabled.

The local 2^20 check uses eight workers, one warmup and one sample. Its
evaluation prover changed from 1.421894 s to 1.240663 s and verifier from
83.156 ms to 3.836 ms, with the same 289,256-byte proof. Smaller development
measurements are also retained in the evidence: the 2^18 prover measurement
regressed from 395.080 ms to 660.701 ms while verification improved. These
single small runs do not establish a scaling trend; the AWS comparison below
is the target-size measurement.

Run on a Linux machine satisfying the saved 112 GiB preflight budget:

```sh
RUSTFLAGS='-C target-cpu=native' cargo +1.92.0 build --release --locked --bin compare_iopps
cargo +1.92.0 test --release --locked --lib
RUSTFLAGS='-C target-cpu=native' python3 -B scripts/run_large_iopp_plan.py \
  artifact_results/2026-10-16-era-compact/plan.json \
  results/era-compact-reproduction \
  --experiment codeswitching --logs 28 --threads 16 \
  --samples 1 --warmups 1 --memory-budget-gib 112 \
  --instance-type r7a.4xlarge --profile
```

The runner saves exact proof files, accepted timing rows, peak process RSS,
prover stages, separate ERA verifier stages, environment metadata, a source
archive, and SHA-256 checksums. Stage timings are nested wall-clock timings;
only disjoint/exclusive times can be added. Setup and proof/profile file
writes are outside the reported prover/verification timers. RSS covers the
whole process, including setup, warmup, proving, and verification.


## AWS results, October 16, 2026

Both fresh runs completed on the same on-demand r7a.4xlarge (16 AMD EPYC
9R14 cores, 128 GiB advertised RAM), with 16 Rayon workers, one warmup and
one measured sample per protocol. Compilation used Rust 1.92.0 and
`-C target-cpu=native`. Both new runs have prover stage profiling; the new
ERA run also has verifier stage profiling. The previous ERA column uses
its saved profiled run of exactly the same parameters on this host.
These single measurements have no confidence interval.

| Measurement | Previous ERA | Optimized ERA | Fresh BaseFold (local) |
| --- | ---: | ---: | ---: |
| Setup, excluded (s) | 40.355 | 39.819 | 9.625 |
| Commitment (s) | 26.166 | 25.987 | 18.767 |
| Evaluation proof (s) | 102.136 | 57.531 | 18.579 |
| **Total prover (s)** | 128.302 | 83.518 | 37.346 |
| Verifier (ms) | 10,357.805 | 38.495 | 56.703 |
| Exact proof bytes | 3,622,568 | 3,622,568 | 6,004,040 |
| Peak process RSS (GiB) | 90.908 | 87.246 | 44.277 |

ERA total prover time decreased **34.9%**;
evaluation proving decreased **43.7%**.
Verification is **269.1x faster** than the previous implementation.
Against the fresh local BaseFold baseline, ERA has a **39.7% smaller proof**,
a **2.24x longer total prover time**, and
**32.1% less verification time** in this sample.

The baseline remains the repository's local recursive BaseFold IOPP, not an
upstream Plonky3 optimized fork. It uses 16 interleaved rows, row message
2^24, rate 1/2, terminal size 2^12, and 1290 queries. Its parameters and
proof also match the earlier same-host baseline. This run changes neither
baseline parameter selection nor its fixed rate/terminal search scope.

### Where prover time went

These are inclusive substage comparisons; overlapping rows must not be
summed. They explain the change within the full prover table above.

| Substage | Previous (s) | Optimized (s) |
| --- | ---: | ---: |
| Permutation denominators | 6.614 | 0.453 |
| All GKR | 26.954 | 11.845 |
| GKR fraction trees | 7.263 | 0.970 |
| GKR layer tables | 9.693 | 2.036 |
| GKR layer sumchecks | 9.078 | 8.839 |
| Terminal permutation claims | 12.719 | 2.086 |
| Final claim table construction | 6.034 | 0.897 |
| Final claim endpoint checks | 0.322 | 0.009 |
| Tensor check | 2.695 | 0.788 |

GKR still traverses 25 layers with 300 scalar sumcheck rounds. Most of its
improvement is in fraction-tree and layer-table construction; sumcheck
arithmetic is nearly unchanged. The initial commitment now costs 25.987 s,
and the online auxiliary commitment costs 16.904 s (14.654 s encoding,
1.500 s Merkle hashing). Together these commitments account for **51.4%**
of total proving. GKR is 14.2%, and the starting sumcheck is 10.3%.

### New verifier profile

| Disjoint work | Milliseconds |
| --- | ---: |
| Initial ERA openings | 16.035 |
| Compact final weight evaluations and endpoint checks | 8.514 |
| Terminal BaseFold verification | 12.540 |
| Permutation/GKR checks | 0.799 |
| Remaining verifier work | 0.607 |
| **Total** | **38.495** |

The tensor's compact public evaluation is included in the final endpoint
checks. It does not expand a tensor-sized array. The non-power-of-two
packing limitation described above remains; the 38.5 ms result is an online
measurement, not a proof of polylogarithmic asymptotic complexity.

### Exact identity and retained evidence

Both downloaded full-size proofs were directly compared byte-for-byte with
their previous versions. The ERA proof is still **3,622,568 bytes**, SHA-256:

```text
463d4d7dcbe0c5ec5a81335bc9937f26979ec16e0b68c626d043836444f10e36
```

The fresh BaseFold proof is still **6,004,040 bytes**, SHA-256:

```text
41c038c00d566fd26537a013bb8864ef5d1e2c0a58616d21ff6ee26794d0759e
```

Validation passed 204 library tests, 18 distance tests, and two planning
model tests. The default 2^22 proof hashes also matched the prior ERA and
BaseFold references. Local checks passed with parallel features disabled,
and Rust formatting and diff-whitespace checks passed. Clippy completed
with warnings; this repository does not have a clean warning baseline.
All 17 files in the full remote checksum manifest were retrieved and
verified. All 53 Rust/Cargo files match the measured source snapshot.
Exclusive profile times sum to their roots, and exclusive byte counts sum
to the exact proof length for both prover and ERA verifier profiles.

The [compact evidence](./) includes
raw timing/profile CSVs, aggregates, before/after comparisons, commands,
source provenance, a scoped optimization patch, test logs, and proof hashes.
Full proofs and the source archive remain in ignored
`results/era-compact-20261016/remote/results/full-n28/`. The remote campaign
and previous runs remain intact. No codeswitching results were added to
README or the paper.
