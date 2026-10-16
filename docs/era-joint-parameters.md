# Joint ERA-to-BaseFold parameter search at 2^28

Updated implementation measurements with identical proof bytes are in
[Compact verifier and prover optimization](era-compact-verifier.md).
The measurements below preserve the earlier implementation as a baseline.
Commands run the current code with those parameters; reproducing historical
timings requires the archived source snapshot.

This experiment varies the interleaving and the codeswitch output dimensions
together, using the current serialized proof-size model. The earlier AWS
search fixed the output message length at 2^15; it therefore did not optimize
the same parameter space as the paper's worked example.

The pipeline is one ERA codeswitch followed by the recursive BaseFold IOPP.
There are no GKR checkpoint commitments. The field is the secp256k1 scalar
field and the hash is BLAKE3, as in the preceding AWS campaigns.

## Selected parameters

| Parameter | Value |
| --- | ---: |
| Total input | 2^28 elements |
| Initial interleaving | 64 rows (`--eta 6`) |
| ERA row message | 2^22 elements |
| Inner Brakedown message / block | 2,048 / 2,109 |
| Brakedown alpha / inverse rate | 0.017 / 1.03 |
| Sparse degrees cn / dn | 9 / 20 |
| Terminal base code | zero padding, [36,35,1] |
| Inner distance used | 0.00478 |
| Tensor distance used | 0.0000228484 |
| ERA repetition | 4 |
| ERA row block length | 17,791,524 |
| Rounded numerical ERA distance | 0.216292 |
| Initial ERA queries | 888 |
| BaseFold output message | 2^21 elements |
| BaseFold output rate | 1/8 |
| Rounded numerical BaseFold distance | 0.752157 |
| BaseFold queries | 156 |
| Terminal message | 2^11 elements |
| Index / online stack heights | 39 / 23 |
| Expected serialized proof | 3,629,891 bytes |

The Brakedown base uses no Reed–Solomon encoding. Its recursive probability
bounds were rechecked using exact rational inequalities for the ideal
sampler. The ERA distance still uses numerical CalcDist and a separate
numerical maximization check, not certified all-roots isolation or a new
end-to-end Fiat–Shamir soundness proof. Query budgets retain the previous
104-bit convention; constituent setup checks use 102 bits.

## Memory lifetimes

The old borrowed-commitment API keeps the original ERA encoded rows and Merkle
tree alive until the caller drops them. This unnecessarily overlaps about
35.935 GiB with GKR and terminal BaseFold for these parameters.
`Setup::prove_consuming_with_profile` takes ownership and drops that commitment
immediately after its last Merkle opening. The caller keeps the 32-byte root
for verification. The verifier and serialized protocol are unchanged.

The benchmark opts in with `--consume-era-commitment`; existing borrowed APIs
remain available. The conservative model now takes the maximum of stage
allocations rather than retaining the original commitment in every stage:

| Stage | Modeled live GiB before margin |
| --- | ---: |
| Original commitment construction | 88.166 |
| Initial sumcheck | 85.198 |
| Before original commitment openings | 90.609 |
| After original commitment openings | 82.237 |

The resulting peak estimate is **104.201 GiB including a 15% margin**, below
the 112 GiB preflight budget. The old lifetime model predicted 135.897 GiB
including that same margin. The completed run measured 90.901 GiB peak RSS.

## Search and reproduction

The search reuses all 4,973 passing candidates from the sparse-base grid. For
each of 68 combinations of row size and inner block length, it selects the
base with the fewest estimated encoding multiplications. It then checks
2,640 combinations of output length and inverse rate, minimizing the terminal
message size separately. This is a finite grid search, not a global optimum.
Square tensor codes require even row-message exponents. Output exponents run
from 13 through one below the row-message exponent; inverse rates are
2, 4, 8, 16, 32; terminal exponents are 6 through min(output_log-1,15).

```sh
python3 -B scripts/search_era_base.py results/base-grid.json \
  --message-log 28 --threads 16 --memory-budget-gib 112
python3 -B scripts/search_era_joint.py results/base-grid.json results/joint-grid.json
python3 -B scripts/check_era_sparse_base.py \
  artifact_results/2026-10-15-era-joint-params/search-summary.json

RUSTFLAGS='-C target-cpu=native' cargo +1.92.0 build --release --locked --bin compare_iopps
python3 -B scripts/run_large_iopp_plan.py \
  artifact_results/2026-10-15-era-joint-params/plan.json results/era-joint-params-reproduction \
  --experiment codeswitching --logs 28 --threads 16 --warmups 1 --samples 1 \
  --memory-budget-gib 112
```

The saved plan runs **2^28 only**, with 16 Rayon workers, seed 2025, one warmup
and one measured sample. The target is the on-demand AWS r7a.4xlarge with
128 GiB advertised memory. Setup is reported separately from online prover
time. Total prover time means commitment plus evaluation-proof generation.
Each proof is serialized, verified, saved, and accompanied by process peak
RSS, source/environment provenance and checksums. Output directories must be
new. Large raw evidence stays under ignored `results/`.

The [compact evidence](../artifact_results/2026-10-15-era-joint-params/) includes
the exact plan, query counts, search summary and distance checks. It does not
mix measurements from the previous Spot instances or input sizes.

## Measured result

The fresh AWS run completed on 2026-10-16 at 03:16:45 UTC (October 15 local
time). It used one warmup and one measured sample, with no stage profiler.

| Measurement | Result |
| --- | ---: |
| Setup, excluded from online prover total | 40.310 s |
| Commitment | 26.169 s |
| Evaluation proof | 101.905 s |
| **Total online prover** | **128.074 s** |
| Verifier | 10.284 s |
| **Exact serialized proof** | **3,622,568 bytes (3.623 decimal MB)** |
| Process peak RSS, including setup/warmup/verification | 90.901 GiB |

The proof passed verification. Its size is 0.202% below the expected-size
model; shared authentication nodes and repeated coordinates depend on the
transcript. All nine files in the full-run SHA-256 manifest were retrieved
and verified, and all 51 Rust/Cargo source files in the measured snapshot
match the workspace. The source archive and full proof remain under ignored
the archives listed in [the retention index](repository-layout.md).

The compact records contain the command, environment, source provenance,
timings, memory, proof hashes, and distance validation. AWS passed all 201
library tests, 18 distance tests and two multiproof-model tests. Byte-identity
tests cover both commitment APIs across output rates and checkpoint modes;
the default 2^22 consuming proof also exactly matches the saved proof from
the earlier borrowed implementation. The new 2^28 parameter set naturally
has its own transcript; the lifetime change does not modify that protocol.

This parameter choice favors proof size over speed:

| Same-host 2^28 configuration | Proof bytes | Total prover (s) | Verifier (s) | Peak RSS (GiB) |
| --- | ---: | ---: | ---: | ---: |
| Earlier sparse ERA, 256 rows, k'=2^15 | 17,668,488 | 59.103 | 1.258 | 71.403 |
| **New sparse ERA, 64 rows, k'=2^21** | **3,622,568** | **128.074** | **10.284** | **90.901** |
| Local recursive BaseFold reference | 6,004,040 | 37.521 | 0.0565 | 44.230 |

The reference rows are the already completed, fresh on-demand r7a.4xlarge
16-worker runs in [the sparse-base campaign](era-sparse-base.md); they were
not rerun in this single-case campaign. The new ERA proof is 4.88 times
smaller than the previous sparse ERA proof, at about 2.17 times the prover
time. The larger switched messages and row checks also increase verifier
work in this implementation. Setup remains separate in every comparison.

A subsequent [stage profile](era-joint-profile.md) reproduced the exact proof
and measured 128.302 s total. Permutation checks took 46.344 s, including
26.954 s of GKR; terminal BaseFold took 1.857 s. The linked report contains
the disjoint time breakdown and reproduction command.
