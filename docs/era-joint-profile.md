# Profile of the 3.62 MB ERA-to-BaseFold prover

Updated implementation measurements with identical proof bytes are in
[Compact verifier and prover optimization](era-compact-verifier.md).
The measurements below preserve the earlier implementation as a baseline.
Commands run the current code; the earlier measurements require their archived
source snapshot.

The fresh profile uses exactly the binary and parameters from the
[joint parameter experiment](era-joint-parameters.md): 2^28 input elements,
64 interleaved rows, k'=2^21, BaseFold rate 1/8, terminal message 2^11,
888 ERA queries and 156 BaseFold queries, with no GKR checkpoints.
The original ERA commitment is consumed after its last opening.

The run used 16 Rayon workers on the same on-demand AWS r7a.4xlarge, seed
2025, one warmup and one measured sample. It completed October 15, 2026,
at 23:34 EDT. These are nested wall-clock timings, not sampled CPU times.
There were no implementation changes for this profile.

## Whole prover

| Measurement | Seconds |
| --- | ---: |
| Setup, excluded from prover total | 40.355 |
| Original ERA commitment | 26.166 |
| Evaluation proof | 102.136 |
| **Total prover** | **128.302** |
| Verification, separate and not stage-profiled | 10.358 |

Peak process RSS was **90.908 GiB**. The previous unprofiled total was
128.074 s, so this single profiled sample is 0.178% higher. That difference
includes ordinary run variation; it is not an isolated estimate of profiler
overhead. Proof and profile-file writes are outside the prover timers.

The following rows are disjoint and sum to the full prover total:

| Stage | Seconds | Share of full prover |
| --- | ---: | ---: |
| Permutation checks, including GKR and claim preparation | 46.344 | 36.12% |
| Original ERA commitment | 26.166 | 20.39% |
| Online auxiliary commitment | 16.900 | 13.17% |
| Final claim reduction, including terminal BaseFold | 12.334 | 9.61% |
| Starting sumcheck | 8.589 | 6.69% |
| Remaining work | 17.968 | 14.00% |
| **Total** | **128.302** | **100%** |

Remaining work comprises public evaluation (4.470 s), initial/OOD claims
(3.190 s), tensor check (2.695 s), ERA openings and original-commitment release
(2.143 s), auxiliary witness construction (2.037 s), accumulator claims
(1.597 s), interleaved row folding (0.670 s), and other/root overhead
(1.167 s). The initial commitment has only a combined timer; this profile
does not infer its internal encoding/hash split.

## Permutation checks and GKR

| Component | Seconds |
| --- | ---: |
| Denominator construction | 6.614 |
| GKR, including tree/table preparation | 26.954 |
| Terminal linear-claim preparation | 12.719 |
| Other permutation work | 0.057 |
| **Permutation checks total** | **46.344** |

Within GKR:

| Component | Seconds |
| --- | ---: |
| Fraction-tree construction | 7.263 |
| Layer-table construction | 9.693 |
| Layer sumchecks | 9.078 |
| Other GKR work | 0.920 |
| **GKR total** | **26.954** |

The batched GKR traverses 25 layers. Its layer sumchecks contain 300 scalar
rounds in total (0+1+...+24). Polynomial evaluation takes 6.728 s and table
folding takes 1.379 s within the 9.078 s sumcheck subtotal.

Tree and layer-table construction together take **16.956 s**, almost 63% of
the GKR block. GKR sumchecks themselves are **7.08% of the full prover**.
This points toward table construction and allocation, and the 12.719 s of
terminal permutation-claim preparation, as useful targets before further
optimizing only GKR sumcheck arithmetic. This is a conclusion from stage
timings; the profile does not separate allocator, cache, or memory-bandwidth
costs inside those stages.

## Commitments, final claim reduction and BaseFold

The online auxiliary commitment takes **14.632 s encoding**, **1.522 s Merkle
hashing**, and **0.746 s packing and other work**, totaling **16.900 s**.

| Final claim-reduction component | Seconds |
| --- | ---: |
| Build and combine claim tables | 6.034 |
| Batched sumcheck | 3.206 |
| Endpoint checks | 0.322 |
| Fold source messages | 0.339 |
| Terminal recursive BaseFold | 1.857 |
| Other work | 0.576 |
| **Final claim reduction total** | **12.334** |

Terminal BaseFold is only **1.45% of the full prover**. It takes 0.876 s to
encode the virtual combined codeword and 0.769 s for its folding commitments;
its remaining work is about 0.212 s. There are ten BaseFold fold rounds.

## Proof identity, evidence and reproduction

The proof independently verifies and is **byte-for-byte identical** to the
previous unprofiled proof: **3,622,568 bytes**. SHA-256:

```text
463d4d7dcbe0c5ec5a81335bc9937f26979ec16e0b68c626d043836444f10e36
```

All ten files in the remote result manifest were retrieved and checksum
verified, and all 51 Rust/Cargo source files match the measured snapshot.
The command differs from the original only in profiling/output destinations.
Exclusive stage times sum to the profile root, and exclusive byte counts sum
to the exact proof length. No nested inclusive timings are added together in
the disjoint whole-prover table above.

The [compact evidence](../artifact_results/2026-10-15-era-joint-profile/)
contains raw stage CSVs, aggregated stages, the unprofiled control, environment,
source provenance, commands, validation and proof hashes. Full proofs and the
source archive remain under ignored
the [retained campaign archives](repository-layout.md).

Run on a machine that satisfies the saved 112 GiB preflight budget:

```sh
RUSTFLAGS='-C target-cpu=native' cargo +1.92.0 build --release --locked --bin compare_iopps
python3 -B scripts/run_large_iopp_plan.py \
  artifact_results/2026-10-15-era-joint-params/plan.json results/era-joint-profile-reproduction \
  --experiment codeswitching --logs 28 --threads 16 --warmups 1 --samples 1 \
  --memory-budget-gib 112 --profile
```

The runner saves the profile in
`results/era-joint-profile-reproduction/era-codeswitch-n28-eta6/stages.csv`.
Recompute the aggregate of the saved compact CSVs with:

```sh
python3 -B scripts/summarize_iopp_profile.py \
  artifact_results/2026-10-15-era-joint-profile
```

The numerical distance and soundness qualifications in the parameter report
are unchanged. This profile is specific to the 64-row AWS configuration; it
should not be combined with the earlier 2^22 laptop or 256-row AWS profiles.
