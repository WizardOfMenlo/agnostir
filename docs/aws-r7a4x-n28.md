# Initial AWS comparison at 2^28 elements

This is the October 15 campaign record. Its four interleaved rows remain the
reference measurements. Its two complete-IOPP rows predate the final sparse
base and compact verifier; use the [final results](../artifact/results.md) and
[parameters](../artifact/parameters.md) for the current IOPP comparison.

This completed campaign ran all six protocols from scratch on an on-demand
r7a.4xlarge: 16 physical AMD EPYC 9R14 cores, 128 GiB advertised RAM (about
123 GiB visible to Linux). Each protocol uses 16 Rayon workers, one warmup,
and one measured sample. Historical 32-worker Spot pilot rows are not included.
No 2^29 run is scheduled.

The field is the secp256k1 scalar field and the hash is BLAKE3. Interleaving
minimizes the estimated serialized proof size over the planner's allowed row
sizes, with the other encoder parameters fixed. EA retains its conjectured
0.1 distance. The codeswitching implementation uses no GKR checkpoints;
the comparison IOPP is the local recursive BaseFold implementation. The
conditional distance and soundness qualifications in [the planning report](aws-size-plan.md)
still apply.

| Protocol | eta | Rows | Input elements per row |
| --- | ---: | ---: | ---: |
| Interleaved ERA | 8 | 256 | 2^20 |
| Interleaved BaseFold code | 9 | 512 | 2^19 |
| Interleaved Brakedown | 9 | 512 | 2^19 |
| Interleaved EA | 9 | 512 | 2^19 |
| Uncheckpointed codeswitching ERA | 10 | 1,024 | 2^18 |
| Local recursive BaseFold IOPP | 4 | 16 | 2^24 |

## Reproduction

Use the [artifact guide](../artifact/README.md) to build with Rust 1.92.0
and the locked dependencies. The four retained interleaved cases use the
same parameters as this campaign:

```sh
RUSTFLAGS='-C target-cpu=native' bash artifact/run.sh interleaved28 results/interleaved28
```

The final `codeswitch28` and `full28` modes use the newer complete-IOPP
parameters. The original six-case plan remains in the campaign evidence for
provenance; reproducing an older implementation also requires its original
source snapshot from the [retained archives](repository-layout.md).

The campaign retains exact proof files, timing CSVs, process peak RSS,
commands, source, compiler/CPU metadata and checksums under ignored `results/`.
Prover totals are commitment plus evaluation proof generation, excluding
setup and input generation. Peak RSS covers the complete process, including
the warmup. The measured proof is verified by the benchmark harness.

## Measured results

All six measured proofs verified on the instance. All six binary proof files
were downloaded, and every file in the remote result checksum manifest was
verified locally. The 198 library tests and two planner tests passed; the two
small default IOPP proofs matched the pre-optimization Mac reference bytes.

| Protocol | Commit (s) | Evaluation prove (s) | Total prover (s) | Verify (s) | Exact proof bytes | Peak RSS (GiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Interleaved ERA | 29.575 | 18.132 | **47.707** | 1.046 | 40,541,384 | 58.817 |
| Interleaved BaseFold code | 17.193 | 18.089 | **35.282** | 0.232 | 33,989,320 | 40.154 |
| Interleaved Brakedown | 86.297 | 18.200 | **104.496** | 1.367 | 49,624,040 | 41.149 |
| Interleaved EA | 937.552 | 18.172 | **955.723** | 10.610 | 49,622,792 | 48.560 |
| Codeswitching ERA (uncheckpointed) | 69.690 | 18.960 | **88.650** | 0.499 | 30,348,584 | 65.848 |
| Local recursive BaseFold IOPP | 18.822 | 18.706 | **37.529** | 0.057 | 6,004,040 | 44.277 |

These are single measured samples after one warmup, not averages. The exact
serialized proof size excludes the separately supplied 32-byte public commitment.
Setup is recorded separately in `results.json`. Peak RSS includes setup, input
generation, the warmup and measured run.

Compact evidence is in [the campaign bundle](../artifact_results/2026-10-15-aws-r7a4x-n28/).
Full proof payloads and original source are preserved in the archives listed
in [the retention index](repository-layout.md);
`proof-manifest.json` records their exact lengths and SHA-256 hashes.
