# Original October 15 AWS campaign, 2^28 elements

**Scope:** the four common-interleaved rows below remain the reference results.
The last two IOPP rows are historical: ERA still used the older parameterization
and verifier, and BaseFold was measured in that same earlier campaign. For the
final optimized ERA/BaseFold pair and current reproduction commands, use the
[artifact guide](../../artifact/README.md) and
[final reference table](../../artifact/results.md). In particular, the final
ERA proof is 3,622,568 bytes; the 30,348,584-byte proof below is superseded.

Fresh six-protocol campaign: 16 workers, one warmup and one measured sample
per protocol. No historical Spot measurements are included. See
[the original campaign report](../../docs/aws-r7a4x-n28.md).

| Protocol | Commit (s) | Evaluation prove (s) | Total prover (s) | Verify (s) | Exact proof bytes | Peak RSS (GiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Interleaved ERA | 29.575 | 18.132 | **47.707** | 1.046 | 40,541,384 | 58.817 |
| Interleaved BaseFold code | 17.193 | 18.089 | **35.282** | 0.232 | 33,989,320 | 40.154 |
| Interleaved Brakedown | 86.297 | 18.200 | **104.496** | 1.367 | 49,624,040 | 41.149 |
| Interleaved EA | 937.552 | 18.172 | **955.723** | 10.610 | 49,622,792 | 48.560 |
| Historical codeswitching ERA (uncheckpointed) | 69.690 | 18.960 | **88.650** | 0.499 | 30,348,584 | 65.848 |
| Historical local recursive BaseFold IOPP sample | 18.822 | 18.706 | **37.529** | 0.057 | 6,004,040 | 44.277 |

`source.tar.gz` is the exact measured source snapshot. `environment.json`,
per-case commands, raw timings and memory records retain the execution details.
`full-results.SHA256SUMS` is the checksum manifest for the complete retrieved
result directory, including the six proofs. Large proof payloads stay under
ignored `results/`; see `proof-manifest.json` for paths, sizes and hashes.
`SHA256SUMS` covers the files in this compact bundle.
