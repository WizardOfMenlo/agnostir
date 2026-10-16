# Reference measurements

All online times below are seconds; setup is excluded. Proof bytes are exact.

## Paper Tables 4 and 6: AWS experiments at 2^28

| Protocol | Commit | Evaluation prove | Total prover | Verify | Proof bytes | Peak GiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| interleaved-era | 29.575 | 18.132 | 47.707 | 1.046157 | 40,541,384 | 58.817 |
| interleaved-basefold | 17.193 | 18.089 | 35.282 | 0.232447 | 33,989,320 | 40.154 |
| interleaved-brakedown | 86.297 | 18.200 | 104.496 | 1.367456 | 49,624,040 | 41.149 |
| interleaved-ea | 937.552 | 18.172 | 955.723 | 10.610487 | 49,622,792 | 48.560 |
| era-codeswitch | 25.987 | 57.531 | 83.518 | 0.038495 | 3,622,568 | 87.246 |
| basefold-local | 18.767 | 18.579 | 37.346 | 0.056703 | 6,004,040 | 44.277 |

The first four rows share the common interleaved argument and are one comparison. The last two are complete IOPPs and are a separate comparison. All used 16 workers, one warmup and one measured sample on the same on-demand r7a.4xlarge.

## Paper Table 3: AWS Docker at 2^22

| Encoder | Commit ms | Prove ms | Verify ms | Proof bytes |
| --- | ---: | ---: | ---: | ---: |
| ERA | 547.936 | 404.666 | 61.858 | 4,010,824 |
| BaseFold-code | 432.036 | 410.508 | 30.499 | 4,177,416 |
| Brakedown | 1,012.292 | 421.097 | 147.110 | 6,438,728 |
| EA | 6,696.191 | 409.794 | 811.055 | 6,443,944 |

AWS r7a.4xlarge, Rust 1.92.0, `target-cpu=native`, Docker with eight workers,
an eight-CPU quota and an 8 GiB memory cap; eta=6. One measured sample after
one warmup, recorded October 16, 2026. Raw samples are under
`evidence/container-validation/validation/paper22/`; all four proofs match
the historical reference proofs byte-for-byte. No timing variance is inferred.

## Historical Apple M2 measurements at 2^22

| Encoder | Commit ms | Prove ms | Verify ms | Proof bytes |
| --- | ---: | ---: | ---: | ---: |
| ERA | 731.398 | 713.131 | 52.291 | 4,010,824 |
| BaseFold-code | 544.411 | 702.622 | 36.226 | 4,177,416 |
| Brakedown | 1,179.932 | 711.054 | 122.155 | 6,438,728 |
| EA | 8,524.394 | 763.297 | 617.407 | 6,443,944 |

Apple M2, 16 GiB, eight workers, eta=6; stage medians of three measured runs after one warmup. Raw samples are preserved in evidence/paper22. No confidence interval is inferred from these small samples.
