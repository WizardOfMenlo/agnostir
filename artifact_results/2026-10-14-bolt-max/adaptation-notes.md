# Bolt-max adapted to the common interleaved experiment

`--code bolt-max` selects Bolt's degree-8, compression-8, all-one sketch over
the secp256k1 scalar field. It uses the same BLAKE3 commitments, Fiat-Shamir
channel, starting sumcheck, column multiproofs, parser, and measurement
boundaries as [Bolt-min](bolt-adaptation.md) and the other interleaved rows.
The paper calls this **bolt-max (adapted)**. It is a sketched-code adaptation,
not the native binary-field Bolt code-switching PCS.

## Construction

The encoder is `C(x) = x || B(Hx)`, with rate-1/2 BaseFold as the syndrome code
`B`. The graph follows the degree-8 `bench_bolt_xor` profile in the
[pinned upstream source](https://github.com/bcc-research/bolt-rs/blob/3832e47b24e7b3e10525c9c5bcfc1cfe66d525f2/src/bin/quick_bench.rs).
Each of the `m` input coordinates has eight edges. Shuffle all `8m` edge
positions and partition them into `m/8` checks of 64 edges. Preserve parallel
edges. Every coefficient is one, so each check is an ordinary prime-field sum:
there is no coefficient allocation and no sketch multiplication. In this
field, adding the same element twice does not cancel. Using upstream's XOR
operation would be incorrect.

As with Bolt-min, BaseFold replaces the binary-field additive Reed-Solomon
syndrome code. The overall inverse rate is 1.25. At `N=2^22`, `eta=6`, there
are 64 messages of length 65536, syndromes of length 8192, parity of length
16384, and encoded rows of length 81920. Outer encoding still performs field
multiplications; only the sketch is addition-only. Commitment parallelizes
across rows without nested encoder parallelism. Verification can parallelize
the single sketch and outer encoding. The setup recipe and transcript code
identifier are distinct from Bolt-min.

## Explicit distance assumption, not a security certificate

The [upstream LDPC script](https://github.com/bcc-research/bolt-rs/blob/3832e47b24e7b3e10525c9c5bcfc1cfe66d525f2/distance_analysis/ldpc.py)
uses degree 8, right degree 64, and target kernel relative distance 0.013 in a
binary asymptotic analysis. This does **not** establish a finite-length
prime-field distance or a 100-bit setup-failure bound for our adaptation.
Bolt-min's separate random-coefficient proof also does not apply: Bolt-max has
no independent coefficients to make a check vanish with probability at most
`1/(|F|-1)`. Duplicate columns of `H`, for example, admit the kernel vector
`(1,-1)` and a codeword of weight two, regardless of the regular degrees.

For a conditional performance row, we explicitly **assume**
`d(ker H)/m >= 0.013`. The complete-code distance must account for its parity:

\[
 d(C) \geq \min\{d(\ker H),d(B)\},\qquad
 \delta_C \geq \min\{0.013/1.25,\delta_B/5\}=0.0104.
\]

The inherited conditional BaseFold estimate is 0.224 at this size, so the
assumed kernel bound is the limiting term. It remains limiting for all
supported row sizes `2^12` through `2^22`. Applying the common query model gives

\[
 q=\left\lceil-300/\log_2(1-0.0104)\right\rceil=19891.
\]

Using 0.013 as the full-code distance would undercount queries. Using
Bolt-min's 0.0448 would also be unjustified. The CLI emits the extra assumption,
`scripts/calibrate_bolt.py` records it separately from Bolt-min's certificate,
and the paper labels the row accordingly. Successful proof verification and
thread determinism establish implementation behavior, not minimum distance or
soundness. A prime-field distance proof with finite-length setup bounds is
still needed before claiming an equal-security comparison.

## Local measurements at 2^22 elements

Apple M2, 16 GiB, Rust 1.92 release, no explicit CPU flags, seed 2025,
interleaving 64. Times are medians of three runs after one warmup, in ms.

| Workers | Commit | Prove | Verify | Commit + prove |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 801.607 | 2334.299 | 280.972 | 3135.906 |
| 8 | 182.287 | 927.059 | 255.222 | 1109.346 |

The sum column adds stage medians. The exact serialized proof is
**39,119,368 bytes (38202.508 KiB)**, excluding the public 32-byte initial
root. It uses 19,891 query draws with deduplicated openings and shared Merkle
paths. Every timed proof verified. The 1-, 8-, and 32-worker full-size runs
produced byte-identical proofs. The 32-worker run was a functional check on
this same 8-core host, not a measurement on a 32-core AWS instance.

Eight-worker commitment ranged from 181.491 to
187.758 ms and proving from 924.430 to
981.281 ms. These are local samples, not a controlled scaling
study. Compared with the earlier adapted Bolt-min measurements, the sketch
commits faster but the additional queries increase proof size and verification
work. The Bolt-min refactor reproduced the previously saved full proof exactly.

Validation passed 189 default-feature and 188 serial library tests, formatting,
and Clippy (existing repository warnings remain). Tests cover both dense
matrix equivalence and linearity, addition and parallel-edge semantics,
honest serialized arguments, tampering, incorrect public claims, and worker
consistency. Raw CSVs, source, logs, calibration, and the actual proof are in
[`artifact_results/2026-10-14-bolt-max`](../artifact_results/2026-10-14-bolt-max/).

## Reproduction

```sh
cargo run --locked --release --bin interleaved_iopp -- \
  --code bolt-max --message-log 22 --eta 6 --threads 32 --samples 5 --csv
# Includes both adapted Bolt variants, all other rows, and the two recursive protocols.
RAYON_NUM_THREADS=32 SAMPLES=5 \
  bash scripts/reproduce_artifact.sh results/aws-with-bolt-max full
```

`--proof-out PATH` saves the exact serialized proof. All timed proofs are
verified before acceptance is reported. The public initial 32-byte root is
excluded from proof bytes. Setup and input generation are timed separately
from commitment, proving, and verification. Rebuild all rows on AWS with the
same CPU flags and run them without competing heavy workloads.
