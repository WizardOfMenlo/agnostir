# Bolt-min adapted to the common interleaved experiment

`--code bolt-min` now selects a complete serialized evaluation argument over
the **secp256k1 scalar field**, using the same BLAKE3 commitments, Fiat–Shamir
channel, StartingIOR sumcheck, column multiproofs, parser, and timing boundaries
as Brakedown, EA, BaseFold, and ERA. It is named **bolt-min (adapted)** in the
paper. This is Bolt's sketched code inside our common interleaved argument,
not an implementation of Bolt's separate code-switching PCS.

The earlier [upstream binary-field commitment measurements](bolt-comparison.md)
remain available as historical reference data. They are no longer the Bolt row
in the paper's main comparison.

The separate [Bolt-max adaptation](bolt-max-adaptation.md) uses an all-one
degree-8 sketch. Its distance is an additional assumption; the weighted-kernel
certificate in this document applies only to Bolt-min.

## Local results at 2^22 elements

Apple M2, 16 GiB, Rust 1.92 release without explicit CPU flags, seed 2025,
interleaving 64, three samples after one warmup. Times below are medians in ms.
The proof is **11,621,288 bytes (11,348.914 KiB)**, excluding the public 32-byte
initial root, and uses 4537 query draws.

| Workers | Commit | Prove | Verify | Commit + prove |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 2649.562 | 2352.619 | 120.338 | 5002.182 |
| 8 | 695.659 | 902.238 | 85.948 | 1597.897 |

The sum column adds stage medians; it is not a separately measured median.
Eight-worker commit samples ranged from 630.132 to 891.950 ms, so these local
measurements should not substitute for the intended controlled AWS run. Raw
CSV files, calibration, logs, source snapshot, and the serialized proof are in
[`artifact_results/2026-10-14-bolt-adapted`](../artifact_results/2026-10-14-bolt-adapted/).
Every measured proof was verified. A full-size 32-worker functional run also
verified and produced exactly the same proof bytes as the 8-worker run. That
run uses the same 8-core host and is not a 32-core scaling measurement.

Validation passed 187 default-feature and 186 no-default-feature library tests,
formatting, and Clippy (existing repository warnings remain). The main artifact
reproduction script's 32-worker smoke run includes the adaptation and the kernel
calibration. The revised paper table was compiled and visually checked.

## Construction and differences from upstream

Following the degree-16 `bolt32` configuration in the
[pinned reference implementation](https://github.com/bcc-research/bolt-rs/tree/3832e47b24e7b3e10525c9c5bcfc1cfe66d525f2),
the adapted encoder is

\[
 C(x) = x\mathbin\|B(Hx).
\]

For a row message of length `m`, `H` has `m/8` rows. Repeat each input index
16 times, shuffle the `16m` edge positions uniformly, partition them into checks
of 128 edges, and assign independent nonzero scalar coefficients. Parallel
edges are retained and added in the field, as required by the configuration
model. Coefficients use canonical rejection sampling, avoiding modular-reduction
bias. Every input has exactly 16 incident edges; no inputs are left untouched.

Upstream uses additive Reed–Solomon over GF(2^32). Its characteristic-two FFT
cannot run over this prime field; the scalar modulus has 2-adicity 6 and thus
also lacks a radix-2 multiplicative domain of the required size. We use the
existing rate-1/2 **BaseFold code** for `B`. This preserves the sketch's degree,
compression, and overall rate 4/5, but changes its distance and performance.
It is not labeled as a reproduction of the published binary-field Bolt-min.

At `N=2^22`, `eta=6`: 64 rows, `m=65536`, 8192 syndrome elements, 16384 parity
elements, and 81920 symbols per encoded row. All input and proof field elements
occupy 32 bytes. The deterministic setup recipe has a distinct transcript code
identifier. Coefficients and indices are stored separately, with sorted check
rows. Commitment parallelizes across the 64 rows and uses sequential inner
encoders; verification can parallelize its single sketch and BaseFold encoding.

## Distance and query count

For every nonzero `x`, either `Hx=0`, in which case the systematic part has
weight at least `d(ker H)`, or `Hx!=0`, in which case the parity part has weight
at least `d(B)`. Therefore

\[
 d(C)\geq\min\{d(\ker H),d(B)\}.
\]

The kernel bound below excludes all weights through `m/16` in the ideal random
ensemble with failure probability below `2^-101`. The outer distances are
**conditional estimates**, recomputed with the repository's existing BaseFold
formula at field-size lower bound 255 bits and setup budget 102 bits, then
rounded down to three decimals. At outer message length `2^13`, the estimate
is 0.224. Since parity occupies one fifth of the complete codeword,

\[
 \delta_C\geq\min\{1/20,\delta_B/5\}=0.0448,
 \qquad q=\left\lceil-300/\log_2(1-0.0448)\right\rceil=4537.
\]

This recalculation is essential: the binary-field Bolt distance and the outer
BaseFold distance cannot be used directly as the complete sketch's distance.
The CLI uses 4537 query draws at this size; actual proof bytes reflect duplicate
queries and shared Merkle paths through the common serializer.

These are conditional 100-bit **query-model** parameters, matching the reporting
convention of the other rows. The BaseFold formula's applicability to the exact
implementation, fixed seeded setup, full IOPP error composition, and Fiat–Shamir
security are not certified by this addition. A small seeded benchmark is not a
sample from an information-theoretically uniform ensemble. Successful proof
verification does not certify code distance.

### Finite-length kernel bound

Here is a separate derivation for the ideal prime-field sketch ensemble. Let
`t=m/8`, `D=128`, `d=16`, and `W=m/16`. For support size `w<=W`, require at
least `h0=ceil(9w/8)` touched checks. A fixed support has `dw` edge positions
uniformly distributed without replacement. A union bound over supports and
check sets gives, with `h=h0-1`,

\[
 \Pr[\exists S:|S|=w,\ |N(S)|<h_0]
 \leq {m\choose w}{t\choose h}
       \frac{{Dh\choose dw}}{{dm\choose dw}}
 \leq (3m/w)^w(3t/h)^h(h/t)^{16w}.
\]

We used `e<3` and the without-replacement probability bound `(h/t)^(16w)`.
The right side increases in `h` for `0<h<=t`, so substitute `h=9w/8`.
Call the resulting bound `A(w)`. Its logarithm has the form
`w*(constant+(111/8)*log(w))`, which is convex, giving

\[
 \sum_{w=1}^{W} A(w)\leq W\max\{A(1),A(W)\}.
\]

At `m=4096`, both endpoint bounds are at most `2^-102`.
`scripts/calibrate_bolt.py` verifies this using integer arithmetic after raising
the bound to the eighth power; no floating-point comparison establishes this
certificate. The approximate exponents are -107.979 and -1266.706.
For doubling `m`, `W*A(1)` decreases by `2^(-103/8)`, and
`A(W)=K^W` for constant `K<1`; doubling `W` multiplies `W*A(W)` by
`2*K^W<1`. Thus the certificate applies to every supported power-of-two `m`
from `2^12` through `2^22`.

Conditioned on the graph expansion, fix a nonzero vector with support `w` and
normalize its first nonzero entry to 1. Each touched check vanishes with
probability at most `1/(|F|-1)`: reveal all but one nonzero edge coefficient in
that check. Checks use disjoint independent coefficients, including when there
are parallel edges. Union-bounding the normalized vectors gives

\[
 \Pr[\exists x\ne0,\ Hx=0,\ |x|\leq W\mid\text{expansion}]
 \leq\sum_{w=1}^{W}{m\choose w}(|F|-1)^{w-1-\lceil9w/8\rceil}
 <2^{-255}\sum_{w\geq1}2^{-9w}<2^{-263},
\]

using `|F|-1>2^255` and `log2(m)<=22`. Combining graph and coefficient failures
gives `<2^-101` for the ideal kernel ensemble. If the outer code's assumed
`2^-102` setup-failure budget applies, the combined code-setup failure is below
`2^-100`; this does not include the evaluation protocol's other error terms.

## Reproduction and checks

```sh
python3 scripts/calibrate_bolt.py
cargo test --locked --lib bolt
cargo run --locked --release --bin interleaved_iopp -- \
  --code bolt-min --message-log 22 --eta 6 --threads 32 --samples 5 --csv
# The full artifact script includes this row by default.
RAYON_NUM_THREADS=32 SAMPLES=5 \
  bash scripts/reproduce_artifact.sh results/aws-with-bolt full
```

Use explicit `RUSTFLAGS='-C target-cpu=native'` consistently across all rows
when rebuilding on AWS. `--proof-out PATH` saves the actual final byte string.
The binary verifies every timed proof, including parsing and all arithmetic
checks, before reporting acceptance. Unit tests compare the sparse encoder to
a dense matrix, check linearity and systematic coordinates, exercise arbitrary
and Boolean public points, reject tampering and incorrect public claims, and
compare transcript bytes across worker counts.
