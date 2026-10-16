# Parameters used by the reproduction entry points

Both experiments use the secp256k1 scalar field, canonical 32-byte elements,
BLAKE3, and seed 2025. `eta` is log2 of the number of interleaved rows.
The fixed full-size configuration is `artifact/evaluation-plan.json`; the
runner records every concrete command in each output directory.

## Common interleaved experiment, 2^28 elements

| Code | eta | Row message elements | Encoded row length | Queries | Distance parameter |
| --- | ---: | ---: | ---: | ---: | ---: |
| ERA | 8 | 2^20 | 4,404,016 | 816 | 0.225055 |
| BaseFold-code | 9 | 2^19 | 1,048,576 | 1,033 | 0.182429 |
| Brakedown | 9 | 2^19 | 1,048,576 | 1,974 | 0.1 |
| EA | 9 | 2^19 | 1,048,576 | 1,974 | 0.1 (conjectured) |

These are the original common-interleaved presets, including their original
base encoders. The later sparse-base parameter changes apply to the ERA
codeswitching experiment below. The input size and interleaving choices are
additional AWS results; the paper's Table 3 uses 2^22 elements with eta=6 for
all four codes. Its query counts are respectively 836, 927, 1974, and 1974.

## ERA codeswitching IOPP, 2^28 elements

- 64 rows (eta=6), each containing 2^22 message elements.
- Tensor base built from a [2109,2048] Brakedown code: alpha=0.017,
  inverse_rate=1.03, cn=9, dn=20, zero-padding terminal base (no RS invocation).
- Inner-code distance parameter 0.00478; tensor distance 0.0000228484;
  resulting ERA numerical distance candidate 0.2162928446, rounded down
  to 0.216292 for query planning. These are conditional numerical parameters,
  with the qualifications in changes.md.
- Encoded ERA row length 17,791,524; 888 initial queries.
- Codeswitch output: 2^21 message elements, BaseFold rate 1/8,
  156 terminal queries, terminal message size 2^11.
- Packed auxiliary commitment uses 39 index rows and 23 online rows.
- Uncheckpointed batched GKR, 25 layers and 300 scalar sumcheck rounds.
- Consume/release the initial commitment after its last opening to keep
  estimated memory below the 112 GiB preflight allowance.

## Local recursive BaseFold IOPP, 2^28 elements

16 rows (eta=4), row message size 2^24, rate 1/2, encoded row length 2^25,
terminal message size 2^12, and 1290 queries. Its numerical distance candidate
is 0.1543985025, rounded down to 0.154398. This is the local implementation,
not a benchmark of an optimized upstream Plonky3 BaseFold fork. Parameter
selection optimizes the modeled proof size within the recorded search scope;
it does not establish a global optimum over all protocol parameters.
