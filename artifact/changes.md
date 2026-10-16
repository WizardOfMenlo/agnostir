# Changes and scientific limits

The artifact implements the following corrections relative to the early prototype
and the simplified figures/communication model in the supplied paper:

- Brakedown samples distinct outgoing neighbors per input with the specified
  degrees; earlier code sampled incoming edges and did not justify its distance.
  The systematic RS base is linear. The alternative zero-padding base used in
  the latest codeswitch experiment has distance one and was separately recalibrated.
- The common interleaved argument starts with sumcheck before random row folding,
  so arbitrary public evaluation points (including Boolean points) are supported.
- Fiat-Shamir binds the statement, setup recipe, dimensions, root and messages.
  Canonical scalars, uniform query sampling, Merkle domain separation, full proof
  parsing, and rejection of trailing data are included in all measured timings.
- ERA has two independent multiplier vectors. The codeswitching proof binds
  auxiliary/index oracles before challenge-dependent checks and authenticates
  the permutation argument with batched logUp-GKR. Duplicate query coefficients
  add. Every unique oracle receives an independent batching power.
- Tight packing of non-power-of-two families, OOD claims, extra index rows,
  sumcheck messages, real multiproofs and serialization affect the proof size.
  The old analytical paper model is not the exact wire format.
- Latest optimization preserves the proof byte-for-byte: compact public weight
  evaluation, parallel GKR tree/table construction, parallel denominator/claim
  preparation, shared dense prover arrays, and earlier release of dead storage.
  GKR remains uncheckpointed (25 layers / 300 scalar sumcheck rounds at 2^28).

## Claims that are not made

The query parameters use numerical distance estimates and conditional soundness
budgets. They are not a certified complete 100-bit composed Fiat-Shamir security
proof. ERA's numerical critical-point search and Brakedown's floating-point
sufficient bounds are not interval certificates. EA retains the paper's
conjectured 0.1 distance. SmallRng seeds fix repeatable experiments; they are not
cryptographic setup randomness or certificates for a particular sampled code.

Compact weight evaluation removes oracle-width public arrays in the online
verifier. The non-power-of-two tensor still uses O(n log k') arithmetic for
inner block length n (2109 in the main run). This is not fully polylogarithmic
verification. Preprocessed setup storage and construction are excluded from
online verification timing.

The BaseFold comparison is the local recursive implementation, at rate 1/2
and a saved interleaving/termination choice. It is not a claim about the fastest
available upstream implementation or a global sweep over every BaseFold rate.
