# Artifact audit and corrected implementation (14 October 2026)

This audit found defects that invalidate treating the historical measurements as
validated, serialized 100-bit proofs. The new implementation executes complete
Fiat–Shamir proofs and independent verification. It is a research implementation,
not a completed formal soundness audit. This report predates final packaging.

This report records the prototype corrections. Current scope and limitations
are in [artifact/changes.md](../artifact/changes.md); final reproduction and
licensing are in [the artifact guide](../artifact/README.md). Superseded Bolt
adaptations have been archived and are outside the retained comparison.

## Findings and implemented repairs

1. **Brakedown's graph orientation was wrong.** The old E1 sampled `cn` incoming
   edges per output, not `cn` outgoing edges per input. An input missed by every
   E1 edge affects only its systematic coordinate. Its codeword difference has
   weight one, contradicting the distance assumptions. The new encoder samples
   distinct outgoing neighbours per input and stores the resulting edges by
   output for efficient gathers. E2 is corrected similarly. Recursive dimensions
   use `ceil(alpha*k)` and exact integer codeword lengths.
2. **Brakedown was affine.** Its base case appended fixed random constants.
   `Enc(0)` could be nonzero. Equality-weight folding alone concealed this because
   the weights sum to one. General codeswitch batching does not have that
   property. The base case is now a systematic Reed–Solomon code, with tests for
   zero, linearity, systematic coordinates, and known-polynomial extrapolation.
   Recursion terminates when the proposed expander degrees exceed available
   neighbours; degree is never silently reduced.
3. **The original experiment was interactive.** It accepted externally supplied
   challenges and reported a model or payload count. The new path binds the
   public statement, setup recipe, code dimensions, commitments, evaluations,
   messages and protocol version into a BLAKE3 Fiat–Shamir channel. Query and
   field challenges use rejection sampling. The verifier parses canonical
   scalars, rejects trailing/truncated data, and derives challenges itself.
4. **Arbitrary evaluation points need randomization for proximity.** Direct
   folding at a Boolean row point ignores other rows. The artifact first runs
   `StartingIOR`'s equality-times-message sumcheck, including its cost. It checks
   the final evaluation on the message, not the encoded word.
5. **Merkle hashing lacked domain separation.** Leaf hashes now include a leaf
   tag and column height; internal nodes use a different tag. Complete retained
   trees are timed for commitment. Actual multiproofs deduplicate repeated
   queries and shared siblings. Proof bytes come from the emitted byte vector.
6. **TIP batching in the paper reused a coefficient.** `(a,b)` and `(a+t,b-t)`
   have the same sum but generally different products. Assigning the same gamma
   power to both factors authenticates only their sum. The implementation sends
   each unique oracle's evaluation once and uses distinct powers after those
   values are fixed. The paper figure's two factor ranges are corrected.
7. **Basic permutation checks incorrectly demanded pointwise equality.** Honest
   inverse witnesses are permuted, not equal. For example `(1/59,1/54)` and
   `(1/54,1/59)` have equal sums but unequal coordinates. The figure now uses sums;
   the implementation uses fractional GKR, with no inverse-witness oracles.
8. **The stated quadratic logUp justification was invalid.** The derivative of
   `X²+X*pi+w` is `2X+pi`, not 1. Moreover a product of those quadratic factors
   does not uniquely encode labelled values: labels `(0,1,2)` and values
   `(-49,-30,-48)` versus `(-36,-56,-35)` yield the same product, with roots
   `(-8,-7,-6,5,6,7)`. This is a counterexample to the product assertion, not a
   claimed attack on every rational-sum variant. The replacement uses standard
   independent affine compression `alpha + beta*label + value`, in characteristic
   greater than the vector length. Poles cause rejection, not division by zero.
9. **Permutation orientation matters.** The code uses gather permutations
   `destination[j]=source[pi[j]]`. It compares source pairs `(j,source[j]) with
   destination pairs `(pi[j],destination[j])`. Using `pi` on the source side
   would require the inverse permutation instead.
10. **The GKR communication estimate omits messages.** The four simultaneous
    fraction trees require root numerator/denominator values and child values
    at every layer. The implementation sends eight root scalars and sixteen
    child scalars per layer, plus the batched cubic sumcheck polynomials. Every
    child message precedes the next random folding challenge. Exact transport
    includes these messages. The paper's polynomial-only count is not a full
    serialized-proof estimate.
11. **Stack commitments must precede dependent randomness.** All online message,
    base-code, and permutation vectors are committed together before OOD,
    spot-check, and permutation challenges. The indexer commitment is trusted
    preprocessing and is bound into the transcript. It is not prover-selectable.
12. **Repeated spot queries were ambiguous.** Their weights now add at repeated
    positions, with independent powers indexed by query occurrence. The final
    accumulator claim is reduced directly to a triple product using suffix sums.
13. **Reusing one multiplier leaves a conditioning gap.** The first-stage word
    already depends on the multiplication matrix used again in the paper's
    second-stage bound. Applying a fixed-input random-multiplier lemma needs
    justification under that dependence. The artifact uses independent nonzero
    `M1` and `M2`, as the existing encoder API already allowed. Both are included
    in the indexer. This changes the index stack from `ell_g+3*ell_ERA` to
    `ell_g+4*ell_ERA`. The full distance proof and union bounds still need author
    review; changing the implementation does not by itself repair the theorem.
14. **Non-power-of-two shapes need a contract.** Physical ERA words use exact
    lengths; split messages have zero-padded tails. Tensor claims use packed
    rectangular weights, not an incorrect power-of-two stride. GKR pads with
    numerator 0 and denominator 1, and checks the public mask at its endpoint.
15. **Unsafe uninitialized buffers were unnecessary.** ERA now initializes field
    buffers before borrowing them, checks constructor lengths in release builds,
    and uses single-pass sequential scans when rows are parallelized.
16. **The old estimator admitted equal codeswitch lengths.** Its search now uses
    strictly decreasing lengths. Its remaining cost formulas are historical and
    must not be substituted for serialized measurements of the corrected proof.
17. **Benchmark seeds are not a cryptographic setup guarantee.** The executables
    use deterministic `SmallRng` fixtures with a 64-bit seed to reproduce inputs
    and code matrices. The distance analysis assumes independent uniform setup
    randomness; these fixtures do not establish that distribution or its claimed
    failure probability. The verifier fixes the setup, so the prover cannot
    replace it through the proof. A deployment needs an agreed setup-generation
    procedure with suitable entropy and a reviewed argument for the generated
    code, independently of these reproducible timing fixtures.

## Concrete construction implemented

`src/era_iopp.rs` performs StartingIOR, commits split messages and auxiliaries,
collects an OOD evaluation per online split row, checks sampled initial columns,
proves the tensor encoding relation, runs both affine logUp permutation checks
through batched fractional GKR, emulates accumulation with weighted triple
products, batches all IP/TIP constraints in a sumcheck, batches the unique oracle
evaluations with distinct coefficients, and invokes `src/basefold_iopp.rs`.
The verifier consumes only public setup, public statement, and proof bytes.
The old `src/codeswitching/` helpers are retained as legacy material and are not
called by either new executable.

There are deliberate differences from the paper's optimized cost model:

- Two independent multiplier families, extra GKR messages, and one OOD per split
  online row are counted in the real proof.
- The tensor sumcheck uses a generic cubic bound, even though a specialized
  implementation can exploit disjoint variables to reduce it to quadratic.
- The original verifier materialized public packed weights. The final
  [compact evaluator](era-compact-verifier.md) removes these large arrays;
  the non-power-of-two tensor still has a non-polylogarithmic evaluation cost.
- Initial virtual BaseFold oracles require opening both butterfly coordinates
  from every contributing stack. The transport counts those actual openings.
- Parameters are a documented finite-size adaptation, not a fresh global search
  for the minimum serialized size.

These remaining performance gaps are explicit; this audit does not establish
that no further optimization is possible.

## Finite-size parameter adaptation

The paper's explicit custom table is for `2^32`. Retaining its interleaving
factor 64 at `2^22` gives ERA row length `2^16`, an inner tensor dimension 256,
and a codeswitch to BaseFold length `2^15`, inverse rate 8, termination `2^12`.
The paper's loose tensor distance `0.0001` has no feasible `c` in the numerical
solver at this size. The actual corrected inner encoder terminates at a
systematic `[281,256,26]` RS code; its tensor distance is exactly
`(26/281)^2 = 0.008561188434796923`. This supplies a stronger finite-size input
without changing the inner inverse-rate target 1.1.

`scripts/calibrate_custom.py` uses this input, exact ERA length 315844,
`log2(|F|) >= 255.999`, a nominal 102-bit setup budget and 104-bit query budget,
and rounds numerical distances downward to six decimals:

| Stage | Distance used | Queries |
| --- | ---: | ---: |
| Initial ERA | 0.228604 | 834 |
| Terminal BaseFold, message `2^15`, inverse rate 8 | 0.774422 | 146 |
| Local baseline, message `2^17`, inverse rate 2 | 0.203888 | 949 |

The margins allow room for multiple error terms, but the numerical solvers are
not interval-certified and the complete composed bound (including mutual
correlated agreement, OODs, code setup, sumchecks, random batching and the
Fiat–Shamir transform) is **not certified** by this artifact. The interleaved
CLI's inherited tables are explicitly conditional distance inputs and also need
recalibration against every corrected encoder and integer recursion level.

## Upstream BaseFold status

The pinned Plonky3 revision `a9d5bbb` has FRI but no BaseFold implementation.
The user was asked to identify the intended repository/branch. The paper
[authors' reference](https://github.com/hadasz/plonkish_basefold) was inspected at
`c29f08653121637b456e4705d901d078cd6fc668`.
Its single-proof `verify` in
`plonkish/plonkish_backend/src/pcs/multilinear/basefold.rs` does not use its `comm`
argument and shadows its public `eval` with a value read from the proof.
External transcript binding would have to compensate; the standalone API does
not perform those checks. This is an additional reason not to silently report
that code as a validated comparison.

The delivered recursive baseline extends this repository's nested BaseFold
encoder, uses the same field/hash/transport as ERA, supports initial interleaving
and early termination, and checks both the public root and value. **It is not a
modified upstream Plonky3 implementation. That requested comparison remains
outstanding.** No third-party source from the inspected checkout was vendored.

## Paper changes and remaining review

Small, unambiguous fixes were applied to the sibling paper's StartingIOR,
Reduce, permutation figures, and interleaved evaluation check. More substantial
issues are documented here rather than silently replacing the paper's theorem
or historical performance tables. In particular the independent-multiplier
distance argument, all communication formulas, padding contract, complete error
budget, and revised benchmark tables still require a coherent author-reviewed
paper revision. The multi-file paper compiled with pdfLaTeX, Biber, and two
further pdfLaTeX passes to a 77-page PDF in a temporary directory. Bibliography
and overfull-box warnings remain; this was a compilation check, not publication
layout approval. The initial latexmk attempt incorrectly selected BibTeX, so the
successful check used Biber explicitly.

## Requirements and submission blockers

The [ASIACRYPT artifact call](https://asiacrypt.iacr.org/2026/artifacts.php)
requires source, dependencies, usable build/run instructions, paper mapping,
licensing, and disclosure of generated content. It also requires submission
metadata, the paper PDF, and a fixed version reference. The new README, scripts,
lockfile, results, and `AI_DISCLOSURE.md` address the technical packaging work.
The submission deadline is 15 October 2026.

The subsequent [submission package](artifact-submission.md) supplies the
MIT license, author metadata, dependency notices, fixed source snapshots,
Docker validation and the completed 16-worker on-demand AWS measurements.
It has not been uploaded. An optimized upstream BaseFold comparison and the
scientific qualifications above were not resolved by packaging; they remain
explicitly outside the claims of the delivered artifact.
