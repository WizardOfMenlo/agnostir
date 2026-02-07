# Codeswitching Scaffolding Plan (Interface-First)

Status: draft
Owner: next implementation pass

## Goal
Build interface-level scaffolding for the codeswitching reduction described in:
- `codeswitching.tex`
- `reduce-ior.tex`
- `CodeswitchOracles.tex`
- `CodeswitchClaims.tex`

This pass is **not** for full cryptographic implementation. It is for protocol structure, typed interfaces, and round wiring using existing primitives in `src/`.

## Error-handling policy (explicit)
For this phase, **panic on any mismatch**:
- dimension inconsistencies
- invalid lengths
- invalid oracle references
- phase/round ordering violations
- unsupported parameter combinations in scaffolding

Use `assert!`, `assert_eq!`, and `panic!` (not `Result`-based flow for protocol mismatches in this phase).

---

## Phase 0: module wiring
- [ ] Resolve module name mismatch first:
  - `src/lib.rs` exports `pub mod codeswitch;`
  - existing directory is `src/codeswitching/`
- [ ] Choose one naming convention and make it compile before further work.

---

## Phase 1: protocol types and dimensions
Create `src/codeswitching/types.rs` with:
- [ ] `ProtocolDims` (k, k_out, n_base, n_era, n_out, l_msg, l_base, l_era, etc.)
- [ ] `ReduceConfig` (distance params, spot-check count, optimization toggles)
- [ ] `MepInstance<F>` and `MepWitness<F>`
- [ ] `validate()` methods that assert all algebraic equalities from the spec

Notes:
- All invariants should be checked eagerly and panic on failure.

---

## Phase 2: oracle and challenge abstractions
Create `src/codeswitching/oracle.rs` and `src/codeswitching/transcript.rs` with:
- [ ] `OracleId` newtype
- [ ] `OracleRole` enum (`Index`, `MessageChunk`, `Era`, `Base`, `Perm`, `Mult`, `Acc`, `Aux`, `Virtual`)
- [ ] `OracleBackend<F>` trait:
  - `commit(role, values) -> OracleId`
  - `query(id, index) -> F`
  - `len(id) -> usize`
- [ ] `ChallengeSource<F>` trait:
  - `sample_field(label) -> F`
  - `sample_point(label, dim) -> Vec<F>`
  - `sample_indices(label, count, domain_size) -> Vec<usize>`

Notes:
- Backend/transcript implementations can initially be in-memory test scaffolding.
- Invalid queries/ids must panic.

---

## Phase 3: split helpers and claim descriptors
Create `src/codeswitching/split.rs` and `src/codeswitching/claims.rs` with:
- [ ] `split_and_encode(...)` interface for chunking + encoding under output code
- [ ] claim descriptor structs:
  - `IpClaim<F>`
  - `TipClaim<F>`
  - `LinearForm<F>` (eq-point, sparse powers, geometric, dense)
- [ ] `split_claim_ip(...) -> Vec<IpClaim<F>>`
- [ ] `split_claim_tip(...) -> Vec<TipClaim<F>>`

Notes:
- This layer should describe claims and wiring only.
- Claim construction validates shapes and panics on mismatch.

---

## Phase 4: indexer scaffolding (`CodeswitchOracles`)
Create `src/codeswitching/indexer.rs` with:
- [ ] `CodeswitchIndexInput`
- [ ] `EraPublicParams<F>` sidecar (permutations/multipliers/public vectors)
- [ ] `CodeswitchIndexArtifacts` (index oracles + metadata)
- [ ] `build_codeswitch_oracles(...)`

Notes:
- Since ERA internals are not fully exposed, prefer explicit public-params input.
- Any length/permutation mismatch should panic.

---

## Phase 5: `CodeswitchClaims` planner (round skeleton)
Create `src/codeswitching/codeswitch_claims.rs` with:
- [ ] `generate_codeswitch_claims(...) -> CodeswitchClaimsArtifacts<F>`
- [ ] staged outputs for:
  - committed aux oracles
  - generated IP/TIP claim descriptors
  - counters (`num_ip`, `num_tip`, aux oracle count)
  - trace/log of round actions

Notes:
- This is claim graph + sequencing, not final proof machinery.
- Enforce commit-before-challenge ordering from spec; panic on violations.

---

## Phase 6: top-level reduction skeleton (`Reduce IOR`)
Create `src/codeswitching/reduce.rs` with:
- [ ] `index(...) -> ReduceIndexOutput`
- [ ] `prove_round(...) -> ReduceProverOutput<F>`
- [ ] `verify_round(...) -> ReduceVerifierOutput<F>`
- [ ] round flow corresponding to `reduce-ior.tex`

Notes:
- Sumcheck/permutation internals may remain `todo!()` placeholders in this phase.
- Structural checks and wiring must be implemented and panic on mismatch.

---

## Phase 7: scaffolding tests
Create `src/codeswitching/tests.rs` (or submodule tests) with:
- [ ] dimension validation tests
- [ ] split-and-encode shape tests
- [ ] index oracle count/length tests
- [ ] claim planner count tests (`num_ip`, `num_tip`, aux)
- [ ] round-order tests (commit/challenge discipline)

Notes:
- Tests should use small toy parameters.

---

## Open spec items to keep visible
- [ ] finalize `numSpotChecks`
- [ ] decide OOD policy (shared vs per-piece points)
- [ ] decide when to activate sigma-compression optimization
- [ ] decide stacked-oracle strategy (single vs pre/post-challenge split)
- [ ] normalize naming inconsistencies from tex into code terms

---

## Non-goals for this pass
- full sumcheck implementation
- full permutation argument implementation
- proof-system optimization work
- final transcript/Fiat-Shamir integration

This pass is only for robust interfaces and executable scaffolding.