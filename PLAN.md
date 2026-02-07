# Reduce IOR implementation plan (codeswitching)

This plan is based on `reduce-ior.tex` and the current Rust module in `src/codeswitch/mod.rs`.

## 1) Lock down notation and parameter mapping

- Map paper symbols to code fields and assert invariants early:
  - `k = 2^{log_start_code_message}`
  - `k' = 2^{log_new_code_message}`
  - `\ell_msg = 2^{log_start_code_message - log_new_code_message}`
  - `n = 2^{log_start_code_blocklength}`
- Keep one place that validates all shape checks and claim sizes.
- Decide final naming for `repetition_parameter` vs `num_spot_checks` (paper uses `numSpotChecks`).

## 2) Complete round-1 message/oracle handling

- Split witness into `\ell_msg` blocks of size `k'`.
- For each block:
  - compute `word_i = Enc(C')(msg_i)`
  - compute `y_eval_i = H_i(z_2)`
  - sample `z_ood_i`
  - compute `y_ood_i = H_i(z_ood_i)`
- Implement and test the verifier check:
  - `sum_b Eq(z_1, b) * y_eval_b == EvalValue`.

## 3) Codeswitch-claims subprotocol integration

- Keep a dedicated interface for the `CodeswitchClaims` subprotocol output:
  - auxiliary oracles
  - IP claims (`oracle ref`, `v`, `sigma`, witness)
  - DIP claims (`left/right oracle refs`, `v`, `sigma`, witnesses)
- Add strict validation for:
  - oracle references
  - oracle lengths (`n'`)
  - vector/witness lengths (`k'`).
- Replace scaffolded/empty claims with real subprotocol generation once `fig:codeswitch-claims` details are fully encoded.

## 4) Replace scaffolded sumcheck with real interaction

- Current scaffold computes `y_r` directly at a random `r`.
- Next step: plug in full sumcheck rounds for
  - folded polynomial `f(X)`
  - target sum `sigma`
  - final claim `f(r)=y_r`.
- Keep transcript/challenge derivation explicit (`beta`, then per-round challenges, then `r`).

## 5) Individual opening checks at `r`

- Keep current structure for `a_eval`, `a_ood`, `a_ip`, `a_dip_left`, `a_dip_right`.
- Confirm exact DIP term indexing from the paper (there are likely minor typos in the draft formulas).
- Add tests that intentionally break one opening and ensure verifier rejects.

## 6) Batching stage and reduced MEP instance

- Keep batching as linear-combination utilities over:
  - scalar openings (`y'`)
  - virtual oracle (`word'`)
  - witness (`msg'`).
- Re-check gamma exponent schedule for DIP terms once formulas are finalized.
- Final output should be:
  - reduced instance `(r, y')`
  - reduced oracle `word'`
  - reduced witness `msg'`.

## 7) Testing and hardening milestones

- Unit tests (small deterministic instances):
  - shape checks
  - eval consistency check
  - oracle reference validation
  - batching linearity
- Property tests:
  - random valid inputs pass
  - small perturbations in claims fail with high probability.
- Add optional tracing hooks for round boundaries and sampled challenges.

---

## What is already scaffolded in code

Implemented in `src/codeswitch/mod.rs`:

- Parameter + input structs for the Reduce IOR flow.
- Round-1 block handling (`msg_i`, `word_i`, `y_eval_i`, `z_ood_i`, `y_ood_i`).
- Spot-check sampling and oracle querying.
- Structured claim containers for IP/DIP with oracle references.
- Scaffolded sumcheck phase (local computation at random `r`).
- Opening aggregation and final batching into reduced claim `(r, y', word', msg')`.
- Basic tests for success path and eval-consistency rejection.
