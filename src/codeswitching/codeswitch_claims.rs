//! CodeswitchClaims API from `codeswitching.tex` / `CodeswitchClaims.tex`.
//!
//! Implemented so far:
//! - Steps 1-6 (through the codeswitch IP claim over sampled spotchecks).
//! - Base-code encoding (`word^CodeB = Enc_CodeB(msg)`) and split/encode.
//! - Step 10 challenge sampling: `r^x <- F^{log2(n_CodeB)}`.
//! - Step 11 (`sigma_code_b_at_r_x = w_hat^CodeB(r^x)`).
//! - Step 12 reduction via `TIPSumcheck` to
//!   `(base_code_sumcheck_challenges, base_code_sumcheck_reduced_claim)`.
//! - Step 13 evaluations at `r^y`:
//!   `sigma_code_b_g_left_at_r_y`, `sigma_code_b_g_right_at_r_y`,
//!   `sigma_code_b_msg_at_r_y`.
//! - Step 14 split IP claims at points `r^x`, `(r^x_1, r^y_1)`,
//!   `(r^x_2, r^y_2)`, and `r^y`.
//! - Steps 15-17 repeated-vector claims/oracle simulation.
//! - Step 18 first permute commitment (`word^perm`, `oracle^perm`).
//! - Step 19 first permute out-of-domain check.
//! - Step 20 first-permutation checks through transition sumcheck reductions
//!   and related opening/IP claims (currently using placeholder
//!   prefix-product witnesses for `a_2,b_2`).
//! - Step 21 first multiply vector `word^mult = word^perm ⊙ v_1`.
//! - Step 22 first multiply split encoding + OOD opening/IP claim.
//! - Step 23 first multiply geometric challenge vector `r^mult` and
//!   triple-product claim `sigma^mult`.
//! - Step 24 first multiply `SplitClaimTIP(word^perm, v_1, r^mult, sigma^mult)`
//!   and `SplitClaimIP(word^mult, r^mult, sigma^mult)` reductions.
//! - Step 25 first accumulate vector `word^acc = A * word^mult` (using the
//!   standard prefix-sum accumulate map).
//! - Step 26 first accumulate split encoding + OOD opening/IP claim.
//! - Steps 27-31 first-accumulate random-point reduction and paired
//!   `SplitClaimIP` checks against `word^mult`/`word^acc`.
//! - Step 33 second permute commitment (`word^perm_2`, `oracle^{perm_2}`)
//!   and out-of-domain check.
//! - Step 34 second-permutation consistency checks (analogue of step 20)
//!   through transition sumcheck reductions and related opening/IP claims
//!   (currently using placeholder prefix-product witnesses for `a_2,b_2`).
//! - Step 35 second multiply/accumulate chain (using `multiplier_2`) ending
//!   with validation that the second accumulate output reconstructs `word^ERA`.

use rand::Rng;

use super::claims::{SplitIpClaim, SplitTipClaim, split_claim_ip, split_claim_tip};
use super::oracles::{SplitEncoding, split_and_encode};
use super::sumcheck::{
    PermutationTransitionSumcheck, TIPSumcheck, build_permutation_transition_tables,
};
use crate::poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint};
use crate::{ErrorCorrectingCode, FieldElement};

/// One verifier spotcheck target used by `CodeswitchClaims`.
///
/// `alpha` is a 0-based oracle index in `[0, n_era)`.
#[derive(Debug, Clone)]
pub struct CodeswitchSpotcheck<F> {
    pub alpha: usize,
    pub sigma_cs: F,
}

/// Full input contract for `CodeswitchClaims`.
#[derive(Debug, Clone)]
pub struct CodeswitchClaimsInput<F> {
    /// Prover witness message `msg`.
    pub msg: Vec<F>,
    /// Spotcheck pairs `(alpha_j, sigma_cs_j)`.
    pub spotchecks: Vec<CodeswitchSpotcheck<F>>,
    /// Flattened generator matrix of `CodeB'` (row-major), of shape
    /// `sqrt(n_code_b) × sqrt(k)` as used in the base-code sumcheck.
    pub base_code_prime_generator_matrix: Vec<F>,
    /// First permutation vector over `[0, n_era)` used to define `word^perm`.
    pub permutation_1: Vec<usize>,
    /// Second permutation vector over `[0, n_era)` used to define `word^perm_2`.
    pub permutation_2: Vec<usize>,
    /// First multiply vector `v_1` of length `n_era`.
    pub multiplier_1: Vec<F>,
    /// Second multiply vector `v_2` of length `n_era`.
    pub multiplier_2: Vec<F>,
}

/// Full output contract for `CodeswitchClaims`.
#[derive(Debug, Clone)]
pub struct CodeswitchClaimsOutput<F> {
    /// `word^ERA = Enc_ERA(msg)`.
    pub word_era: Vec<F>,
    /// Split output-code commitments to `word^ERA`.
    pub era_oracles: SplitEncoding<F>,

    /// Sampled verifier out-of-domain point `z_ood^ERA`.
    pub z_ood_era: Vec<F>,
    /// Claimed OOD value `sigma_ood^ERA = w_hat^ERA(z_ood^ERA)`.
    pub sigma_ood_era: F,
    /// Claims produced by
    /// `SplitClaimIP(word^ERA, eq(z_ood^ERA), sigma_ood^ERA, ...)`.
    pub ood_ip_claims: Vec<SplitIpClaim<F>>,

    /// Sampled verifier challenge from step 3.
    pub beta: F,

    /// Codeswitch vector from step 4.
    pub v_cs: Vec<F>,
    /// Aggregated spotcheck scalar from step 5.
    pub sigma_cs: F,
    /// Claims produced by `SplitClaimIP(word^ERA, v_cs, sigma_cs, ...)`.
    pub codeswitch_ip_claims: Vec<SplitIpClaim<F>>,

    /// `word^CodeB = Enc_CodeB(msg)`.
    pub word_code_b: Vec<F>,
    /// Split output-code commitments to `word^CodeB`.
    pub code_b_oracles: SplitEncoding<F>,

    /// Step 10 challenge `r^x` sampled by the verifier.
    pub r_x_code_b: Vec<F>,
    /// Step 11 claimed value `w_hat^CodeB(r^x)`.
    pub sigma_code_b_at_r_x: F,

    /// Step 12 TIP-sumcheck prover messages `(h(0), h(1/2), h(2))` per round.
    pub base_code_sumcheck_round_polys: Vec<[F; 3]>,
    /// Step 12 verifier challenges sampled during sumcheck rounds (`r^y`,
    /// in round order).
    pub base_code_sumcheck_challenges: Vec<F>,
    /// Step 12 reduced claim at `r^y` (named `sigma_eval^CodeB` in the spec).
    pub base_code_sumcheck_reduced_claim: F,

    /// Step 13 value `g_hat(r_x_left, r_y_left)`.
    pub sigma_code_b_g_left_at_r_y: F,
    /// Step 13 value `g_hat(r_x_right, r_y_right)`.
    pub sigma_code_b_g_right_at_r_y: F,
    /// Step 13 value `m_hat(r_y)`.
    pub sigma_code_b_msg_at_r_y: F,

    /// Step 14 split-IP claims for
    /// `SplitClaimIP(word^CodeB, eq(r^x), sigma_code_b_at_r_x, ...)`.
    pub base_code_word_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 14 split-IP claims for
    /// `SplitClaimIP(g, eq(r_x_left, r_y_left), sigma_code_b_g_left_at_r_y, ...)`.
    pub base_code_g_left_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 14 split-IP claims for
    /// `SplitClaimIP(g, eq(r_x_right, r_y_right), sigma_code_b_g_right_at_r_y, ...)`.
    pub base_code_g_right_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 14 split-IP claims for
    /// `SplitClaimIP(msg, eq(r^y), sigma_code_b_msg_at_r_y, ...)`.
    pub base_code_msg_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 15 repeated vector `word^rep` (repeat `word^CodeB` by `n_era/n_code_b`).
    pub word_rep: Vec<F>,
    /// Step 16-17 simulated repeated oracles from `code_b_oracles`.
    pub rep_oracles: SplitEncoding<F>,
    /// Step 17 evaluation point used for repeated-vector IP claim.
    pub r_rep: Vec<F>,
    /// Step 17 claimed value `w_hat^rep(r_rep)`.
    pub sigma_rep_at_r_rep: F,
    /// Step 17 split-IP claims for
    /// `SplitClaimIP(word^rep, eq(r_rep), sigma_rep_at_r_rep, ...)`.
    pub repeat_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 18 first permuted vector `word^perm`.
    pub word_perm: Vec<F>,
    /// Step 18 split output-code commitments to `word^perm`.
    pub perm_oracles: SplitEncoding<F>,

    /// Step 19 sampled verifier out-of-domain point `z_ood^perm`.
    pub z_ood_perm: Vec<F>,
    /// Step 19 claimed value `sigma_ood^perm = w_hat^perm(z_ood^perm)`.
    pub sigma_ood_perm: F,
    /// Step 19 split-IP claims for
    /// `SplitClaimIP(word^perm, eq(z_ood^perm), sigma_ood^perm, ...)`.
    pub perm_ood_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 20 permutation-check challenge `alpha`.
    pub permutation_alpha: F,
    /// Step 20 permutation-check challenge `beta`.
    pub permutation_beta: F,

    /// Step 20 identity vector `id` over `[0, n_era)` encoded in the field.
    pub permutation_identity_vector: Vec<F>,
    /// Step 20 first permutation vector `pi_1` encoded in the field.
    pub permutation_pi_1_vector: Vec<F>,

    /// Step 20 permutation witness vector `a_1`.
    pub permutation_a_1: Vec<F>,
    /// Step 20 permutation witness vector `a_2`.
    pub permutation_a_2: Vec<F>,
    /// Step 20 permutation witness vector `b_1`.
    pub permutation_b_1: Vec<F>,
    /// Step 20 permutation witness vector `b_2`.
    pub permutation_b_2: Vec<F>,

    /// Step 20 split output-code commitments to `a_1`.
    pub permutation_a_1_oracles: SplitEncoding<F>,
    /// Step 20 split output-code commitments to `a_2`.
    pub permutation_a_2_oracles: SplitEncoding<F>,
    /// Step 20 split output-code commitments to `b_1`.
    pub permutation_b_1_oracles: SplitEncoding<F>,
    /// Step 20 split output-code commitments to `b_2`.
    pub permutation_b_2_oracles: SplitEncoding<F>,

    /// Step 20 OOD point for `a_1`.
    pub permutation_a_1_z_ood: Vec<F>,
    /// Step 20 OOD point for `a_2`.
    pub permutation_a_2_z_ood: Vec<F>,
    /// Step 20 OOD point for `b_1`.
    pub permutation_b_1_z_ood: Vec<F>,
    /// Step 20 OOD point for `b_2`.
    pub permutation_b_2_z_ood: Vec<F>,

    /// Step 20 OOD value `a_1(z_ood)`.
    pub permutation_a_1_sigma_ood: F,
    /// Step 20 OOD value `a_2(z_ood)`.
    pub permutation_a_2_sigma_ood: F,
    /// Step 20 OOD value `b_1(z_ood)`.
    pub permutation_b_1_sigma_ood: F,
    /// Step 20 OOD value `b_2(z_ood)`.
    pub permutation_b_2_sigma_ood: F,

    /// Step 20 `SplitClaimIP(a_1, eq(z_ood), sigma_ood, ...)` claims.
    pub permutation_a_1_ood_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(a_2, eq(z_ood), sigma_ood, ...)` claims.
    pub permutation_a_2_ood_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(b_1, eq(z_ood), sigma_ood, ...)` claims.
    pub permutation_b_1_ood_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(b_2, eq(z_ood), sigma_ood, ...)` claims.
    pub permutation_b_2_ood_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 20 fixed point used for the initial `a_1/b_1` consistency opening.
    pub permutation_fixed_point: Vec<F>,
    /// Step 20 value `a_1(permutation_fixed_point)`.
    pub permutation_a_1_sigma_fixed: F,
    /// Step 20 value `b_1(permutation_fixed_point)`.
    pub permutation_b_1_sigma_fixed: F,
    /// Step 20 `SplitClaimIP(a_1, eq(permutation_fixed_point), ...)` claims.
    pub permutation_a_1_fixed_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(b_1, eq(permutation_fixed_point), ...)` claims.
    pub permutation_b_1_fixed_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 20 permutation challenge point `r^perm`.
    pub permutation_r_perm: Vec<F>,
    /// Step 20 value `a_1(r^perm)`.
    pub permutation_sigma_a_at_r_perm: F,
    /// Step 20 value `b_1(r^perm)`.
    pub permutation_sigma_b_at_r_perm: F,
    /// Step 20 value `id(r^perm)`.
    pub permutation_sigma_id_at_r_perm: F,
    /// Step 20 value `word^rep(r^perm)`.
    pub permutation_sigma_word_rep_at_r_perm: F,
    /// Step 20 value `word^perm(r^perm)`.
    pub permutation_sigma_word_perm_at_r_perm: F,
    /// Step 20 value `pi_1(r^perm)`.
    pub permutation_sigma_pi_1_at_r_perm: F,

    /// Step 20 `SplitClaimIP(a_1, eq(r^perm), sigma_a, ...)` claims.
    pub permutation_a_1_r_perm_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(b_1, eq(r^perm), sigma_b, ...)` claims.
    pub permutation_b_1_r_perm_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(word^rep, eq(r^perm), sigma_word_rep, ...)` claims.
    pub permutation_word_rep_r_perm_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(word^perm, eq(r^perm), sigma_word_perm, ...)` claims.
    pub permutation_word_perm_r_perm_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(id, eq(r^perm), sigma_id, ...)` claims.
    pub permutation_identity_r_perm_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(pi_1, eq(r^perm), sigma_pi_1, ...)` claims.
    pub permutation_pi_1_r_perm_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 20 transition-sumcheck claim
    /// `sum_x eq(x, r^perm) * (a(1,x) - a(x,0)a(x,1))`.
    pub permutation_a_transition_sum_claim: F,
    /// Step 20 transition-sumcheck round messages for `a`.
    pub permutation_a_transition_sumcheck_round_polys: Vec<[F; 3]>,
    /// Step 20 transition-sumcheck verifier challenges for `a` (round order).
    pub permutation_a_transition_sumcheck_challenges: Vec<F>,
    /// Step 20 reduced claim `y_{r^a}` from the `a` transition sumcheck.
    pub permutation_a_transition_reduced_claim: F,
    /// Step 20 random point `r^a` (multilinear variable order).
    pub permutation_r_a: Vec<F>,
    /// Step 20 opening `a(1, r^a) = a_2(r^a)`.
    pub permutation_a_sigma_one_at_r_a: F,
    /// Step 20 openings `a(i, r_R^a, j)` stored as `[i][j]`.
    pub permutation_a_sigma_i_r_a_tail_j: [[F; 2]; 2],
    /// Step 20 interpolated opening `a(r^a, 0)`.
    pub permutation_a_sigma_r_a_0: F,
    /// Step 20 interpolated opening `a(r^a, 1)`.
    pub permutation_a_sigma_r_a_1: F,
    /// Step 20 `SplitClaimIP(a_2, eq(r^a), a(1,r^a), ...)` claims.
    pub permutation_a_2_r_a_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(a_{i+1}, eq(r_R^a, j), a(i,r_R^a,j), ...)` claims
    /// stored as `[i][j]`.
    pub permutation_a_r_a_tail_ip_claims: [[Vec<SplitIpClaim<F>>; 2]; 2],

    /// Step 20 transition-sumcheck claim
    /// `sum_x eq(x, r^perm) * (b(1,x) - b(x,0)b(x,1))`.
    pub permutation_b_transition_sum_claim: F,
    /// Step 20 transition-sumcheck round messages for `b`.
    pub permutation_b_transition_sumcheck_round_polys: Vec<[F; 3]>,
    /// Step 20 transition-sumcheck verifier challenges for `b` (round order).
    pub permutation_b_transition_sumcheck_challenges: Vec<F>,
    /// Step 20 reduced claim `y_{r^b}` from the `b` transition sumcheck.
    pub permutation_b_transition_reduced_claim: F,
    /// Step 20 random point `r^b` (multilinear variable order).
    pub permutation_r_b: Vec<F>,
    /// Step 20 opening `b(1, r^b) = b_2(r^b)`.
    pub permutation_b_sigma_one_at_r_b: F,
    /// Step 20 openings `b(i, r_R^b, j)` stored as `[i][j]`.
    pub permutation_b_sigma_i_r_b_tail_j: [[F; 2]; 2],
    /// Step 20 interpolated opening `b(r^b, 0)`.
    pub permutation_b_sigma_r_b_0: F,
    /// Step 20 interpolated opening `b(r^b, 1)`.
    pub permutation_b_sigma_r_b_1: F,
    /// Step 20 `SplitClaimIP(b_2, eq(r^b), b(1,r^b), ...)` claims.
    pub permutation_b_2_r_b_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 20 `SplitClaimIP(b_{i+1}, eq(r_R^b, j), b(i,r_R^b,j), ...)` claims
    /// stored as `[i][j]`.
    pub permutation_b_r_b_tail_ip_claims: [[Vec<SplitIpClaim<F>>; 2]; 2],

    /// Step 21 first multiplied vector `word^mult = word^perm ⊙ v_1`.
    pub word_mult: Vec<F>,
    /// Step 22 split output-code commitments to `word^mult`.
    pub mult_oracles: SplitEncoding<F>,
    /// Step 22 sampled verifier out-of-domain point `z_ood^mult`.
    pub z_ood_mult: Vec<F>,
    /// Step 22 claimed value `sigma_ood^mult = w_hat^mult(z_ood^mult)`.
    pub sigma_ood_mult: F,
    /// Step 22 split-IP claims for
    /// `SplitClaimIP(word^mult, eq(z_ood^mult), sigma_ood^mult, ...)`.
    pub mult_ood_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 23 scalar challenge `r_mult` used to derive the geometric vector.
    pub r_mult_challenge: F,
    /// Step 23 geometric vector `(1, r_mult, r_mult^2, ..., r_mult^{n_era-1})`.
    pub r_mult: Vec<F>,
    /// Step 23 triple-product value
    /// `sigma^mult = <word^perm ⊙ v_1, r^mult>`.
    pub sigma_mult: F,

    /// Step 24 split-TIP claims for
    /// `SplitClaimTIP(word^perm, v_1, r^mult, sigma^mult, ...)`.
    pub multiply_tip_claims: Vec<SplitTipClaim<F>>,
    /// Step 24 split-IP claims for
    /// `SplitClaimIP(word^mult, r^mult, sigma^mult, ...)`.
    pub mult_r_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 25 first accumulated vector `word^acc = A * word^mult`.
    pub word_acc: Vec<F>,
    /// Step 26 split output-code commitments to `word^acc`.
    pub acc_oracles: SplitEncoding<F>,
    /// Step 26 sampled verifier out-of-domain point `z_ood^acc`.
    pub z_ood_acc: Vec<F>,
    /// Step 26 claimed value `sigma_ood^acc = w_hat^acc(z_ood^acc)`.
    pub sigma_ood_acc: F,
    /// Step 26 split-IP claims for
    /// `SplitClaimIP(word^acc, eq(z_ood^acc), sigma_ood^acc, ...)`.
    pub acc_ood_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 27 verifier challenge point `r^acc`.
    pub r_acc: Vec<F>,
    /// Step 28 accumulate-map row `A_{r^acc}` for the prefix-sum map.
    pub acc_map_row_at_r_acc: Vec<F>,
    /// Step 29 claimed value `sigma^acc = w_hat^acc(r^acc)`.
    pub sigma_acc: F,
    /// Step 30 split-IP claims for
    /// `SplitClaimIP(word^mult, A_{r^acc}, sigma^acc, ...)`.
    pub acc_mult_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 31 split-IP claims for
    /// `SplitClaimIP(word^acc, eq(r^acc), sigma^acc, ...)`.
    pub acc_r_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 33 second permuted vector `word^perm_2`.
    pub word_perm_2: Vec<F>,
    /// Step 33 split output-code commitments to `word^perm_2`.
    pub perm_2_oracles: SplitEncoding<F>,
    /// Step 33 sampled verifier out-of-domain point `z_ood^{perm_2}`.
    pub z_ood_perm_2: Vec<F>,
    /// Step 33 claimed value `sigma_ood^{perm_2} = w_hat^{perm_2}(z_ood^{perm_2})`.
    pub sigma_ood_perm_2: F,
    /// Step 33 split-IP claims for
    /// `SplitClaimIP(word^{perm_2}, eq(z_ood^{perm_2}), sigma_ood^{perm_2}, ...)`.
    pub perm_2_ood_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 35 second multiplied vector `word^mult_2 = word^{perm_2} ⊙ v_2`.
    pub word_mult_2: Vec<F>,
    /// Step 35 split output-code commitments to `word^mult_2`.
    pub mult_2_oracles: SplitEncoding<F>,
    /// Step 35 sampled verifier out-of-domain point `z_ood^{mult_2}`.
    pub z_ood_mult_2: Vec<F>,
    /// Step 35 claimed value `sigma_ood^{mult_2} = w_hat^{mult_2}(z_ood^{mult_2})`.
    pub sigma_ood_mult_2: F,
    /// Step 35 split-IP claims for
    /// `SplitClaimIP(word^{mult_2}, eq(z_ood^{mult_2}), sigma_ood^{mult_2}, ...)`.
    pub mult_2_ood_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 35 scalar challenge `r_mult_2`.
    pub r_mult_challenge_2: F,
    /// Step 35 geometric vector `(1, r_mult_2, r_mult_2^2, ..., r_mult_2^{n_era-1})`.
    pub r_mult_2: Vec<F>,
    /// Step 35 triple-product value
    /// `sigma^{mult_2} = <word^{perm_2} ⊙ v_2, r^{mult_2}>`.
    pub sigma_mult_2: F,
    /// Step 35 split-TIP claims for
    /// `SplitClaimTIP(word^{perm_2}, v_2, r^{mult_2}, sigma^{mult_2}, ...)`.
    pub multiply_tip_claims_2: Vec<SplitTipClaim<F>>,
    /// Step 35 split-IP claims for
    /// `SplitClaimIP(word^{mult_2}, r^{mult_2}, sigma^{mult_2}, ...)`.
    pub mult_2_r_ip_claims: Vec<SplitIpClaim<F>>,

    /// Step 35 second accumulated vector `word^acc_2 = A * word^mult_2`.
    pub word_acc_2: Vec<F>,
    /// Step 35 split output-code commitments to `word^acc_2`.
    pub acc_2_oracles: SplitEncoding<F>,
    /// Step 35 sampled verifier out-of-domain point `z_ood^{acc_2}`.
    pub z_ood_acc_2: Vec<F>,
    /// Step 35 claimed value `sigma_ood^{acc_2} = w_hat^{acc_2}(z_ood^{acc_2})`.
    pub sigma_ood_acc_2: F,
    /// Step 35 split-IP claims for
    /// `SplitClaimIP(word^{acc_2}, eq(z_ood^{acc_2}), sigma_ood^{acc_2}, ...)`.
    pub acc_2_ood_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 35 verifier challenge point `r^{acc_2}`.
    pub r_acc_2: Vec<F>,
    /// Step 35 accumulate-map row `A_{r^{acc_2}}` for the prefix-sum map.
    pub acc_map_row_at_r_acc_2: Vec<F>,
    /// Step 35 claimed value `sigma^{acc_2} = w_hat^{acc_2}(r^{acc_2})`.
    pub sigma_acc_2: F,
    /// Step 35 split-IP claims for
    /// `SplitClaimIP(word^{mult_2}, A_{r^{acc_2}}, sigma^{acc_2}, ...)`.
    pub acc_mult_2_ip_claims: Vec<SplitIpClaim<F>>,
    /// Step 35 split-IP claims for
    /// `SplitClaimIP(word^{acc_2}, eq(r^{acc_2}), sigma^{acc_2}, ...)`.
    pub acc_2_r_ip_claims: Vec<SplitIpClaim<F>>,

    /// Accumulated protocol artifacts.
    pub aux_oracles: Vec<SplitEncoding<F>>,
    pub ip_claims: Vec<SplitIpClaim<F>>,
    pub tip_claims: Vec<SplitTipClaim<F>>,
}

/// Compute `base^exp` over the field.
fn pow_field<F: FieldElement>(base: F, exp: usize) -> F {
    let mut result = F::ONE;
    let mut cur = base;
    let mut e = exp;

    while e > 0 {
        if e & 1 == 1 {
            result *= cur;
        }
        cur *= cur;
        e >>= 1;
    }

    result
}

fn evaluate_generator_matrix_rows_at_point<F: FieldElement>(
    generator_matrix_flat: &[F],
    row_count: usize,
    col_count: usize,
    row_point: &[F],
) -> Vec<F> {
    assert_eq!(
        generator_matrix_flat.len(),
        row_count * col_count,
        "base_code_prime_generator_matrix must match row_count * col_count"
    );

    let row_weights = MultilinearPoint(row_point.to_vec()).eq_weights();
    assert_eq!(
        row_weights.len(),
        row_count,
        "row challenge dimension does not match generator matrix row dimension"
    );

    (0..col_count)
        .map(|col| {
            (0..row_count).fold(F::ZERO, |acc, row| {
                acc + row_weights[row] * generator_matrix_flat[row * col_count + col]
            })
        })
        .collect()
}

fn build_base_code_sumcheck_tip_tables<F: FieldElement>(
    base_code_prime_generator_matrix: &[F],
    r_x_code_b: &[F],
    msg: &[F],
) -> (Vec<F>, Vec<F>, Vec<F>) {
    assert!(
        !r_x_code_b.is_empty(),
        "base-code sumcheck requires non-empty r_x challenge"
    );
    assert!(
        r_x_code_b.len().is_multiple_of(2),
        "base-code sumcheck requires an even-sized r_x challenge to parse (r_x_left, r_x_right)"
    );

    let msg_len = msg.len();
    assert!(
        msg_len.is_power_of_two(),
        "msg length must be a power of two"
    );
    let log_k = msg_len.ilog2() as usize;
    assert!(
        log_k.is_multiple_of(2),
        "base-code sumcheck requires even log2(k) to parse y=(y_left,y_right)"
    );

    let code_b_prime_row_count = 1usize << (r_x_code_b.len() / 2);
    let code_b_prime_col_count = 1usize << (log_k / 2);

    assert_eq!(
        base_code_prime_generator_matrix.len(),
        code_b_prime_row_count * code_b_prime_col_count,
        "base_code_prime_generator_matrix must have length sqrt(n_code_b) * sqrt(k)"
    );

    let (r_x_left_half, r_x_right_half) = r_x_code_b.split_at(r_x_code_b.len() / 2);

    let generator_eval_at_r_x_left = evaluate_generator_matrix_rows_at_point(
        base_code_prime_generator_matrix,
        code_b_prime_row_count,
        code_b_prime_col_count,
        r_x_left_half,
    );
    let generator_eval_at_r_x_right = evaluate_generator_matrix_rows_at_point(
        base_code_prime_generator_matrix,
        code_b_prime_row_count,
        code_b_prime_col_count,
        r_x_right_half,
    );

    let mut generator_left_table = Vec::with_capacity(msg_len);
    let mut generator_right_table = Vec::with_capacity(msg_len);

    for left_eval in &generator_eval_at_r_x_left {
        for right_eval in &generator_eval_at_r_x_right {
            generator_left_table.push(*left_eval);
            generator_right_table.push(*right_eval);
        }
    }

    (generator_left_table, generator_right_table, msg.to_vec())
}

fn repeat_vector<F: Copy>(values: &[F], repeat_factor: usize) -> Vec<F> {
    assert!(repeat_factor > 0, "repeat_factor must be > 0");

    let mut repeated = Vec::with_capacity(values.len() * repeat_factor);
    for _ in 0..repeat_factor {
        repeated.extend_from_slice(values);
    }
    repeated
}

fn repeat_split_encoding<F: Clone>(
    encoding: &SplitEncoding<F>,
    repeat_factor: usize,
) -> SplitEncoding<F> {
    assert!(repeat_factor > 0, "repeat_factor must be > 0");

    let mut chunks = Vec::with_capacity(encoding.chunks.len() * repeat_factor);
    let mut codewords = Vec::with_capacity(encoding.codewords.len() * repeat_factor);

    for _ in 0..repeat_factor {
        chunks.extend(encoding.chunks.iter().cloned());
        codewords.extend(encoding.codewords.iter().cloned());
    }

    SplitEncoding { chunks, codewords }
}

fn assert_is_permutation(perm: &[usize], n: usize, label: &str) {
    assert_eq!(perm.len(), n, "{label} length must be exactly {n}");
    let mut seen = vec![false; n];
    for &value in perm {
        assert!(value < n, "{label} contains out-of-range value {value}");
        assert!(!seen[value], "{label} contains duplicate value {value}");
        seen[value] = true;
    }
}

fn apply_permutation<F: Copy>(values: &[F], permutation: &[usize]) -> Vec<F> {
    assert_eq!(
        values.len(),
        permutation.len(),
        "permutation length must match values length"
    );

    permutation.iter().map(|&idx| values[idx]).collect()
}

fn hadamard_product<F: FieldElement>(
    lhs: &[F],
    rhs: &[F],
    lhs_label: &str,
    rhs_label: &str,
) -> Vec<F> {
    assert_eq!(
        lhs.len(),
        rhs.len(),
        "{lhs_label} length must match {rhs_label} length"
    );

    lhs.iter()
        .zip(rhs.iter())
        .map(|(&lhs_value, &rhs_value)| lhs_value * rhs_value)
        .collect()
}

fn inner_product<F: FieldElement>(lhs: &[F], rhs: &[F], lhs_label: &str, rhs_label: &str) -> F {
    assert_eq!(
        lhs.len(),
        rhs.len(),
        "{lhs_label} length must match {rhs_label} length"
    );

    lhs.iter()
        .zip(rhs.iter())
        .fold(F::ZERO, |acc, (&lhs_value, &rhs_value)| {
            acc + lhs_value * rhs_value
        })
}

fn triple_product<F: FieldElement>(
    first: &[F],
    second: &[F],
    third: &[F],
    first_label: &str,
    second_label: &str,
    third_label: &str,
) -> F {
    assert_eq!(
        first.len(),
        second.len(),
        "{first_label} length must match {second_label} length"
    );
    assert_eq!(
        first.len(),
        third.len(),
        "{first_label} length must match {third_label} length"
    );

    first.iter().zip(second.iter()).zip(third.iter()).fold(
        F::ZERO,
        |acc, ((&first_value, &second_value), &third_value)| {
            acc + first_value * second_value * third_value
        },
    )
}

fn geometric_power_vector<F: FieldElement>(base: F, len: usize) -> Vec<F> {
    assert!(len > 0, "geometric vector length must be > 0");

    let mut out = Vec::with_capacity(len);
    let mut cur = F::ONE;
    for _ in 0..len {
        out.push(cur);
        cur *= base;
    }
    out
}

fn prefix_sums<F: FieldElement>(values: &[F]) -> Vec<F> {
    assert!(!values.is_empty(), "prefix-sums input must be non-empty");

    let mut out = Vec::with_capacity(values.len());
    let mut acc = F::ZERO;
    for &value in values {
        acc += value;
        out.push(acc);
    }
    out
}

fn prefix_sum_accumulate_row_at_point<F: FieldElement>(point: &[F]) -> Vec<F> {
    let eq_weights = MultilinearPoint(point.to_vec()).eq_weights();
    assert!(
        !eq_weights.is_empty(),
        "accumulate-map row requires a non-empty point"
    );

    let mut row = vec![F::ZERO; eq_weights.len()];
    let mut suffix = F::ZERO;
    for index in (0..eq_weights.len()).rev() {
        suffix += eq_weights[index];
        row[index] = suffix;
    }

    row
}

fn prefix_products<F: FieldElement>(values: &[F]) -> Vec<F> {
    assert!(
        !values.is_empty(),
        "prefix-products input must be non-empty"
    );

    let mut out = Vec::with_capacity(values.len());
    let mut acc = F::ONE;
    for &value in values {
        acc *= value;
        out.push(acc);
    }
    out
}

fn build_first_permute_witness_vectors<F: FieldElement>(
    word_rep: &[F],
    word_perm: &[F],
    permutation_1: &[usize],
    permutation_alpha: F,
    permutation_beta: F,
) -> (Vec<F>, Vec<F>, Vec<F>, Vec<F>, Vec<F>, Vec<F>) {
    assert_eq!(
        word_rep.len(),
        word_perm.len(),
        "step 20 requires word_rep and word_perm to have the same length"
    );
    assert_eq!(
        permutation_1.len(),
        word_rep.len(),
        "step 20 requires permutation_1 length to match n_era"
    );

    let permutation_identity_vector: Vec<F> = (0..word_rep.len())
        .map(|index| F::from_u32(index as u32))
        .collect();
    let permutation_pi_1_vector: Vec<F> = permutation_1
        .iter()
        .copied()
        .map(|value| F::from_u32(value as u32))
        .collect();

    let permutation_a_1: Vec<F> = word_rep
        .iter()
        .zip(permutation_pi_1_vector.iter())
        .map(|(&word_value, &pi_value)| {
            permutation_alpha - (word_value + permutation_beta * pi_value)
        })
        .collect();
    let permutation_b_1: Vec<F> = word_perm
        .iter()
        .zip(permutation_identity_vector.iter())
        .map(|(&word_value, &id_value)| {
            permutation_alpha - (word_value + permutation_beta * id_value)
        })
        .collect();

    // TODO: Replace this prefix-product witness with the exact ChenBBZ/Blaze
    // O(n)-time witness construction used by the full permutation argument.
    let permutation_a_2 = prefix_products(&permutation_a_1);
    let permutation_b_2 = prefix_products(&permutation_b_1);

    (
        permutation_identity_vector,
        permutation_pi_1_vector,
        permutation_a_1,
        permutation_a_2,
        permutation_b_1,
        permutation_b_2,
    )
}

fn evaluate_multilinear_table<F: FieldElement>(table: &[F], point: &[F]) -> F {
    EvaluationsList::new(table.to_vec()).evaluate(&MultilinearPoint(point.to_vec()))
}

fn append_coord<F: Copy>(coords: &[F], coord: F) -> Vec<F> {
    let mut out = Vec::with_capacity(coords.len() + 1);
    out.extend_from_slice(coords);
    out.push(coord);
    out
}

fn build_first_permute_fixed_point<F: FieldElement>(dimension: usize) -> Vec<F> {
    assert!(
        dimension >= 2,
        "step 20 fixed-point opening requires log2(n_era) >= 2"
    );

    let mut point = vec![F::ZERO; dimension - 2];
    point.push(F::ONE);
    point.push(F::ZERO);
    point
}

/// Internal helper implementing steps 1-6, base-code encoding, step 10
/// verifier challenge sampling (`r^x`), and steps 11-35 (including first
/// accumulate random-point checks, second-permutation consistency checks,
/// and the second multiply/accumulate chain).
#[must_use]
pub fn generate_codeswitch_claims_up_to_base_code_encoding<F, CEra, CBase, COut>(
    input: &CodeswitchClaimsInput<F>,
    era_code: &CEra,
    base_code: &CBase,
    output_code: &COut,
    rng: &mut impl Rng,
) -> CodeswitchClaimsOutput<F>
where
    F: FieldElement,
    CEra: ErrorCorrectingCode<Alphabet = F>,
    CBase: ErrorCorrectingCode<Alphabet = F>,
    COut: ErrorCorrectingCode<Alphabet = F>,
{
    assert_eq!(
        input.msg.len(),
        era_code.message_size(),
        "msg length must match ERA message size"
    );
    assert_eq!(
        input.msg.len(),
        base_code.message_size(),
        "msg length must match base code message size"
    );

    // Step 1.
    let word_era = era_code.encode(&input.msg);
    assert_eq!(
        word_era.len(),
        era_code.block_length(),
        "ERA encoding length must match ERA block length"
    );

    let era_oracles = split_and_encode(&word_era, output_code);

    // Step 2.
    let n_era = word_era.len();
    assert!(
        n_era.is_power_of_two(),
        "step 2 currently assumes n_era is a power of two"
    );

    // All logs in the paper are base-2.
    let ood_dim = n_era.ilog2() as usize;
    let z_ood_era: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();

    let z_ood_era_ml = MultilinearPoint(z_ood_era.clone());
    let sigma_ood_era = EvaluationsList::new(word_era.clone()).evaluate(&z_ood_era_ml);
    let eq_z_ood = z_ood_era_ml.eq_weights();

    let k_prime = output_code.message_size();
    let ood_ip_claims = split_claim_ip(&word_era, &eq_z_ood, sigma_ood_era, k_prime);

    // Step 3.
    let beta = F::random(rng);

    // Step 4.
    let mut v_cs = vec![F::ZERO; n_era];
    for spot in &input.spotchecks {
        assert!(
            spot.alpha < n_era,
            "spotcheck alpha={} is out of range for n_era={n_era}",
            spot.alpha
        );

        // TeX uses 1-based indexing and beta^(alpha_j - 1).
        // Here alpha is 0-based, so the exponent is `alpha`.
        v_cs[spot.alpha] = pow_field(beta, spot.alpha);
    }

    // Step 5.
    let sigma_cs = input.spotchecks.iter().fold(F::ZERO, |acc, spot| {
        acc + pow_field(beta, spot.alpha) * spot.sigma_cs
    });

    // Step 6.
    let codeswitch_ip_claims = split_claim_ip(&word_era, &v_cs, sigma_cs, k_prime);

    // First step inside "Checking the base code encoding".
    let word_code_b = base_code.encode(&input.msg);
    assert_eq!(
        word_code_b.len(),
        base_code.block_length(),
        "base-code encoding length must match base-code block length"
    );
    let code_b_oracles = split_and_encode(&word_code_b, output_code);

    // Step 10.
    let n_code_b = word_code_b.len();
    assert!(
        n_code_b.is_power_of_two(),
        "step 10 currently assumes n_code_b is a power of two"
    );

    let r_x_dim = n_code_b.ilog2() as usize;
    let r_x_code_b: Vec<F> = (0..r_x_dim).map(|_| F::random(rng)).collect();

    // Step 11.
    let sigma_code_b_at_r_x =
        EvaluationsList::new(word_code_b.clone()).evaluate(&MultilinearPoint(r_x_code_b.clone()));

    // Step 12.
    let (generator_left_table, generator_right_table, message_table) =
        build_base_code_sumcheck_tip_tables(
            &input.base_code_prime_generator_matrix,
            &r_x_code_b,
            &input.msg,
        );

    let claimed_sum_over_y = generator_left_table
        .iter()
        .zip(generator_right_table.iter())
        .zip(message_table.iter())
        .fold(F::ZERO, |acc, ((&left, &right), &message_value)| {
            acc + left * right * message_value
        });
    assert_eq!(
        claimed_sum_over_y, sigma_code_b_at_r_x,
        "base-code sumcheck claim does not match sigma_code_b_at_r_x"
    );

    let mut base_code_sumcheck =
        TIPSumcheck::new(generator_left_table, generator_right_table, message_table);
    let base_code_sumcheck_output = base_code_sumcheck.run_sumcheck_protocol(rng);

    // Step 13.
    let sigma_code_b_g_left_at_r_y = base_code_sumcheck_output.first_value;
    let sigma_code_b_g_right_at_r_y = base_code_sumcheck_output.second_value;
    let sigma_code_b_msg_at_r_y = base_code_sumcheck_output.third_value;
    assert_eq!(
        sigma_code_b_g_left_at_r_y * sigma_code_b_g_right_at_r_y * sigma_code_b_msg_at_r_y,
        base_code_sumcheck_output.final_claim,
        "base-code step 13 product check does not match reduced claim"
    );

    // Step 14.
    assert!(
        r_x_code_b.len().is_multiple_of(2),
        "step 14 requires even-sized r_x challenge to parse (r_x_left, r_x_right)"
    );
    let (r_x_left_half, r_x_right_half) = r_x_code_b.split_at(r_x_code_b.len() / 2);

    // TIP sumcheck challenges are sampled in compression-round order.
    // Reverse to multilinear variable order for eq-polynomials.
    let r_y_code_b: Vec<F> = base_code_sumcheck_output
        .randomness
        .iter()
        .copied()
        .rev()
        .collect();
    assert!(
        r_y_code_b.len().is_multiple_of(2),
        "step 14 requires even-sized r_y challenge to parse (r_y_left, r_y_right)"
    );
    let (r_y_left_half, r_y_right_half) = r_y_code_b.split_at(r_y_code_b.len() / 2);

    let eq_r_x_code_b = MultilinearPoint(r_x_code_b.clone()).eq_weights();

    let mut r_x_left_r_y_left = Vec::with_capacity(r_x_left_half.len() + r_y_left_half.len());
    r_x_left_r_y_left.extend_from_slice(r_x_left_half);
    r_x_left_r_y_left.extend_from_slice(r_y_left_half);
    let eq_r_x_left_r_y_left = MultilinearPoint(r_x_left_r_y_left).eq_weights();

    let mut r_x_right_r_y_right = Vec::with_capacity(r_x_right_half.len() + r_y_right_half.len());
    r_x_right_r_y_right.extend_from_slice(r_x_right_half);
    r_x_right_r_y_right.extend_from_slice(r_y_right_half);
    let eq_r_x_right_r_y_right = MultilinearPoint(r_x_right_r_y_right).eq_weights();

    let eq_r_y_code_b = MultilinearPoint(r_y_code_b).eq_weights();

    let base_code_word_ip_claims =
        split_claim_ip(&word_code_b, &eq_r_x_code_b, sigma_code_b_at_r_x, k_prime);
    let base_code_g_left_ip_claims = split_claim_ip(
        &input.base_code_prime_generator_matrix,
        &eq_r_x_left_r_y_left,
        sigma_code_b_g_left_at_r_y,
        k_prime,
    );
    let base_code_g_right_ip_claims = split_claim_ip(
        &input.base_code_prime_generator_matrix,
        &eq_r_x_right_r_y_right,
        sigma_code_b_g_right_at_r_y,
        k_prime,
    );
    let base_code_msg_ip_claims =
        split_claim_ip(&input.msg, &eq_r_y_code_b, sigma_code_b_msg_at_r_y, k_prime);

    // Steps 15-17.
    assert_eq!(
        n_era % n_code_b,
        0,
        "step 15 requires n_era to be divisible by n_code_b"
    );
    let repeat_factor = n_era / n_code_b;
    // TODO: Relax this to support non-power-of-two repeat factors.
    // Current step-17 point construction uses a prefix selector of length
    // log2(repeat_factor), so we require repeat_factor to be a power of two.
    assert!(
        repeat_factor.is_power_of_two(),
        "step 15 currently assumes repeat factor n_era/n_code_b is a power of two"
    );

    let word_rep = repeat_vector(&word_code_b, repeat_factor);
    assert_eq!(
        word_rep.len(),
        n_era,
        "step 15 repeated vector length must match n_era"
    );

    let rep_oracles = repeat_split_encoding(&code_b_oracles, repeat_factor);
    let rep_oracles_from_split = split_and_encode(&word_rep, output_code);
    assert_eq!(
        &rep_oracles.chunks, &rep_oracles_from_split.chunks,
        "step 16-17 repeated chunks must match split-and-encode of word_rep"
    );
    assert_eq!(
        &rep_oracles.codewords, &rep_oracles_from_split.codewords,
        "step 16-17 simulated repeated codewords must match split-and-encode of word_rep"
    );

    let repeat_dim = repeat_factor.ilog2() as usize;
    let mut r_rep = vec![F::ZERO; repeat_dim];
    r_rep.extend_from_slice(&r_x_code_b);
    assert_eq!(
        r_rep.len(),
        n_era.ilog2() as usize,
        "step 17 repeated-vector point must have log2(n_era) coordinates"
    );

    let sigma_rep_at_r_rep =
        EvaluationsList::new(word_rep.clone()).evaluate(&MultilinearPoint(r_rep.clone()));
    assert_eq!(
        sigma_rep_at_r_rep, sigma_code_b_at_r_x,
        "step 17 repeated-vector claim at selector 0 must match sigma_code_b_at_r_x"
    );

    let eq_r_rep = MultilinearPoint(r_rep.clone()).eq_weights();
    let repeat_ip_claims = split_claim_ip(&word_rep, &eq_r_rep, sigma_rep_at_r_rep, k_prime);

    // Step 18.
    assert_is_permutation(&input.permutation_1, n_era, "permutation_1");
    let word_perm = apply_permutation(&word_rep, &input.permutation_1);
    let perm_oracles = split_and_encode(&word_perm, output_code);

    // Step 19.
    let z_ood_perm: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let z_ood_perm_ml = MultilinearPoint(z_ood_perm.clone());
    let sigma_ood_perm = EvaluationsList::new(word_perm.clone()).evaluate(&z_ood_perm_ml);
    let eq_z_ood_perm = z_ood_perm_ml.eq_weights();
    let perm_ood_ip_claims = split_claim_ip(&word_perm, &eq_z_ood_perm, sigma_ood_perm, k_prime);

    // Step 20.
    let permutation_alpha = F::random(rng);
    let permutation_beta = F::random(rng);

    let (
        permutation_identity_vector,
        permutation_pi_1_vector,
        permutation_a_1,
        permutation_a_2,
        permutation_b_1,
        permutation_b_2,
    ) = build_first_permute_witness_vectors(
        &word_rep,
        &word_perm,
        &input.permutation_1,
        permutation_alpha,
        permutation_beta,
    );

    let permutation_a_1_oracles = split_and_encode(&permutation_a_1, output_code);
    let permutation_a_2_oracles = split_and_encode(&permutation_a_2, output_code);
    let permutation_b_1_oracles = split_and_encode(&permutation_b_1, output_code);
    let permutation_b_2_oracles = split_and_encode(&permutation_b_2, output_code);

    // Witness-vector OOD checks.
    let permutation_a_1_z_ood: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let permutation_a_2_z_ood: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let permutation_b_1_z_ood: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let permutation_b_2_z_ood: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();

    let permutation_a_1_sigma_ood =
        evaluate_multilinear_table(&permutation_a_1, &permutation_a_1_z_ood);
    let permutation_a_2_sigma_ood =
        evaluate_multilinear_table(&permutation_a_2, &permutation_a_2_z_ood);
    let permutation_b_1_sigma_ood =
        evaluate_multilinear_table(&permutation_b_1, &permutation_b_1_z_ood);
    let permutation_b_2_sigma_ood =
        evaluate_multilinear_table(&permutation_b_2, &permutation_b_2_z_ood);

    let permutation_a_1_ood_ip_claims = split_claim_ip(
        &permutation_a_1,
        &MultilinearPoint(permutation_a_1_z_ood.clone()).eq_weights(),
        permutation_a_1_sigma_ood,
        k_prime,
    );
    let permutation_a_2_ood_ip_claims = split_claim_ip(
        &permutation_a_2,
        &MultilinearPoint(permutation_a_2_z_ood.clone()).eq_weights(),
        permutation_a_2_sigma_ood,
        k_prime,
    );
    let permutation_b_1_ood_ip_claims = split_claim_ip(
        &permutation_b_1,
        &MultilinearPoint(permutation_b_1_z_ood.clone()).eq_weights(),
        permutation_b_1_sigma_ood,
        k_prime,
    );
    let permutation_b_2_ood_ip_claims = split_claim_ip(
        &permutation_b_2,
        &MultilinearPoint(permutation_b_2_z_ood.clone()).eq_weights(),
        permutation_b_2_sigma_ood,
        k_prime,
    );

    // Step 20 fixed-point consistency openings.
    let permutation_fixed_point = build_first_permute_fixed_point::<F>(ood_dim);
    let permutation_a_1_sigma_fixed =
        evaluate_multilinear_table(&permutation_a_1, &permutation_fixed_point);
    let permutation_b_1_sigma_fixed =
        evaluate_multilinear_table(&permutation_b_1, &permutation_fixed_point);

    let eq_permutation_fixed_point = MultilinearPoint(permutation_fixed_point.clone()).eq_weights();
    let permutation_a_1_fixed_ip_claims = split_claim_ip(
        &permutation_a_1,
        &eq_permutation_fixed_point,
        permutation_a_1_sigma_fixed,
        k_prime,
    );
    let permutation_b_1_fixed_ip_claims = split_claim_ip(
        &permutation_b_1,
        &eq_permutation_fixed_point,
        permutation_b_1_sigma_fixed,
        k_prime,
    );

    // Step 20 challenge point r^perm and linear consistency checks.
    let permutation_r_perm: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();

    let permutation_sigma_a_at_r_perm =
        evaluate_multilinear_table(&permutation_a_1, &permutation_r_perm);
    let permutation_sigma_b_at_r_perm =
        evaluate_multilinear_table(&permutation_b_1, &permutation_r_perm);
    let permutation_sigma_id_at_r_perm =
        evaluate_multilinear_table(&permutation_identity_vector, &permutation_r_perm);
    let permutation_sigma_word_rep_at_r_perm =
        evaluate_multilinear_table(&word_rep, &permutation_r_perm);
    let permutation_sigma_word_perm_at_r_perm =
        evaluate_multilinear_table(&word_perm, &permutation_r_perm);
    let permutation_sigma_pi_1_at_r_perm =
        evaluate_multilinear_table(&permutation_pi_1_vector, &permutation_r_perm);

    assert_eq!(
        permutation_sigma_a_at_r_perm,
        permutation_alpha
            - (permutation_sigma_word_rep_at_r_perm
                + permutation_beta * permutation_sigma_pi_1_at_r_perm),
        "step 20 a_1 consistency check failed at r^perm"
    );
    assert_eq!(
        permutation_sigma_b_at_r_perm,
        permutation_alpha
            - (permutation_sigma_word_perm_at_r_perm
                + permutation_beta * permutation_sigma_id_at_r_perm),
        "step 20 b_1 consistency check failed at r^perm"
    );

    let eq_r_perm = MultilinearPoint(permutation_r_perm.clone()).eq_weights();
    let permutation_a_1_r_perm_ip_claims = split_claim_ip(
        &permutation_a_1,
        &eq_r_perm,
        permutation_sigma_a_at_r_perm,
        k_prime,
    );
    let permutation_b_1_r_perm_ip_claims = split_claim_ip(
        &permutation_b_1,
        &eq_r_perm,
        permutation_sigma_b_at_r_perm,
        k_prime,
    );
    let permutation_word_rep_r_perm_ip_claims = split_claim_ip(
        &word_rep,
        &eq_r_perm,
        permutation_sigma_word_rep_at_r_perm,
        k_prime,
    );
    let permutation_word_perm_r_perm_ip_claims = split_claim_ip(
        &word_perm,
        &eq_r_perm,
        permutation_sigma_word_perm_at_r_perm,
        k_prime,
    );
    let permutation_identity_r_perm_ip_claims = split_claim_ip(
        &permutation_identity_vector,
        &eq_r_perm,
        permutation_sigma_id_at_r_perm,
        k_prime,
    );
    let permutation_pi_1_r_perm_ip_claims = split_claim_ip(
        &permutation_pi_1_vector,
        &eq_r_perm,
        permutation_sigma_pi_1_at_r_perm,
        k_prime,
    );

    // Step 20 transition sumchecks for a and b.
    let mut permutation_a_transition_sumcheck = PermutationTransitionSumcheck::new(
        build_permutation_transition_tables(&permutation_a_1, &permutation_a_2),
        eq_r_perm.clone(),
    );
    let permutation_a_transition_sumcheck =
        permutation_a_transition_sumcheck.run_sumcheck_protocol(rng);

    let mut permutation_b_transition_sumcheck = PermutationTransitionSumcheck::new(
        build_permutation_transition_tables(&permutation_b_1, &permutation_b_2),
        eq_r_perm.clone(),
    );
    let permutation_b_transition_sumcheck =
        permutation_b_transition_sumcheck.run_sumcheck_protocol(rng);

    let permutation_r_a: Vec<F> = permutation_a_transition_sumcheck
        .randomness
        .iter()
        .copied()
        .rev()
        .collect();
    let permutation_r_b: Vec<F> = permutation_b_transition_sumcheck
        .randomness
        .iter()
        .copied()
        .rev()
        .collect();

    let (&permutation_r_a_1, permutation_r_a_tail) = permutation_r_a
        .split_first()
        .expect("step 20 requires non-empty r^a challenge");
    let (&permutation_r_b_1, permutation_r_b_tail) = permutation_r_b
        .split_first()
        .expect("step 20 requires non-empty r^b challenge");

    let permutation_r_a_tail_0 = append_coord(permutation_r_a_tail, F::ZERO);
    let permutation_r_a_tail_1 = append_coord(permutation_r_a_tail, F::ONE);
    let permutation_r_b_tail_0 = append_coord(permutation_r_b_tail, F::ZERO);
    let permutation_r_b_tail_1 = append_coord(permutation_r_b_tail, F::ONE);

    let permutation_a_sigma_one_at_r_a =
        evaluate_multilinear_table(&permutation_a_2, &permutation_r_a);
    let permutation_b_sigma_one_at_r_b =
        evaluate_multilinear_table(&permutation_b_2, &permutation_r_b);

    let permutation_a_sigma_i_r_a_tail_j = [
        [
            evaluate_multilinear_table(&permutation_a_1, &permutation_r_a_tail_0),
            evaluate_multilinear_table(&permutation_a_1, &permutation_r_a_tail_1),
        ],
        [
            evaluate_multilinear_table(&permutation_a_2, &permutation_r_a_tail_0),
            evaluate_multilinear_table(&permutation_a_2, &permutation_r_a_tail_1),
        ],
    ];
    let permutation_b_sigma_i_r_b_tail_j = [
        [
            evaluate_multilinear_table(&permutation_b_1, &permutation_r_b_tail_0),
            evaluate_multilinear_table(&permutation_b_1, &permutation_r_b_tail_1),
        ],
        [
            evaluate_multilinear_table(&permutation_b_2, &permutation_r_b_tail_0),
            evaluate_multilinear_table(&permutation_b_2, &permutation_r_b_tail_1),
        ],
    ];

    let permutation_a_sigma_r_a_0 = (F::ONE - permutation_r_a_1)
        * permutation_a_sigma_i_r_a_tail_j[0][0]
        + permutation_r_a_1 * permutation_a_sigma_i_r_a_tail_j[1][0];
    let permutation_a_sigma_r_a_1 = (F::ONE - permutation_r_a_1)
        * permutation_a_sigma_i_r_a_tail_j[0][1]
        + permutation_r_a_1 * permutation_a_sigma_i_r_a_tail_j[1][1];
    let permutation_b_sigma_r_b_0 = (F::ONE - permutation_r_b_1)
        * permutation_b_sigma_i_r_b_tail_j[0][0]
        + permutation_r_b_1 * permutation_b_sigma_i_r_b_tail_j[1][0];
    let permutation_b_sigma_r_b_1 = (F::ONE - permutation_r_b_1)
        * permutation_b_sigma_i_r_b_tail_j[0][1]
        + permutation_r_b_1 * permutation_b_sigma_i_r_b_tail_j[1][1];

    let permutation_eq_r_a_r_perm = MultilinearPoint(permutation_r_a.clone())
        .eq_poly_outside(&MultilinearPoint(permutation_r_perm.clone()));
    let permutation_eq_r_b_r_perm = MultilinearPoint(permutation_r_b.clone())
        .eq_poly_outside(&MultilinearPoint(permutation_r_perm.clone()));

    assert_eq!(
        permutation_a_transition_sumcheck.eq_value, permutation_eq_r_a_r_perm,
        "step 20 a-transition eq-value mismatch"
    );
    assert_eq!(
        permutation_b_transition_sumcheck.eq_value, permutation_eq_r_b_r_perm,
        "step 20 b-transition eq-value mismatch"
    );
    assert_eq!(
        permutation_a_transition_sumcheck.upper_value, permutation_a_sigma_one_at_r_a,
        "step 20 a-transition upper opening mismatch"
    );
    assert_eq!(
        permutation_b_transition_sumcheck.upper_value, permutation_b_sigma_one_at_r_b,
        "step 20 b-transition upper opening mismatch"
    );
    assert_eq!(
        permutation_a_transition_sumcheck.lower_left_value, permutation_a_sigma_r_a_0,
        "step 20 a-transition lower-left opening mismatch"
    );
    assert_eq!(
        permutation_a_transition_sumcheck.lower_right_value, permutation_a_sigma_r_a_1,
        "step 20 a-transition lower-right opening mismatch"
    );
    assert_eq!(
        permutation_b_transition_sumcheck.lower_left_value, permutation_b_sigma_r_b_0,
        "step 20 b-transition lower-left opening mismatch"
    );
    assert_eq!(
        permutation_b_transition_sumcheck.lower_right_value, permutation_b_sigma_r_b_1,
        "step 20 b-transition lower-right opening mismatch"
    );

    assert_eq!(
        permutation_a_transition_sumcheck.final_claim,
        permutation_eq_r_a_r_perm
            * (permutation_a_sigma_one_at_r_a
                - permutation_a_sigma_r_a_0 * permutation_a_sigma_r_a_1),
        "step 20 a-transition reduced claim mismatch"
    );
    assert_eq!(
        permutation_b_transition_sumcheck.final_claim,
        permutation_eq_r_b_r_perm
            * (permutation_b_sigma_one_at_r_b
                - permutation_b_sigma_r_b_0 * permutation_b_sigma_r_b_1),
        "step 20 b-transition reduced claim mismatch"
    );

    let eq_r_a = MultilinearPoint(permutation_r_a.clone()).eq_weights();
    let eq_r_b = MultilinearPoint(permutation_r_b.clone()).eq_weights();

    let permutation_a_2_r_a_ip_claims = split_claim_ip(
        &permutation_a_2,
        &eq_r_a,
        permutation_a_sigma_one_at_r_a,
        k_prime,
    );
    let permutation_b_2_r_b_ip_claims = split_claim_ip(
        &permutation_b_2,
        &eq_r_b,
        permutation_b_sigma_one_at_r_b,
        k_prime,
    );

    let eq_r_a_tail_0 = MultilinearPoint(permutation_r_a_tail_0.clone()).eq_weights();
    let eq_r_a_tail_1 = MultilinearPoint(permutation_r_a_tail_1.clone()).eq_weights();
    let eq_r_b_tail_0 = MultilinearPoint(permutation_r_b_tail_0.clone()).eq_weights();
    let eq_r_b_tail_1 = MultilinearPoint(permutation_r_b_tail_1.clone()).eq_weights();

    let permutation_a_r_a_tail_ip_claims = [
        [
            split_claim_ip(
                &permutation_a_1,
                &eq_r_a_tail_0,
                permutation_a_sigma_i_r_a_tail_j[0][0],
                k_prime,
            ),
            split_claim_ip(
                &permutation_a_1,
                &eq_r_a_tail_1,
                permutation_a_sigma_i_r_a_tail_j[0][1],
                k_prime,
            ),
        ],
        [
            split_claim_ip(
                &permutation_a_2,
                &eq_r_a_tail_0,
                permutation_a_sigma_i_r_a_tail_j[1][0],
                k_prime,
            ),
            split_claim_ip(
                &permutation_a_2,
                &eq_r_a_tail_1,
                permutation_a_sigma_i_r_a_tail_j[1][1],
                k_prime,
            ),
        ],
    ];
    let permutation_b_r_b_tail_ip_claims = [
        [
            split_claim_ip(
                &permutation_b_1,
                &eq_r_b_tail_0,
                permutation_b_sigma_i_r_b_tail_j[0][0],
                k_prime,
            ),
            split_claim_ip(
                &permutation_b_1,
                &eq_r_b_tail_1,
                permutation_b_sigma_i_r_b_tail_j[0][1],
                k_prime,
            ),
        ],
        [
            split_claim_ip(
                &permutation_b_2,
                &eq_r_b_tail_0,
                permutation_b_sigma_i_r_b_tail_j[1][0],
                k_prime,
            ),
            split_claim_ip(
                &permutation_b_2,
                &eq_r_b_tail_1,
                permutation_b_sigma_i_r_b_tail_j[1][1],
                k_prime,
            ),
        ],
    ];

    // Step 21.
    let word_mult = hadamard_product(&word_perm, &input.multiplier_1, "word_perm", "multiplier_1");

    // Step 22.
    let mult_oracles = split_and_encode(&word_mult, output_code);
    let z_ood_mult: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let sigma_ood_mult = evaluate_multilinear_table(&word_mult, &z_ood_mult);
    let mult_ood_ip_claims = split_claim_ip(
        &word_mult,
        &MultilinearPoint(z_ood_mult.clone()).eq_weights(),
        sigma_ood_mult,
        k_prime,
    );

    // Step 23.
    let r_mult_challenge = F::random(rng);
    let r_mult = geometric_power_vector(r_mult_challenge, n_era);
    let sigma_mult = triple_product(
        &word_perm,
        &input.multiplier_1,
        &r_mult,
        "word_perm",
        "multiplier_1",
        "r_mult",
    );

    let sigma_mult_from_word_mult = inner_product(&word_mult, &r_mult, "word_mult", "r_mult");
    assert_eq!(
        sigma_mult, sigma_mult_from_word_mult,
        "step 23 triple-product claim does not match word^mult inner-product claim"
    );

    // Step 24.
    let multiply_tip_claims = split_claim_tip(
        &word_perm,
        &input.multiplier_1,
        &r_mult,
        sigma_mult,
        k_prime,
    );
    let mult_r_ip_claims = split_claim_ip(&word_mult, &r_mult, sigma_mult, k_prime);

    // Step 25.
    // The current ERA implementation uses the standard accumulate map where
    // A is the lower-triangular all-ones matrix (prefix sums).
    let word_acc = prefix_sums(&word_mult);

    // Step 26.
    let acc_oracles = split_and_encode(&word_acc, output_code);
    let z_ood_acc: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let sigma_ood_acc = evaluate_multilinear_table(&word_acc, &z_ood_acc);
    let acc_ood_ip_claims = split_claim_ip(
        &word_acc,
        &MultilinearPoint(z_ood_acc.clone()).eq_weights(),
        sigma_ood_acc,
        k_prime,
    );

    // Step 27.
    let r_acc: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();

    // Step 28.
    let acc_map_row_at_r_acc = prefix_sum_accumulate_row_at_point(&r_acc);

    // Step 29.
    let sigma_acc = evaluate_multilinear_table(&word_acc, &r_acc);

    // Step 30.
    let sigma_acc_from_word_mult = inner_product(
        &word_mult,
        &acc_map_row_at_r_acc,
        "word_mult",
        "acc_map_row_at_r_acc",
    );
    assert_eq!(
        sigma_acc, sigma_acc_from_word_mult,
        "step 30 accumulate-map reduction does not match sigma_acc"
    );
    let acc_mult_ip_claims = split_claim_ip(&word_mult, &acc_map_row_at_r_acc, sigma_acc, k_prime);

    // Step 31.
    let eq_r_acc = MultilinearPoint(r_acc.clone()).eq_weights();
    let acc_r_ip_claims = split_claim_ip(&word_acc, &eq_r_acc, sigma_acc, k_prime);

    // Steps 33-35: second permute, permutation checks, and multiply/accumulate chain.
    assert_is_permutation(&input.permutation_2, n_era, "permutation_2");

    let word_perm_2 = apply_permutation(&word_acc, &input.permutation_2);
    let perm_2_oracles = split_and_encode(&word_perm_2, output_code);

    let z_ood_perm_2: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let sigma_ood_perm_2 = evaluate_multilinear_table(&word_perm_2, &z_ood_perm_2);
    let perm_2_ood_ip_claims = split_claim_ip(
        &word_perm_2,
        &MultilinearPoint(z_ood_perm_2.clone()).eq_weights(),
        sigma_ood_perm_2,
        k_prime,
    );

    // Step 34: second permutation consistency checks.
    let permutation_alpha_2 = F::random(rng);
    let permutation_beta_2 = F::random(rng);

    let (
        permutation_identity_vector_2,
        permutation_pi_2_vector,
        permutation_2_a_1,
        permutation_2_a_2,
        permutation_2_b_1,
        permutation_2_b_2,
    ) = build_first_permute_witness_vectors(
        &word_acc,
        &word_perm_2,
        &input.permutation_2,
        permutation_alpha_2,
        permutation_beta_2,
    );
    assert_eq!(
        permutation_identity_vector_2, permutation_identity_vector,
        "step 34 identity vector mismatch between permutation checks"
    );

    let permutation_2_a_1_oracles = split_and_encode(&permutation_2_a_1, output_code);
    let permutation_2_a_2_oracles = split_and_encode(&permutation_2_a_2, output_code);
    let permutation_2_b_1_oracles = split_and_encode(&permutation_2_b_1, output_code);
    let permutation_2_b_2_oracles = split_and_encode(&permutation_2_b_2, output_code);

    let permutation_2_a_1_z_ood: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let permutation_2_a_2_z_ood: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let permutation_2_b_1_z_ood: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let permutation_2_b_2_z_ood: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();

    let permutation_2_a_1_sigma_ood =
        evaluate_multilinear_table(&permutation_2_a_1, &permutation_2_a_1_z_ood);
    let permutation_2_a_2_sigma_ood =
        evaluate_multilinear_table(&permutation_2_a_2, &permutation_2_a_2_z_ood);
    let permutation_2_b_1_sigma_ood =
        evaluate_multilinear_table(&permutation_2_b_1, &permutation_2_b_1_z_ood);
    let permutation_2_b_2_sigma_ood =
        evaluate_multilinear_table(&permutation_2_b_2, &permutation_2_b_2_z_ood);

    let permutation_2_a_1_ood_ip_claims = split_claim_ip(
        &permutation_2_a_1,
        &MultilinearPoint(permutation_2_a_1_z_ood.clone()).eq_weights(),
        permutation_2_a_1_sigma_ood,
        k_prime,
    );
    let permutation_2_a_2_ood_ip_claims = split_claim_ip(
        &permutation_2_a_2,
        &MultilinearPoint(permutation_2_a_2_z_ood.clone()).eq_weights(),
        permutation_2_a_2_sigma_ood,
        k_prime,
    );
    let permutation_2_b_1_ood_ip_claims = split_claim_ip(
        &permutation_2_b_1,
        &MultilinearPoint(permutation_2_b_1_z_ood.clone()).eq_weights(),
        permutation_2_b_1_sigma_ood,
        k_prime,
    );
    let permutation_2_b_2_ood_ip_claims = split_claim_ip(
        &permutation_2_b_2,
        &MultilinearPoint(permutation_2_b_2_z_ood.clone()).eq_weights(),
        permutation_2_b_2_sigma_ood,
        k_prime,
    );

    let permutation_2_fixed_point = build_first_permute_fixed_point::<F>(ood_dim);
    let permutation_2_a_1_sigma_fixed =
        evaluate_multilinear_table(&permutation_2_a_1, &permutation_2_fixed_point);
    let permutation_2_b_1_sigma_fixed =
        evaluate_multilinear_table(&permutation_2_b_1, &permutation_2_fixed_point);

    let eq_permutation_2_fixed_point =
        MultilinearPoint(permutation_2_fixed_point.clone()).eq_weights();
    let permutation_2_a_1_fixed_ip_claims = split_claim_ip(
        &permutation_2_a_1,
        &eq_permutation_2_fixed_point,
        permutation_2_a_1_sigma_fixed,
        k_prime,
    );
    let permutation_2_b_1_fixed_ip_claims = split_claim_ip(
        &permutation_2_b_1,
        &eq_permutation_2_fixed_point,
        permutation_2_b_1_sigma_fixed,
        k_prime,
    );

    let permutation_2_r_perm: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let permutation_2_sigma_a_at_r_perm =
        evaluate_multilinear_table(&permutation_2_a_1, &permutation_2_r_perm);
    let permutation_2_sigma_b_at_r_perm =
        evaluate_multilinear_table(&permutation_2_b_1, &permutation_2_r_perm);
    let permutation_2_sigma_id_at_r_perm =
        evaluate_multilinear_table(&permutation_identity_vector, &permutation_2_r_perm);
    let permutation_2_sigma_word_acc_at_r_perm =
        evaluate_multilinear_table(&word_acc, &permutation_2_r_perm);
    let permutation_2_sigma_word_perm_at_r_perm =
        evaluate_multilinear_table(&word_perm_2, &permutation_2_r_perm);
    let permutation_2_sigma_pi_2_at_r_perm =
        evaluate_multilinear_table(&permutation_pi_2_vector, &permutation_2_r_perm);

    assert_eq!(
        permutation_2_sigma_a_at_r_perm,
        permutation_alpha_2
            - (permutation_2_sigma_word_acc_at_r_perm
                + permutation_beta_2 * permutation_2_sigma_pi_2_at_r_perm),
        "step 34 a_1 consistency check failed at r^perm_2"
    );
    assert_eq!(
        permutation_2_sigma_b_at_r_perm,
        permutation_alpha_2
            - (permutation_2_sigma_word_perm_at_r_perm
                + permutation_beta_2 * permutation_2_sigma_id_at_r_perm),
        "step 34 b_1 consistency check failed at r^perm_2"
    );

    let eq_r_perm_2 = MultilinearPoint(permutation_2_r_perm.clone()).eq_weights();
    let permutation_2_a_1_r_perm_ip_claims = split_claim_ip(
        &permutation_2_a_1,
        &eq_r_perm_2,
        permutation_2_sigma_a_at_r_perm,
        k_prime,
    );
    let permutation_2_b_1_r_perm_ip_claims = split_claim_ip(
        &permutation_2_b_1,
        &eq_r_perm_2,
        permutation_2_sigma_b_at_r_perm,
        k_prime,
    );
    let permutation_2_word_acc_r_perm_ip_claims = split_claim_ip(
        &word_acc,
        &eq_r_perm_2,
        permutation_2_sigma_word_acc_at_r_perm,
        k_prime,
    );
    let permutation_2_word_perm_r_perm_ip_claims = split_claim_ip(
        &word_perm_2,
        &eq_r_perm_2,
        permutation_2_sigma_word_perm_at_r_perm,
        k_prime,
    );
    let permutation_2_identity_r_perm_ip_claims = split_claim_ip(
        &permutation_identity_vector,
        &eq_r_perm_2,
        permutation_2_sigma_id_at_r_perm,
        k_prime,
    );
    let permutation_2_pi_2_r_perm_ip_claims = split_claim_ip(
        &permutation_pi_2_vector,
        &eq_r_perm_2,
        permutation_2_sigma_pi_2_at_r_perm,
        k_prime,
    );

    let mut permutation_2_a_transition_sumcheck = PermutationTransitionSumcheck::new(
        build_permutation_transition_tables(&permutation_2_a_1, &permutation_2_a_2),
        eq_r_perm_2.clone(),
    );
    let permutation_2_a_transition_sumcheck =
        permutation_2_a_transition_sumcheck.run_sumcheck_protocol(rng);

    let mut permutation_2_b_transition_sumcheck = PermutationTransitionSumcheck::new(
        build_permutation_transition_tables(&permutation_2_b_1, &permutation_2_b_2),
        eq_r_perm_2.clone(),
    );
    let permutation_2_b_transition_sumcheck =
        permutation_2_b_transition_sumcheck.run_sumcheck_protocol(rng);

    let permutation_2_r_a: Vec<F> = permutation_2_a_transition_sumcheck
        .randomness
        .iter()
        .copied()
        .rev()
        .collect();
    let permutation_2_r_b: Vec<F> = permutation_2_b_transition_sumcheck
        .randomness
        .iter()
        .copied()
        .rev()
        .collect();

    let (&permutation_2_r_a_1, permutation_2_r_a_tail) = permutation_2_r_a
        .split_first()
        .expect("step 34 requires non-empty r^a_2 challenge");
    let (&permutation_2_r_b_1, permutation_2_r_b_tail) = permutation_2_r_b
        .split_first()
        .expect("step 34 requires non-empty r^b_2 challenge");

    let permutation_2_r_a_tail_0 = append_coord(permutation_2_r_a_tail, F::ZERO);
    let permutation_2_r_a_tail_1 = append_coord(permutation_2_r_a_tail, F::ONE);
    let permutation_2_r_b_tail_0 = append_coord(permutation_2_r_b_tail, F::ZERO);
    let permutation_2_r_b_tail_1 = append_coord(permutation_2_r_b_tail, F::ONE);

    let permutation_2_a_sigma_one_at_r_a =
        evaluate_multilinear_table(&permutation_2_a_2, &permutation_2_r_a);
    let permutation_2_b_sigma_one_at_r_b =
        evaluate_multilinear_table(&permutation_2_b_2, &permutation_2_r_b);

    let permutation_2_a_sigma_i_r_a_tail_j = [
        [
            evaluate_multilinear_table(&permutation_2_a_1, &permutation_2_r_a_tail_0),
            evaluate_multilinear_table(&permutation_2_a_1, &permutation_2_r_a_tail_1),
        ],
        [
            evaluate_multilinear_table(&permutation_2_a_2, &permutation_2_r_a_tail_0),
            evaluate_multilinear_table(&permutation_2_a_2, &permutation_2_r_a_tail_1),
        ],
    ];
    let permutation_2_b_sigma_i_r_b_tail_j = [
        [
            evaluate_multilinear_table(&permutation_2_b_1, &permutation_2_r_b_tail_0),
            evaluate_multilinear_table(&permutation_2_b_1, &permutation_2_r_b_tail_1),
        ],
        [
            evaluate_multilinear_table(&permutation_2_b_2, &permutation_2_r_b_tail_0),
            evaluate_multilinear_table(&permutation_2_b_2, &permutation_2_r_b_tail_1),
        ],
    ];

    let permutation_2_a_sigma_r_a_0 = (F::ONE - permutation_2_r_a_1)
        * permutation_2_a_sigma_i_r_a_tail_j[0][0]
        + permutation_2_r_a_1 * permutation_2_a_sigma_i_r_a_tail_j[1][0];
    let permutation_2_a_sigma_r_a_1 = (F::ONE - permutation_2_r_a_1)
        * permutation_2_a_sigma_i_r_a_tail_j[0][1]
        + permutation_2_r_a_1 * permutation_2_a_sigma_i_r_a_tail_j[1][1];
    let permutation_2_b_sigma_r_b_0 = (F::ONE - permutation_2_r_b_1)
        * permutation_2_b_sigma_i_r_b_tail_j[0][0]
        + permutation_2_r_b_1 * permutation_2_b_sigma_i_r_b_tail_j[1][0];
    let permutation_2_b_sigma_r_b_1 = (F::ONE - permutation_2_r_b_1)
        * permutation_2_b_sigma_i_r_b_tail_j[0][1]
        + permutation_2_r_b_1 * permutation_2_b_sigma_i_r_b_tail_j[1][1];

    let permutation_2_eq_r_a_r_perm = MultilinearPoint(permutation_2_r_a.clone())
        .eq_poly_outside(&MultilinearPoint(permutation_2_r_perm.clone()));
    let permutation_2_eq_r_b_r_perm = MultilinearPoint(permutation_2_r_b.clone())
        .eq_poly_outside(&MultilinearPoint(permutation_2_r_perm.clone()));

    assert_eq!(
        permutation_2_a_transition_sumcheck.eq_value, permutation_2_eq_r_a_r_perm,
        "step 34 a-transition eq-value mismatch"
    );
    assert_eq!(
        permutation_2_b_transition_sumcheck.eq_value, permutation_2_eq_r_b_r_perm,
        "step 34 b-transition eq-value mismatch"
    );
    assert_eq!(
        permutation_2_a_transition_sumcheck.upper_value, permutation_2_a_sigma_one_at_r_a,
        "step 34 a-transition upper opening mismatch"
    );
    assert_eq!(
        permutation_2_b_transition_sumcheck.upper_value, permutation_2_b_sigma_one_at_r_b,
        "step 34 b-transition upper opening mismatch"
    );
    assert_eq!(
        permutation_2_a_transition_sumcheck.lower_left_value, permutation_2_a_sigma_r_a_0,
        "step 34 a-transition lower-left opening mismatch"
    );
    assert_eq!(
        permutation_2_a_transition_sumcheck.lower_right_value, permutation_2_a_sigma_r_a_1,
        "step 34 a-transition lower-right opening mismatch"
    );
    assert_eq!(
        permutation_2_b_transition_sumcheck.lower_left_value, permutation_2_b_sigma_r_b_0,
        "step 34 b-transition lower-left opening mismatch"
    );
    assert_eq!(
        permutation_2_b_transition_sumcheck.lower_right_value, permutation_2_b_sigma_r_b_1,
        "step 34 b-transition lower-right opening mismatch"
    );

    assert_eq!(
        permutation_2_a_transition_sumcheck.final_claim,
        permutation_2_eq_r_a_r_perm
            * (permutation_2_a_sigma_one_at_r_a
                - permutation_2_a_sigma_r_a_0 * permutation_2_a_sigma_r_a_1),
        "step 34 a-transition reduced claim mismatch"
    );
    assert_eq!(
        permutation_2_b_transition_sumcheck.final_claim,
        permutation_2_eq_r_b_r_perm
            * (permutation_2_b_sigma_one_at_r_b
                - permutation_2_b_sigma_r_b_0 * permutation_2_b_sigma_r_b_1),
        "step 34 b-transition reduced claim mismatch"
    );

    let eq_r_a_2 = MultilinearPoint(permutation_2_r_a.clone()).eq_weights();
    let eq_r_b_2 = MultilinearPoint(permutation_2_r_b.clone()).eq_weights();

    let permutation_2_a_2_r_a_ip_claims = split_claim_ip(
        &permutation_2_a_2,
        &eq_r_a_2,
        permutation_2_a_sigma_one_at_r_a,
        k_prime,
    );
    let permutation_2_b_2_r_b_ip_claims = split_claim_ip(
        &permutation_2_b_2,
        &eq_r_b_2,
        permutation_2_b_sigma_one_at_r_b,
        k_prime,
    );

    let eq_r_a_2_tail_0 = MultilinearPoint(permutation_2_r_a_tail_0.clone()).eq_weights();
    let eq_r_a_2_tail_1 = MultilinearPoint(permutation_2_r_a_tail_1.clone()).eq_weights();
    let eq_r_b_2_tail_0 = MultilinearPoint(permutation_2_r_b_tail_0.clone()).eq_weights();
    let eq_r_b_2_tail_1 = MultilinearPoint(permutation_2_r_b_tail_1.clone()).eq_weights();

    let permutation_2_a_r_a_tail_ip_claims = [
        [
            split_claim_ip(
                &permutation_2_a_1,
                &eq_r_a_2_tail_0,
                permutation_2_a_sigma_i_r_a_tail_j[0][0],
                k_prime,
            ),
            split_claim_ip(
                &permutation_2_a_1,
                &eq_r_a_2_tail_1,
                permutation_2_a_sigma_i_r_a_tail_j[0][1],
                k_prime,
            ),
        ],
        [
            split_claim_ip(
                &permutation_2_a_2,
                &eq_r_a_2_tail_0,
                permutation_2_a_sigma_i_r_a_tail_j[1][0],
                k_prime,
            ),
            split_claim_ip(
                &permutation_2_a_2,
                &eq_r_a_2_tail_1,
                permutation_2_a_sigma_i_r_a_tail_j[1][1],
                k_prime,
            ),
        ],
    ];
    let permutation_2_b_r_b_tail_ip_claims = [
        [
            split_claim_ip(
                &permutation_2_b_1,
                &eq_r_b_2_tail_0,
                permutation_2_b_sigma_i_r_b_tail_j[0][0],
                k_prime,
            ),
            split_claim_ip(
                &permutation_2_b_1,
                &eq_r_b_2_tail_1,
                permutation_2_b_sigma_i_r_b_tail_j[0][1],
                k_prime,
            ),
        ],
        [
            split_claim_ip(
                &permutation_2_b_2,
                &eq_r_b_2_tail_0,
                permutation_2_b_sigma_i_r_b_tail_j[1][0],
                k_prime,
            ),
            split_claim_ip(
                &permutation_2_b_2,
                &eq_r_b_2_tail_1,
                permutation_2_b_sigma_i_r_b_tail_j[1][1],
                k_prime,
            ),
        ],
    ];

    // Step 35: second multiply/accumulate checks.
    let word_mult_2 = hadamard_product(
        &word_perm_2,
        &input.multiplier_2,
        "word_perm_2",
        "multiplier_2",
    );

    let mult_2_oracles = split_and_encode(&word_mult_2, output_code);
    let z_ood_mult_2: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let sigma_ood_mult_2 = evaluate_multilinear_table(&word_mult_2, &z_ood_mult_2);
    let mult_2_ood_ip_claims = split_claim_ip(
        &word_mult_2,
        &MultilinearPoint(z_ood_mult_2.clone()).eq_weights(),
        sigma_ood_mult_2,
        k_prime,
    );

    let r_mult_challenge_2 = F::random(rng);
    let r_mult_2 = geometric_power_vector(r_mult_challenge_2, n_era);
    let sigma_mult_2 = triple_product(
        &word_perm_2,
        &input.multiplier_2,
        &r_mult_2,
        "word_perm_2",
        "multiplier_2",
        "r_mult_2",
    );

    let sigma_mult_2_from_word_mult_2 =
        inner_product(&word_mult_2, &r_mult_2, "word_mult_2", "r_mult_2");
    assert_eq!(
        sigma_mult_2, sigma_mult_2_from_word_mult_2,
        "step 35 second-multiply triple-product claim does not match word^mult_2 inner-product claim"
    );

    let multiply_tip_claims_2 = split_claim_tip(
        &word_perm_2,
        &input.multiplier_2,
        &r_mult_2,
        sigma_mult_2,
        k_prime,
    );
    let mult_2_r_ip_claims = split_claim_ip(&word_mult_2, &r_mult_2, sigma_mult_2, k_prime);

    let word_acc_2 = prefix_sums(&word_mult_2);
    let acc_2_oracles = split_and_encode(&word_acc_2, output_code);
    let z_ood_acc_2: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let sigma_ood_acc_2 = evaluate_multilinear_table(&word_acc_2, &z_ood_acc_2);
    let acc_2_ood_ip_claims = split_claim_ip(
        &word_acc_2,
        &MultilinearPoint(z_ood_acc_2.clone()).eq_weights(),
        sigma_ood_acc_2,
        k_prime,
    );

    let r_acc_2: Vec<F> = (0..ood_dim).map(|_| F::random(rng)).collect();
    let acc_map_row_at_r_acc_2 = prefix_sum_accumulate_row_at_point(&r_acc_2);
    let sigma_acc_2 = evaluate_multilinear_table(&word_acc_2, &r_acc_2);

    let sigma_acc_2_from_word_mult_2 = inner_product(
        &word_mult_2,
        &acc_map_row_at_r_acc_2,
        "word_mult_2",
        "acc_map_row_at_r_acc_2",
    );
    assert_eq!(
        sigma_acc_2, sigma_acc_2_from_word_mult_2,
        "step 35 second-accumulate reduction does not match sigma_acc_2"
    );

    let acc_mult_2_ip_claims =
        split_claim_ip(&word_mult_2, &acc_map_row_at_r_acc_2, sigma_acc_2, k_prime);
    let acc_2_r_ip_claims = split_claim_ip(
        &word_acc_2,
        &MultilinearPoint(r_acc_2.clone()).eq_weights(),
        sigma_acc_2,
        k_prime,
    );

    assert_eq!(
        word_acc_2, word_era,
        "step 35 second accumulate output must reconstruct word^ERA"
    );

    let mut ip_claims = Vec::with_capacity(
        ood_ip_claims.len()
            + codeswitch_ip_claims.len()
            + base_code_word_ip_claims.len()
            + base_code_g_left_ip_claims.len()
            + base_code_g_right_ip_claims.len()
            + base_code_msg_ip_claims.len()
            + repeat_ip_claims.len()
            + perm_ood_ip_claims.len()
            + mult_ood_ip_claims.len()
            + mult_r_ip_claims.len()
            + acc_ood_ip_claims.len()
            + permutation_a_1_ood_ip_claims.len()
            + permutation_a_2_ood_ip_claims.len()
            + permutation_b_1_ood_ip_claims.len()
            + permutation_b_2_ood_ip_claims.len()
            + permutation_a_1_fixed_ip_claims.len()
            + permutation_b_1_fixed_ip_claims.len()
            + permutation_a_1_r_perm_ip_claims.len()
            + permutation_b_1_r_perm_ip_claims.len()
            + permutation_word_rep_r_perm_ip_claims.len()
            + permutation_word_perm_r_perm_ip_claims.len()
            + permutation_identity_r_perm_ip_claims.len()
            + permutation_pi_1_r_perm_ip_claims.len()
            + permutation_a_2_r_a_ip_claims.len()
            + permutation_b_2_r_b_ip_claims.len()
            + permutation_a_r_a_tail_ip_claims[0][0].len()
            + permutation_a_r_a_tail_ip_claims[0][1].len()
            + permutation_a_r_a_tail_ip_claims[1][0].len()
            + permutation_a_r_a_tail_ip_claims[1][1].len()
            + permutation_b_r_b_tail_ip_claims[0][0].len()
            + permutation_b_r_b_tail_ip_claims[0][1].len()
            + permutation_b_r_b_tail_ip_claims[1][0].len()
            + permutation_b_r_b_tail_ip_claims[1][1].len()
            + mult_ood_ip_claims.len()
            + mult_r_ip_claims.len()
            + acc_ood_ip_claims.len()
            + acc_mult_ip_claims.len()
            + acc_r_ip_claims.len()
            + perm_2_ood_ip_claims.len()
            + permutation_2_a_1_ood_ip_claims.len()
            + permutation_2_a_2_ood_ip_claims.len()
            + permutation_2_b_1_ood_ip_claims.len()
            + permutation_2_b_2_ood_ip_claims.len()
            + permutation_2_a_1_fixed_ip_claims.len()
            + permutation_2_b_1_fixed_ip_claims.len()
            + permutation_2_a_1_r_perm_ip_claims.len()
            + permutation_2_b_1_r_perm_ip_claims.len()
            + permutation_2_word_acc_r_perm_ip_claims.len()
            + permutation_2_word_perm_r_perm_ip_claims.len()
            + permutation_2_identity_r_perm_ip_claims.len()
            + permutation_2_pi_2_r_perm_ip_claims.len()
            + permutation_2_a_2_r_a_ip_claims.len()
            + permutation_2_b_2_r_b_ip_claims.len()
            + permutation_2_a_r_a_tail_ip_claims[0][0].len()
            + permutation_2_a_r_a_tail_ip_claims[0][1].len()
            + permutation_2_a_r_a_tail_ip_claims[1][0].len()
            + permutation_2_a_r_a_tail_ip_claims[1][1].len()
            + permutation_2_b_r_b_tail_ip_claims[0][0].len()
            + permutation_2_b_r_b_tail_ip_claims[0][1].len()
            + permutation_2_b_r_b_tail_ip_claims[1][0].len()
            + permutation_2_b_r_b_tail_ip_claims[1][1].len()
            + mult_2_ood_ip_claims.len()
            + mult_2_r_ip_claims.len()
            + acc_2_ood_ip_claims.len()
            + acc_mult_2_ip_claims.len()
            + acc_2_r_ip_claims.len(),
    );
    ip_claims.extend(ood_ip_claims.iter().cloned());
    ip_claims.extend(codeswitch_ip_claims.iter().cloned());
    ip_claims.extend(base_code_word_ip_claims.iter().cloned());
    ip_claims.extend(base_code_g_left_ip_claims.iter().cloned());
    ip_claims.extend(base_code_g_right_ip_claims.iter().cloned());
    ip_claims.extend(base_code_msg_ip_claims.iter().cloned());
    ip_claims.extend(repeat_ip_claims.iter().cloned());
    ip_claims.extend(perm_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_a_1_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_a_2_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_b_1_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_b_2_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_a_1_fixed_ip_claims.iter().cloned());
    ip_claims.extend(permutation_b_1_fixed_ip_claims.iter().cloned());
    ip_claims.extend(permutation_a_1_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_b_1_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_word_rep_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_word_perm_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_identity_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_pi_1_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_a_2_r_a_ip_claims.iter().cloned());
    ip_claims.extend(permutation_b_2_r_b_ip_claims.iter().cloned());
    ip_claims.extend(permutation_a_r_a_tail_ip_claims[0][0].iter().cloned());
    ip_claims.extend(permutation_a_r_a_tail_ip_claims[0][1].iter().cloned());
    ip_claims.extend(permutation_a_r_a_tail_ip_claims[1][0].iter().cloned());
    ip_claims.extend(permutation_a_r_a_tail_ip_claims[1][1].iter().cloned());
    ip_claims.extend(permutation_b_r_b_tail_ip_claims[0][0].iter().cloned());
    ip_claims.extend(permutation_b_r_b_tail_ip_claims[0][1].iter().cloned());
    ip_claims.extend(permutation_b_r_b_tail_ip_claims[1][0].iter().cloned());
    ip_claims.extend(permutation_b_r_b_tail_ip_claims[1][1].iter().cloned());
    ip_claims.extend(mult_ood_ip_claims.iter().cloned());
    ip_claims.extend(mult_r_ip_claims.iter().cloned());
    ip_claims.extend(acc_ood_ip_claims.iter().cloned());
    ip_claims.extend(acc_mult_ip_claims.iter().cloned());
    ip_claims.extend(acc_r_ip_claims.iter().cloned());
    ip_claims.extend(perm_2_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_a_1_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_a_2_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_b_1_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_b_2_ood_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_a_1_fixed_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_b_1_fixed_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_a_1_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_b_1_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_word_acc_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_word_perm_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_identity_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_pi_2_r_perm_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_a_2_r_a_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_b_2_r_b_ip_claims.iter().cloned());
    ip_claims.extend(permutation_2_a_r_a_tail_ip_claims[0][0].iter().cloned());
    ip_claims.extend(permutation_2_a_r_a_tail_ip_claims[0][1].iter().cloned());
    ip_claims.extend(permutation_2_a_r_a_tail_ip_claims[1][0].iter().cloned());
    ip_claims.extend(permutation_2_a_r_a_tail_ip_claims[1][1].iter().cloned());
    ip_claims.extend(permutation_2_b_r_b_tail_ip_claims[0][0].iter().cloned());
    ip_claims.extend(permutation_2_b_r_b_tail_ip_claims[0][1].iter().cloned());
    ip_claims.extend(permutation_2_b_r_b_tail_ip_claims[1][0].iter().cloned());
    ip_claims.extend(permutation_2_b_r_b_tail_ip_claims[1][1].iter().cloned());
    ip_claims.extend(mult_2_ood_ip_claims.iter().cloned());
    ip_claims.extend(mult_2_r_ip_claims.iter().cloned());
    ip_claims.extend(acc_2_ood_ip_claims.iter().cloned());
    ip_claims.extend(acc_mult_2_ip_claims.iter().cloned());
    ip_claims.extend(acc_2_r_ip_claims.iter().cloned());

    let mut tip_claims =
        Vec::with_capacity(multiply_tip_claims.len() + multiply_tip_claims_2.len());
    tip_claims.extend(multiply_tip_claims.iter().cloned());
    tip_claims.extend(multiply_tip_claims_2.iter().cloned());

    CodeswitchClaimsOutput {
        word_era,
        era_oracles: era_oracles.clone(),
        z_ood_era,
        sigma_ood_era,
        ood_ip_claims,
        beta,
        v_cs,
        sigma_cs,
        codeswitch_ip_claims,
        word_code_b,
        code_b_oracles: code_b_oracles.clone(),
        r_x_code_b,
        sigma_code_b_at_r_x,
        base_code_sumcheck_round_polys: base_code_sumcheck_output.round_polys,
        base_code_sumcheck_challenges: base_code_sumcheck_output.randomness,
        base_code_sumcheck_reduced_claim: base_code_sumcheck_output.final_claim,
        sigma_code_b_g_left_at_r_y,
        sigma_code_b_g_right_at_r_y,
        sigma_code_b_msg_at_r_y,
        base_code_word_ip_claims,
        base_code_g_left_ip_claims,
        base_code_g_right_ip_claims,
        base_code_msg_ip_claims,
        word_rep,
        rep_oracles: rep_oracles.clone(),
        r_rep,
        sigma_rep_at_r_rep,
        repeat_ip_claims,
        word_perm,
        perm_oracles: perm_oracles.clone(),
        z_ood_perm,
        sigma_ood_perm,
        perm_ood_ip_claims,
        permutation_alpha,
        permutation_beta,
        permutation_identity_vector,
        permutation_pi_1_vector,
        permutation_a_1,
        permutation_a_2,
        permutation_b_1,
        permutation_b_2,
        permutation_a_1_oracles: permutation_a_1_oracles.clone(),
        permutation_a_2_oracles: permutation_a_2_oracles.clone(),
        permutation_b_1_oracles: permutation_b_1_oracles.clone(),
        permutation_b_2_oracles: permutation_b_2_oracles.clone(),
        permutation_a_1_z_ood,
        permutation_a_2_z_ood,
        permutation_b_1_z_ood,
        permutation_b_2_z_ood,
        permutation_a_1_sigma_ood,
        permutation_a_2_sigma_ood,
        permutation_b_1_sigma_ood,
        permutation_b_2_sigma_ood,
        permutation_a_1_ood_ip_claims,
        permutation_a_2_ood_ip_claims,
        permutation_b_1_ood_ip_claims,
        permutation_b_2_ood_ip_claims,
        permutation_fixed_point,
        permutation_a_1_sigma_fixed,
        permutation_b_1_sigma_fixed,
        permutation_a_1_fixed_ip_claims,
        permutation_b_1_fixed_ip_claims,
        permutation_r_perm,
        permutation_sigma_a_at_r_perm,
        permutation_sigma_b_at_r_perm,
        permutation_sigma_id_at_r_perm,
        permutation_sigma_word_rep_at_r_perm,
        permutation_sigma_word_perm_at_r_perm,
        permutation_sigma_pi_1_at_r_perm,
        permutation_a_1_r_perm_ip_claims,
        permutation_b_1_r_perm_ip_claims,
        permutation_word_rep_r_perm_ip_claims,
        permutation_word_perm_r_perm_ip_claims,
        permutation_identity_r_perm_ip_claims,
        permutation_pi_1_r_perm_ip_claims,
        permutation_a_transition_sum_claim: permutation_a_transition_sumcheck.sum_claim,
        permutation_a_transition_sumcheck_round_polys: permutation_a_transition_sumcheck
            .round_polys,
        permutation_a_transition_sumcheck_challenges: permutation_a_transition_sumcheck.randomness,
        permutation_a_transition_reduced_claim: permutation_a_transition_sumcheck.final_claim,
        permutation_r_a,
        permutation_a_sigma_one_at_r_a,
        permutation_a_sigma_i_r_a_tail_j,
        permutation_a_sigma_r_a_0,
        permutation_a_sigma_r_a_1,
        permutation_a_2_r_a_ip_claims,
        permutation_a_r_a_tail_ip_claims,
        permutation_b_transition_sum_claim: permutation_b_transition_sumcheck.sum_claim,
        permutation_b_transition_sumcheck_round_polys: permutation_b_transition_sumcheck
            .round_polys,
        permutation_b_transition_sumcheck_challenges: permutation_b_transition_sumcheck.randomness,
        permutation_b_transition_reduced_claim: permutation_b_transition_sumcheck.final_claim,
        permutation_r_b,
        permutation_b_sigma_one_at_r_b,
        permutation_b_sigma_i_r_b_tail_j,
        permutation_b_sigma_r_b_0,
        permutation_b_sigma_r_b_1,
        permutation_b_2_r_b_ip_claims,
        permutation_b_r_b_tail_ip_claims,
        word_mult,
        mult_oracles: mult_oracles.clone(),
        z_ood_mult,
        sigma_ood_mult,
        mult_ood_ip_claims,
        r_mult_challenge,
        r_mult,
        sigma_mult,
        multiply_tip_claims,
        mult_r_ip_claims,
        word_acc,
        acc_oracles: acc_oracles.clone(),
        z_ood_acc,
        sigma_ood_acc,
        acc_ood_ip_claims,
        r_acc,
        acc_map_row_at_r_acc,
        sigma_acc,
        acc_mult_ip_claims,
        acc_r_ip_claims,
        word_perm_2,
        perm_2_oracles: perm_2_oracles.clone(),
        z_ood_perm_2,
        sigma_ood_perm_2,
        perm_2_ood_ip_claims,
        word_mult_2,
        mult_2_oracles: mult_2_oracles.clone(),
        z_ood_mult_2,
        sigma_ood_mult_2,
        mult_2_ood_ip_claims,
        r_mult_challenge_2,
        r_mult_2,
        sigma_mult_2,
        multiply_tip_claims_2,
        mult_2_r_ip_claims,
        word_acc_2,
        acc_2_oracles: acc_2_oracles.clone(),
        z_ood_acc_2,
        sigma_ood_acc_2,
        acc_2_ood_ip_claims,
        r_acc_2,
        acc_map_row_at_r_acc_2,
        sigma_acc_2,
        acc_mult_2_ip_claims,
        acc_2_r_ip_claims,
        aux_oracles: vec![
            era_oracles,
            code_b_oracles,
            rep_oracles,
            perm_oracles,
            mult_oracles,
            acc_oracles,
            perm_2_oracles,
            permutation_2_a_1_oracles,
            permutation_2_a_2_oracles,
            permutation_2_b_1_oracles,
            permutation_2_b_2_oracles,
            mult_2_oracles,
            acc_2_oracles,
            permutation_a_1_oracles,
            permutation_a_2_oracles,
            permutation_b_1_oracles,
            permutation_b_2_oracles,
        ],
        ip_claims,
        tip_claims,
    }
}

/// Build claims/oracles for the implemented `CodeswitchClaims` steps.
///
/// Implemented through step 35 (including second-permutation checks and
/// second multiply/accumulate), with placeholder prefix-product witnesses
/// for `a_2,b_2`.
#[must_use]
pub fn generate_codeswitch_claims<F, CEra, CBase, COut>(
    input: CodeswitchClaimsInput<F>,
    era_code: &CEra,
    base_code: &CBase,
    output_code: &COut,
    rng: &mut impl Rng,
) -> CodeswitchClaimsOutput<F>
where
    F: FieldElement,
    CEra: ErrorCorrectingCode<Alphabet = F>,
    CBase: ErrorCorrectingCode<Alphabet = F>,
    COut: ErrorCorrectingCode<Alphabet = F>,
{
    generate_codeswitch_claims_up_to_base_code_encoding(
        &input,
        era_code,
        base_code,
        output_code,
        rng,
    )
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint};
    use crate::{ErrorCorrectingCode, FieldElement, IdentityCode};

    fn f(x: u32) -> KoalaBear {
        <KoalaBear as FieldElement>::from_u32(x)
    }

    #[derive(Debug, Clone)]
    struct RepeatIdentityCode {
        message_size: usize,
        repeat_factor: usize,
    }

    impl RepeatIdentityCode {
        fn new(message_size: usize, repeat_factor: usize) -> Self {
            assert!(repeat_factor > 0, "repeat_factor must be > 0");
            Self {
                message_size,
                repeat_factor,
            }
        }
    }

    impl ErrorCorrectingCode for RepeatIdentityCode {
        type Alphabet = KoalaBear;

        fn message_size(&self) -> usize {
            self.message_size
        }

        fn block_length(&self) -> usize {
            self.message_size * self.repeat_factor
        }

        fn encode(&self, msg: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
            assert_eq!(
                msg.len(),
                self.message_size,
                "repeat-identity code expects full message input"
            );

            repeat_vector(msg, self.repeat_factor)
        }
    }

    #[test]
    fn test_generate_codeswitch_claims_up_to_base_code_encoding_basic() {
        let era_code = IdentityCode::<KoalaBear>::new(4);
        let base_code = IdentityCode::<KoalaBear>::new(4);
        let output_code = IdentityCode::<KoalaBear>::new(2);

        let input = CodeswitchClaimsInput {
            msg: vec![f(1), f(2), f(3), f(4)],
            spotchecks: vec![
                CodeswitchSpotcheck {
                    alpha: 1,
                    sigma_cs: f(2),
                },
                CodeswitchSpotcheck {
                    alpha: 3,
                    sigma_cs: f(4),
                },
            ],
            // Generator matrix of CodeB' = Identity(2), flattened row-major.
            base_code_prime_generator_matrix: vec![f(1), f(0), f(0), f(1)],
            permutation_1: vec![1, 0, 3, 2],
            permutation_2: vec![0, 1, 2, 3],
            multiplier_1: vec![f(5), f(6), f(7), f(8)],
            multiplier_2: vec![
                f(10).inverse().expect("non-zero"),
                f(16).inverse().expect("non-zero"),
                f(44).inverse().expect("non-zero"),
                f(68).inverse().expect("non-zero"),
            ],
        };

        let mut rng = SmallRng::seed_from_u64(42);
        let out = generate_codeswitch_claims_up_to_base_code_encoding(
            &input,
            &era_code,
            &base_code,
            &output_code,
            &mut rng,
        );

        assert_eq!(out.word_era, vec![f(1), f(2), f(3), f(4)]);
        assert_eq!(out.era_oracles.chunk_count(), 2);
        assert_eq!(out.word_code_b, vec![f(1), f(2), f(3), f(4)]);
        assert_eq!(out.code_b_oracles.chunk_count(), 2);

        let repeat_factor = out.word_era.len() / out.word_code_b.len();
        let expected_word_rep = repeat_vector(&out.word_code_b, repeat_factor);
        assert_eq!(out.word_rep, expected_word_rep);

        let expected_rep_oracles = repeat_split_encoding(&out.code_b_oracles, repeat_factor);
        assert_eq!(&out.rep_oracles.chunks, &expected_rep_oracles.chunks);
        assert_eq!(&out.rep_oracles.codewords, &expected_rep_oracles.codewords);

        let expected_word_perm = apply_permutation(&out.word_rep, &input.permutation_1);
        assert_eq!(out.word_perm, expected_word_perm);
        let expected_perm_oracles = split_and_encode(&out.word_perm, &output_code);
        assert_eq!(&out.perm_oracles.chunks, &expected_perm_oracles.chunks);
        assert_eq!(
            &out.perm_oracles.codewords,
            &expected_perm_oracles.codewords
        );

        let expected_word_mult = hadamard_product(
            &out.word_perm,
            &input.multiplier_1,
            "word_perm",
            "multiplier_1",
        );
        assert_eq!(out.word_mult, expected_word_mult);

        let expected_word_acc = prefix_sums(&out.word_mult);
        assert_eq!(out.word_acc, expected_word_acc);

        // Replay verifier randomness.
        let mut replay_rng = SmallRng::seed_from_u64(42);
        let expected_z = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_beta = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let expected_r_x = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_r_y = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_z_perm = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_permutation_alpha = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let expected_permutation_beta = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let expected_permutation_a_1_z_ood = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_permutation_a_2_z_ood = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_permutation_b_1_z_ood = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_permutation_b_2_z_ood = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_permutation_r_perm = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_permutation_a_transition_sumcheck_challenges = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_permutation_b_transition_sumcheck_challenges = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_z_ood_mult = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_r_mult_challenge = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let expected_z_ood_acc = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_r_acc = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_z_ood_perm_2 = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let _expected_permutation_alpha_2 = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let _expected_permutation_beta_2 = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let _expected_permutation_2_a_1_z_ood = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let _expected_permutation_2_a_2_z_ood = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let _expected_permutation_2_b_1_z_ood = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let _expected_permutation_2_b_2_z_ood = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let _expected_permutation_2_r_perm = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let _expected_permutation_2_a_transition_sumcheck_challenges = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let _expected_permutation_2_b_transition_sumcheck_challenges = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_z_ood_mult_2 = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_r_mult_challenge_2 = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let expected_z_ood_acc_2 = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];
        let expected_r_acc_2 = vec![
            <KoalaBear as FieldElement>::random(&mut replay_rng),
            <KoalaBear as FieldElement>::random(&mut replay_rng),
        ];

        assert_eq!(out.z_ood_era, expected_z);
        assert_eq!(out.beta, expected_beta);
        assert_eq!(out.r_x_code_b, expected_r_x);
        assert_eq!(out.base_code_sumcheck_challenges, expected_r_y);
        assert_eq!(out.z_ood_perm, expected_z_perm);
        assert_eq!(out.permutation_alpha, expected_permutation_alpha);
        assert_eq!(out.permutation_beta, expected_permutation_beta);
        assert_eq!(out.permutation_a_1_z_ood, expected_permutation_a_1_z_ood);
        assert_eq!(out.permutation_a_2_z_ood, expected_permutation_a_2_z_ood);
        assert_eq!(out.permutation_b_1_z_ood, expected_permutation_b_1_z_ood);
        assert_eq!(out.permutation_b_2_z_ood, expected_permutation_b_2_z_ood);
        assert_eq!(out.permutation_r_perm, expected_permutation_r_perm);
        assert_eq!(
            out.permutation_a_transition_sumcheck_challenges,
            expected_permutation_a_transition_sumcheck_challenges
        );
        assert_eq!(
            out.permutation_b_transition_sumcheck_challenges,
            expected_permutation_b_transition_sumcheck_challenges
        );
        assert_eq!(out.z_ood_mult, expected_z_ood_mult);
        assert_eq!(out.r_mult_challenge, expected_r_mult_challenge);
        assert_eq!(out.z_ood_acc, expected_z_ood_acc);
        assert_eq!(out.r_acc, expected_r_acc);
        assert_eq!(out.z_ood_perm_2, expected_z_ood_perm_2);
        assert_eq!(out.z_ood_mult_2, expected_z_ood_mult_2);
        assert_eq!(out.r_mult_challenge_2, expected_r_mult_challenge_2);
        assert_eq!(out.z_ood_acc_2, expected_z_ood_acc_2);
        assert_eq!(out.r_acc_2, expected_r_acc_2);

        let sigma_ood_expected = EvaluationsList::new(out.word_era.clone())
            .evaluate(&MultilinearPoint(out.z_ood_era.clone()));
        assert_eq!(out.sigma_ood_era, sigma_ood_expected);

        let beta_1 = pow_field(out.beta, 1);
        let beta_3 = pow_field(out.beta, 3);
        assert_eq!(out.v_cs[1], beta_1);
        assert_eq!(out.v_cs[3], beta_3);
        assert_eq!(out.v_cs[0], KoalaBear::ZERO);
        assert_eq!(out.v_cs[2], KoalaBear::ZERO);

        let sigma_cs_expected = beta_1 * f(2) + beta_3 * f(4);
        assert_eq!(out.sigma_cs, sigma_cs_expected);

        let sigma_code_b_at_r_x_expected = EvaluationsList::new(out.word_code_b.clone())
            .evaluate(&MultilinearPoint(out.r_x_code_b.clone()));
        assert_eq!(out.sigma_code_b_at_r_x, sigma_code_b_at_r_x_expected);

        let (generator_left_table, generator_right_table, message_table) =
            build_base_code_sumcheck_tip_tables(
                &input.base_code_prime_generator_matrix,
                &out.r_x_code_b,
                &input.msg,
            );

        let claimed_sum_over_y = generator_left_table
            .iter()
            .zip(generator_right_table.iter())
            .zip(message_table.iter())
            .fold(KoalaBear::ZERO, |acc, ((&left, &right), &message_value)| {
                acc + left * right * message_value
            });
        assert_eq!(claimed_sum_over_y, out.sigma_code_b_at_r_x);

        // TIPSumcheck compresses adjacent pairs each round, so the sampled
        // randomness is in low-to-high variable order.
        let r_y_eval_point = MultilinearPoint(
            out.base_code_sumcheck_challenges
                .iter()
                .copied()
                .rev()
                .collect(),
        );
        let generator_left_eval =
            EvaluationsList::new(generator_left_table).evaluate(&r_y_eval_point);
        let generator_right_eval =
            EvaluationsList::new(generator_right_table).evaluate(&r_y_eval_point);
        let message_eval = EvaluationsList::new(message_table).evaluate(&r_y_eval_point);

        assert_eq!(out.sigma_code_b_g_left_at_r_y, generator_left_eval);
        assert_eq!(out.sigma_code_b_g_right_at_r_y, generator_right_eval);
        assert_eq!(out.sigma_code_b_msg_at_r_y, message_eval);
        assert_eq!(
            out.base_code_sumcheck_reduced_claim,
            out.sigma_code_b_g_left_at_r_y
                * out.sigma_code_b_g_right_at_r_y
                * out.sigma_code_b_msg_at_r_y
        );
        assert_eq!(
            out.base_code_sumcheck_round_polys.len(),
            out.word_code_b.len().ilog2() as usize
        );

        let k_prime = output_code.message_size();

        let eq_r_x_code_b = MultilinearPoint(out.r_x_code_b.clone()).eq_weights();
        let expected_base_code_word_ip_claims = split_claim_ip(
            &out.word_code_b,
            &eq_r_x_code_b,
            out.sigma_code_b_at_r_x,
            k_prime,
        );
        assert_eq!(
            out.base_code_word_ip_claims,
            expected_base_code_word_ip_claims
        );

        let (r_x_left_half, r_x_right_half) = out.r_x_code_b.split_at(out.r_x_code_b.len() / 2);
        let (r_y_left_half, r_y_right_half) = r_y_eval_point
            .0
            .split_at(r_y_eval_point.num_variables() / 2);

        let mut r_x_left_r_y_left = Vec::new();
        r_x_left_r_y_left.extend_from_slice(r_x_left_half);
        r_x_left_r_y_left.extend_from_slice(r_y_left_half);
        let eq_r_x_left_r_y_left = MultilinearPoint(r_x_left_r_y_left).eq_weights();
        let expected_base_code_g_left_ip_claims = split_claim_ip(
            &input.base_code_prime_generator_matrix,
            &eq_r_x_left_r_y_left,
            out.sigma_code_b_g_left_at_r_y,
            k_prime,
        );
        assert_eq!(
            out.base_code_g_left_ip_claims,
            expected_base_code_g_left_ip_claims
        );

        let mut r_x_right_r_y_right = Vec::new();
        r_x_right_r_y_right.extend_from_slice(r_x_right_half);
        r_x_right_r_y_right.extend_from_slice(r_y_right_half);
        let eq_r_x_right_r_y_right = MultilinearPoint(r_x_right_r_y_right).eq_weights();
        let expected_base_code_g_right_ip_claims = split_claim_ip(
            &input.base_code_prime_generator_matrix,
            &eq_r_x_right_r_y_right,
            out.sigma_code_b_g_right_at_r_y,
            k_prime,
        );
        assert_eq!(
            out.base_code_g_right_ip_claims,
            expected_base_code_g_right_ip_claims
        );

        let eq_r_y_code_b = r_y_eval_point.eq_weights();
        let expected_base_code_msg_ip_claims = split_claim_ip(
            &input.msg,
            &eq_r_y_code_b,
            out.sigma_code_b_msg_at_r_y,
            k_prime,
        );
        assert_eq!(
            out.base_code_msg_ip_claims,
            expected_base_code_msg_ip_claims
        );

        let mut expected_r_rep = vec![KoalaBear::ZERO; repeat_factor.ilog2() as usize];
        expected_r_rep.extend_from_slice(&out.r_x_code_b);
        assert_eq!(out.r_rep, expected_r_rep);

        let expected_sigma_rep_at_r_rep = EvaluationsList::new(out.word_rep.clone())
            .evaluate(&MultilinearPoint(out.r_rep.clone()));
        assert_eq!(out.sigma_rep_at_r_rep, expected_sigma_rep_at_r_rep);
        assert_eq!(out.sigma_rep_at_r_rep, out.sigma_code_b_at_r_x);

        let eq_r_rep = MultilinearPoint(out.r_rep.clone()).eq_weights();
        let expected_repeat_ip_claims =
            split_claim_ip(&out.word_rep, &eq_r_rep, out.sigma_rep_at_r_rep, k_prime);
        assert_eq!(out.repeat_ip_claims, expected_repeat_ip_claims);

        let expected_sigma_ood_perm = EvaluationsList::new(out.word_perm.clone())
            .evaluate(&MultilinearPoint(out.z_ood_perm.clone()));
        assert_eq!(out.sigma_ood_perm, expected_sigma_ood_perm);

        let eq_z_ood_perm = MultilinearPoint(out.z_ood_perm.clone()).eq_weights();
        let expected_perm_ood_ip_claims =
            split_claim_ip(&out.word_perm, &eq_z_ood_perm, out.sigma_ood_perm, k_prime);
        assert_eq!(out.perm_ood_ip_claims, expected_perm_ood_ip_claims);

        let expected_permutation_identity_vector: Vec<KoalaBear> = (0..out.word_rep.len())
            .map(|index| f(index as u32))
            .collect();
        let expected_permutation_pi_1_vector: Vec<KoalaBear> = input
            .permutation_1
            .iter()
            .copied()
            .map(|value| f(value as u32))
            .collect();
        assert_eq!(
            out.permutation_identity_vector,
            expected_permutation_identity_vector
        );
        assert_eq!(
            out.permutation_pi_1_vector,
            expected_permutation_pi_1_vector
        );

        let expected_permutation_a_1: Vec<KoalaBear> = out
            .word_rep
            .iter()
            .zip(out.permutation_pi_1_vector.iter())
            .map(|(&word_value, &pi_value)| {
                out.permutation_alpha - (word_value + out.permutation_beta * pi_value)
            })
            .collect();
        let expected_permutation_b_1: Vec<KoalaBear> = out
            .word_perm
            .iter()
            .zip(out.permutation_identity_vector.iter())
            .map(|(&word_value, &id_value)| {
                out.permutation_alpha - (word_value + out.permutation_beta * id_value)
            })
            .collect();
        assert_eq!(out.permutation_a_1, expected_permutation_a_1);
        assert_eq!(out.permutation_b_1, expected_permutation_b_1);

        let expected_permutation_a_2 = prefix_products(&out.permutation_a_1);
        let expected_permutation_b_2 = prefix_products(&out.permutation_b_1);
        assert_eq!(out.permutation_a_2, expected_permutation_a_2);
        assert_eq!(out.permutation_b_2, expected_permutation_b_2);

        let expected_permutation_a_1_oracles = split_and_encode(&out.permutation_a_1, &output_code);
        let expected_permutation_a_2_oracles = split_and_encode(&out.permutation_a_2, &output_code);
        let expected_permutation_b_1_oracles = split_and_encode(&out.permutation_b_1, &output_code);
        let expected_permutation_b_2_oracles = split_and_encode(&out.permutation_b_2, &output_code);
        assert_eq!(
            &out.permutation_a_1_oracles.chunks,
            &expected_permutation_a_1_oracles.chunks
        );
        assert_eq!(
            &out.permutation_a_1_oracles.codewords,
            &expected_permutation_a_1_oracles.codewords
        );
        assert_eq!(
            &out.permutation_a_2_oracles.chunks,
            &expected_permutation_a_2_oracles.chunks
        );
        assert_eq!(
            &out.permutation_a_2_oracles.codewords,
            &expected_permutation_a_2_oracles.codewords
        );
        assert_eq!(
            &out.permutation_b_1_oracles.chunks,
            &expected_permutation_b_1_oracles.chunks
        );
        assert_eq!(
            &out.permutation_b_1_oracles.codewords,
            &expected_permutation_b_1_oracles.codewords
        );
        assert_eq!(
            &out.permutation_b_2_oracles.chunks,
            &expected_permutation_b_2_oracles.chunks
        );
        assert_eq!(
            &out.permutation_b_2_oracles.codewords,
            &expected_permutation_b_2_oracles.codewords
        );

        let expected_permutation_a_1_sigma_ood = EvaluationsList::new(out.permutation_a_1.clone())
            .evaluate(&MultilinearPoint(out.permutation_a_1_z_ood.clone()));
        let expected_permutation_a_2_sigma_ood = EvaluationsList::new(out.permutation_a_2.clone())
            .evaluate(&MultilinearPoint(out.permutation_a_2_z_ood.clone()));
        let expected_permutation_b_1_sigma_ood = EvaluationsList::new(out.permutation_b_1.clone())
            .evaluate(&MultilinearPoint(out.permutation_b_1_z_ood.clone()));
        let expected_permutation_b_2_sigma_ood = EvaluationsList::new(out.permutation_b_2.clone())
            .evaluate(&MultilinearPoint(out.permutation_b_2_z_ood.clone()));
        assert_eq!(
            out.permutation_a_1_sigma_ood,
            expected_permutation_a_1_sigma_ood
        );
        assert_eq!(
            out.permutation_a_2_sigma_ood,
            expected_permutation_a_2_sigma_ood
        );
        assert_eq!(
            out.permutation_b_1_sigma_ood,
            expected_permutation_b_1_sigma_ood
        );
        assert_eq!(
            out.permutation_b_2_sigma_ood,
            expected_permutation_b_2_sigma_ood
        );

        let expected_permutation_a_1_ood_ip_claims = split_claim_ip(
            &out.permutation_a_1,
            &MultilinearPoint(out.permutation_a_1_z_ood.clone()).eq_weights(),
            out.permutation_a_1_sigma_ood,
            k_prime,
        );
        let expected_permutation_a_2_ood_ip_claims = split_claim_ip(
            &out.permutation_a_2,
            &MultilinearPoint(out.permutation_a_2_z_ood.clone()).eq_weights(),
            out.permutation_a_2_sigma_ood,
            k_prime,
        );
        let expected_permutation_b_1_ood_ip_claims = split_claim_ip(
            &out.permutation_b_1,
            &MultilinearPoint(out.permutation_b_1_z_ood.clone()).eq_weights(),
            out.permutation_b_1_sigma_ood,
            k_prime,
        );
        let expected_permutation_b_2_ood_ip_claims = split_claim_ip(
            &out.permutation_b_2,
            &MultilinearPoint(out.permutation_b_2_z_ood.clone()).eq_weights(),
            out.permutation_b_2_sigma_ood,
            k_prime,
        );
        assert_eq!(
            out.permutation_a_1_ood_ip_claims,
            expected_permutation_a_1_ood_ip_claims
        );
        assert_eq!(
            out.permutation_a_2_ood_ip_claims,
            expected_permutation_a_2_ood_ip_claims
        );
        assert_eq!(
            out.permutation_b_1_ood_ip_claims,
            expected_permutation_b_1_ood_ip_claims
        );
        assert_eq!(
            out.permutation_b_2_ood_ip_claims,
            expected_permutation_b_2_ood_ip_claims
        );

        let expected_fixed_point =
            build_first_permute_fixed_point::<KoalaBear>(out.word_rep.len().ilog2() as usize);
        assert_eq!(out.permutation_fixed_point, expected_fixed_point);

        let expected_a_1_sigma_fixed = EvaluationsList::new(out.permutation_a_1.clone())
            .evaluate(&MultilinearPoint(out.permutation_fixed_point.clone()));
        let expected_b_1_sigma_fixed = EvaluationsList::new(out.permutation_b_1.clone())
            .evaluate(&MultilinearPoint(out.permutation_fixed_point.clone()));
        assert_eq!(out.permutation_a_1_sigma_fixed, expected_a_1_sigma_fixed);
        assert_eq!(out.permutation_b_1_sigma_fixed, expected_b_1_sigma_fixed);

        let eq_permutation_fixed =
            MultilinearPoint(out.permutation_fixed_point.clone()).eq_weights();
        let expected_permutation_a_1_fixed_ip_claims = split_claim_ip(
            &out.permutation_a_1,
            &eq_permutation_fixed,
            out.permutation_a_1_sigma_fixed,
            k_prime,
        );
        let expected_permutation_b_1_fixed_ip_claims = split_claim_ip(
            &out.permutation_b_1,
            &eq_permutation_fixed,
            out.permutation_b_1_sigma_fixed,
            k_prime,
        );
        assert_eq!(
            out.permutation_a_1_fixed_ip_claims,
            expected_permutation_a_1_fixed_ip_claims
        );
        assert_eq!(
            out.permutation_b_1_fixed_ip_claims,
            expected_permutation_b_1_fixed_ip_claims
        );

        let expected_sigma_a_at_r_perm = EvaluationsList::new(out.permutation_a_1.clone())
            .evaluate(&MultilinearPoint(out.permutation_r_perm.clone()));
        let expected_sigma_b_at_r_perm = EvaluationsList::new(out.permutation_b_1.clone())
            .evaluate(&MultilinearPoint(out.permutation_r_perm.clone()));
        let expected_sigma_id_at_r_perm =
            EvaluationsList::new(out.permutation_identity_vector.clone())
                .evaluate(&MultilinearPoint(out.permutation_r_perm.clone()));
        let expected_sigma_word_rep_at_r_perm = EvaluationsList::new(out.word_rep.clone())
            .evaluate(&MultilinearPoint(out.permutation_r_perm.clone()));
        let expected_sigma_word_perm_at_r_perm = EvaluationsList::new(out.word_perm.clone())
            .evaluate(&MultilinearPoint(out.permutation_r_perm.clone()));
        let expected_sigma_pi_1_at_r_perm =
            EvaluationsList::new(out.permutation_pi_1_vector.clone())
                .evaluate(&MultilinearPoint(out.permutation_r_perm.clone()));

        assert_eq!(
            out.permutation_sigma_a_at_r_perm,
            expected_sigma_a_at_r_perm
        );
        assert_eq!(
            out.permutation_sigma_b_at_r_perm,
            expected_sigma_b_at_r_perm
        );
        assert_eq!(
            out.permutation_sigma_id_at_r_perm,
            expected_sigma_id_at_r_perm
        );
        assert_eq!(
            out.permutation_sigma_word_rep_at_r_perm,
            expected_sigma_word_rep_at_r_perm
        );
        assert_eq!(
            out.permutation_sigma_word_perm_at_r_perm,
            expected_sigma_word_perm_at_r_perm
        );
        assert_eq!(
            out.permutation_sigma_pi_1_at_r_perm,
            expected_sigma_pi_1_at_r_perm
        );

        assert_eq!(
            out.permutation_sigma_a_at_r_perm,
            out.permutation_alpha
                - (out.permutation_sigma_word_rep_at_r_perm
                    + out.permutation_beta * out.permutation_sigma_pi_1_at_r_perm)
        );
        assert_eq!(
            out.permutation_sigma_b_at_r_perm,
            out.permutation_alpha
                - (out.permutation_sigma_word_perm_at_r_perm
                    + out.permutation_beta * out.permutation_sigma_id_at_r_perm)
        );

        let eq_r_perm = MultilinearPoint(out.permutation_r_perm.clone()).eq_weights();
        assert_eq!(
            out.permutation_a_1_r_perm_ip_claims,
            split_claim_ip(
                &out.permutation_a_1,
                &eq_r_perm,
                out.permutation_sigma_a_at_r_perm,
                k_prime,
            )
        );
        assert_eq!(
            out.permutation_b_1_r_perm_ip_claims,
            split_claim_ip(
                &out.permutation_b_1,
                &eq_r_perm,
                out.permutation_sigma_b_at_r_perm,
                k_prime,
            )
        );
        assert_eq!(
            out.permutation_word_rep_r_perm_ip_claims,
            split_claim_ip(
                &out.word_rep,
                &eq_r_perm,
                out.permutation_sigma_word_rep_at_r_perm,
                k_prime,
            )
        );
        assert_eq!(
            out.permutation_word_perm_r_perm_ip_claims,
            split_claim_ip(
                &out.word_perm,
                &eq_r_perm,
                out.permutation_sigma_word_perm_at_r_perm,
                k_prime,
            )
        );
        assert_eq!(
            out.permutation_identity_r_perm_ip_claims,
            split_claim_ip(
                &out.permutation_identity_vector,
                &eq_r_perm,
                out.permutation_sigma_id_at_r_perm,
                k_prime,
            )
        );
        assert_eq!(
            out.permutation_pi_1_r_perm_ip_claims,
            split_claim_ip(
                &out.permutation_pi_1_vector,
                &eq_r_perm,
                out.permutation_sigma_pi_1_at_r_perm,
                k_prime,
            )
        );

        assert_eq!(out.permutation_r_a.len(), out.permutation_r_perm.len());
        assert_eq!(out.permutation_r_b.len(), out.permutation_r_perm.len());
        assert_eq!(
            out.permutation_a_transition_sumcheck_round_polys.len(),
            out.permutation_r_perm.len()
        );
        assert_eq!(
            out.permutation_b_transition_sumcheck_round_polys.len(),
            out.permutation_r_perm.len()
        );

        assert_eq!(
            out.permutation_a_sigma_one_at_r_a,
            EvaluationsList::new(out.permutation_a_2.clone())
                .evaluate(&MultilinearPoint(out.permutation_r_a.clone()))
        );
        assert_eq!(
            out.permutation_b_sigma_one_at_r_b,
            EvaluationsList::new(out.permutation_b_2.clone())
                .evaluate(&MultilinearPoint(out.permutation_r_b.clone()))
        );

        let (&r_a_1, r_a_tail) = out.permutation_r_a.split_first().unwrap();
        let (&r_b_1, r_b_tail) = out.permutation_r_b.split_first().unwrap();
        let r_a_tail_0 = append_coord(r_a_tail, KoalaBear::ZERO);
        let r_a_tail_1 = append_coord(r_a_tail, KoalaBear::ONE);
        let r_b_tail_0 = append_coord(r_b_tail, KoalaBear::ZERO);
        let r_b_tail_1 = append_coord(r_b_tail, KoalaBear::ONE);

        let expected_a_sigma_i_r_tail_j = [
            [
                EvaluationsList::new(out.permutation_a_1.clone())
                    .evaluate(&MultilinearPoint(r_a_tail_0.clone())),
                EvaluationsList::new(out.permutation_a_1.clone())
                    .evaluate(&MultilinearPoint(r_a_tail_1.clone())),
            ],
            [
                EvaluationsList::new(out.permutation_a_2.clone())
                    .evaluate(&MultilinearPoint(r_a_tail_0.clone())),
                EvaluationsList::new(out.permutation_a_2.clone())
                    .evaluate(&MultilinearPoint(r_a_tail_1.clone())),
            ],
        ];
        let expected_b_sigma_i_r_tail_j = [
            [
                EvaluationsList::new(out.permutation_b_1.clone())
                    .evaluate(&MultilinearPoint(r_b_tail_0.clone())),
                EvaluationsList::new(out.permutation_b_1.clone())
                    .evaluate(&MultilinearPoint(r_b_tail_1.clone())),
            ],
            [
                EvaluationsList::new(out.permutation_b_2.clone())
                    .evaluate(&MultilinearPoint(r_b_tail_0.clone())),
                EvaluationsList::new(out.permutation_b_2.clone())
                    .evaluate(&MultilinearPoint(r_b_tail_1.clone())),
            ],
        ];
        assert_eq!(
            out.permutation_a_sigma_i_r_a_tail_j,
            expected_a_sigma_i_r_tail_j
        );
        assert_eq!(
            out.permutation_b_sigma_i_r_b_tail_j,
            expected_b_sigma_i_r_tail_j
        );

        let expected_a_sigma_r_a_0 = (KoalaBear::ONE - r_a_1) * expected_a_sigma_i_r_tail_j[0][0]
            + r_a_1 * expected_a_sigma_i_r_tail_j[1][0];
        let expected_a_sigma_r_a_1 = (KoalaBear::ONE - r_a_1) * expected_a_sigma_i_r_tail_j[0][1]
            + r_a_1 * expected_a_sigma_i_r_tail_j[1][1];
        let expected_b_sigma_r_b_0 = (KoalaBear::ONE - r_b_1) * expected_b_sigma_i_r_tail_j[0][0]
            + r_b_1 * expected_b_sigma_i_r_tail_j[1][0];
        let expected_b_sigma_r_b_1 = (KoalaBear::ONE - r_b_1) * expected_b_sigma_i_r_tail_j[0][1]
            + r_b_1 * expected_b_sigma_i_r_tail_j[1][1];
        assert_eq!(out.permutation_a_sigma_r_a_0, expected_a_sigma_r_a_0);
        assert_eq!(out.permutation_a_sigma_r_a_1, expected_a_sigma_r_a_1);
        assert_eq!(out.permutation_b_sigma_r_b_0, expected_b_sigma_r_b_0);
        assert_eq!(out.permutation_b_sigma_r_b_1, expected_b_sigma_r_b_1);

        let eq_r_a_r_perm = MultilinearPoint(out.permutation_r_a.clone())
            .eq_poly_outside(&MultilinearPoint(out.permutation_r_perm.clone()));
        let eq_r_b_r_perm = MultilinearPoint(out.permutation_r_b.clone())
            .eq_poly_outside(&MultilinearPoint(out.permutation_r_perm.clone()));
        assert_eq!(
            out.permutation_a_transition_reduced_claim,
            eq_r_a_r_perm
                * (out.permutation_a_sigma_one_at_r_a
                    - out.permutation_a_sigma_r_a_0 * out.permutation_a_sigma_r_a_1)
        );
        assert_eq!(
            out.permutation_b_transition_reduced_claim,
            eq_r_b_r_perm
                * (out.permutation_b_sigma_one_at_r_b
                    - out.permutation_b_sigma_r_b_0 * out.permutation_b_sigma_r_b_1)
        );

        assert_eq!(
            out.permutation_a_2_r_a_ip_claims,
            split_claim_ip(
                &out.permutation_a_2,
                &MultilinearPoint(out.permutation_r_a.clone()).eq_weights(),
                out.permutation_a_sigma_one_at_r_a,
                k_prime,
            )
        );
        assert_eq!(
            out.permutation_b_2_r_b_ip_claims,
            split_claim_ip(
                &out.permutation_b_2,
                &MultilinearPoint(out.permutation_r_b.clone()).eq_weights(),
                out.permutation_b_sigma_one_at_r_b,
                k_prime,
            )
        );

        assert_eq!(
            out.permutation_a_r_a_tail_ip_claims[0][0],
            split_claim_ip(
                &out.permutation_a_1,
                &MultilinearPoint(r_a_tail_0).eq_weights(),
                out.permutation_a_sigma_i_r_a_tail_j[0][0],
                k_prime,
            )
        );
        assert_eq!(
            out.permutation_a_r_a_tail_ip_claims[0][1],
            split_claim_ip(
                &out.permutation_a_1,
                &MultilinearPoint(r_a_tail_1).eq_weights(),
                out.permutation_a_sigma_i_r_a_tail_j[0][1],
                k_prime,
            )
        );
        assert_eq!(
            out.permutation_b_r_b_tail_ip_claims[0][0],
            split_claim_ip(
                &out.permutation_b_1,
                &MultilinearPoint(r_b_tail_0).eq_weights(),
                out.permutation_b_sigma_i_r_b_tail_j[0][0],
                k_prime,
            )
        );
        assert_eq!(
            out.permutation_b_r_b_tail_ip_claims[0][1],
            split_claim_ip(
                &out.permutation_b_1,
                &MultilinearPoint(r_b_tail_1).eq_weights(),
                out.permutation_b_sigma_i_r_b_tail_j[0][1],
                k_prime,
            )
        );

        let expected_mult_oracles = split_and_encode(&out.word_mult, &output_code);
        assert_eq!(&out.mult_oracles.chunks, &expected_mult_oracles.chunks);
        assert_eq!(
            &out.mult_oracles.codewords,
            &expected_mult_oracles.codewords
        );

        let expected_sigma_ood_mult = EvaluationsList::new(out.word_mult.clone())
            .evaluate(&MultilinearPoint(out.z_ood_mult.clone()));
        assert_eq!(out.sigma_ood_mult, expected_sigma_ood_mult);
        assert_eq!(
            out.mult_ood_ip_claims,
            split_claim_ip(
                &out.word_mult,
                &MultilinearPoint(out.z_ood_mult.clone()).eq_weights(),
                out.sigma_ood_mult,
                k_prime,
            )
        );

        let expected_r_mult = geometric_power_vector(out.r_mult_challenge, out.word_mult.len());
        assert_eq!(out.r_mult, expected_r_mult);

        let expected_sigma_mult = triple_product(
            &out.word_perm,
            &input.multiplier_1,
            &out.r_mult,
            "word_perm",
            "multiplier_1",
            "r_mult",
        );
        assert_eq!(out.sigma_mult, expected_sigma_mult);
        assert_eq!(
            out.sigma_mult,
            inner_product(&out.word_mult, &out.r_mult, "word_mult", "r_mult")
        );

        assert_eq!(
            out.multiply_tip_claims,
            split_claim_tip(
                &out.word_perm,
                &input.multiplier_1,
                &out.r_mult,
                out.sigma_mult,
                k_prime,
            )
        );
        assert_eq!(
            out.mult_r_ip_claims,
            split_claim_ip(&out.word_mult, &out.r_mult, out.sigma_mult, k_prime)
        );

        let expected_acc_oracles = split_and_encode(&out.word_acc, &output_code);
        assert_eq!(&out.acc_oracles.chunks, &expected_acc_oracles.chunks);
        assert_eq!(&out.acc_oracles.codewords, &expected_acc_oracles.codewords);

        let expected_sigma_ood_acc = EvaluationsList::new(out.word_acc.clone())
            .evaluate(&MultilinearPoint(out.z_ood_acc.clone()));
        assert_eq!(out.sigma_ood_acc, expected_sigma_ood_acc);
        assert_eq!(
            out.acc_ood_ip_claims,
            split_claim_ip(
                &out.word_acc,
                &MultilinearPoint(out.z_ood_acc.clone()).eq_weights(),
                out.sigma_ood_acc,
                k_prime,
            )
        );

        let expected_acc_map_row_at_r_acc = prefix_sum_accumulate_row_at_point(&out.r_acc);
        assert_eq!(out.acc_map_row_at_r_acc, expected_acc_map_row_at_r_acc);
        assert_eq!(
            out.sigma_acc,
            EvaluationsList::new(out.word_acc.clone())
                .evaluate(&MultilinearPoint(out.r_acc.clone()))
        );
        assert_eq!(
            out.sigma_acc,
            inner_product(
                &out.word_mult,
                &out.acc_map_row_at_r_acc,
                "word_mult",
                "acc_map_row_at_r_acc"
            )
        );
        assert_eq!(
            out.acc_mult_ip_claims,
            split_claim_ip(
                &out.word_mult,
                &out.acc_map_row_at_r_acc,
                out.sigma_acc,
                k_prime
            )
        );
        assert_eq!(
            out.acc_r_ip_claims,
            split_claim_ip(
                &out.word_acc,
                &MultilinearPoint(out.r_acc.clone()).eq_weights(),
                out.sigma_acc,
                k_prime,
            )
        );

        let expected_word_perm_2 = apply_permutation(&out.word_acc, &input.permutation_2);
        assert_eq!(out.word_perm_2, expected_word_perm_2);
        let expected_word_mult_2 = hadamard_product(
            &out.word_perm_2,
            &input.multiplier_2,
            "word_perm_2",
            "multiplier_2",
        );
        assert_eq!(out.word_mult_2, expected_word_mult_2);
        assert_eq!(out.word_acc_2, prefix_sums(&out.word_mult_2));
        assert_eq!(out.word_acc_2, out.word_era);

        assert_eq!(
            out.sigma_ood_perm_2,
            EvaluationsList::new(out.word_perm_2.clone())
                .evaluate(&MultilinearPoint(out.z_ood_perm_2.clone()))
        );
        assert_eq!(
            out.perm_2_ood_ip_claims,
            split_claim_ip(
                &out.word_perm_2,
                &MultilinearPoint(out.z_ood_perm_2.clone()).eq_weights(),
                out.sigma_ood_perm_2,
                k_prime,
            )
        );

        assert_eq!(
            out.sigma_ood_mult_2,
            EvaluationsList::new(out.word_mult_2.clone())
                .evaluate(&MultilinearPoint(out.z_ood_mult_2.clone()))
        );
        assert_eq!(
            out.mult_2_ood_ip_claims,
            split_claim_ip(
                &out.word_mult_2,
                &MultilinearPoint(out.z_ood_mult_2.clone()).eq_weights(),
                out.sigma_ood_mult_2,
                k_prime,
            )
        );
        assert_eq!(
            out.r_mult_2,
            geometric_power_vector(out.r_mult_challenge_2, out.word_mult_2.len())
        );
        assert_eq!(
            out.sigma_mult_2,
            triple_product(
                &out.word_perm_2,
                &input.multiplier_2,
                &out.r_mult_2,
                "word_perm_2",
                "multiplier_2",
                "r_mult_2",
            )
        );
        assert_eq!(
            out.sigma_mult_2,
            inner_product(&out.word_mult_2, &out.r_mult_2, "word_mult_2", "r_mult_2")
        );
        assert_eq!(
            out.multiply_tip_claims_2,
            split_claim_tip(
                &out.word_perm_2,
                &input.multiplier_2,
                &out.r_mult_2,
                out.sigma_mult_2,
                k_prime,
            )
        );
        assert_eq!(
            out.mult_2_r_ip_claims,
            split_claim_ip(&out.word_mult_2, &out.r_mult_2, out.sigma_mult_2, k_prime)
        );

        assert_eq!(
            out.sigma_ood_acc_2,
            EvaluationsList::new(out.word_acc_2.clone())
                .evaluate(&MultilinearPoint(out.z_ood_acc_2.clone()))
        );
        assert_eq!(
            out.acc_2_ood_ip_claims,
            split_claim_ip(
                &out.word_acc_2,
                &MultilinearPoint(out.z_ood_acc_2.clone()).eq_weights(),
                out.sigma_ood_acc_2,
                k_prime,
            )
        );
        assert_eq!(
            out.acc_map_row_at_r_acc_2,
            prefix_sum_accumulate_row_at_point(&out.r_acc_2)
        );
        assert_eq!(
            out.sigma_acc_2,
            EvaluationsList::new(out.word_acc_2.clone())
                .evaluate(&MultilinearPoint(out.r_acc_2.clone()))
        );
        assert_eq!(
            out.sigma_acc_2,
            inner_product(
                &out.word_mult_2,
                &out.acc_map_row_at_r_acc_2,
                "word_mult_2",
                "acc_map_row_at_r_acc_2"
            )
        );
        assert_eq!(
            out.acc_mult_2_ip_claims,
            split_claim_ip(
                &out.word_mult_2,
                &out.acc_map_row_at_r_acc_2,
                out.sigma_acc_2,
                k_prime,
            )
        );
        assert_eq!(
            out.acc_2_r_ip_claims,
            split_claim_ip(
                &out.word_acc_2,
                &MultilinearPoint(out.r_acc_2.clone()).eq_weights(),
                out.sigma_acc_2,
                k_prime,
            )
        );

        assert_eq!(out.ood_ip_claims.len(), 2);
        assert_eq!(out.codeswitch_ip_claims.len(), 2);
        assert_eq!(out.base_code_word_ip_claims.len(), 2);
        assert_eq!(out.base_code_g_left_ip_claims.len(), 2);
        assert_eq!(out.base_code_g_right_ip_claims.len(), 2);
        assert_eq!(out.base_code_msg_ip_claims.len(), 2);
        assert_eq!(out.repeat_ip_claims.len(), 2);
        assert_eq!(out.perm_ood_ip_claims.len(), 2);
        assert_eq!(out.mult_ood_ip_claims.len(), 2);
        assert_eq!(out.mult_r_ip_claims.len(), 2);
        assert_eq!(out.acc_ood_ip_claims.len(), 2);
        assert_eq!(out.permutation_a_1_ood_ip_claims.len(), 2);
        assert_eq!(out.permutation_a_2_ood_ip_claims.len(), 2);
        assert_eq!(out.permutation_b_1_ood_ip_claims.len(), 2);
        assert_eq!(out.permutation_b_2_ood_ip_claims.len(), 2);
        assert_eq!(out.permutation_a_1_fixed_ip_claims.len(), 2);
        assert_eq!(out.permutation_b_1_fixed_ip_claims.len(), 2);
        assert_eq!(out.permutation_a_1_r_perm_ip_claims.len(), 2);
        assert_eq!(out.permutation_b_1_r_perm_ip_claims.len(), 2);
        assert_eq!(out.permutation_word_rep_r_perm_ip_claims.len(), 2);
        assert_eq!(out.permutation_word_perm_r_perm_ip_claims.len(), 2);
        assert_eq!(out.permutation_identity_r_perm_ip_claims.len(), 2);
        assert_eq!(out.permutation_pi_1_r_perm_ip_claims.len(), 2);
        assert_eq!(out.permutation_a_2_r_a_ip_claims.len(), 2);
        assert_eq!(out.permutation_b_2_r_b_ip_claims.len(), 2);
        assert_eq!(out.permutation_a_r_a_tail_ip_claims[0][0].len(), 2);
        assert_eq!(out.permutation_a_r_a_tail_ip_claims[0][1].len(), 2);
        assert_eq!(out.permutation_a_r_a_tail_ip_claims[1][0].len(), 2);
        assert_eq!(out.permutation_a_r_a_tail_ip_claims[1][1].len(), 2);
        assert_eq!(out.permutation_b_r_b_tail_ip_claims[0][0].len(), 2);
        assert_eq!(out.permutation_b_r_b_tail_ip_claims[0][1].len(), 2);
        assert_eq!(out.permutation_b_r_b_tail_ip_claims[1][0].len(), 2);
        assert_eq!(out.permutation_b_r_b_tail_ip_claims[1][1].len(), 2);
        assert_eq!(out.acc_mult_ip_claims.len(), 2);
        assert_eq!(out.acc_r_ip_claims.len(), 2);
        assert_eq!(out.perm_2_ood_ip_claims.len(), 2);
        assert_eq!(out.mult_2_ood_ip_claims.len(), 2);
        assert_eq!(out.mult_2_r_ip_claims.len(), 2);
        assert_eq!(out.acc_2_ood_ip_claims.len(), 2);
        assert_eq!(out.acc_mult_2_ip_claims.len(), 2);
        assert_eq!(out.acc_2_r_ip_claims.len(), 2);

        assert_eq!(out.ip_claims.len(), 126);
        assert_eq!(out.aux_oracles.len(), 17);
        assert_eq!(out.tip_claims.len(), 4);
    }

    #[test]
    fn test_generate_codeswitch_claims_repeat_step_with_repeat_factor_two() {
        let era_code = RepeatIdentityCode::new(4, 2);
        let base_code = IdentityCode::<KoalaBear>::new(4);
        let output_code = IdentityCode::<KoalaBear>::new(2);

        let input = CodeswitchClaimsInput {
            msg: vec![f(1), f(2), f(3), f(4)],
            spotchecks: vec![CodeswitchSpotcheck {
                alpha: 1,
                sigma_cs: f(2),
            }],
            base_code_prime_generator_matrix: vec![f(1), f(0), f(0), f(1)],
            permutation_1: vec![4, 5, 6, 7, 0, 1, 2, 3],
            permutation_2: vec![0, 1, 2, 3, 4, 5, 6, 7],
            multiplier_1: vec![f(10), f(11), f(12), f(13), f(14), f(15), f(16), f(17)],
            multiplier_2: vec![
                f(10).inverse().expect("non-zero"),
                f(32).inverse().expect("non-zero"),
                f(68).inverse().expect("non-zero"),
                f(120).inverse().expect("non-zero"),
                (-f(3)) * f(134).inverse().expect("non-zero"),
                f(164).inverse().expect("non-zero"),
                f(212).inverse().expect("non-zero"),
                f(280).inverse().expect("non-zero"),
            ],
        };

        let mut rng = SmallRng::seed_from_u64(123);
        let out = generate_codeswitch_claims_up_to_base_code_encoding(
            &input,
            &era_code,
            &base_code,
            &output_code,
            &mut rng,
        );

        assert_eq!(
            out.word_era,
            vec![f(1), f(2), f(3), f(4), f(1), f(2), f(3), f(4)]
        );
        assert_eq!(out.word_code_b, vec![f(1), f(2), f(3), f(4)]);
        assert_eq!(out.word_rep, out.word_era);

        let expected_word_perm = apply_permutation(&out.word_rep, &input.permutation_1);
        assert_eq!(out.word_perm, expected_word_perm);
        let expected_perm_oracles = split_and_encode(&out.word_perm, &output_code);
        assert_eq!(&out.perm_oracles.chunks, &expected_perm_oracles.chunks);
        assert_eq!(
            &out.perm_oracles.codewords,
            &expected_perm_oracles.codewords
        );

        let expected_word_mult = hadamard_product(
            &out.word_perm,
            &input.multiplier_1,
            "word_perm",
            "multiplier_1",
        );
        assert_eq!(out.word_mult, expected_word_mult);

        let expected_word_acc = prefix_sums(&out.word_mult);
        assert_eq!(out.word_acc, expected_word_acc);

        let expected_sigma_ood_perm = EvaluationsList::new(out.word_perm.clone())
            .evaluate(&MultilinearPoint(out.z_ood_perm.clone()));
        assert_eq!(out.sigma_ood_perm, expected_sigma_ood_perm);

        let expected_r_rep = {
            let mut point = vec![KoalaBear::ZERO];
            point.extend_from_slice(&out.r_x_code_b);
            point
        };
        assert_eq!(out.r_rep, expected_r_rep);

        let eq_r_rep = MultilinearPoint(out.r_rep.clone()).eq_weights();
        let expected_repeat_ip_claims = split_claim_ip(
            &out.word_rep,
            &eq_r_rep,
            out.sigma_rep_at_r_rep,
            output_code.message_size(),
        );
        assert_eq!(out.repeat_ip_claims, expected_repeat_ip_claims);

        let eq_z_ood_perm = MultilinearPoint(out.z_ood_perm.clone()).eq_weights();
        let expected_perm_ood_ip_claims = split_claim_ip(
            &out.word_perm,
            &eq_z_ood_perm,
            out.sigma_ood_perm,
            output_code.message_size(),
        );
        assert_eq!(out.perm_ood_ip_claims, expected_perm_ood_ip_claims);

        let expected_permutation_a_1: Vec<KoalaBear> = out
            .word_rep
            .iter()
            .zip(out.permutation_pi_1_vector.iter())
            .map(|(&word_value, &pi_value)| {
                out.permutation_alpha - (word_value + out.permutation_beta * pi_value)
            })
            .collect();
        let expected_permutation_b_1: Vec<KoalaBear> = out
            .word_perm
            .iter()
            .zip(out.permutation_identity_vector.iter())
            .map(|(&word_value, &id_value)| {
                out.permutation_alpha - (word_value + out.permutation_beta * id_value)
            })
            .collect();
        assert_eq!(out.permutation_a_1, expected_permutation_a_1);
        assert_eq!(out.permutation_b_1, expected_permutation_b_1);
        assert_eq!(out.permutation_a_2, prefix_products(&out.permutation_a_1));
        assert_eq!(out.permutation_b_2, prefix_products(&out.permutation_b_1));

        let expected_permutation_a_1_ood_ip_claims = split_claim_ip(
            &out.permutation_a_1,
            &MultilinearPoint(out.permutation_a_1_z_ood.clone()).eq_weights(),
            out.permutation_a_1_sigma_ood,
            output_code.message_size(),
        );
        let expected_permutation_a_2_ood_ip_claims = split_claim_ip(
            &out.permutation_a_2,
            &MultilinearPoint(out.permutation_a_2_z_ood.clone()).eq_weights(),
            out.permutation_a_2_sigma_ood,
            output_code.message_size(),
        );
        let expected_permutation_b_1_ood_ip_claims = split_claim_ip(
            &out.permutation_b_1,
            &MultilinearPoint(out.permutation_b_1_z_ood.clone()).eq_weights(),
            out.permutation_b_1_sigma_ood,
            output_code.message_size(),
        );
        let expected_permutation_b_2_ood_ip_claims = split_claim_ip(
            &out.permutation_b_2,
            &MultilinearPoint(out.permutation_b_2_z_ood.clone()).eq_weights(),
            out.permutation_b_2_sigma_ood,
            output_code.message_size(),
        );
        assert_eq!(
            out.permutation_a_1_ood_ip_claims,
            expected_permutation_a_1_ood_ip_claims
        );
        assert_eq!(
            out.permutation_a_2_ood_ip_claims,
            expected_permutation_a_2_ood_ip_claims
        );
        assert_eq!(
            out.permutation_b_1_ood_ip_claims,
            expected_permutation_b_1_ood_ip_claims
        );
        assert_eq!(
            out.permutation_b_2_ood_ip_claims,
            expected_permutation_b_2_ood_ip_claims
        );

        assert_eq!(
            out.permutation_sigma_a_at_r_perm,
            out.permutation_alpha
                - (out.permutation_sigma_word_rep_at_r_perm
                    + out.permutation_beta * out.permutation_sigma_pi_1_at_r_perm)
        );
        assert_eq!(
            out.permutation_sigma_b_at_r_perm,
            out.permutation_alpha
                - (out.permutation_sigma_word_perm_at_r_perm
                    + out.permutation_beta * out.permutation_sigma_id_at_r_perm)
        );

        assert_eq!(
            out.permutation_a_transition_sumcheck_round_polys.len(),
            out.permutation_r_perm.len()
        );
        assert_eq!(
            out.permutation_b_transition_sumcheck_round_polys.len(),
            out.permutation_r_perm.len()
        );

        let expected_mult_oracles = split_and_encode(&out.word_mult, &output_code);
        assert_eq!(&out.mult_oracles.chunks, &expected_mult_oracles.chunks);
        assert_eq!(
            &out.mult_oracles.codewords,
            &expected_mult_oracles.codewords
        );

        let expected_sigma_ood_mult = EvaluationsList::new(out.word_mult.clone())
            .evaluate(&MultilinearPoint(out.z_ood_mult.clone()));
        assert_eq!(out.sigma_ood_mult, expected_sigma_ood_mult);
        assert_eq!(
            out.mult_ood_ip_claims,
            split_claim_ip(
                &out.word_mult,
                &MultilinearPoint(out.z_ood_mult.clone()).eq_weights(),
                out.sigma_ood_mult,
                output_code.message_size(),
            )
        );

        let expected_r_mult = geometric_power_vector(out.r_mult_challenge, out.word_mult.len());
        assert_eq!(out.r_mult, expected_r_mult);

        let expected_sigma_mult = triple_product(
            &out.word_perm,
            &input.multiplier_1,
            &out.r_mult,
            "word_perm",
            "multiplier_1",
            "r_mult",
        );
        assert_eq!(out.sigma_mult, expected_sigma_mult);
        assert_eq!(
            out.sigma_mult,
            inner_product(&out.word_mult, &out.r_mult, "word_mult", "r_mult")
        );

        assert_eq!(
            out.multiply_tip_claims,
            split_claim_tip(
                &out.word_perm,
                &input.multiplier_1,
                &out.r_mult,
                out.sigma_mult,
                output_code.message_size(),
            )
        );
        assert_eq!(
            out.mult_r_ip_claims,
            split_claim_ip(
                &out.word_mult,
                &out.r_mult,
                out.sigma_mult,
                output_code.message_size(),
            )
        );

        let expected_acc_oracles = split_and_encode(&out.word_acc, &output_code);
        assert_eq!(&out.acc_oracles.chunks, &expected_acc_oracles.chunks);
        assert_eq!(&out.acc_oracles.codewords, &expected_acc_oracles.codewords);

        let expected_sigma_ood_acc = EvaluationsList::new(out.word_acc.clone())
            .evaluate(&MultilinearPoint(out.z_ood_acc.clone()));
        assert_eq!(out.sigma_ood_acc, expected_sigma_ood_acc);
        assert_eq!(
            out.acc_ood_ip_claims,
            split_claim_ip(
                &out.word_acc,
                &MultilinearPoint(out.z_ood_acc.clone()).eq_weights(),
                out.sigma_ood_acc,
                output_code.message_size(),
            )
        );

        assert_eq!(
            out.acc_map_row_at_r_acc,
            prefix_sum_accumulate_row_at_point(&out.r_acc)
        );
        assert_eq!(
            out.acc_mult_ip_claims,
            split_claim_ip(
                &out.word_mult,
                &out.acc_map_row_at_r_acc,
                out.sigma_acc,
                output_code.message_size(),
            )
        );
        assert_eq!(
            out.acc_r_ip_claims,
            split_claim_ip(
                &out.word_acc,
                &MultilinearPoint(out.r_acc.clone()).eq_weights(),
                out.sigma_acc,
                output_code.message_size(),
            )
        );

        assert_eq!(
            out.word_perm_2,
            apply_permutation(&out.word_acc, &input.permutation_2)
        );
        assert_eq!(
            out.word_mult_2,
            hadamard_product(
                &out.word_perm_2,
                &input.multiplier_2,
                "word_perm_2",
                "multiplier_2",
            )
        );
        assert_eq!(out.word_acc_2, prefix_sums(&out.word_mult_2));
        assert_eq!(out.word_acc_2, out.word_era);

        assert_eq!(
            out.perm_2_ood_ip_claims,
            split_claim_ip(
                &out.word_perm_2,
                &MultilinearPoint(out.z_ood_perm_2.clone()).eq_weights(),
                out.sigma_ood_perm_2,
                output_code.message_size(),
            )
        );
        assert_eq!(
            out.mult_2_ood_ip_claims,
            split_claim_ip(
                &out.word_mult_2,
                &MultilinearPoint(out.z_ood_mult_2.clone()).eq_weights(),
                out.sigma_ood_mult_2,
                output_code.message_size(),
            )
        );
        assert_eq!(
            out.multiply_tip_claims_2,
            split_claim_tip(
                &out.word_perm_2,
                &input.multiplier_2,
                &out.r_mult_2,
                out.sigma_mult_2,
                output_code.message_size(),
            )
        );
        assert_eq!(
            out.mult_2_r_ip_claims,
            split_claim_ip(
                &out.word_mult_2,
                &out.r_mult_2,
                out.sigma_mult_2,
                output_code.message_size(),
            )
        );
        assert_eq!(
            out.acc_2_ood_ip_claims,
            split_claim_ip(
                &out.word_acc_2,
                &MultilinearPoint(out.z_ood_acc_2.clone()).eq_weights(),
                out.sigma_ood_acc_2,
                output_code.message_size(),
            )
        );
        assert_eq!(
            out.acc_mult_2_ip_claims,
            split_claim_ip(
                &out.word_mult_2,
                &out.acc_map_row_at_r_acc_2,
                out.sigma_acc_2,
                output_code.message_size(),
            )
        );
        assert_eq!(
            out.acc_2_r_ip_claims,
            split_claim_ip(
                &out.word_acc_2,
                &MultilinearPoint(out.r_acc_2.clone()).eq_weights(),
                out.sigma_acc_2,
                output_code.message_size(),
            )
        );

        assert_eq!(out.rep_oracles.chunk_count(), 4);
        assert_eq!(out.perm_oracles.chunk_count(), 4);
        assert_eq!(out.repeat_ip_claims.len(), 4);
        assert_eq!(out.perm_ood_ip_claims.len(), 4);
        assert_eq!(out.mult_ood_ip_claims.len(), 4);
        assert_eq!(out.mult_r_ip_claims.len(), 4);
        assert_eq!(out.acc_ood_ip_claims.len(), 4);
        assert_eq!(out.permutation_a_1_ood_ip_claims.len(), 4);
        assert_eq!(out.permutation_a_2_ood_ip_claims.len(), 4);
        assert_eq!(out.permutation_b_1_ood_ip_claims.len(), 4);
        assert_eq!(out.permutation_b_2_ood_ip_claims.len(), 4);
        assert_eq!(out.permutation_a_1_fixed_ip_claims.len(), 4);
        assert_eq!(out.permutation_b_1_fixed_ip_claims.len(), 4);
        assert_eq!(out.permutation_a_1_r_perm_ip_claims.len(), 4);
        assert_eq!(out.permutation_b_1_r_perm_ip_claims.len(), 4);
        assert_eq!(out.permutation_word_rep_r_perm_ip_claims.len(), 4);
        assert_eq!(out.permutation_word_perm_r_perm_ip_claims.len(), 4);
        assert_eq!(out.permutation_identity_r_perm_ip_claims.len(), 4);
        assert_eq!(out.permutation_pi_1_r_perm_ip_claims.len(), 4);
        assert_eq!(out.permutation_a_2_r_a_ip_claims.len(), 4);
        assert_eq!(out.permutation_b_2_r_b_ip_claims.len(), 4);
        assert_eq!(out.permutation_a_r_a_tail_ip_claims[0][0].len(), 4);
        assert_eq!(out.permutation_a_r_a_tail_ip_claims[0][1].len(), 4);
        assert_eq!(out.permutation_a_r_a_tail_ip_claims[1][0].len(), 4);
        assert_eq!(out.permutation_a_r_a_tail_ip_claims[1][1].len(), 4);
        assert_eq!(out.permutation_b_r_b_tail_ip_claims[0][0].len(), 4);
        assert_eq!(out.permutation_b_r_b_tail_ip_claims[0][1].len(), 4);
        assert_eq!(out.permutation_b_r_b_tail_ip_claims[1][0].len(), 4);
        assert_eq!(out.permutation_b_r_b_tail_ip_claims[1][1].len(), 4);
        assert_eq!(out.acc_mult_ip_claims.len(), 4);
        assert_eq!(out.acc_r_ip_claims.len(), 4);
        assert_eq!(out.perm_2_ood_ip_claims.len(), 4);
        assert_eq!(out.mult_2_ood_ip_claims.len(), 4);
        assert_eq!(out.mult_2_r_ip_claims.len(), 4);
        assert_eq!(out.acc_2_ood_ip_claims.len(), 4);
        assert_eq!(out.acc_mult_2_ip_claims.len(), 4);
        assert_eq!(out.acc_2_r_ip_claims.len(), 4);
        assert_eq!(out.ip_claims.len(), 244);
        assert_eq!(out.aux_oracles.len(), 17);
        assert_eq!(out.tip_claims.len(), 8);
    }

    #[test]
    #[should_panic]
    fn test_generate_codeswitch_claims_up_to_base_code_encoding_panics_on_bad_spotcheck() {
        let era_code = IdentityCode::<KoalaBear>::new(4);
        let base_code = IdentityCode::<KoalaBear>::new(4);
        let output_code = IdentityCode::<KoalaBear>::new(2);

        let input = CodeswitchClaimsInput {
            msg: vec![f(1), f(2), f(3), f(4)],
            spotchecks: vec![CodeswitchSpotcheck {
                alpha: 4, // out of range for n_era = 4
                sigma_cs: f(9),
            }],
            base_code_prime_generator_matrix: vec![f(1), f(0), f(0), f(1)],
            permutation_1: vec![0, 1, 2, 3],
            permutation_2: vec![0, 1, 2, 3],
            multiplier_1: vec![f(1), f(1), f(1), f(1)],
            multiplier_2: vec![f(1), f(1), f(1), f(1)],
        };

        let mut rng = SmallRng::seed_from_u64(7);
        let _ = generate_codeswitch_claims_up_to_base_code_encoding(
            &input,
            &era_code,
            &base_code,
            &output_code,
            &mut rng,
        );
    }

    #[test]
    #[should_panic]
    fn test_generate_codeswitch_claims_up_to_base_code_encoding_panics_on_bad_permutation_1() {
        let era_code = IdentityCode::<KoalaBear>::new(4);
        let base_code = IdentityCode::<KoalaBear>::new(4);
        let output_code = IdentityCode::<KoalaBear>::new(2);

        let input = CodeswitchClaimsInput {
            msg: vec![f(1), f(2), f(3), f(4)],
            spotchecks: vec![CodeswitchSpotcheck {
                alpha: 1,
                sigma_cs: f(2),
            }],
            base_code_prime_generator_matrix: vec![f(1), f(0), f(0), f(1)],
            permutation_1: vec![0, 1, 2, 4], // out-of-range 4 for n_era = 4
            permutation_2: vec![0, 1, 2, 3],
            multiplier_1: vec![f(1), f(1), f(1), f(1)],
            multiplier_2: vec![f(1), f(1), f(1), f(1)],
        };

        let mut rng = SmallRng::seed_from_u64(8);
        let _ = generate_codeswitch_claims_up_to_base_code_encoding(
            &input,
            &era_code,
            &base_code,
            &output_code,
            &mut rng,
        );
    }

    #[test]
    #[should_panic(expected = "word_perm length must match multiplier_1 length")]
    fn test_generate_codeswitch_claims_up_to_base_code_encoding_panics_on_bad_multiplier_1_length()
    {
        let era_code = IdentityCode::<KoalaBear>::new(4);
        let base_code = IdentityCode::<KoalaBear>::new(4);
        let output_code = IdentityCode::<KoalaBear>::new(2);

        let input = CodeswitchClaimsInput {
            msg: vec![f(1), f(2), f(3), f(4)],
            spotchecks: vec![CodeswitchSpotcheck {
                alpha: 1,
                sigma_cs: f(2),
            }],
            base_code_prime_generator_matrix: vec![f(1), f(0), f(0), f(1)],
            permutation_1: vec![0, 1, 2, 3],
            permutation_2: vec![0, 1, 2, 3],
            multiplier_1: vec![f(1), f(1), f(1)],
            multiplier_2: vec![f(1), f(1), f(1), f(1)],
        };

        let mut rng = SmallRng::seed_from_u64(12);
        let _ = generate_codeswitch_claims_up_to_base_code_encoding(
            &input,
            &era_code,
            &base_code,
            &output_code,
            &mut rng,
        );
    }

    #[test]
    #[should_panic(expected = "base-code sumcheck claim does not match sigma_code_b_at_r_x")]
    fn test_generate_codeswitch_claims_up_to_base_code_encoding_panics_on_bad_base_code_generator_matrix()
     {
        let era_code = IdentityCode::<KoalaBear>::new(4);
        let base_code = IdentityCode::<KoalaBear>::new(4);
        let output_code = IdentityCode::<KoalaBear>::new(2);

        let input = CodeswitchClaimsInput {
            msg: vec![f(1), f(2), f(3), f(4)],
            spotchecks: vec![CodeswitchSpotcheck {
                alpha: 1,
                sigma_cs: f(2),
            }],
            // Deliberately incorrect for CodeB' = Identity(2).
            base_code_prime_generator_matrix: vec![f(1), f(1), f(1), f(1)],
            permutation_1: vec![0, 1, 2, 3],
            permutation_2: vec![0, 1, 2, 3],
            multiplier_1: vec![f(1), f(1), f(1), f(1)],
            multiplier_2: vec![f(1), f(1), f(1), f(1)],
        };

        let mut rng = SmallRng::seed_from_u64(9);
        let _ = generate_codeswitch_claims_up_to_base_code_encoding(
            &input,
            &era_code,
            &base_code,
            &output_code,
            &mut rng,
        );
    }

    #[test]
    fn test_generate_codeswitch_claims_matches_full_helper() {
        let era_code = IdentityCode::<KoalaBear>::new(4);
        let base_code = IdentityCode::<KoalaBear>::new(4);
        let output_code = IdentityCode::<KoalaBear>::new(2);

        let input = CodeswitchClaimsInput {
            msg: vec![f(1), f(2), f(3), f(4)],
            spotchecks: vec![CodeswitchSpotcheck {
                alpha: 1,
                sigma_cs: f(2),
            }],
            base_code_prime_generator_matrix: vec![f(1), f(0), f(0), f(1)],
            permutation_1: vec![0, 1, 2, 3],
            permutation_2: vec![0, 1, 2, 3],
            multiplier_1: vec![f(3), f(4), f(5), f(6)],
            multiplier_2: vec![
                f(3).inverse().expect("non-zero"),
                f(11).inverse().expect("non-zero"),
                f(26).inverse().expect("non-zero"),
                f(50).inverse().expect("non-zero"),
            ],
        };

        let mut full_rng = SmallRng::seed_from_u64(11);
        let out_full = generate_codeswitch_claims(
            input.clone(),
            &era_code,
            &base_code,
            &output_code,
            &mut full_rng,
        );

        let mut helper_rng = SmallRng::seed_from_u64(11);
        let out_helper = generate_codeswitch_claims_up_to_base_code_encoding(
            &input,
            &era_code,
            &base_code,
            &output_code,
            &mut helper_rng,
        );

        assert_eq!(out_full.word_era, out_helper.word_era);
        assert_eq!(out_full.word_perm, out_helper.word_perm);
        assert_eq!(out_full.word_mult, out_helper.word_mult);
        assert_eq!(out_full.word_acc, out_helper.word_acc);
        assert_eq!(out_full.word_perm_2, out_helper.word_perm_2);
        assert_eq!(out_full.word_mult_2, out_helper.word_mult_2);
        assert_eq!(out_full.word_acc_2, out_helper.word_acc_2);
        assert_eq!(out_full.z_ood_mult, out_helper.z_ood_mult);
        assert_eq!(out_full.z_ood_acc, out_helper.z_ood_acc);
        assert_eq!(out_full.r_mult, out_helper.r_mult);
        assert_eq!(out_full.sigma_mult, out_helper.sigma_mult);
        assert_eq!(out_full.permutation_r_perm, out_helper.permutation_r_perm);
        assert_eq!(
            out_full.permutation_a_transition_reduced_claim,
            out_helper.permutation_a_transition_reduced_claim
        );
        assert_eq!(
            out_full.permutation_b_transition_reduced_claim,
            out_helper.permutation_b_transition_reduced_claim
        );
        assert_eq!(out_full.ip_claims, out_helper.ip_claims);
        assert_eq!(out_full.tip_claims, out_helper.tip_claims);
        assert_eq!(out_full.aux_oracles.len(), out_helper.aux_oracles.len());
    }
}
