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
//!
//! Not implemented yet:
//! - First multiply/accumulate checks and the second permute/multiply/accumulate chain.

use rand::Rng;

use super::claims::{SplitIpClaim, SplitTipClaim, split_claim_ip};
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
/// verifier challenge sampling (`r^x`), and steps 11-20 (through full step-20 checks).
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

    let mut ip_claims = Vec::with_capacity(
        ood_ip_claims.len()
            + codeswitch_ip_claims.len()
            + base_code_word_ip_claims.len()
            + base_code_g_left_ip_claims.len()
            + base_code_g_right_ip_claims.len()
            + base_code_msg_ip_claims.len()
            + repeat_ip_claims.len()
            + perm_ood_ip_claims.len()
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
            + permutation_b_r_b_tail_ip_claims[1][1].len(),
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
        aux_oracles: vec![
            era_oracles,
            code_b_oracles,
            rep_oracles,
            perm_oracles,
            permutation_a_1_oracles,
            permutation_a_2_oracles,
            permutation_b_1_oracles,
            permutation_b_2_oracles,
        ],
        ip_claims,
        tip_claims: Vec::new(),
    }
}

/// Build claims/oracles for the implemented `CodeswitchClaims` steps.
///
/// Currently implemented through the full first-permutation step (step 20),
/// with placeholder prefix-product witnesses for `a_2,b_2`.
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

        assert_eq!(out.ood_ip_claims.len(), 2);
        assert_eq!(out.codeswitch_ip_claims.len(), 2);
        assert_eq!(out.base_code_word_ip_claims.len(), 2);
        assert_eq!(out.base_code_g_left_ip_claims.len(), 2);
        assert_eq!(out.base_code_g_right_ip_claims.len(), 2);
        assert_eq!(out.base_code_msg_ip_claims.len(), 2);
        assert_eq!(out.repeat_ip_claims.len(), 2);
        assert_eq!(out.perm_ood_ip_claims.len(), 2);
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

        assert_eq!(out.ip_claims.len(), 60);
        assert_eq!(out.aux_oracles.len(), 8);
        assert!(out.tip_claims.is_empty());
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

        assert_eq!(out.rep_oracles.chunk_count(), 4);
        assert_eq!(out.perm_oracles.chunk_count(), 4);
        assert_eq!(out.repeat_ip_claims.len(), 4);
        assert_eq!(out.perm_ood_ip_claims.len(), 4);
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
        assert_eq!(out.ip_claims.len(), 112);
        assert_eq!(out.aux_oracles.len(), 8);
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
    fn test_generate_codeswitch_claims_matches_step_20_helper() {
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
        assert_eq!(out_full.aux_oracles.len(), out_helper.aux_oracles.len());
        assert!(out_full.tip_claims.is_empty());
    }
}
