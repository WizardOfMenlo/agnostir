//! CodeswitchClaims API from `codeswitching.tex` / `CodeswitchClaims.tex`.
//!
//! Implemented so far:
//! - Steps 1-6 (through the codeswitch IP claim over sampled spotchecks).
//! - Base-code encoding (`word^CodeB = Enc_CodeB(msg)`) and split/encode.
//! - Step 10 challenge sampling: `r^x <- F^{log2(n_CodeB)}`.
//! - Step 11 (`sigma_code_b_at_r_x = w_hat^CodeB(r^x)`).
//! - Step 12 reduction via `TIPSumcheck` to
//!   `(base_code_sumcheck_challenges, base_code_sumcheck_reduced_claim)`.
//!
//! Not implemented yet:
//! - Remaining checks inside "Checking the base code encoding".
//! - All subsequent sections.

use rand::Rng;

use super::claims::{SplitIpClaim, SplitTipClaim, split_claim_ip};
use super::oracles::{SplitEncoding, split_and_encode};
use super::sumcheck::TIPSumcheck;
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

/// Internal helper implementing steps 1-6, base-code encoding, step 10
/// verifier challenge sampling (`r^x`), and steps 11-12.
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

    let mut ip_claims = Vec::with_capacity(ood_ip_claims.len() + codeswitch_ip_claims.len());
    ip_claims.extend(ood_ip_claims.iter().cloned());
    ip_claims.extend(codeswitch_ip_claims.iter().cloned());

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
        aux_oracles: vec![era_oracles, code_b_oracles],
        ip_claims,
        tip_claims: Vec::new(),
    }
}

/// Build all claims/oracles required by the `CodeswitchClaims` subprotocol.
///
/// Currently implemented through step 6, base-code encoding, and steps 10-12
/// inside "Checking the base code encoding".
///
/// # Panics
/// Always panics with `todo!` after step 12, before the remaining checks in
/// "Checking the base code encoding".
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
    let _partial = generate_codeswitch_claims_up_to_base_code_encoding(
        &input,
        era_code,
        base_code,
        output_code,
        rng,
    );

    todo!("CodeswitchClaims: remaining checks for base-code encoding and subsequent steps")
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint};
    use crate::{FieldElement, IdentityCode};

    fn f(x: u32) -> KoalaBear {
        <KoalaBear as FieldElement>::from_u32(x)
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

        assert_eq!(out.z_ood_era, expected_z);
        assert_eq!(out.beta, expected_beta);
        assert_eq!(out.r_x_code_b, expected_r_x);
        assert_eq!(out.base_code_sumcheck_challenges, expected_r_y);

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

        assert_eq!(
            out.base_code_sumcheck_reduced_claim,
            generator_left_eval * generator_right_eval * message_eval
        );
        assert_eq!(
            out.base_code_sumcheck_round_polys.len(),
            out.word_code_b.len().ilog2() as usize
        );

        assert_eq!(out.ood_ip_claims.len(), 2);
        assert_eq!(out.codeswitch_ip_claims.len(), 2);
        assert_eq!(out.ip_claims.len(), 4);
        assert_eq!(out.aux_oracles.len(), 2);
        assert!(out.tip_claims.is_empty());
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
    #[should_panic(expected = "not yet implemented")]
    fn test_generate_codeswitch_claims_hits_todo_after_base_code_encoding_step() {
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
        };

        let mut rng = SmallRng::seed_from_u64(11);
        let _ = generate_codeswitch_claims(input, &era_code, &base_code, &output_code, &mut rng);
    }
}
