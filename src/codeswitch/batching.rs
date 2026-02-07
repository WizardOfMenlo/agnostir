//! Batching stage: combine individual opening claims into one reduced MEP claim.

use crate::{ErrorCorrectingCode, FieldElement, poly_utils::multilinear::MultilinearPoint};

use super::{
    claims::resolve_oracle,
    errors::{CodeswitchError, CodeswitchResult},
    params::CodeswitchParameters,
    types::{CodeswitchClaims, EvaluationOpenings, ReducedMepClaim, Round1Block},
    utils::{add_scaled, pow_usize},
};

/// Batch all individual evaluation claims into a reduced instance `(r, y')`,
/// virtual oracle `word'`, and witness `msg'`.
pub(crate) fn batch_to_reduced_claim<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
    gamma: F,
    params: &CodeswitchParameters<C, F>,
    r: &MultilinearPoint<F>,
    round1_blocks: &[Round1Block<F>],
    claims: &CodeswitchClaims<F>,
    openings: &EvaluationOpenings<F>,
) -> CodeswitchResult<ReducedMepClaim<F>> {
    let new_code_message_len = params.new_code_message_len();
    let new_code_block_len = params.new_code_block_len();

    let mut y_prime = F::ZERO;
    let mut oracle_prime = vec![F::ZERO; new_code_block_len];
    let mut witness_prime = vec![F::ZERO; new_code_message_len];

    let l_msg = round1_blocks.len();
    let num_ip = claims.ip_claims.len();
    let num_dip = claims.dip_claims.len();

    for (i, block) in round1_blocks.iter().enumerate() {
        let coeff_eval = gamma_coeff_eval(gamma, i);
        let coeff_ood = gamma_coeff_ood(gamma, l_msg, i);

        y_prime += coeff_eval * openings.a_eval[i];
        y_prime += coeff_ood * openings.a_ood[i];

        add_scaled(&mut oracle_prime, &block.oracle_word, coeff_eval);
        add_scaled(&mut oracle_prime, &block.oracle_word, coeff_ood);

        add_scaled(&mut witness_prime, &block.message, coeff_eval);
        add_scaled(&mut witness_prime, &block.message, coeff_ood);
    }

    for (i, claim) in claims.ip_claims.iter().enumerate() {
        let coeff = gamma_coeff_ip(gamma, l_msg, i);

        y_prime += coeff * openings.a_ip[i];
        add_scaled(&mut witness_prime, &claim.witness, coeff);

        let oracle = resolve_oracle(claim.oracle, round1_blocks, &claims.auxiliary_oracles).ok_or(
            CodeswitchError::InvalidOracleReference {
                reference: claim.oracle,
                message_block_count: round1_blocks.len(),
                auxiliary_count: claims.auxiliary_oracles.len(),
            },
        )?;
        add_scaled(&mut oracle_prime, oracle, coeff);
    }

    for (i, claim) in claims.dip_claims.iter().enumerate() {
        let left_coeff = gamma_coeff_dip_left(gamma, l_msg, num_ip, i);
        let right_coeff = gamma_coeff_dip_right(gamma, l_msg, num_ip, num_dip, i);

        y_prime += left_coeff * openings.a_dip_left[i];
        y_prime += right_coeff * openings.a_dip_right[i];

        add_scaled(&mut witness_prime, &claim.left_witness, left_coeff);
        add_scaled(&mut witness_prime, &claim.right_witness, right_coeff);

        let left_oracle =
            resolve_oracle(claim.left_oracle, round1_blocks, &claims.auxiliary_oracles).ok_or(
                CodeswitchError::InvalidOracleReference {
                    reference: claim.left_oracle,
                    message_block_count: round1_blocks.len(),
                    auxiliary_count: claims.auxiliary_oracles.len(),
                },
            )?;
        let right_oracle =
            resolve_oracle(claim.right_oracle, round1_blocks, &claims.auxiliary_oracles).ok_or(
                CodeswitchError::InvalidOracleReference {
                    reference: claim.right_oracle,
                    message_block_count: round1_blocks.len(),
                    auxiliary_count: claims.auxiliary_oracles.len(),
                },
            )?;

        add_scaled(&mut oracle_prime, left_oracle, left_coeff);
        add_scaled(&mut oracle_prime, right_oracle, right_coeff);
    }

    Ok(ReducedMepClaim {
        point: r.clone(),
        value: y_prime,
        oracle_word: oracle_prime,
        witness_message: witness_prime,
    })
}

fn gamma_coeff_eval<F: FieldElement>(gamma: F, index: usize) -> F {
    pow_usize(gamma, index + 1)
}

fn gamma_coeff_ood<F: FieldElement>(gamma: F, l_msg: usize, index: usize) -> F {
    pow_usize(gamma, l_msg + index + 1)
}

fn gamma_coeff_ip<F: FieldElement>(gamma: F, l_msg: usize, index: usize) -> F {
    pow_usize(gamma, (2 * l_msg) + index + 1)
}

fn gamma_coeff_dip_left<F: FieldElement>(gamma: F, l_msg: usize, num_ip: usize, index: usize) -> F {
    // Mirrors the current formula sketch in reduce-ior.tex:
    // gamma^{2l + numIP + i} * gamma^i
    let base = pow_usize(gamma, (2 * l_msg) + num_ip + index + 1);
    let mix = pow_usize(gamma, index + 1);
    base * mix
}

fn gamma_coeff_dip_right<F: FieldElement>(
    gamma: F,
    l_msg: usize,
    num_ip: usize,
    num_dip: usize,
    index: usize,
) -> F {
    // Mirrors the current formula sketch in reduce-ior.tex:
    // gamma^{2l + numIP + numDIP + i} * gamma^i
    let base = pow_usize(gamma, (2 * l_msg) + num_ip + num_dip + index + 1);
    let mix = pow_usize(gamma, index + 1);
    base * mix
}
