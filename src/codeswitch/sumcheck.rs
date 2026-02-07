//! Sumcheck-related scaffold routines.
//!
//! The current implementation computes the folded expression directly at a
//! sampled point `r` (instead of running interactive sumcheck rounds).

use crate::{FieldElement, poly_utils::multilinear::MultilinearPoint};

use super::{
    errors::{CodeswitchError, CodeswitchResult},
    types::{CodeswitchClaims, EvaluationOpenings, Round1Block},
    utils::evaluate_mle,
};

/// Compute the sumcheck target scalar `sigma` from round-1 values and claims.
pub(crate) fn compute_sigma<F: FieldElement>(
    beta: F,
    round1_blocks: &[Round1Block<F>],
    claims: &CodeswitchClaims<F>,
) -> F {
    let mut sigma = F::ZERO;
    let mut beta_power = beta;

    for block in round1_blocks {
        sigma += beta_power * block.y_eval;
        beta_power *= beta;
    }

    for block in round1_blocks {
        sigma += beta_power * block.y_ood;
        beta_power *= beta;
    }

    for claim in &claims.ip_claims {
        sigma += beta_power * claim.sigma;
        beta_power *= beta;
    }

    for claim in &claims.dip_claims {
        sigma += beta_power * claim.sigma;
        beta_power *= beta;
    }

    sigma
}

/// Compute individual openings at point `r`.
pub(crate) fn compute_openings_at_r<F: FieldElement>(
    r: &MultilinearPoint<F>,
    round1_blocks: &[Round1Block<F>],
    claims: &CodeswitchClaims<F>,
) -> EvaluationOpenings<F> {
    let a_eval: Vec<F> = round1_blocks
        .iter()
        .map(|block| evaluate_mle(&block.message, r))
        .collect();

    // In the current scaffold, `a_ood` mirrors `a_eval` as in the source draft.
    let a_ood = a_eval.clone();

    let a_ip: Vec<F> = claims
        .ip_claims
        .iter()
        .map(|claim| evaluate_mle(&claim.witness, r))
        .collect();

    let a_dip_left: Vec<F> = claims
        .dip_claims
        .iter()
        .map(|claim| evaluate_mle(&claim.left_witness, r))
        .collect();

    let a_dip_right: Vec<F> = claims
        .dip_claims
        .iter()
        .map(|claim| evaluate_mle(&claim.right_witness, r))
        .collect();

    EvaluationOpenings {
        a_eval,
        a_ood,
        a_ip,
        a_dip_left,
        a_dip_right,
    }
}

/// Evaluate the folded expression at point `r`.
pub(crate) fn compute_y_r<F: FieldElement>(
    beta: F,
    z2: &MultilinearPoint<F>,
    r: &MultilinearPoint<F>,
    round1_blocks: &[Round1Block<F>],
    claims: &CodeswitchClaims<F>,
    openings: &EvaluationOpenings<F>,
) -> F {
    let mut y_r = F::ZERO;
    let mut beta_power = beta;

    let eq_z2_r = z2.eq_poly_outside(r);

    for a_eval in &openings.a_eval {
        y_r += beta_power * *a_eval * eq_z2_r;
        beta_power *= beta;
    }

    for (a_ood, block) in openings.a_ood.iter().zip(round1_blocks) {
        let eq_ood_r = block.z_ood.eq_poly_outside(r);
        y_r += beta_power * *a_ood * eq_ood_r;
        beta_power *= beta;
    }

    for (a_ip, claim) in openings.a_ip.iter().zip(&claims.ip_claims) {
        let v_eval = evaluate_mle(&claim.vector, r);
        y_r += beta_power * *a_ip * v_eval;
        beta_power *= beta;
    }

    for ((a_left, a_right), claim) in openings
        .a_dip_left
        .iter()
        .zip(&openings.a_dip_right)
        .zip(&claims.dip_claims)
    {
        let v_eval = evaluate_mle(&claim.vector, r);
        y_r += beta_power * *a_left * *a_right * v_eval;
        beta_power *= beta;
    }

    y_r
}

/// Ensure the opening tuple is self-consistent with `y_r`.
pub(crate) fn ensure_opening_consistency<F: FieldElement>(
    y_r: F,
    beta: F,
    z2: &MultilinearPoint<F>,
    r: &MultilinearPoint<F>,
    round1_blocks: &[Round1Block<F>],
    claims: &CodeswitchClaims<F>,
    openings: &EvaluationOpenings<F>,
) -> CodeswitchResult<()> {
    let recomputed = compute_y_r(beta, z2, r, round1_blocks, claims, openings);
    if recomputed == y_r {
        Ok(())
    } else {
        Err(CodeswitchError::OpeningConsistencyCheckFailed)
    }
}
