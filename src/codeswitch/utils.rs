//! Shared helper utilities used across protocol phases.

use rand::Rng;

use crate::{
    FieldElement,
    poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
};

/// Sample a random point in `F^num_variables`.
pub(crate) fn sample_random_point<F: FieldElement>(
    rng: &mut impl Rng,
    num_variables: usize,
) -> MultilinearPoint<F> {
    MultilinearPoint((0..num_variables).map(|_| F::random(rng)).collect())
}

/// Evaluate a multilinear polynomial from its evaluation table.
pub(crate) fn evaluate_mle<F: FieldElement>(evals: &[F], point: &MultilinearPoint<F>) -> F {
    EvaluationsList::new(evals.to_vec()).evaluate(point)
}

/// In-place `dst += scale * src`.
pub(crate) fn add_scaled<F: FieldElement>(dst: &mut [F], src: &[F], scale: F) {
    debug_assert_eq!(dst.len(), src.len());
    for (dst_item, src_item) in dst.iter_mut().zip(src) {
        *dst_item += *src_item * scale;
    }
}

/// Exponentiation by repeated multiplication with a `usize` exponent.
pub(crate) fn pow_usize<F: FieldElement>(base: F, exponent: usize) -> F {
    let mut acc = F::ONE;
    for _ in 0..exponent {
        acc *= base;
    }
    acc
}
