use p3_maybe_rayon::prelude::*;
use rand::{SeedableRng, rngs::SmallRng};

use crate::{
    ErrorCorrectingCode, FieldElement, OptimizedEraCode,
    poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
};

#[derive(Debug, Clone)]
pub struct CodeswitchParameters<C, F> {
    message_interleaving: usize,   // \ell_m in the paper
    base_code_interleaving: usize, // \ell_{n_B} in paper
    era_interleaving: usize,       // \ell_{n_{ERA}} in paper

    log_original_code_message: usize,
    log_new_code_message: usize,

    era_code: OptimizedEraCode<C, F>,
}

#[derive(Debug, Clone)]
pub struct CodeswitchInput<F: FieldElement> {
    message: Vec<F>,
    point: Vec<F>,
}

pub fn codeswitch<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
    params: &CodeswitchParameters<C, F>,
    input: CodeswitchInput<F>,
    point: MultilinearPoint<F>,
) {
    assert_eq!(
        input.message.len(),
        params.message_interleaving * (1 << params.log_new_code_message)
    );
    assert_eq!(params.log_original_code_message, point.0.len());

    let new_code_message_len = 1 << params.log_new_code_message;

    let _z_1 = MultilinearPoint(
        point.0[..(params.log_original_code_message - params.log_new_code_message)].to_vec(),
    );
    let z_2 = MultilinearPoint(
        point.0[(params.log_original_code_message - params.log_new_code_message)..].to_vec(),
    );

    // Assume that message is of size params.message_interleaving * (1 << params.log_new_code_message)

    let blocks: Vec<_> = input
        .message
        .par_chunks_exact(new_code_message_len)
        .map(|chunk| EvaluationsList::new(chunk.to_vec()))
        .collect();

    debug_assert_eq!(blocks.len(), params.message_interleaving);

    let y_evals: Vec<F> = blocks
        .par_iter()
        .map(|block| block.evaluate(&z_2))
        .collect();

    // Sample one OOD point per block.
    let mut rng = SmallRng::seed_from_u64(0xC0DE_CAFE_u64);
    let ood_points: Vec<_> = (0..params.message_interleaving)
        .map(|_| {
            MultilinearPoint(
                (0..z_2.0.len())
                    .map(|_| F::random(&mut rng))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();

    let ood_evaluations: Vec<F> = blocks
        .par_iter()
        .zip(ood_points.par_iter())
        .map(|(block, point)| block.evaluate(point))
        .collect();

    // Verifier checks consistency.

    let _ = (&y_evals, &ood_evaluations);
}
