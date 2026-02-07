//! Round-1 of the Reduce-IOR scaffold:
//! message block parsing, per-block evaluations, and initial consistency check.

use rand::Rng;

use crate::{
    ErrorCorrectingCode, FieldElement,
    poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
};

use super::{
    errors::{CodeswitchError, CodeswitchResult},
    params::CodeswitchParameters,
    types::Round1Block,
    utils::sample_random_point,
};

/// Split `z = (z1, z2)` according to `log k` / `log k'`.
pub(crate) fn split_eval_point<F: FieldElement, C>(
    params: &CodeswitchParameters<C, F>,
    point: &MultilinearPoint<F>,
) -> CodeswitchResult<(MultilinearPoint<F>, MultilinearPoint<F>)> {
    let Some(z1_num_variables) = params.z1_num_variables() else {
        return Err(CodeswitchError::InvalidLogSplit {
            log_start_code_message: params.log_start_code_message(),
            log_new_code_message: params.log_new_code_message(),
        });
    };

    let z1 = MultilinearPoint(point.0[..z1_num_variables].to_vec());
    let z2 = MultilinearPoint(point.0[z1_num_variables..].to_vec());
    Ok((z1, z2))
}

/// Build round-1 block data `(msg_i, word_i, y_eval_i, z_ood_i, y_ood_i)`.
pub(crate) fn build_round1_blocks<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
    params: &CodeswitchParameters<C, F>,
    witness_message: &[F],
    z2: &MultilinearPoint<F>,
    rng: &mut impl Rng,
) -> Vec<Round1Block<F>> {
    let new_code_message_len = params.new_code_message_len();
    let new_code = params.new_code();

    witness_message
        .chunks_exact(new_code_message_len)
        .map(|chunk| {
            let block_message = chunk.to_vec();
            let block_poly = EvaluationsList::new(block_message.clone());

            let y_eval = block_poly.evaluate(z2);
            let z_ood = sample_random_point(rng, z2.num_variables());
            let y_ood = block_poly.evaluate(&z_ood);

            let oracle_word = new_code.encode(&block_message);

            Round1Block {
                message: block_message,
                oracle_word,
                y_eval,
                z_ood,
                y_ood,
            }
        })
        .collect()
}

/// Verify `sum_b Eq(z1, b) * y_eval_b == eval_value`.
pub(crate) fn verify_eval_consistency<F: FieldElement>(
    z1: &MultilinearPoint<F>,
    round1_blocks: &[Round1Block<F>],
    eval_value: F,
) -> CodeswitchResult<()> {
    let eq_weights = z1.eq_weights();
    if eq_weights.len() != round1_blocks.len() {
        return Err(CodeswitchError::MessageInterleavingMismatch {
            expected: eq_weights.len(),
            found: round1_blocks.len(),
        });
    }

    let lhs = eq_weights
        .iter()
        .zip(round1_blocks)
        .fold(F::ZERO, |acc, (eq_weight, block)| {
            acc + (*eq_weight * block.y_eval)
        });

    if lhs != eval_value {
        return Err(CodeswitchError::EvalConsistencyCheckFailed);
    }

    Ok(())
}
