use p3_koala_bear::KoalaBear;
use rand::{Rng, SeedableRng, rngs::SmallRng};

use super::*;
use crate::{ErrorCorrectingCode, IdentityCode, random_permutation};

fn random_field_vector(rng: &mut impl Rng, n: usize) -> Vec<KoalaBear> {
    (0..n).map(|_| KoalaBear::new(rng.random())).collect()
}

fn build_fixture() -> (
    CodeswitchParameters<IdentityCode<KoalaBear>, KoalaBear>,
    ReduceIorInput<KoalaBear>,
) {
    let mut rng = SmallRng::seed_from_u64(777);

    let new_code_log_k = 2;
    let start_code_log_k = 2;
    let start_code_log_n = 3;

    let new_code_message_len = 1 << new_code_log_k;
    let start_code_message_len = 1 << start_code_log_k;

    let base_code = IdentityCode::new(new_code_message_len);
    let repetition = 2;
    let interleaving = 0;

    let segment_block_length = repetition * base_code.block_length();
    let p1 = random_permutation(&mut rng, segment_block_length);
    let p2 = random_permutation(&mut rng, segment_block_length);
    let m1 = random_field_vector(&mut rng, segment_block_length);
    let m2 = random_field_vector(&mut rng, segment_block_length);

    let era_code =
        crate::OptimizedEraCode::new(base_code, repetition, interleaving, p1, p2, m1, m2);

    let params = CodeswitchParameters::new(
        1,
        0,
        interleaving,
        3,
        start_code_log_k,
        start_code_log_n,
        new_code_log_k,
        era_code,
    );

    let witness_message = random_field_vector(&mut rng, start_code_message_len);
    let eval_point = crate::poly_utils::multilinear::MultilinearPoint(random_field_vector(
        &mut rng,
        start_code_log_k,
    ));

    let z1_num_variables = start_code_log_k - new_code_log_k;
    let z2 =
        crate::poly_utils::multilinear::MultilinearPoint(eval_point.0[z1_num_variables..].to_vec());
    let z1 =
        crate::poly_utils::multilinear::MultilinearPoint(eval_point.0[..z1_num_variables].to_vec());

    let block_polys: Vec<_> = witness_message
        .chunks_exact(new_code_message_len)
        .map(|chunk| crate::poly_utils::evals::EvaluationsList::new(chunk.to_vec()))
        .collect();

    let y_evals: Vec<_> = block_polys.iter().map(|poly| poly.evaluate(&z2)).collect();

    let eval_value = z1.eq_weights().iter().zip(&y_evals).fold(
        <KoalaBear as crate::FieldElement>::ZERO,
        |acc, (weight, y)| acc + (*weight * *y),
    );

    let oracle_word = params.era_code().encode(&witness_message);

    let input = ReduceIorInput {
        eval_point,
        eval_value,
        oracle_word,
        witness_message,
    };

    (params, input)
}

#[test]
fn scaffold_runs_with_empty_claims() {
    let (params, input) = build_fixture();
    let mut rng = SmallRng::seed_from_u64(2026);

    let output = run_reduce_ior_scaffold(&params, input, CodeswitchClaims::default(), &mut rng)
        .expect("scaffold should succeed");

    assert_eq!(output.round1_blocks.len(), params.message_interleaving());
    assert_eq!(output.spot_checks.len(), params.num_spot_checks());
    assert_eq!(
        output.sumcheck.r.num_variables(),
        params.log_new_code_message()
    );
    assert_eq!(
        output.reduced_claim.witness_message.len(),
        params.new_code_message_len()
    );
    assert_eq!(
        output.reduced_claim.oracle_word.len(),
        params.new_code_block_len()
    );
}

#[test]
fn scaffold_rejects_inconsistent_eval_value() {
    let (params, mut input) = build_fixture();
    let mut rng = SmallRng::seed_from_u64(2027);

    input.eval_value += <KoalaBear as crate::FieldElement>::ONE;

    let err = run_reduce_ior_scaffold(&params, input, CodeswitchClaims::default(), &mut rng)
        .expect_err("bad eval value should be rejected");

    assert_eq!(err, CodeswitchError::EvalConsistencyCheckFailed);
}
