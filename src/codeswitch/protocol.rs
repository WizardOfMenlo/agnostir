//! Top-level orchestration for the codeswitch Reduce-IOR scaffold.

use rand::{Rng, SeedableRng, rngs::SmallRng};

use crate::{ErrorCorrectingCode, FieldElement};

use super::{
    batching::batch_to_reduced_claim,
    claims::validate_claims,
    errors::{CodeswitchError, CodeswitchResult},
    params::CodeswitchParameters,
    round1::{build_round1_blocks, split_eval_point, verify_eval_consistency},
    spotcheck::sample_spot_checks,
    sumcheck::{compute_openings_at_r, compute_sigma, compute_y_r, ensure_opening_consistency},
    types::{CodeswitchClaims, ReduceIorInput, ReduceIorScaffoldOutput, SumcheckScaffold},
    utils::sample_random_point,
};

/// Convenience entrypoint that runs the scaffold with empty external claims
/// and a deterministic local RNG seed.
pub fn codeswitch<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
    params: &CodeswitchParameters<C, F>,
    input: ReduceIorInput<F>,
) -> CodeswitchResult<ReduceIorScaffoldOutput<F>> {
    let mut rng = SmallRng::seed_from_u64(0xC0DE_CAFE_u64);
    run_reduce_ior_scaffold(params, input, CodeswitchClaims::default(), &mut rng)
}

/// Run the full Reduce-IOR scaffold flow and return all intermediate artifacts.
pub fn run_reduce_ior_scaffold<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
    params: &CodeswitchParameters<C, F>,
    input: ReduceIorInput<F>,
    claims: CodeswitchClaims<F>,
    rng: &mut impl Rng,
) -> CodeswitchResult<ReduceIorScaffoldOutput<F>> {
    validate_input_shape(params, &input)?;

    let (z1, z2) = split_eval_point(params, &input.eval_point)?;
    let round1_blocks = build_round1_blocks(params, &input.witness_message, &z2, rng);

    verify_eval_consistency(&z1, &round1_blocks, input.eval_value)?;
    validate_claims(params, &round1_blocks, &claims)?;

    let spot_checks = sample_spot_checks(params, &input.oracle_word, rng);

    let beta = F::random(rng);
    let sigma = compute_sigma(beta, &round1_blocks, &claims);

    // Sumcheck is currently scaffolded by directly sampling r and evaluating the
    // folded expression locally, instead of running the interactive protocol.
    let r = sample_random_point(rng, params.log_new_code_message());
    let openings = compute_openings_at_r(&r, &round1_blocks, &claims);
    let y_r = compute_y_r(beta, &z2, &r, &round1_blocks, &claims, &openings);

    ensure_opening_consistency(y_r, beta, &z2, &r, &round1_blocks, &claims, &openings)?;

    let sumcheck = SumcheckScaffold {
        beta,
        sigma,
        r: r.clone(),
        y_r,
    };

    let gamma = F::random(rng);
    let reduced_claim =
        batch_to_reduced_claim(gamma, params, &r, &round1_blocks, &claims, &openings)?;

    Ok(ReduceIorScaffoldOutput {
        z1,
        z2,
        round1_blocks,
        spot_checks,
        claims,
        sumcheck,
        openings,
        gamma,
        reduced_claim,
    })
}

fn validate_input_shape<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
    params: &CodeswitchParameters<C, F>,
    input: &ReduceIorInput<F>,
) -> CodeswitchResult<()> {
    let Some(z1_num_variables) = params.z1_num_variables() else {
        return Err(CodeswitchError::InvalidLogSplit {
            log_start_code_message: params.log_start_code_message(),
            log_new_code_message: params.log_new_code_message(),
        });
    };

    let expected_interleaving = 1usize << z1_num_variables;
    if params.message_interleaving() != expected_interleaving {
        return Err(CodeswitchError::MessageInterleavingMismatch {
            expected: expected_interleaving,
            found: params.message_interleaving(),
        });
    }

    let expected_new_code_message_len = params.new_code_message_len();
    let found_new_code_message_len = params.new_code().message_size();
    if found_new_code_message_len != expected_new_code_message_len {
        return Err(CodeswitchError::NewCodeMessageSizeMismatch {
            expected: expected_new_code_message_len,
            found: found_new_code_message_len,
        });
    }

    let expected_witness_len = params.start_code_message_len();
    if input.witness_message.len() != expected_witness_len {
        return Err(CodeswitchError::WitnessLengthMismatch {
            expected: expected_witness_len,
            found: input.witness_message.len(),
        });
    }

    if input.eval_point.num_variables() != params.log_start_code_message() {
        return Err(CodeswitchError::EvalPointLengthMismatch {
            expected: params.log_start_code_message(),
            found: input.eval_point.num_variables(),
        });
    }

    let expected_oracle_len = params.start_code_blocklength();
    if input.oracle_word.len() != expected_oracle_len {
        return Err(CodeswitchError::OracleLengthMismatch {
            expected: expected_oracle_len,
            found: input.oracle_word.len(),
        });
    }

    Ok(())
}
