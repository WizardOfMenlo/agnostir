use rand::{Rng, SeedableRng, rngs::SmallRng};

use crate::{
    ErrorCorrectingCode, FieldElement, OptimizedEraCode,
    poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
};

#[derive(Debug, Clone)]
pub struct CodeswitchParameters<C, F> {
    message_interleaving: usize,   // \ell_m in the paper
    base_code_interleaving: usize, // \ell_{n_B} in the paper
    era_interleaving: usize,       // \ell_{n_{ERA}} in the paper

    repetition_parameter: usize, // used as number of spot checks in the scaffold

    log_start_code_message: usize,
    log_start_code_blocklength: usize,
    log_new_code_message: usize,

    era_code: OptimizedEraCode<C, F>,
}

impl<C, F> CodeswitchParameters<C, F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_interleaving: usize,
        base_code_interleaving: usize,
        era_interleaving: usize,
        repetition_parameter: usize,
        log_start_code_message: usize,
        log_start_code_blocklength: usize,
        log_new_code_message: usize,
        era_code: OptimizedEraCode<C, F>,
    ) -> Self {
        Self {
            message_interleaving,
            base_code_interleaving,
            era_interleaving,
            repetition_parameter,
            log_start_code_message,
            log_start_code_blocklength,
            log_new_code_message,
            era_code,
        }
    }

    pub const fn message_interleaving(&self) -> usize {
        self.message_interleaving
    }

    pub const fn base_code_interleaving(&self) -> usize {
        self.base_code_interleaving
    }

    pub const fn era_interleaving(&self) -> usize {
        self.era_interleaving
    }

    pub const fn num_spot_checks(&self) -> usize {
        self.repetition_parameter
    }

    pub const fn log_start_code_message(&self) -> usize {
        self.log_start_code_message
    }

    pub const fn log_start_code_blocklength(&self) -> usize {
        self.log_start_code_blocklength
    }

    pub const fn log_new_code_message(&self) -> usize {
        self.log_new_code_message
    }

    pub fn z1_num_variables(&self) -> Option<usize> {
        self.log_start_code_message
            .checked_sub(self.log_new_code_message)
    }

    pub fn start_code_blocklength(&self) -> usize {
        1usize << self.log_start_code_blocklength
    }

    pub fn new_code_message_len(&self) -> usize {
        1usize << self.log_new_code_message
    }

    pub fn start_code_message_len(&self) -> usize {
        1usize << self.log_start_code_message
    }

    pub fn new_code(&self) -> &C {
        self.era_code.base_code()
    }
}

impl<C, F> CodeswitchParameters<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F>,
    F: FieldElement,
{
    pub fn new_code_block_len(&self) -> usize {
        self.new_code().block_length()
    }
}

#[derive(Debug, Clone)]
pub struct ReduceIorInput<F: FieldElement> {
    pub eval_point: MultilinearPoint<F>,
    pub eval_value: F,
    pub oracle_word: Vec<F>,
    pub witness_message: Vec<F>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleReference {
    MessageBlock(usize),
    Auxiliary(usize),
}

#[derive(Debug, Clone)]
pub struct IpClaim<F: FieldElement> {
    pub oracle: OracleReference,
    pub vector: Vec<F>,
    pub sigma: F,
    pub witness: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct DipClaim<F: FieldElement> {
    pub left_oracle: OracleReference,
    pub right_oracle: OracleReference,
    pub vector: Vec<F>,
    pub sigma: F,
    pub left_witness: Vec<F>,
    pub right_witness: Vec<F>,
}

#[derive(Debug, Clone, Default)]
pub struct CodeswitchClaims<F: FieldElement> {
    pub auxiliary_oracles: Vec<Vec<F>>,
    pub ip_claims: Vec<IpClaim<F>>,
    pub dip_claims: Vec<DipClaim<F>>,
}

#[derive(Debug, Clone)]
pub struct Round1Block<F: FieldElement> {
    pub message: Vec<F>,
    pub oracle_word: Vec<F>,
    pub y_eval: F,
    pub z_ood: MultilinearPoint<F>,
    pub y_ood: F,
}

#[derive(Debug, Clone)]
pub struct SpotCheck<F: FieldElement> {
    pub index: usize,
    pub value: F,
}

#[derive(Debug, Clone)]
pub struct SumcheckScaffold<F: FieldElement> {
    pub beta: F,
    pub sigma: F,
    pub r: MultilinearPoint<F>,
    pub y_r: F,
}

#[derive(Debug, Clone)]
pub struct EvaluationOpenings<F: FieldElement> {
    pub a_eval: Vec<F>,
    pub a_ood: Vec<F>,
    pub a_ip: Vec<F>,
    pub a_dip_left: Vec<F>,
    pub a_dip_right: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct ReducedMepClaim<F: FieldElement> {
    pub point: MultilinearPoint<F>,
    pub value: F,
    pub oracle_word: Vec<F>,
    pub witness_message: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct ReduceIorScaffoldOutput<F: FieldElement> {
    pub z1: MultilinearPoint<F>,
    pub z2: MultilinearPoint<F>,
    pub round1_blocks: Vec<Round1Block<F>>,
    pub spot_checks: Vec<SpotCheck<F>>,
    pub claims: CodeswitchClaims<F>,
    pub sumcheck: SumcheckScaffold<F>,
    pub openings: EvaluationOpenings<F>,
    pub gamma: F,
    pub reduced_claim: ReducedMepClaim<F>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeswitchError {
    InvalidLogSplit {
        log_start_code_message: usize,
        log_new_code_message: usize,
    },
    MessageInterleavingMismatch {
        expected: usize,
        found: usize,
    },
    WitnessLengthMismatch {
        expected: usize,
        found: usize,
    },
    EvalPointLengthMismatch {
        expected: usize,
        found: usize,
    },
    OracleLengthMismatch {
        expected: usize,
        found: usize,
    },
    NewCodeMessageSizeMismatch {
        expected: usize,
        found: usize,
    },
    ClaimVectorLengthMismatch {
        expected: usize,
        found: usize,
    },
    ClaimWitnessLengthMismatch {
        expected: usize,
        found: usize,
    },
    ClaimOracleLengthMismatch {
        expected: usize,
        found: usize,
    },
    InvalidOracleReference {
        reference: OracleReference,
        message_block_count: usize,
        auxiliary_count: usize,
    },
    EvalConsistencyCheckFailed,
    OpeningConsistencyCheckFailed,
}

pub type CodeswitchResult<T> = Result<T, CodeswitchError>;

pub fn codeswitch<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
    params: &CodeswitchParameters<C, F>,
    input: ReduceIorInput<F>,
) -> CodeswitchResult<ReduceIorScaffoldOutput<F>> {
    let mut rng = SmallRng::seed_from_u64(0xC0DE_CAFE_u64);
    run_reduce_ior_scaffold(params, input, CodeswitchClaims::default(), &mut rng)
}

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

fn split_eval_point<F: FieldElement, C>(
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

fn build_round1_blocks<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
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

fn verify_eval_consistency<F: FieldElement>(
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

fn validate_claims<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
    params: &CodeswitchParameters<C, F>,
    round1_blocks: &[Round1Block<F>],
    claims: &CodeswitchClaims<F>,
) -> CodeswitchResult<()> {
    let expected_message_len = params.new_code_message_len();
    let expected_oracle_len = params.new_code_block_len();

    for aux in &claims.auxiliary_oracles {
        if aux.len() != expected_oracle_len {
            return Err(CodeswitchError::ClaimOracleLengthMismatch {
                expected: expected_oracle_len,
                found: aux.len(),
            });
        }
    }

    for block in round1_blocks {
        if block.oracle_word.len() != expected_oracle_len {
            return Err(CodeswitchError::ClaimOracleLengthMismatch {
                expected: expected_oracle_len,
                found: block.oracle_word.len(),
            });
        }
    }

    for claim in &claims.ip_claims {
        validate_oracle_reference(claim.oracle, round1_blocks, &claims.auxiliary_oracles)?;

        if claim.vector.len() != expected_message_len {
            return Err(CodeswitchError::ClaimVectorLengthMismatch {
                expected: expected_message_len,
                found: claim.vector.len(),
            });
        }
        if claim.witness.len() != expected_message_len {
            return Err(CodeswitchError::ClaimWitnessLengthMismatch {
                expected: expected_message_len,
                found: claim.witness.len(),
            });
        }
    }

    for claim in &claims.dip_claims {
        validate_oracle_reference(claim.left_oracle, round1_blocks, &claims.auxiliary_oracles)?;
        validate_oracle_reference(claim.right_oracle, round1_blocks, &claims.auxiliary_oracles)?;

        if claim.vector.len() != expected_message_len {
            return Err(CodeswitchError::ClaimVectorLengthMismatch {
                expected: expected_message_len,
                found: claim.vector.len(),
            });
        }
        if claim.left_witness.len() != expected_message_len {
            return Err(CodeswitchError::ClaimWitnessLengthMismatch {
                expected: expected_message_len,
                found: claim.left_witness.len(),
            });
        }
        if claim.right_witness.len() != expected_message_len {
            return Err(CodeswitchError::ClaimWitnessLengthMismatch {
                expected: expected_message_len,
                found: claim.right_witness.len(),
            });
        }
    }

    Ok(())
}

fn validate_oracle_reference<F: FieldElement>(
    reference: OracleReference,
    round1_blocks: &[Round1Block<F>],
    auxiliary_oracles: &[Vec<F>],
) -> CodeswitchResult<()> {
    let is_valid = match reference {
        OracleReference::MessageBlock(index) => index < round1_blocks.len(),
        OracleReference::Auxiliary(index) => index < auxiliary_oracles.len(),
    };

    if is_valid {
        Ok(())
    } else {
        Err(CodeswitchError::InvalidOracleReference {
            reference,
            message_block_count: round1_blocks.len(),
            auxiliary_count: auxiliary_oracles.len(),
        })
    }
}

fn sample_spot_checks<F: FieldElement, C>(
    params: &CodeswitchParameters<C, F>,
    oracle_word: &[F],
    rng: &mut impl Rng,
) -> Vec<SpotCheck<F>> {
    let domain_size = params.start_code_blocklength();

    (0..params.num_spot_checks())
        .map(|_| {
            let index = rng.random_range(0..domain_size);
            SpotCheck {
                index,
                value: oracle_word[index],
            }
        })
        .collect()
}

fn compute_sigma<F: FieldElement>(
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

fn compute_openings_at_r<F: FieldElement>(
    r: &MultilinearPoint<F>,
    round1_blocks: &[Round1Block<F>],
    claims: &CodeswitchClaims<F>,
) -> EvaluationOpenings<F> {
    let a_eval: Vec<F> = round1_blocks
        .iter()
        .map(|block| evaluate_mle(&block.message, r))
        .collect();

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

fn compute_y_r<F: FieldElement>(
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

fn ensure_opening_consistency<F: FieldElement>(
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

fn batch_to_reduced_claim<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
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

fn resolve_oracle<'a, F: FieldElement>(
    reference: OracleReference,
    round1_blocks: &'a [Round1Block<F>],
    auxiliary_oracles: &'a [Vec<F>],
) -> Option<&'a [F]> {
    match reference {
        OracleReference::MessageBlock(index) => round1_blocks
            .get(index)
            .map(|block| block.oracle_word.as_slice()),
        OracleReference::Auxiliary(index) => auxiliary_oracles.get(index).map(Vec::as_slice),
    }
}

fn sample_random_point<F: FieldElement>(
    rng: &mut impl Rng,
    num_variables: usize,
) -> MultilinearPoint<F> {
    MultilinearPoint((0..num_variables).map(|_| F::random(rng)).collect())
}

fn evaluate_mle<F: FieldElement>(evals: &[F], point: &MultilinearPoint<F>) -> F {
    EvaluationsList::new(evals.to_vec()).evaluate(point)
}

fn add_scaled<F: FieldElement>(dst: &mut [F], src: &[F], scale: F) {
    debug_assert_eq!(dst.len(), src.len());
    for (dst_item, src_item) in dst.iter_mut().zip(src) {
        *dst_item += *src_item * scale;
    }
}

fn pow_usize<F: FieldElement>(base: F, exponent: usize) -> F {
    let mut acc = F::ONE;
    for _ in 0..exponent {
        acc *= base;
    }
    acc
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

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use rand::{Rng, SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::{IdentityCode, random_permutation};

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

        let era_code = OptimizedEraCode::new(base_code, repetition, interleaving, p1, p2, m1, m2);

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
        let eval_point = MultilinearPoint(random_field_vector(&mut rng, start_code_log_k));

        let z1_num_variables = start_code_log_k - new_code_log_k;
        let z2 = MultilinearPoint(eval_point.0[z1_num_variables..].to_vec());
        let z1 = MultilinearPoint(eval_point.0[..z1_num_variables].to_vec());

        let block_polys: Vec<_> = witness_message
            .chunks_exact(new_code_message_len)
            .map(|chunk| EvaluationsList::new(chunk.to_vec()))
            .collect();

        let y_evals: Vec<_> = block_polys.iter().map(|poly| poly.evaluate(&z2)).collect();

        let eval_value = z1.eq_weights().iter().zip(&y_evals).fold(
            <KoalaBear as crate::FieldElement>::ZERO,
            |acc, (weight, y)| acc + (*weight * *y),
        );

        let oracle_word = params.era_code.encode(&witness_message);

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

        assert_eq!(output.round1_blocks.len(), params.message_interleaving);
        assert_eq!(output.spot_checks.len(), params.repetition_parameter);
        assert_eq!(
            output.sumcheck.r.num_variables(),
            params.log_new_code_message
        );
        assert_eq!(
            output.reduced_claim.witness_message.len(),
            1 << params.log_new_code_message
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
}
