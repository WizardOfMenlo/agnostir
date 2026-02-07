use super::claims::{
    CodeswitchClaimContext, CodeswitchClaimsBuilder, CodeswitchClaimsPlan, OracleNamespace,
    OracleRef,
};
use super::oracles::{CodeswitchOraclesOutput, split_and_encode};
use crate::{ErrorCorrectingCode, FieldElement};

/// Parameters/challenges needed to scaffold `CodeswitchClaims`.
#[derive(Debug, Clone)]
pub struct CodeswitchClaimsParams<F> {
    pub permutation_1: Vec<usize>,
    pub permutation_2: Vec<usize>,
    pub multiplier_1: Vec<F>,
    pub multiplier_2: Vec<F>,

    /// Spot-check positions over `[0, n_era)`.
    pub spotcheck_indices: Vec<usize>,
    /// Claimed ERA evaluations at `spotcheck_indices`.
    pub spotcheck_evals: Vec<F>,
    /// The random combiner used to aggregate spot checks.
    pub beta_codeswitch: F,

    /// Random combiner for the first multiply check.
    pub r_mult_round_1: F,
    /// Random combiner for the second multiply check.
    pub r_mult_round_2: F,

    /// Random vector for the first accumulate check.
    pub r_acc_round_1: Vec<F>,
    /// Random vector for the second accumulate check.
    pub r_acc_round_2: Vec<F>,
}

impl<F: FieldElement> CodeswitchClaimsParams<F> {
    pub fn n_era(&self) -> usize {
        self.multiplier_1.len()
    }

    pub fn validate(&self) {
        let n_era = self.n_era();
        assert!(n_era > 0, "CodeswitchClaims requires n_era > 0");

        assert_eq!(
            self.permutation_1.len(),
            n_era,
            "permutation_1 length must equal n_era"
        );
        assert_eq!(
            self.permutation_2.len(),
            n_era,
            "permutation_2 length must equal n_era"
        );
        assert_eq!(
            self.multiplier_2.len(),
            n_era,
            "multiplier_2 length must equal n_era"
        );
        assert_eq!(
            self.r_acc_round_1.len(),
            n_era,
            "r_acc_round_1 length must equal n_era"
        );
        assert_eq!(
            self.r_acc_round_2.len(),
            n_era,
            "r_acc_round_2 length must equal n_era"
        );

        assert_eq!(
            self.spotcheck_indices.len(),
            self.spotcheck_evals.len(),
            "spotcheck_indices and spotcheck_evals lengths must match"
        );
        assert!(
            !self.spotcheck_indices.is_empty(),
            "at least one spotcheck index is required"
        );

        assert_is_permutation(&self.permutation_1, n_era, "permutation_1");
        assert_is_permutation(&self.permutation_2, n_era, "permutation_2");

        for &index in &self.spotcheck_indices {
            assert!(
                index < n_era,
                "spotcheck index {index} is out of range for n_era={n_era}"
            );
        }
    }
}

/// Main witness vectors derived while wiring `CodeswitchClaims`.
#[derive(Debug, Clone)]
pub struct CodeswitchWireVectors<F> {
    pub base: Vec<F>,
    pub repeat_round_1: Vec<F>,
    pub perm_round_1: Vec<F>,
    pub mult_round_1: Vec<F>,
    pub acc_round_1: Vec<F>,
    pub perm_round_2: Vec<F>,
    pub mult_round_2: Vec<F>,
    pub era: Vec<F>,
}

/// Oracle references used by the generated claim plan.
#[derive(Debug, Clone)]
pub struct CodeswitchOracleRefs {
    pub message: Vec<OracleRef>,
    pub era: Vec<OracleRef>,
    pub base: Vec<OracleRef>,
    pub repeat_round_1: Vec<OracleRef>,
    pub perm_round_1: Vec<OracleRef>,
    pub mult_round_1: Vec<OracleRef>,
    pub acc_round_1: Vec<OracleRef>,
    pub perm_round_2: Vec<OracleRef>,
    pub mult_round_2: Vec<OracleRef>,
    pub acc_round_2: Vec<OracleRef>,
}

/// Output of the `CodeswitchClaims` scaffolding pass.
#[derive(Debug, Clone)]
pub struct CodeswitchClaimsArtifacts<F> {
    pub plan: CodeswitchClaimsPlan<F>,
    pub oracles: CodeswitchOracleRefs,
    pub wires: CodeswitchWireVectors<F>,
    pub trace: Vec<String>,
}

impl<F> CodeswitchClaimsArtifacts<F> {
    pub fn num_ip(&self) -> usize {
        self.plan.num_ip()
    }

    pub fn num_tip(&self) -> usize {
        self.plan.num_tip()
    }

    pub fn num_aux(&self) -> usize {
        self.plan.aux_oracles.len()
    }
}

/// Scaffold the `CodeswitchClaims` subprotocol.
///
/// This function wires the split-claim graph and tracks round structure.
/// Sumcheck subprotocols are intentionally left as TODO markers for now.
pub fn generate_codeswitch_claims<F, CBase, COut>(
    msg: &[F],
    base_code: &CBase,
    output_code: &COut,
    index_oracles: &CodeswitchOraclesOutput<F>,
    params: &CodeswitchClaimsParams<F>,
) -> CodeswitchClaimsArtifacts<F>
where
    F: FieldElement,
    CBase: ErrorCorrectingCode<Alphabet = F>,
    COut: ErrorCorrectingCode<Alphabet = F>,
{
    params.validate();

    let k_prime = output_code.message_size();
    assert!(k_prime > 0, "output code message_size must be > 0");
    assert_eq!(
        msg.len() % k_prime,
        0,
        "message length must be divisible by k_prime"
    );

    let l_msg = msg.len() / k_prime;
    assert!(
        l_msg > 0,
        "CodeswitchClaims requires at least one msg chunk"
    );

    let n_era = params.n_era();
    assert_eq!(
        n_era % k_prime,
        0,
        "n_era must be divisible by output code message_size"
    );
    let l_era = n_era / k_prime;

    let context = CodeswitchClaimContext::from_codeswitch_oracles(l_msg, index_oracles);
    assert_eq!(
        context.index_oracles.identity, l_era,
        "index identity chunk count must match l_era"
    );
    assert_eq!(
        context.index_oracles.permutation_1, l_era,
        "index permutation_1 chunk count must match l_era"
    );
    assert_eq!(
        context.index_oracles.permutation_2, l_era,
        "index permutation_2 chunk count must match l_era"
    );
    assert_eq!(
        context.index_oracles.multiplier_1, l_era,
        "index multiplier_1 chunk count must match l_era"
    );
    assert_eq!(
        context.index_oracles.multiplier_2, l_era,
        "index multiplier_2 chunk count must match l_era"
    );

    let mut builder = CodeswitchClaimsBuilder::new(k_prime, context);
    let mut trace = Vec::new();

    // Witness vectors for the ERA transition chain.
    let base = base_code.encode(msg);
    assert!(!base.is_empty(), "base code output must be non-empty");

    let repeat_round_1 = repeat_to_length(&base, n_era);
    let perm_round_1 = apply_permutation(&repeat_round_1, &params.permutation_1);
    let mult_round_1 = hadamard_product(&perm_round_1, &params.multiplier_1);
    let acc_round_1 = prefix_sum(&mult_round_1);

    let perm_round_2 = apply_permutation(&acc_round_1, &params.permutation_2);
    let mult_round_2 = hadamard_product(&perm_round_2, &params.multiplier_2);
    let era = prefix_sum(&mult_round_2);

    // Spot-check consistency against the claimed ERA evaluations.
    for (spotcheck_pos, (&index, &claimed_eval)) in params
        .spotcheck_indices
        .iter()
        .zip(params.spotcheck_evals.iter())
        .enumerate()
    {
        assert_eq!(
            claimed_eval, era[index],
            "spotcheck evaluation mismatch at position {spotcheck_pos} (index={index})"
        );
    }

    let message_refs = oracle_refs_for_namespace(OracleNamespace::Message, l_msg);

    trace.push("commit split oracles for base/ERA transition chain".to_string());
    let era_refs = builder.register_aux_oracle_chunks("era", split_and_encode(&era, output_code));
    let base_refs =
        builder.register_aux_oracle_chunks("base", split_and_encode(&base, output_code));
    let repeat_round_1_refs = builder.register_aux_oracle_chunks(
        "repeat_round_1",
        split_and_encode(&repeat_round_1, output_code),
    );
    let perm_round_1_refs = builder
        .register_aux_oracle_chunks("perm_round_1", split_and_encode(&perm_round_1, output_code));
    let mult_round_1_refs = builder
        .register_aux_oracle_chunks("mult_round_1", split_and_encode(&mult_round_1, output_code));
    let acc_round_1_refs = builder
        .register_aux_oracle_chunks("acc_round_1", split_and_encode(&acc_round_1, output_code));
    let perm_round_2_refs = builder
        .register_aux_oracle_chunks("perm_round_2", split_and_encode(&perm_round_2, output_code));
    let mult_round_2_refs = builder
        .register_aux_oracle_chunks("mult_round_2", split_and_encode(&mult_round_2, output_code));

    // ERA spotcheck aggregation claim.
    trace.push("SplitClaimIP: ERA spotcheck aggregation".to_string());
    let v_cs = build_codeswitch_vector(n_era, &params.spotcheck_indices, params.beta_codeswitch);
    let sigma_cs = weighted_spotcheck_sum(
        params.beta_codeswitch,
        &params.spotcheck_indices,
        &params.spotcheck_evals,
    );
    let _chunk_sigmas =
        builder.split_claim_ip("codeswitch.era_spotcheck", &era, &v_cs, sigma_cs, &era_refs);

    // Base-code consistency.
    trace.push("TODO(sumcheck): base-code encoding consistency sumcheck".to_string());

    // Permutation round 1 relation (grand-product style checks).
    trace.push("TODO(sumcheck): first permutation sumcheck checks".to_string());

    // Multiply round 1.
    trace.push("SplitClaimTIP/IP: first multiply step".to_string());
    let r_mult_round_1 = geometric_vector(params.r_mult_round_1, n_era);
    let sigma_mult_round_1 =
        triple_product_full(&perm_round_1, &params.multiplier_1, &r_mult_round_1);
    let index_multiplier_1_refs =
        oracle_refs_for_namespace(OracleNamespace::IndexMultiplier1, l_era);

    let _tip_chunk_sigmas_round_1 = builder.split_claim_tip(
        "codeswitch.round1.multiply.tip",
        &perm_round_1,
        &params.multiplier_1,
        &r_mult_round_1,
        sigma_mult_round_1,
        &perm_round_1_refs,
        &index_multiplier_1_refs,
    );
    let _ip_chunk_sigmas_round_1 = builder.split_claim_ip(
        "codeswitch.round1.multiply.ip",
        &mult_round_1,
        &r_mult_round_1,
        sigma_mult_round_1,
        &mult_round_1_refs,
    );

    // Accumulate round 1 relation: <mult, A_r> == <acc, r>.
    trace.push("SplitClaimIP: first accumulate step".to_string());
    let a_r_round_1 = suffix_sums(&params.r_acc_round_1);
    let sigma_acc_round_1 = inner_product_full(&acc_round_1, &params.r_acc_round_1);
    let _acc_lhs_chunk_sigmas_round_1 = builder.split_claim_ip(
        "codeswitch.round1.accumulate.lhs",
        &mult_round_1,
        &a_r_round_1,
        sigma_acc_round_1,
        &mult_round_1_refs,
    );
    let _acc_rhs_chunk_sigmas_round_1 = builder.split_claim_ip(
        "codeswitch.round1.accumulate.rhs",
        &acc_round_1,
        &params.r_acc_round_1,
        sigma_acc_round_1,
        &acc_round_1_refs,
    );

    // Permutation round 2 relation (grand-product style checks).
    trace.push("TODO(sumcheck): second permutation sumcheck checks".to_string());

    // Multiply round 2.
    trace.push("SplitClaimTIP/IP: second multiply step".to_string());
    let r_mult_round_2 = geometric_vector(params.r_mult_round_2, n_era);
    let sigma_mult_round_2 =
        triple_product_full(&perm_round_2, &params.multiplier_2, &r_mult_round_2);
    let index_multiplier_2_refs =
        oracle_refs_for_namespace(OracleNamespace::IndexMultiplier2, l_era);

    let _tip_chunk_sigmas_round_2 = builder.split_claim_tip(
        "codeswitch.round2.multiply.tip",
        &perm_round_2,
        &params.multiplier_2,
        &r_mult_round_2,
        sigma_mult_round_2,
        &perm_round_2_refs,
        &index_multiplier_2_refs,
    );
    let _ip_chunk_sigmas_round_2 = builder.split_claim_ip(
        "codeswitch.round2.multiply.ip",
        &mult_round_2,
        &r_mult_round_2,
        sigma_mult_round_2,
        &mult_round_2_refs,
    );

    // Accumulate round 2 relation: <mult, A_r> == <era, r>.
    trace.push("SplitClaimIP: second accumulate step".to_string());
    let a_r_round_2 = suffix_sums(&params.r_acc_round_2);
    let sigma_acc_round_2 = inner_product_full(&era, &params.r_acc_round_2);
    let _acc_lhs_chunk_sigmas_round_2 = builder.split_claim_ip(
        "codeswitch.round2.accumulate.lhs",
        &mult_round_2,
        &a_r_round_2,
        sigma_acc_round_2,
        &mult_round_2_refs,
    );
    let _acc_rhs_chunk_sigmas_round_2 = builder.split_claim_ip(
        "codeswitch.round2.accumulate.rhs",
        &era,
        &params.r_acc_round_2,
        sigma_acc_round_2,
        &era_refs,
    );

    let plan = builder.finish();

    let oracles = CodeswitchOracleRefs {
        message: message_refs,
        era: era_refs.clone(),
        base: base_refs,
        repeat_round_1: repeat_round_1_refs,
        perm_round_1: perm_round_1_refs,
        mult_round_1: mult_round_1_refs,
        acc_round_1: acc_round_1_refs,
        perm_round_2: perm_round_2_refs,
        mult_round_2: mult_round_2_refs,
        acc_round_2: era_refs,
    };

    let wires = CodeswitchWireVectors {
        base,
        repeat_round_1,
        perm_round_1,
        mult_round_1,
        acc_round_1,
        perm_round_2,
        mult_round_2,
        era,
    };

    CodeswitchClaimsArtifacts {
        plan,
        oracles,
        wires,
        trace,
    }
}

fn assert_is_permutation(perm: &[usize], n: usize, label: &str) {
    assert_eq!(perm.len(), n, "{label} length must be exactly n_era");

    let mut seen = vec![false; n];
    for &value in perm {
        assert!(value < n, "{label} contains out-of-range value {value}");
        assert!(!seen[value], "{label} contains duplicate value {value}");
        seen[value] = true;
    }
}

fn oracle_refs_for_namespace(namespace: OracleNamespace, count: usize) -> Vec<OracleRef> {
    (0..count)
        .map(|index| OracleRef::new(namespace, index))
        .collect()
}

fn repeat_to_length<F: Copy>(base: &[F], target_len: usize) -> Vec<F> {
    assert!(!base.is_empty(), "cannot repeat an empty base vector");
    assert_eq!(
        target_len % base.len(),
        0,
        "target repetition length must be divisible by base length"
    );

    let mut repeated = Vec::with_capacity(target_len);
    while repeated.len() < target_len {
        repeated.extend_from_slice(base);
    }
    repeated
}

fn apply_permutation<F: Copy>(values: &[F], permutation: &[usize]) -> Vec<F> {
    assert_eq!(
        values.len(),
        permutation.len(),
        "permutation length must match vector length"
    );

    permutation
        .iter()
        .copied()
        .map(|index| {
            assert!(
                index < values.len(),
                "permutation index {index} out of range"
            );
            values[index]
        })
        .collect()
}

fn hadamard_product<F: FieldElement>(lhs: &[F], rhs: &[F]) -> Vec<F> {
    assert_eq!(lhs.len(), rhs.len(), "hadamard-product length mismatch");
    lhs.iter().zip(rhs.iter()).map(|(&x, &y)| x * y).collect()
}

fn prefix_sum<F: FieldElement>(values: &[F]) -> Vec<F> {
    let mut out = Vec::with_capacity(values.len());
    let mut acc = F::ZERO;
    for &value in values {
        acc += value;
        out.push(acc);
    }
    out
}

fn suffix_sums<F: FieldElement>(values: &[F]) -> Vec<F> {
    let mut out = vec![F::ZERO; values.len()];
    let mut acc = F::ZERO;

    for (i, value) in values.iter().copied().enumerate().rev() {
        acc += value;
        out[i] = acc;
    }

    out
}

fn geometric_vector<F: FieldElement>(base: F, len: usize) -> Vec<F> {
    assert!(len > 0, "geometric vector length must be > 0");

    let mut out = Vec::with_capacity(len);
    let mut cur = F::ONE;
    for _ in 0..len {
        out.push(cur);
        cur *= base;
    }

    out
}

fn weighted_spotcheck_sum<F: FieldElement>(beta: F, indices: &[usize], evals: &[F]) -> F {
    assert_eq!(
        indices.len(),
        evals.len(),
        "spotcheck indices/evals length mismatch"
    );

    indices
        .iter()
        .copied()
        .zip(evals.iter().copied())
        .fold(F::ZERO, |acc, (index, eval)| {
            acc + field_pow(beta, index) * eval
        })
}

fn build_codeswitch_vector<F: FieldElement>(n_era: usize, indices: &[usize], beta: F) -> Vec<F> {
    let mut vector = vec![F::ZERO; n_era];

    for &index in indices {
        assert!(
            index < n_era,
            "codeswitch index {index} is out of range for n_era={n_era}"
        );
        vector[index] += field_pow(beta, index);
    }

    vector
}

fn field_pow<F: FieldElement>(base: F, mut exp: usize) -> F {
    if exp == 0 {
        return F::ONE;
    }

    let mut acc = F::ONE;
    let mut cur = base;
    while exp > 0 {
        if exp & 1 == 1 {
            acc *= cur;
        }
        exp >>= 1;
        if exp > 0 {
            cur = cur.square();
        }
    }
    acc
}

fn inner_product_full<F: FieldElement>(lhs: &[F], rhs: &[F]) -> F {
    assert_eq!(lhs.len(), rhs.len(), "inner-product length mismatch");
    lhs.iter()
        .zip(rhs.iter())
        .fold(F::ZERO, |acc, (&x, &y)| acc + x * y)
}

fn triple_product_full<F: FieldElement>(lhs: &[F], rhs: &[F], coeffs: &[F]) -> F {
    assert_eq!(
        lhs.len(),
        rhs.len(),
        "triple-product lhs/rhs length mismatch"
    );
    assert_eq!(
        lhs.len(),
        coeffs.len(),
        "triple-product coeff length mismatch"
    );

    lhs.iter()
        .zip(rhs.iter())
        .zip(coeffs.iter())
        .fold(F::ZERO, |acc, ((&x, &y), &c)| acc + x * y * c)
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::codeswitching::oracles::{CodeswitchOraclesInput, build_codeswitch_oracles};
    use crate::{FieldElement, IdentityCode};

    fn f(x: u32) -> KoalaBear {
        <KoalaBear as FieldElement>::from_u32(x)
    }

    fn sample_permutations(n: usize) -> (Vec<usize>, Vec<usize>) {
        let p1 = (0..n).map(|i| (i + 1) % n).collect();
        let p2 = (0..n).map(|i| (i * 5 + 3) % n).collect();
        (p1, p2)
    }

    #[test]
    fn test_generate_codeswitch_claims_scaffold_happy_path() {
        let msg: Vec<KoalaBear> = (1..=8).map(f).collect();
        let base_code = IdentityCode::<KoalaBear>::new(8);
        let output_code = IdentityCode::<KoalaBear>::new(4);

        let n_era = 16;
        let (permutation_1, permutation_2) = sample_permutations(n_era);
        let multiplier_1: Vec<KoalaBear> = (10..10 + n_era as u32).map(f).collect();
        let multiplier_2: Vec<KoalaBear> = (100..100 + n_era as u32).map(f).collect();

        let base = base_code.encode(&msg);
        let repeat_round_1 = repeat_to_length(&base, n_era);
        let perm_round_1 = apply_permutation(&repeat_round_1, &permutation_1);
        let mult_round_1 = hadamard_product(&perm_round_1, &multiplier_1);
        let acc_round_1 = prefix_sum(&mult_round_1);
        let perm_round_2 = apply_permutation(&acc_round_1, &permutation_2);
        let mult_round_2 = hadamard_product(&perm_round_2, &multiplier_2);
        let era = prefix_sum(&mult_round_2);

        let spotcheck_indices = vec![0, 5, 9, 15];
        let spotcheck_evals = spotcheck_indices.iter().map(|&i| era[i]).collect();

        let params = CodeswitchClaimsParams {
            permutation_1: permutation_1.clone(),
            permutation_2: permutation_2.clone(),
            multiplier_1: multiplier_1.clone(),
            multiplier_2: multiplier_2.clone(),
            spotcheck_indices,
            spotcheck_evals,
            beta_codeswitch: f(7),
            r_mult_round_1: f(13),
            r_mult_round_2: f(17),
            r_acc_round_1: (200..200 + n_era as u32).map(f).collect(),
            r_acc_round_2: (300..300 + n_era as u32).map(f).collect(),
        };

        let index_input = CodeswitchOraclesInput {
            n_era,
            generator_vector: (0..16).map(f).collect(),
            permutation_1,
            permutation_2,
            multiplier_1,
            multiplier_2,
        };
        let index_oracles = build_codeswitch_oracles(&index_input, &output_code);

        let artifacts =
            generate_codeswitch_claims(&msg, &base_code, &output_code, &index_oracles, &params);

        let l_era = n_era / output_code.message_size();

        assert_eq!(artifacts.wires.era, era);
        assert_eq!(artifacts.oracles.era.len(), l_era);

        // 1 (spotcheck) + 2 (multiply IPs) + 4 (accumulate IPs) = 7 split-IP invocations.
        assert_eq!(artifacts.num_ip(), 7 * l_era);
        // 2 multiply TIP invocations.
        assert_eq!(artifacts.num_tip(), 2 * l_era);

        assert!(
            artifacts
                .trace
                .iter()
                .any(|line| line.contains("TODO(sumcheck): base-code"))
        );
        assert!(
            artifacts
                .trace
                .iter()
                .any(|line| line.contains("TODO(sumcheck): first permutation"))
        );
        assert!(
            artifacts
                .trace
                .iter()
                .any(|line| line.contains("TODO(sumcheck): second permutation"))
        );
    }

    #[test]
    #[should_panic]
    fn test_generate_codeswitch_claims_panics_on_bad_spotcheck_eval() {
        let msg: Vec<KoalaBear> = (1..=8).map(f).collect();
        let base_code = IdentityCode::<KoalaBear>::new(8);
        let output_code = IdentityCode::<KoalaBear>::new(4);

        let n_era = 16;
        let (permutation_1, permutation_2) = sample_permutations(n_era);
        let multiplier_1: Vec<KoalaBear> = (10..10 + n_era as u32).map(f).collect();
        let multiplier_2: Vec<KoalaBear> = (100..100 + n_era as u32).map(f).collect();

        let params = CodeswitchClaimsParams {
            permutation_1: permutation_1.clone(),
            permutation_2: permutation_2.clone(),
            multiplier_1: multiplier_1.clone(),
            multiplier_2: multiplier_2.clone(),
            spotcheck_indices: vec![0, 7],
            spotcheck_evals: vec![f(1), f(2)], // wrong on purpose
            beta_codeswitch: f(7),
            r_mult_round_1: f(13),
            r_mult_round_2: f(17),
            r_acc_round_1: (200..200 + n_era as u32).map(f).collect(),
            r_acc_round_2: (300..300 + n_era as u32).map(f).collect(),
        };

        let index_input = CodeswitchOraclesInput {
            n_era,
            generator_vector: (0..16).map(f).collect(),
            permutation_1,
            permutation_2,
            multiplier_1,
            multiplier_2,
        };
        let index_oracles = build_codeswitch_oracles(&index_input, &output_code);

        let _ = generate_codeswitch_claims(&msg, &base_code, &output_code, &index_oracles, &params);
    }
}
