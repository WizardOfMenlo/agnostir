use rand::Rng;

use super::{IPSumcheck, TIPSumcheck};
use crate::poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint};
use crate::FieldElement;

#[derive(Debug, Clone)]
pub struct PermutationTransitionTables<F> {
    pub upper: Vec<F>,
    pub lower_left: Vec<F>,
    pub lower_right: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct PermutationTransitionSumcheck<F> {
    upper_table: Vec<F>,
    lower_left_table: Vec<F>,
    lower_right_table: Vec<F>,
    eq_table: Vec<F>,
    upper_sumcheck: IPSumcheck<F>,
    lower_sumcheck: TIPSumcheck<F>,
    current_upper_claim: F,
    current_lower_claim: F,
    current_claim: F,
}

#[derive(Debug, Clone)]
pub struct PermutationTransitionSumcheckOutput<F> {
    /// Claimed sum over the hypercube.
    pub sum_claim: F,
    /// Prover messages for each round, stored as `(h(0), h(1/2), h(2))`.
    pub round_polys: Vec<[F; 3]>,
    /// Verifier challenges sampled per round.
    pub randomness: Vec<F>,
    /// Final reduced claim.
    pub final_claim: F,
    /// Final opening `upper(r)`.
    pub upper_value: F,
    /// Final opening `lower_left(r)`.
    pub lower_left_value: F,
    /// Final opening `lower_right(r)`.
    pub lower_right_value: F,
    /// Final opening `eq(r, r_perm)`.
    pub eq_value: F,
}

#[derive(Debug, Clone)]
struct RoundComponents<F> {
    upper_h_0: F,
    upper_h_half: F,
    upper_h_1: F,
    lower_h_0: F,
    lower_h_half: F,
    lower_h_1: F,
    lower_h_two: F,
    h_0: F,
    h_half: F,
    h_1: F,
    h_two: F,
}

fn evaluate_multilinear_table<F: FieldElement>(table: &[F], point: &[F]) -> F {
    EvaluationsList::new(table.to_vec()).evaluate(&MultilinearPoint(point.to_vec()))
}

#[must_use]
pub fn build_permutation_transition_tables<F: FieldElement>(
    first: &[F],
    second: &[F],
) -> PermutationTransitionTables<F> {
    assert_eq!(
        first.len(),
        second.len(),
        "transition tables require matching witness lengths"
    );
    assert!(
        first.len().is_power_of_two(),
        "transition tables require power-of-two witness length"
    );
    assert!(
        first.len() >= 2,
        "transition tables require witness length >= 2"
    );

    let variable_count = first.len().ilog2() as usize;
    let tail_mask = (1usize << (variable_count - 1)) - 1;

    let mut lower_left = Vec::with_capacity(first.len());
    let mut lower_right = Vec::with_capacity(first.len());

    for index in 0..first.len() {
        let leading_bit = index >> (variable_count - 1);
        let tail_index = index & tail_mask;

        let tail_with_zero = tail_index << 1;
        let tail_with_one = tail_with_zero | 1;

        let source = if leading_bit == 0 { first } else { second };
        lower_left.push(source[tail_with_zero]);
        lower_right.push(source[tail_with_one]);
    }

    PermutationTransitionTables {
        upper: second.to_vec(),
        lower_left,
        lower_right,
    }
}

fn transition_sum_claim<F: FieldElement>(
    upper: &[F],
    lower_left: &[F],
    lower_right: &[F],
    eq_table: &[F],
) -> F {
    assert_eq!(
        upper.len(),
        lower_left.len(),
        "transition table length mismatch"
    );
    assert_eq!(
        upper.len(),
        lower_right.len(),
        "transition table length mismatch"
    );
    assert_eq!(
        upper.len(),
        eq_table.len(),
        "transition table length mismatch"
    );

    upper
        .iter()
        .zip(lower_left.iter())
        .zip(lower_right.iter())
        .zip(eq_table.iter())
        .fold(F::ZERO, |acc, (((&u, &l0), &l1), &eq)| {
            acc + eq * (u - l0 * l1)
        })
}

fn interpolate_quadratic_from_0_half_1<F: FieldElement>(
    value_0: F,
    value_half: F,
    value_1: F,
    at: F,
) -> F {
    // For p(t) = a t^2 + b t + c with
    // p(0)=value_0, p(1/2)=value_half, p(1)=value_1.
    let c = value_0;
    let delta_1 = value_1 - value_0;
    let delta_half = value_half - value_0;

    let four = F::from_u32(4);
    let b = four * delta_half - delta_1;
    let a = delta_1 - b;

    (a * at + b) * at + c
}

fn extrapolate_quadratic_at_two<F: FieldElement>(value_0: F, value_half: F, value_1: F) -> F {
    // Closed form from quadratic interpolation through {0, 1/2, 1}.
    // p(2) = 3 p(0) + 6 p(1) - 8 p(1/2).
    let three = F::from_u32(3);
    let six = F::from_u32(6);
    let eight = F::from_u32(8);
    three * value_0 + six * value_1 - eight * value_half
}

fn interpolate_cubic_from_0_half_1_2<F: FieldElement>(
    value_0: F,
    value_half: F,
    value_1: F,
    value_2: F,
    at: F,
) -> F {
    // Lagrange interpolation at x in {0, 1/2, 1, 2}.
    let two = F::from_u32(2);
    let three = F::from_u32(3);
    let two_inv = two.inverse().expect("2 must be invertible in the field");
    let three_inv = three.inverse().expect("3 must be invertible in the field");

    let one = F::ONE;
    let half = two_inv;
    let eight_thirds = F::from_u32(8) * three_inv;

    let lagrange_0 = -(at - half) * (at - one) * (at - two);
    let lagrange_half = eight_thirds * at * (at - one) * (at - two);
    let lagrange_1 = -two * at * (at - half) * (at - two);
    let lagrange_2 = three_inv * at * (at - half) * (at - one);

    value_0 * lagrange_0 + value_half * lagrange_half + value_1 * lagrange_1 + value_2 * lagrange_2
}

impl<F: FieldElement> PermutationTransitionSumcheck<F> {
    #[must_use]
    pub fn new(tables: PermutationTransitionTables<F>, eq_table: Vec<F>) -> Self {
        let upper_table = tables.upper;
        let lower_left_table = tables.lower_left;
        let lower_right_table = tables.lower_right;

        assert_eq!(
            upper_table.len(),
            lower_left_table.len(),
            "transition table length mismatch"
        );
        assert_eq!(
            upper_table.len(),
            lower_right_table.len(),
            "transition table length mismatch"
        );
        assert_eq!(
            upper_table.len(),
            eq_table.len(),
            "transition table length mismatch"
        );
        assert!(
            upper_table.len().is_power_of_two(),
            "transition sumcheck requires power-of-two table length"
        );
        assert!(
            !upper_table.is_empty(),
            "transition sumcheck requires non-empty tables"
        );

        let sum_upper_claim = eq_table
            .iter()
            .zip(upper_table.iter())
            .fold(F::ZERO, |acc, (&eq_value, &upper_value)| {
                acc + eq_value * upper_value
            });
        let sum_lower_claim = eq_table
            .iter()
            .zip(lower_left_table.iter())
            .zip(lower_right_table.iter())
            .fold(
                F::ZERO,
                |acc, ((&eq_value, &lower_left_value), &lower_right_value)| {
                    acc + eq_value * lower_left_value * lower_right_value
                },
            );

        let sum_claim = transition_sum_claim(
            &upper_table,
            &lower_left_table,
            &lower_right_table,
            &eq_table,
        );
        assert_eq!(
            sum_claim,
            sum_upper_claim - sum_lower_claim,
            "transition sum claim decomposition mismatch"
        );

        let upper_sumcheck = IPSumcheck::new(eq_table.clone(), upper_table.clone());
        let lower_sumcheck = TIPSumcheck::new(
            eq_table.clone(),
            lower_left_table.clone(),
            lower_right_table.clone(),
        );

        Self {
            upper_table,
            lower_left_table,
            lower_right_table,
            eq_table,
            upper_sumcheck,
            lower_sumcheck,
            current_upper_claim: sum_upper_claim,
            current_lower_claim: sum_lower_claim,
            current_claim: sum_claim,
        }
    }

    fn round_components(&self) -> RoundComponents<F> {
        let [upper_h_0, upper_h_half] = self.upper_sumcheck.compute_sumcheck_poly();
        let [lower_h_0, lower_h_half, lower_h_two] = self.lower_sumcheck.compute_sumcheck_poly();

        let upper_h_1 = self.current_upper_claim - upper_h_0;
        let lower_h_1 = self.current_lower_claim - lower_h_0;
        let upper_h_two = extrapolate_quadratic_at_two(upper_h_0, upper_h_half, upper_h_1);

        let h_0 = upper_h_0 - lower_h_0;
        let h_half = upper_h_half - lower_h_half;
        let h_1 = upper_h_1 - lower_h_1;
        let h_two = upper_h_two - lower_h_two;

        assert_eq!(
            h_0 + h_1,
            self.current_claim,
            "transition-sumcheck round consistency failed"
        );

        RoundComponents {
            upper_h_0,
            upper_h_half,
            upper_h_1,
            lower_h_0,
            lower_h_half,
            lower_h_1,
            lower_h_two,
            h_0,
            h_half,
            h_1,
            h_two,
        }
    }

    pub fn compute_sumcheck_poly(&self) -> [F; 3] {
        let round = self.round_components();
        [round.h_0, round.h_half, round.h_two]
    }

    pub fn compress_tables(&mut self, challenge: F) {
        let round = self.round_components();

        self.upper_sumcheck.compress_tables(challenge);
        self.lower_sumcheck.compress_tables(challenge);

        self.current_upper_claim = interpolate_quadratic_from_0_half_1(
            round.upper_h_0,
            round.upper_h_half,
            round.upper_h_1,
            challenge,
        );
        self.current_lower_claim = interpolate_cubic_from_0_half_1_2(
            round.lower_h_0,
            round.lower_h_half,
            round.lower_h_1,
            round.lower_h_two,
            challenge,
        );
        self.current_claim = self.current_upper_claim - self.current_lower_claim;
    }

    pub fn run_sumcheck_protocol(
        &mut self,
        rng: &mut impl Rng,
    ) -> PermutationTransitionSumcheckOutput<F> {
        let round_count = self.eq_table.len().ilog2() as usize;
        let mut round_polys = Vec::with_capacity(round_count);
        let mut randomness = Vec::with_capacity(round_count);

        let sum_claim = self.current_claim;

        for _ in 0..round_count {
            let round_poly = self.compute_sumcheck_poly();
            round_polys.push(round_poly);

            let challenge = F::random(rng);
            randomness.push(challenge);
            self.compress_tables(challenge);
        }

        let eval_point: Vec<F> = randomness.iter().copied().rev().collect();
        let eq_value = evaluate_multilinear_table(&self.eq_table, &eval_point);
        let upper_value = evaluate_multilinear_table(&self.upper_table, &eval_point);
        let lower_left_value = evaluate_multilinear_table(&self.lower_left_table, &eval_point);
        let lower_right_value = evaluate_multilinear_table(&self.lower_right_table, &eval_point);

        let final_claim = eq_value * (upper_value - lower_left_value * lower_right_value);
        assert_eq!(
            final_claim, self.current_claim,
            "transition-sumcheck final claim mismatch"
        );

        PermutationTransitionSumcheckOutput {
            sum_claim,
            round_polys,
            randomness,
            final_claim,
            upper_value,
            lower_left_value,
            lower_right_value,
            eq_value,
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use rand::{rngs::SmallRng, SeedableRng};

    use super::*;

    fn f(x: u32) -> KoalaBear {
        <KoalaBear as FieldElement>::from_u32(x)
    }

    #[test]
    fn test_build_permutation_transition_tables_layout() {
        let first = vec![f(1), f(2), f(3), f(4)];
        let second = vec![f(5), f(6), f(7), f(8)];

        let tables = build_permutation_transition_tables(&first, &second);

        assert_eq!(tables.upper, second);
        assert_eq!(tables.lower_left, vec![f(1), f(3), f(5), f(7)]);
        assert_eq!(tables.lower_right, vec![f(2), f(4), f(6), f(8)]);
    }

    #[test]
    fn test_run_sumcheck_protocol_outputs_claim_and_randomness() {
        let first = vec![f(1), f(2), f(3), f(4)];
        let second = vec![f(5), f(6), f(7), f(8)];
        let eq = vec![f(9), f(10), f(11), f(12)];

        let tables = build_permutation_transition_tables(&first, &second);
        let mut sumcheck = PermutationTransitionSumcheck::new(tables, eq.clone());

        let mut rng = SmallRng::seed_from_u64(99);
        let output = sumcheck.run_sumcheck_protocol(&mut rng);

        assert_eq!(output.round_polys.len(), 2);
        assert_eq!(output.randomness.len(), 2);

        let mut replay_rng = SmallRng::seed_from_u64(99);
        let alpha_0 = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let alpha_1 = <KoalaBear as FieldElement>::random(&mut replay_rng);
        assert_eq!(output.randomness, vec![alpha_0, alpha_1]);

        let eval_point = vec![alpha_1, alpha_0];
        let tables = build_permutation_transition_tables(&first, &second);
        let expected_eq = evaluate_multilinear_table(&eq, &eval_point);
        let expected_upper = evaluate_multilinear_table(&tables.upper, &eval_point);
        let expected_lower_left = evaluate_multilinear_table(&tables.lower_left, &eval_point);
        let expected_lower_right = evaluate_multilinear_table(&tables.lower_right, &eval_point);

        assert_eq!(output.eq_value, expected_eq);
        assert_eq!(output.upper_value, expected_upper);
        assert_eq!(output.lower_left_value, expected_lower_left);
        assert_eq!(output.lower_right_value, expected_lower_right);
        assert_eq!(
            output.final_claim,
            expected_eq * (expected_upper - expected_lower_left * expected_lower_right)
        );
    }
}
