use rand::Rng;

use crate::FieldElement;

#[derive(Debug, Clone)]
pub struct IPSumcheck<F> {
    left: Vec<F>,
    right: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct IPSumcheckOutput<F> {
    /// Prover messages for each sumcheck round, stored as `(h(0), h(1/2))`.
    pub round_polys: Vec<[F; 2]>,
    /// Verifier challenges `(alpha_1, ..., alpha_t)`.
    pub randomness: Vec<F>,
    /// Final reduced claim `l(randomness) * r(randomness)`.
    pub final_claim: F,
}

impl<F: FieldElement> IPSumcheck<F> {
    #[must_use]
    pub fn new(left: Vec<F>, right: Vec<F>) -> Self {
        Self { left, right }
    }

    pub fn compute_sumcheck_poly(&self) -> [F; 2] {
        assert_eq!(
            self.left.len(),
            self.right.len(),
            "left and right tables must have the same length"
        );
        assert_eq!(
            self.left.len() % 2,
            0,
            "left/right table length must be even"
        );

        // Evaluation of sumcheck polynomial at 0:
        // h(0) = sum_b left(0, b) * right(0, b)
        let v_0 = self
            .left
            .chunks_exact(2)
            .zip(self.right.chunks_exact(2))
            .fold(F::ZERO, |acc, (left_pair, right_pair)| {
                acc + left_pair[0] * right_pair[0]
            });

        // Evaluation of sumcheck polynomial at 1/2:
        // h(1/2) = sum_b left(1/2, b) * right(1/2, b)
        // where left(1/2, b) = (left(0,b) + left(1,b))/2 and similarly for right.
        let two_inv = F::from_u32(2)
            .inverse()
            .expect("2 must be invertible in the field");
        let four_inv = two_inv.square();

        let v_half = four_inv
            * self
                .left
                .chunks_exact(2)
                .zip(self.right.chunks_exact(2))
                .fold(F::ZERO, |acc, (left_pair, right_pair)| {
                    let left_sum = left_pair[0] + left_pair[1];
                    let right_sum = right_pair[0] + right_pair[1];
                    acc + left_sum * right_sum
                });

        [v_0, v_half]
    }

    pub fn compress_tables(&mut self, challenge: F) {
        assert_eq!(
            self.left.len(),
            self.right.len(),
            "left and right tables must have the same length"
        );
        assert_eq!(
            self.left.len() % 2,
            0,
            "left/right table length must be even"
        );

        self.left = self
            .left
            .chunks_exact(2)
            .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
            .collect();

        self.right = self
            .right
            .chunks_exact(2)
            .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
            .collect();
    }

    pub fn run_sumcheck_protocol(&mut self, rng: &mut impl Rng) -> IPSumcheckOutput<F> {
        assert_eq!(
            self.left.len(),
            self.right.len(),
            "left and right tables must have the same length"
        );
        assert!(!self.left.is_empty(), "left/right tables must be non-empty");
        assert!(
            self.left.len().is_power_of_two(),
            "left/right table length must be a power of two"
        );

        let mut round_polys = Vec::with_capacity(self.left.len().ilog2() as usize);
        let mut randomness = Vec::with_capacity(round_polys.capacity());

        while self.left.len() > 1 {
            let round_poly = self.compute_sumcheck_poly();
            round_polys.push(round_poly);

            let alpha = F::random(rng);
            randomness.push(alpha);

            self.compress_tables(alpha);
        }

        debug_assert_eq!(self.left.len(), 1);
        debug_assert_eq!(self.right.len(), 1);

        IPSumcheckOutput {
            round_polys,
            randomness,
            final_claim: self.left[0] * self.right[0],
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;

    fn f(x: u32) -> KoalaBear {
        <KoalaBear as FieldElement>::from_u32(x)
    }

    #[test]
    fn test_compute_sumcheck_poly_evaluates_midpoint() {
        let sumcheck = IPSumcheck::new(vec![f(1), f(3), f(5), f(7)], vec![f(2), f(4), f(6), f(8)]);

        let [v_0, v_half] = sumcheck.compute_sumcheck_poly();

        assert_eq!(v_0, f(32));
        assert_eq!(v_half, f(48));
    }

    #[test]
    #[should_panic(expected = "left/right table length must be even")]
    fn test_compute_sumcheck_poly_panics_on_odd_table_length() {
        let sumcheck = IPSumcheck::new(vec![f(1), f(2), f(3)], vec![f(4), f(5), f(6)]);

        let _ = sumcheck.compute_sumcheck_poly();
    }

    #[test]
    fn test_compress_tables_interpolates_at_challenge() {
        let mut sumcheck =
            IPSumcheck::new(vec![f(1), f(3), f(5), f(7)], vec![f(2), f(4), f(6), f(8)]);

        let half = f(2).inverse().expect("2 must be invertible");
        sumcheck.compress_tables(half);

        assert_eq!(sumcheck.left, vec![f(2), f(6)]);
        assert_eq!(sumcheck.right, vec![f(3), f(7)]);
    }

    #[test]
    fn test_compress_tables_respects_endpoints() {
        let mut at_zero =
            IPSumcheck::new(vec![f(1), f(3), f(5), f(7)], vec![f(2), f(4), f(6), f(8)]);
        at_zero.compress_tables(KoalaBear::ZERO);
        assert_eq!(at_zero.left, vec![f(1), f(5)]);
        assert_eq!(at_zero.right, vec![f(2), f(6)]);

        let mut at_one =
            IPSumcheck::new(vec![f(1), f(3), f(5), f(7)], vec![f(2), f(4), f(6), f(8)]);
        at_one.compress_tables(KoalaBear::ONE);
        assert_eq!(at_one.left, vec![f(3), f(7)]);
        assert_eq!(at_one.right, vec![f(4), f(8)]);
    }

    #[test]
    #[should_panic(expected = "left/right table length must be even")]
    fn test_compress_tables_panics_on_odd_table_length() {
        let mut sumcheck = IPSumcheck::new(vec![f(1), f(2), f(3)], vec![f(4), f(5), f(6)]);
        sumcheck.compress_tables(f(9));
    }

    #[test]
    fn test_run_sumcheck_protocol_outputs_claim_and_randomness() {
        let left = vec![f(1), f(3), f(5), f(7)];
        let right = vec![f(2), f(4), f(6), f(8)];
        let mut sumcheck = IPSumcheck::new(left.clone(), right.clone());

        let mut rng = SmallRng::seed_from_u64(123);
        let output = sumcheck.run_sumcheck_protocol(&mut rng);

        assert_eq!(output.round_polys.len(), 2);
        assert_eq!(output.randomness.len(), 2);

        let mut replay_rng = SmallRng::seed_from_u64(123);
        let alpha_0 = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let alpha_1 = <KoalaBear as FieldElement>::random(&mut replay_rng);
        assert_eq!(output.randomness, vec![alpha_0, alpha_1]);

        assert_eq!(output.round_polys[0], [f(32), f(48)]);

        let left_round_1 = [
            left[0] + alpha_0 * (left[1] - left[0]),
            left[2] + alpha_0 * (left[3] - left[2]),
        ];
        let right_round_1 = [
            right[0] + alpha_0 * (right[1] - right[0]),
            right[2] + alpha_0 * (right[3] - right[2]),
        ];

        let two_inv = f(2).inverse().expect("2 must be invertible");
        let four_inv = two_inv.square();
        let round_1_v_0 = left_round_1[0] * right_round_1[0];
        let round_1_v_half =
            four_inv * (left_round_1[0] + left_round_1[1]) * (right_round_1[0] + right_round_1[1]);
        assert_eq!(output.round_polys[1], [round_1_v_0, round_1_v_half]);

        let final_left = left_round_1[0] + alpha_1 * (left_round_1[1] - left_round_1[0]);
        let final_right = right_round_1[0] + alpha_1 * (right_round_1[1] - right_round_1[0]);

        assert_eq!(sumcheck.left, vec![final_left]);
        assert_eq!(sumcheck.right, vec![final_right]);
        assert_eq!(output.final_claim, final_left * final_right);
    }

    #[test]
    #[should_panic(expected = "left/right table length must be a power of two")]
    fn test_run_sumcheck_protocol_panics_on_non_power_of_two_length() {
        let mut sumcheck = IPSumcheck::new(
            vec![f(1), f(2), f(3), f(4), f(5), f(6)],
            vec![f(7), f(8), f(9), f(10), f(11), f(12)],
        );

        let mut rng = SmallRng::seed_from_u64(7);
        let _ = sumcheck.run_sumcheck_protocol(&mut rng);
    }
}
