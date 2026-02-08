use rand::Rng;

use crate::FieldElement;

#[derive(Debug, Clone)]
pub struct TIPSumcheck<F> {
    first: Vec<F>,
    second: Vec<F>,
    third: Vec<F>,
}

#[derive(Debug, Clone)]
pub struct TIPSumcheckOutput<F> {
    /// Prover messages for each sumcheck round, stored as `(h(0), h(1/2), h(2))`.
    pub round_polys: Vec<[F; 3]>,
    /// Verifier challenges `(alpha_1, ..., alpha_t)`.
    pub randomness: Vec<F>,
    /// Final reduced claim `a(randomness) * b(randomness) * c(randomness)`.
    pub final_claim: F,
}

impl<F: FieldElement> TIPSumcheck<F> {
    #[must_use]
    pub fn new(first: Vec<F>, second: Vec<F>, third: Vec<F>) -> Self {
        Self {
            first,
            second,
            third,
        }
    }

    pub fn compute_sumcheck_poly(&self) -> [F; 3] {
        assert_eq!(
            self.first.len(),
            self.second.len(),
            "all TIP tables must have the same length"
        );
        assert_eq!(
            self.first.len(),
            self.third.len(),
            "all TIP tables must have the same length"
        );
        assert_eq!(self.first.len() % 2, 0, "TIP table length must be even");

        // Evaluation at 0:
        // h(0) = sum_b first(0,b) * second(0,b) * third(0,b)
        let v_0 = self
            .first
            .chunks_exact(2)
            .zip(self.second.chunks_exact(2))
            .zip(self.third.chunks_exact(2))
            .fold(F::ZERO, |acc, ((first_pair, second_pair), third_pair)| {
                acc + first_pair[0] * second_pair[0] * third_pair[0]
            });

        // Evaluation at 1/2:
        // h(1/2) = sum_b first(1/2,b) * second(1/2,b) * third(1/2,b)
        // where each v(1/2,b) = (v(0,b) + v(1,b))/2.
        let two = F::from_u32(2);
        let two_inv = two.inverse().expect("2 must be invertible in the field");
        let eight_inv = two_inv.square() * two_inv;

        let v_half = eight_inv
            * self
                .first
                .chunks_exact(2)
                .zip(self.second.chunks_exact(2))
                .zip(self.third.chunks_exact(2))
                .fold(F::ZERO, |acc, ((first_pair, second_pair), third_pair)| {
                    let first_sum = first_pair[0] + first_pair[1];
                    let second_sum = second_pair[0] + second_pair[1];
                    let third_sum = third_pair[0] + third_pair[1];
                    acc + first_sum * second_sum * third_sum
                });

        // Evaluation at 2:
        // h(2) = sum_b first(2,b) * second(2,b) * third(2,b)
        // where each v(2,b) = v(1,b) + (v(1,b) - v(0,b)) = 2*v(1,b) - v(0,b).
        //
        // This avoids 3 scalar multiplications-by-2 per table pair.
        let v_two = self
            .first
            .chunks_exact(2)
            .zip(self.second.chunks_exact(2))
            .zip(self.third.chunks_exact(2))
            .fold(F::ZERO, |acc, ((first_pair, second_pair), third_pair)| {
                let first_delta = first_pair[1] - first_pair[0];
                let second_delta = second_pair[1] - second_pair[0];
                let third_delta = third_pair[1] - third_pair[0];

                let first_two = first_pair[1] + first_delta;
                let second_two = second_pair[1] + second_delta;
                let third_two = third_pair[1] + third_delta;

                acc + first_two * second_two * third_two
            });

        [v_0, v_half, v_two]
    }

    pub fn compress_tables(&mut self, challenge: F) {
        assert_eq!(
            self.first.len(),
            self.second.len(),
            "all TIP tables must have the same length"
        );
        assert_eq!(
            self.first.len(),
            self.third.len(),
            "all TIP tables must have the same length"
        );
        assert_eq!(self.first.len() % 2, 0, "TIP table length must be even");

        self.first = self
            .first
            .chunks_exact(2)
            .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
            .collect();

        self.second = self
            .second
            .chunks_exact(2)
            .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
            .collect();

        self.third = self
            .third
            .chunks_exact(2)
            .map(|pair| pair[0] + challenge * (pair[1] - pair[0]))
            .collect();
    }

    pub fn run_sumcheck_protocol(&mut self, rng: &mut impl Rng) -> TIPSumcheckOutput<F> {
        assert_eq!(
            self.first.len(),
            self.second.len(),
            "all TIP tables must have the same length"
        );
        assert_eq!(
            self.first.len(),
            self.third.len(),
            "all TIP tables must have the same length"
        );
        assert!(!self.first.is_empty(), "TIP tables must be non-empty");
        assert!(
            self.first.len().is_power_of_two(),
            "TIP table length must be a power of two"
        );

        let mut round_polys = Vec::with_capacity(self.first.len().ilog2() as usize);
        let mut randomness = Vec::with_capacity(round_polys.capacity());

        while self.first.len() > 1 {
            let round_poly = self.compute_sumcheck_poly();
            round_polys.push(round_poly);

            let alpha = F::random(rng);
            randomness.push(alpha);

            self.compress_tables(alpha);
        }

        debug_assert_eq!(self.first.len(), 1);
        debug_assert_eq!(self.second.len(), 1);
        debug_assert_eq!(self.third.len(), 1);

        TIPSumcheckOutput {
            round_polys,
            randomness,
            final_claim: self.first[0] * self.second[0] * self.third[0],
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
    fn test_compute_sumcheck_poly_evaluates_midpoint_and_two() {
        let sumcheck = TIPSumcheck::new(
            vec![f(1), f(3), f(5), f(7)],
            vec![f(2), f(4), f(6), f(8)],
            vec![f(3), f(5), f(7), f(9)],
        );

        let [v_0, v_half, v_two] = sumcheck.compute_sumcheck_poly();

        assert_eq!(v_0, f(216));
        assert_eq!(v_half, f(360));
        assert_eq!(v_two, f(1200));
    }

    #[test]
    #[should_panic(expected = "TIP table length must be even")]
    fn test_compute_sumcheck_poly_panics_on_odd_table_length() {
        let sumcheck = TIPSumcheck::new(
            vec![f(1), f(2), f(3)],
            vec![f(4), f(5), f(6)],
            vec![f(7), f(8), f(9)],
        );

        let _ = sumcheck.compute_sumcheck_poly();
    }

    #[test]
    fn test_compress_tables_interpolates_at_challenge() {
        let mut sumcheck = TIPSumcheck::new(
            vec![f(1), f(3), f(5), f(7)],
            vec![f(2), f(4), f(6), f(8)],
            vec![f(3), f(5), f(7), f(9)],
        );

        let half = f(2).inverse().expect("2 must be invertible");
        sumcheck.compress_tables(half);

        assert_eq!(sumcheck.first, vec![f(2), f(6)]);
        assert_eq!(sumcheck.second, vec![f(3), f(7)]);
        assert_eq!(sumcheck.third, vec![f(4), f(8)]);
    }

    #[test]
    fn test_compress_tables_respects_endpoints() {
        let mut at_zero = TIPSumcheck::new(
            vec![f(1), f(3), f(5), f(7)],
            vec![f(2), f(4), f(6), f(8)],
            vec![f(3), f(5), f(7), f(9)],
        );
        at_zero.compress_tables(KoalaBear::ZERO);
        assert_eq!(at_zero.first, vec![f(1), f(5)]);
        assert_eq!(at_zero.second, vec![f(2), f(6)]);
        assert_eq!(at_zero.third, vec![f(3), f(7)]);

        let mut at_one = TIPSumcheck::new(
            vec![f(1), f(3), f(5), f(7)],
            vec![f(2), f(4), f(6), f(8)],
            vec![f(3), f(5), f(7), f(9)],
        );
        at_one.compress_tables(KoalaBear::ONE);
        assert_eq!(at_one.first, vec![f(3), f(7)]);
        assert_eq!(at_one.second, vec![f(4), f(8)]);
        assert_eq!(at_one.third, vec![f(5), f(9)]);
    }

    #[test]
    #[should_panic(expected = "TIP table length must be even")]
    fn test_compress_tables_panics_on_odd_table_length() {
        let mut sumcheck = TIPSumcheck::new(
            vec![f(1), f(2), f(3)],
            vec![f(4), f(5), f(6)],
            vec![f(7), f(8), f(9)],
        );

        sumcheck.compress_tables(f(9));
    }

    #[test]
    fn test_run_sumcheck_protocol_outputs_claim_and_randomness() {
        let first = vec![f(1), f(3), f(5), f(7)];
        let second = vec![f(2), f(4), f(6), f(8)];
        let third = vec![f(3), f(5), f(7), f(9)];
        let mut sumcheck = TIPSumcheck::new(first.clone(), second.clone(), third.clone());

        let mut rng = SmallRng::seed_from_u64(123);
        let output = sumcheck.run_sumcheck_protocol(&mut rng);

        assert_eq!(output.round_polys.len(), 2);
        assert_eq!(output.randomness.len(), 2);

        let mut replay_rng = SmallRng::seed_from_u64(123);
        let alpha_0 = <KoalaBear as FieldElement>::random(&mut replay_rng);
        let alpha_1 = <KoalaBear as FieldElement>::random(&mut replay_rng);
        assert_eq!(output.randomness, vec![alpha_0, alpha_1]);

        assert_eq!(output.round_polys[0], [f(216), f(360), f(1200)]);

        let first_round_1 = [
            first[0] + alpha_0 * (first[1] - first[0]),
            first[2] + alpha_0 * (first[3] - first[2]),
        ];
        let second_round_1 = [
            second[0] + alpha_0 * (second[1] - second[0]),
            second[2] + alpha_0 * (second[3] - second[2]),
        ];
        let third_round_1 = [
            third[0] + alpha_0 * (third[1] - third[0]),
            third[2] + alpha_0 * (third[3] - third[2]),
        ];

        let two = f(2);
        let two_inv = two.inverse().expect("2 must be invertible");
        let eight_inv = two_inv.square() * two_inv;

        let round_1_v_0 = first_round_1[0] * second_round_1[0] * third_round_1[0];
        let round_1_v_half = eight_inv
            * (first_round_1[0] + first_round_1[1])
            * (second_round_1[0] + second_round_1[1])
            * (third_round_1[0] + third_round_1[1]);
        let first_round_1_at_two = first_round_1[0] + two * (first_round_1[1] - first_round_1[0]);
        let second_round_1_at_two =
            second_round_1[0] + two * (second_round_1[1] - second_round_1[0]);
        let third_round_1_at_two = third_round_1[0] + two * (third_round_1[1] - third_round_1[0]);
        let round_1_v_two = first_round_1_at_two * second_round_1_at_two * third_round_1_at_two;

        assert_eq!(
            output.round_polys[1],
            [round_1_v_0, round_1_v_half, round_1_v_two]
        );

        let final_first = first_round_1[0] + alpha_1 * (first_round_1[1] - first_round_1[0]);
        let final_second = second_round_1[0] + alpha_1 * (second_round_1[1] - second_round_1[0]);
        let final_third = third_round_1[0] + alpha_1 * (third_round_1[1] - third_round_1[0]);

        assert_eq!(sumcheck.first, vec![final_first]);
        assert_eq!(sumcheck.second, vec![final_second]);
        assert_eq!(sumcheck.third, vec![final_third]);
        assert_eq!(output.final_claim, final_first * final_second * final_third);
    }

    #[test]
    #[should_panic(expected = "TIP table length must be a power of two")]
    fn test_run_sumcheck_protocol_panics_on_non_power_of_two_length() {
        let mut sumcheck = TIPSumcheck::new(
            vec![f(1), f(2), f(3), f(4), f(5), f(6)],
            vec![f(7), f(8), f(9), f(10), f(11), f(12)],
            vec![f(13), f(14), f(15), f(16), f(17), f(18)],
        );

        let mut rng = SmallRng::seed_from_u64(7);
        let _ = sumcheck.run_sumcheck_protocol(&mut rng);
    }
}
