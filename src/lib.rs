use p3_field::Field;
use rand::Rng;
use std::marker::PhantomData;

pub trait ErrorCorrectingCode {
    type Alphabet;

    fn message_size(&self) -> usize;
    fn block_length(&self) -> usize;
    fn encode(&self, msg: Vec<Self::Alphabet>) -> Vec<Self::Alphabet>;
}

/// Generate a random permutation of 0..n using Fisher-Yates shuffle
pub fn random_permutation(rng: &mut impl Rng, n: usize) -> Vec<usize> {
    let mut perm: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let j = rng.random_range(0..=i);
        perm.swap(i, j);
    }
    perm
}

#[derive(Debug)]
pub struct IdentityCode<F> {
    message_size: usize,

    alphabet: PhantomData<F>,
}

impl<F> IdentityCode<F> {
    pub fn new(message_size: usize) -> Self {
        Self {
            message_size,
            alphabet: PhantomData,
        }
    }
}

impl<F> ErrorCorrectingCode for IdentityCode<F> {
    type Alphabet = F;

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn block_length(&self) -> usize {
        self.message_size
    }

    fn encode(&self, msg: Vec<Self::Alphabet>) -> Vec<Self::Alphabet> {
        msg
    }
}

#[derive(Debug)]
pub struct EraCode<C, F> {
    message_size: usize,
    block_length: usize,
    repetition_parameters: usize,
    base_code: C,

    p1_vector: Vec<usize>,
    p2_vector: Vec<usize>,

    m1_vector: Vec<F>,
    m2_vector: Vec<F>,
}

impl<C, F> EraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F>,
    F: Field,
{
    pub fn new(
        base_code: C,
        repetition_parameters: usize,
        p1_vector: Vec<usize>,
        p2_vector: Vec<usize>,
        m1_vector: Vec<F>,
        m2_vector: Vec<F>,
    ) -> Self {
        let message_size = base_code.message_size();
        let block_length = repetition_parameters * base_code.block_length();

        let code = Self {
            message_size,
            block_length,
            repetition_parameters,
            base_code,
            p1_vector,
            p2_vector,
            m1_vector,
            m2_vector,
        };

        debug_assert!(code.validate_parameters());
        code
    }

    // Check that a vector contains a permutation on 0..v.len()
    fn check_permutation(v: &[usize]) -> bool {
        let n = v.len();
        let mut seen = vec![false; n];

        for &x in v {
            if x >= n || seen[x] {
                return false;
            }
            seen[x] = true;
        }

        true
    }

    fn validate_parameters(&self) -> bool {
        Self::check_permutation(&self.p1_vector)
            && Self::check_permutation(&self.p2_vector)
            && self.base_code.message_size() == self.message_size
            && self.repetition_parameters * self.base_code.block_length() == self.block_length()
    }

    pub fn encode_naive(&self, msg: Vec<C::Alphabet>) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let mut repeat_vector: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut first_permute: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut first_multiply: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut first_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut second_permute: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut second_multiply: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut second_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];

        let base_encoding = self.base_code.encode(msg);

        for i in 0..self.block_length {
            repeat_vector[i] = base_encoding[i % self.base_code.block_length()];
        }

        for i in 0..self.block_length {
            first_permute[i] = repeat_vector[self.p1_vector[i]];
        }

        for i in 0..self.block_length {
            first_multiply[i] = first_permute[i] * self.m1_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += first_multiply[i];
            first_accumulate[i] = acc;
        }

        for i in 0..self.block_length {
            second_permute[i] = first_accumulate[self.p2_vector[i]];
        }

        for i in 0..self.block_length {
            second_multiply[i] = second_permute[i] * self.m2_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += second_multiply[i];
            second_accumulate[i] = acc;
        }

        second_accumulate
    }

    /// Optimized encoding that fuses multiple passes to reduce memory traffic.
    ///
    /// Fuses: repeat + first_permute + first_multiply into one pass
    /// Fuses: second_permute + second_multiply into one pass
    /// Reduces from 7 passes and 7 vectors to 4 passes and 4 vectors.
    pub fn encode_fused(&self, msg: Vec<C::Alphabet>) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let mut first_multiply: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut first_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut second_multiply: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut second_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];

        let base_encoding = self.base_code.encode(msg);
        let base_len = self.base_code.block_length();

        for i in 0..self.block_length {
            let src_idx = self.p1_vector[i] % base_len;
            first_multiply[i] = base_encoding[src_idx] * self.m1_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += first_multiply[i];
            first_accumulate[i] = acc;
        }

        for i in 0..self.block_length {
            second_multiply[i] = first_accumulate[self.p2_vector[i]] * self.m2_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += second_multiply[i];
            second_accumulate[i] = acc;
        }

        second_accumulate
    }

    /// Hybrid encoding: naive first phase, fused second phase.
    ///
    /// Keeps sequential repeat (cache-friendly), fuses second_permute + second_multiply.
    /// Reduces from 7 passes and 7 vectors to 5 passes and 5 vectors.
    pub fn encode_fused_end(&self, msg: Vec<C::Alphabet>) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let mut repeat_vector: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut first_permute: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut first_multiply: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut first_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut second_multiply: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut second_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];

        let base_encoding = self.base_code.encode(msg);

        // Sequential repeat (cache-friendly)
        for i in 0..self.block_length {
            repeat_vector[i] = base_encoding[i % self.base_code.block_length()];
        }

        for i in 0..self.block_length {
            first_permute[i] = repeat_vector[self.p1_vector[i]];
        }

        for i in 0..self.block_length {
            first_multiply[i] = first_permute[i] * self.m1_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += first_multiply[i];
            first_accumulate[i] = acc;
        }

        // Fused: second_permute + second_multiply
        for i in 0..self.block_length {
            second_multiply[i] = first_accumulate[self.p2_vector[i]] * self.m2_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += second_multiply[i];
            second_accumulate[i] = acc;
        }

        second_accumulate
    }
}

impl<C, F> ErrorCorrectingCode for EraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F>,
    F: Field,
{
    type Alphabet = C::Alphabet;

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn block_length(&self) -> usize {
        self.block_length
    }

    fn encode(&self, msg: Vec<Self::Alphabet>) -> Vec<Self::Alphabet> {
        self.encode_naive(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use rand::{Rng, SeedableRng, rngs::SmallRng};

    /// Generate a random vector of field elements
    fn random_field_vector(rng: &mut impl Rng, n: usize) -> Vec<KoalaBear> {
        (0..n).map(|_| KoalaBear::new(rng.random())).collect()
    }

    #[test]
    fn test_identity_code_basic() {
        let message_size = 8;
        let code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        assert_eq!(code.message_size(), message_size);
        assert_eq!(code.block_length(), message_size);

        let msg: Vec<KoalaBear> = (0..message_size as u32).map(KoalaBear::new).collect();
        let encoded = code.encode(msg.clone());

        // Identity code should return the message unchanged
        assert_eq!(encoded, msg);
    }

    #[test]
    fn test_era_code_output_length() {
        let mut rng = SmallRng::seed_from_u64(12345);

        let message_size = 4;
        let repetition = 3;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);

        assert_eq!(era_code.message_size(), message_size);
        assert_eq!(era_code.block_length(), block_length);

        let msg: Vec<KoalaBear> = (0..message_size as u32).map(KoalaBear::new).collect();
        let encoded = era_code.encode(msg);

        assert_eq!(encoded.len(), block_length);
    }

    #[test]
    fn test_era_code_deterministic() {
        let mut rng = SmallRng::seed_from_u64(42);

        let message_size = 4;
        let repetition = 2;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);

        let msg: Vec<KoalaBear> = (1..=message_size as u32).map(KoalaBear::new).collect();

        let encoded1 = era_code.encode(msg.clone());
        let encoded2 = era_code.encode(msg);

        // Same input should produce same output
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_era_code_different_inputs_different_outputs() {
        let mut rng = SmallRng::seed_from_u64(999);

        let message_size = 4;
        let repetition = 2;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);

        let msg1: Vec<KoalaBear> = (0..message_size as u32).map(KoalaBear::new).collect();
        let msg2: Vec<KoalaBear> = (10..10 + message_size as u32).map(KoalaBear::new).collect();

        let encoded1 = era_code.encode(msg1);
        let encoded2 = era_code.encode(msg2);

        // Different inputs should (with high probability) produce different outputs
        assert_ne!(encoded1, encoded2);
    }

    #[test]
    fn test_era_code_with_various_repetition_parameters() {
        let mut rng = SmallRng::seed_from_u64(7777);

        for repetition in [1, 2, 4, 8] {
            let message_size = 4;
            let block_length = message_size * repetition;

            let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

            let p1 = random_permutation(&mut rng, block_length);
            let p2 = random_permutation(&mut rng, block_length);
            let m1 = random_field_vector(&mut rng, block_length);
            let m2 = random_field_vector(&mut rng, block_length);

            let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);

            let msg: Vec<KoalaBear> = (0..message_size as u32).map(KoalaBear::new).collect();
            let encoded = era_code.encode(msg);

            assert_eq!(
                encoded.len(),
                block_length,
                "Failed for repetition = {repetition}"
            );
        }
    }

    #[test]
    fn test_era_code_zero_message() {
        let mut rng = SmallRng::seed_from_u64(1111);

        let message_size = 4;
        let repetition = 2;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);

        // All-zero message
        let msg: Vec<KoalaBear> = vec![KoalaBear::ZERO; message_size];
        let encoded = era_code.encode(msg);

        // Encoding should complete without panic and have correct length
        assert_eq!(encoded.len(), block_length);

        // With zero input, after repeat we get zeros, after multiply we get zeros,
        // after accumulate we should still have all zeros
        for elem in &encoded {
            assert_eq!(*elem, KoalaBear::ZERO);
        }
    }

    #[test]
    fn test_encode_fused_matches_naive() {
        let mut rng = SmallRng::seed_from_u64(54321);

        // Test with various sizes and repetition parameters
        for (message_size, repetition) in [(4, 2), (8, 3), (16, 4), (32, 2)] {
            let block_length = message_size * repetition;

            let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

            let p1 = random_permutation(&mut rng, block_length);
            let p2 = random_permutation(&mut rng, block_length);
            let m1 = random_field_vector(&mut rng, block_length);
            let m2 = random_field_vector(&mut rng, block_length);

            let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);

            // Random message
            let msg: Vec<KoalaBear> = (0..message_size)
                .map(|_| KoalaBear::new(rng.random()))
                .collect();

            let naive_result = era_code.encode_naive(msg.clone());
            let fused_result = era_code.encode_fused(msg.clone());
            let fused_end_result = era_code.encode_fused_end(msg);

            assert_eq!(
                naive_result, fused_result,
                "Fused mismatch for message_size={message_size}, repetition={repetition}"
            );
            assert_eq!(
                naive_result, fused_end_result,
                "Fused-end mismatch for message_size={message_size}, repetition={repetition}"
            );
        }
    }
}
