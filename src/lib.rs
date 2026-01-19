use rand::Rng;

mod era;
mod identity;
mod optimized_era;
mod reed_solomon;

pub use era::EraCode;
pub use identity::IdentityCode;
pub use optimized_era::{EncodeNaiveBuffers, OptimizedEraCode};
pub use reed_solomon::ReedSolomonCode;

pub trait ErrorCorrectingCode {
    type Alphabet;

    fn message_size(&self) -> usize;
    fn block_length(&self) -> usize;
    fn encode(&self, msg: &[Self::Alphabet]) -> Vec<Self::Alphabet>;
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

#[cfg(test)]
mod tests {
    use super::*;
    use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
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
        let encoded = code.encode(&msg);

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
        let encoded = era_code.encode(&msg);

        assert_eq!(encoded.len(), block_length);
    }

    #[test]
    fn test_optimized_era_code_output_length() {
        let mut rng = SmallRng::seed_from_u64(12345);

        let message_size = 4;
        let repetition = 3;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = OptimizedEraCode::new(base_code, repetition, 0, p1, p2, m1, m2);

        assert_eq!(era_code.message_size(), message_size);
        assert_eq!(era_code.block_length(), block_length);

        let msg: Vec<KoalaBear> = (0..message_size as u32).map(KoalaBear::new).collect();
        let encoded = era_code.encode(&msg);

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

        let encoded1 = era_code.encode(&msg);
        let encoded2 = era_code.encode(&msg);

        // Same input should produce same output
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_optimized_era_code_deterministic() {
        let mut rng = SmallRng::seed_from_u64(42);

        let message_size = 4;
        let repetition = 2;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = OptimizedEraCode::new(base_code, repetition, 0, p1, p2, m1, m2);

        let msg: Vec<KoalaBear> = (1..=message_size as u32).map(KoalaBear::new).collect();

        let encoded1 = era_code.encode(&msg);
        let encoded2 = era_code.encode(&msg);

        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn test_optimized_era_code_matches_naive() {
        let mut rng = SmallRng::seed_from_u64(2024);

        let message_size = 1 << 16;
        let repetition = 6;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);
        let mut era_code = OptimizedEraCode::new(base_code, repetition, 0, p1, p2, m1, m2);

        for _ in 0..5 {
            let msg = random_field_vector(&mut rng, message_size);
            let fast = era_code.encode_fast(&msg);
            let naive = era_code.encode_naive(&msg);
            let blocked = era_code.encode_blocked(&msg);

            assert_eq!(fast, naive);
            assert_eq!(blocked, naive.as_slice());
        }
    }

    #[test]
    fn test_optimized_era_code_blocked_reuse() {
        let mut rng = SmallRng::seed_from_u64(2025);

        let message_size = 1 << 12;
        let repetition = 4;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);
        let mut era_code = OptimizedEraCode::new(base_code, repetition, 0, p1, p2, m1, m2);

        let msg = random_field_vector(&mut rng, message_size);
        let expected = era_code.encode_naive(&msg);

        let first = era_code.encode_blocked(&msg);
        assert_eq!(first, expected.as_slice());

        let second = era_code.encode_blocked(&msg);
        assert_eq!(second, expected.as_slice());
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

        let encoded1 = era_code.encode(&msg1);
        let encoded2 = era_code.encode(&msg2);

        // Different inputs should (with high probability) produce different outputs
        assert_ne!(encoded1, encoded2);
    }

    #[test]
    fn test_optimized_era_code_different_inputs_different_outputs() {
        let mut rng = SmallRng::seed_from_u64(999);

        let message_size = 4;
        let repetition = 2;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = OptimizedEraCode::new(base_code, repetition, 0, p1, p2, m1, m2);

        let msg1: Vec<KoalaBear> = (0..message_size as u32).map(KoalaBear::new).collect();
        let msg2: Vec<KoalaBear> = (10..10 + message_size as u32).map(KoalaBear::new).collect();

        let encoded1 = era_code.encode(&msg1);
        let encoded2 = era_code.encode(&msg2);

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
            let encoded = era_code.encode(&msg);

            assert_eq!(
                encoded.len(),
                block_length,
                "Failed for repetition = {repetition}"
            );
        }
    }

    #[test]
    fn test_optimized_era_code_with_various_repetition_parameters() {
        let mut rng = SmallRng::seed_from_u64(7777);

        for repetition in [1, 2, 4, 8] {
            let message_size = 4;
            let block_length = message_size * repetition;

            let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

            let p1 = random_permutation(&mut rng, block_length);
            let p2 = random_permutation(&mut rng, block_length);
            let m1 = random_field_vector(&mut rng, block_length);
            let m2 = random_field_vector(&mut rng, block_length);

            let era_code = OptimizedEraCode::new(base_code, repetition, 0, p1, p2, m1, m2);

            let msg: Vec<KoalaBear> = (0..message_size as u32).map(KoalaBear::new).collect();
            let encoded = era_code.encode(&msg);

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
        let encoded = era_code.encode(&msg);

        // Encoding should complete without panic and have correct length
        assert_eq!(encoded.len(), block_length);

        // With zero input, after repeat we get zeros, after multiply we get zeros,
        // after accumulate we should still have all zeros
        for elem in &encoded {
            assert_eq!(*elem, KoalaBear::ZERO);
        }
    }

    #[test]
    fn test_optimized_era_code_zero_message() {
        let mut rng = SmallRng::seed_from_u64(1111);

        let message_size = 4;
        let repetition = 2;
        let block_length = message_size * repetition;

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);

        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = OptimizedEraCode::new(base_code, repetition, 0, p1, p2, m1, m2);

        let msg: Vec<KoalaBear> = vec![KoalaBear::ZERO; message_size];
        let encoded = era_code.encode(&msg);

        assert_eq!(encoded.len(), block_length);

        for elem in &encoded {
            assert_eq!(*elem, KoalaBear::ZERO);
        }
    }

    #[test]
    fn test_reed_solomon_round_trip_with_idft() {
        let message_size = 4;
        let block_length = 8;
        let code: ReedSolomonCode<KoalaBear, _> = ReedSolomonCode::new(message_size, block_length);

        let msg: Vec<KoalaBear> = (0..message_size as u32).map(KoalaBear::new).collect();
        let encoded = code.encode(&msg);

        assert_eq!(encoded.len(), block_length);

        let dft = Radix2DFTSmallBatch::<KoalaBear>::default();
        let decoded_coeffs = dft.idft(encoded);

        assert_eq!(&decoded_coeffs[..message_size], msg.as_slice());
        assert!(
            decoded_coeffs[message_size..]
                .iter()
                .all(|coeff| *coeff == KoalaBear::ZERO)
        );
    }
}
