use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

use rand::Rng;

mod algebra;
pub mod codeswitching;
mod commit;
mod optimized_era;
pub mod poly_utils;
mod reed_solomon;

pub use codeswitching as codeswitch;

pub use commit::{
    BasefoldCode, BasefoldParams, BrakedownCode, BrakedownParams, EaCode, EaParams, EraCode,
    IdentityCode, TensorCode, blake3_merkle_commit,
};
pub use optimized_era::{EncodeNaiveBuffers, OptimizedEraCode, RadixSortBuffers};
pub use reed_solomon::ReedSolomonCode;

/// Minimal trait for field-like elements used by the error-correcting codes.
///
/// Implemented for `ark_secp256k1::Fr`, `ark_bls12_381::Fr`, and all
/// `p3_field::Field` types, so that the codes can be generic over both.
pub trait FieldElement:
    Copy
    + Clone
    + Default
    + std::fmt::Debug
    + PartialEq
    + Send
    + Sync
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + Neg<Output = Self>
{
    /// The additive identity.
    const ZERO: Self;

    /// The multiplicative identity.
    const ONE: Self;

    /// Create a field element from a `u32`.
    fn from_u32(val: u32) -> Self;

    /// Sample a uniformly random field element.
    fn random(rng: &mut impl Rng) -> Self;

    /// Whether this element is the additive identity.
    fn is_zero(&self) -> bool;

    /// Multiplicative inverse, if it exists.
    fn inverse(self) -> Option<Self>;

    /// Square this element.
    fn square(self) -> Self;
}

// Implement FieldElement for arkworks secp256k1 scalar field.
impl FieldElement for ark_secp256k1::Fr {
    const ZERO: Self = <Self as ark_ff::AdditiveGroup>::ZERO;
    const ONE: Self = <Self as ark_ff::Field>::ONE;

    fn from_u32(val: u32) -> Self {
        Self::from(u64::from(val))
    }

    fn random(rng: &mut impl Rng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        <Self as ark_ff::PrimeField>::from_le_bytes_mod_order(&bytes)
    }

    fn is_zero(&self) -> bool {
        <Self as ark_ff::Zero>::is_zero(self)
    }

    fn inverse(self) -> Option<Self> {
        <Self as ark_ff::Field>::inverse(&self)
    }

    fn square(self) -> Self {
        <Self as ark_ff::Field>::square(&self)
    }
}

// Implement FieldElement for KoalaBear (used by OptimizedEraCode).
impl FieldElement for p3_koala_bear::KoalaBear {
    const ZERO: Self = <Self as p3_field::PrimeCharacteristicRing>::ZERO;
    const ONE: Self = <Self as p3_field::PrimeCharacteristicRing>::ONE;

    fn from_u32(val: u32) -> Self {
        <Self as p3_field::integers::QuotientMap<u32>>::from_int(val)
    }

    fn random(rng: &mut impl Rng) -> Self {
        Self::from_u32(rng.random::<u32>())
    }

    fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    fn inverse(self) -> Option<Self> {
        <Self as p3_field::Field>::try_inverse(&self)
    }

    fn square(self) -> Self {
        <Self as p3_field::PrimeCharacteristicRing>::square(&self)
    }
}

// Implement FieldElement for arkworks BLS12-381 scalar field.
impl FieldElement for ark_bls12_381::Fr {
    const ZERO: Self = <Self as ark_ff::AdditiveGroup>::ZERO;
    const ONE: Self = <Self as ark_ff::Field>::ONE;

    fn from_u32(val: u32) -> Self {
        Self::from(u64::from(val))
    }

    fn random(rng: &mut impl Rng) -> Self {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        <Self as ark_ff::PrimeField>::from_le_bytes_mod_order(&bytes)
    }

    fn is_zero(&self) -> bool {
        <Self as ark_ff::Zero>::is_zero(self)
    }

    fn inverse(self) -> Option<Self> {
        <Self as ark_ff::Field>::inverse(&self)
    }

    fn square(self) -> Self {
        <Self as ark_ff::Field>::square(&self)
    }
}

pub trait ErrorCorrectingCode {
    type Alphabet;

    fn message_size(&self) -> usize;
    fn block_length(&self) -> usize;
    fn encode(&self, msg: &[Self::Alphabet]) -> Vec<Self::Alphabet>;
}

/// Encode by interleaving the message into 2^eta segments and concatenating encodings.
pub fn encode_interleaved<C>(msg: &[C::Alphabet], code: &C, eta: usize) -> Vec<C::Alphabet>
where
    C: ErrorCorrectingCode,
{
    let segment_count = 1usize << eta;
    let base_message_size = code.message_size();
    debug_assert_eq!(msg.len(), base_message_size * segment_count);

    let mut out = Vec::with_capacity(code.block_length() * segment_count);
    for segment in 0..segment_count {
        let start = segment * base_message_size;
        let end = start + base_message_size;
        let enc = code.encode(&msg[start..end]);
        out.extend(enc);
    }
    out
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

/// A single non-zero entry `(row, col, val)` in a sparse matrix.
#[derive(Debug, Clone)]
pub struct SparseMatEntry<F> {
    pub row: usize,
    pub col: usize,
    pub val: F,
}

/// Multiply a sparse matrix (stored column-major as a flat list of entries,
/// `nnz_per_col` entries per output element) by a dense vector `x`.
pub fn sparse_mat_vec<F: FieldElement>(
    x: &[F],
    entries: &[SparseMatEntry<F>],
    y_len: usize,
    nnz_per_col: usize,
) -> Vec<F> {
    (0..y_len)
        .map(|i| {
            let mut acc = F::ZERO;
            for j in 0..nnz_per_col {
                let e = &entries[i * nnz_per_col + j];
                debug_assert_eq!(e.col, i);
                acc += x[e.row] * e.val;
            }
            acc
        })
        .collect()
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
        let encoded = era_code.encode_era(&msg);

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

        let encoded1 = era_code.encode_era(&msg);
        let encoded2 = era_code.encode_era(&msg);

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

        let encoded1 = era_code.encode_era(&msg1);
        let encoded2 = era_code.encode_era(&msg2);

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
            let encoded = era_code.encode_era(&msg);

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
        let msg: Vec<KoalaBear> = vec![<KoalaBear as PrimeCharacteristicRing>::ZERO; message_size];
        let encoded = era_code.encode_era(&msg);

        // Encoding should complete without panic and have correct length
        assert_eq!(encoded.len(), block_length);

        // With zero input, after repeat we get zeros, after multiply we get zeros,
        // after accumulate we should still have all zeros
        for elem in &encoded {
            assert_eq!(*elem, <KoalaBear as PrimeCharacteristicRing>::ZERO);
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

        let msg: Vec<KoalaBear> = vec![<KoalaBear as PrimeCharacteristicRing>::ZERO; message_size];
        let encoded = era_code.encode(&msg);

        assert_eq!(encoded.len(), block_length);

        for elem in &encoded {
            assert_eq!(*elem, <KoalaBear as PrimeCharacteristicRing>::ZERO);
        }
    }

    #[test]
    fn test_reed_solomon_round_trip_with_intt() {
        use ark_ff::{FftField, Field};

        type Fr = ark_bls12_381::Fr;

        let message_size = 4;
        let block_length = 8;
        let code = ReedSolomonCode::new(message_size, block_length);

        let msg: Vec<Fr> = (0..message_size as u64).map(Fr::from).collect();
        let encoded = code.encode(&msg);
        assert_eq!(encoded.len(), block_length);

        // Manual inverse NTT: same butterfly structure but with inverse twiddle factors
        let n = block_length;
        let log_n = n.trailing_zeros();

        // Compute omega^{-1} for this size
        let mut omega = Fr::TWO_ADIC_ROOT_OF_UNITY;
        for _ in 0..(Fr::TWO_ADICITY - log_n) {
            omega = omega * omega;
        }
        let omega_inv = omega.inverse().unwrap();

        // Bit-reversal permutation
        let mut data = encoded;
        for i in 0..n {
            let j = i.reverse_bits() >> (usize::BITS - log_n);
            if i < j {
                data.swap(i, j);
            }
        }

        // Butterfly passes with inverse twiddles
        for s in 0..log_n {
            let m = 1 << (s + 1);
            let half = m >> 1;
            let mut wm = omega_inv;
            for _ in 0..(log_n - s - 1) {
                wm = wm * wm;
            }
            let mut k = 0;
            while k < n {
                let mut w = Fr::from(1u64);
                for j in 0..half {
                    let t = w * data[k + j + half];
                    let u = data[k + j];
                    data[k + j] = u + t;
                    data[k + j + half] = u - t;
                    w = w * wm;
                }
                k += m;
            }
        }

        // Divide by n
        let n_inv = Fr::from(n as u64).inverse().unwrap();
        for d in &mut data {
            *d = *d * n_inv;
        }

        // First `message_size` coefficients should match the original message
        assert_eq!(&data[..message_size], msg.as_slice());
        // Remaining coefficients (zero-padded) should be zero
        assert!(
            data[message_size..]
                .iter()
                .all(|c| ark_ff::Zero::is_zero(c))
        );
    }
}
