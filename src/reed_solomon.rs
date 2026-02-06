use ark_bls12_381::Fr;
use ark_ff::FftField;

use crate::ErrorCorrectingCode;

/// Reed-Solomon code over the BLS12-381 scalar field.
///
/// Encoding pads the message polynomial with zeros to `block_length` coefficients
/// and evaluates it at the roots-of-unity subgroup of that size via a radix-2 NTT.
///
/// BLS12-381's scalar field has 2-adicity 32, so `block_length` can be up to 2^32.
#[derive(Debug)]
pub struct ReedSolomonCode {
    message_size: usize,
    block_length: usize,
    /// Twiddle factors: omega^0, omega^1, ..., omega^{block_length-1}
    /// where omega is a primitive `block_length`-th root of unity.
    twiddles: Vec<Fr>,
}

impl ReedSolomonCode {
    /// Create a new RS code.
    ///
    /// `block_length` must be a power of two and at most 2^32.
    #[must_use]
    pub fn new(message_size: usize, block_length: usize) -> Self {
        assert!(
            block_length.is_power_of_two(),
            "block_length must be a power of two"
        );
        assert!(
            message_size <= block_length,
            "message_size must not exceed block_length"
        );
        let log_n = block_length.trailing_zeros();
        assert!(
            log_n <= Fr::TWO_ADICITY,
            "block_length exceeds the 2-adicity of BLS12-381 scalar field"
        );

        // Compute the primitive `block_length`-th root of unity.
        // TWO_ADIC_ROOT_OF_UNITY is a primitive 2^TWO_ADICITY-th root; squaring
        // (TWO_ADICITY - log_n) times gives a primitive 2^log_n-th root.
        let mut omega = Fr::TWO_ADIC_ROOT_OF_UNITY;
        for _ in 0..(Fr::TWO_ADICITY - log_n) {
            omega = omega * omega;
        }

        // Pre-compute twiddle factors.
        let mut twiddles = Vec::with_capacity(block_length);
        let mut w = Fr::from(1u64);
        for _ in 0..block_length {
            twiddles.push(w);
            w = w * omega;
        }

        Self {
            message_size,
            block_length,
            twiddles,
        }
    }
}

/// In-place iterative radix-2 Cooley-Tukey NTT.
fn ntt_in_place(a: &mut [Fr], twiddles: &[Fr]) {
    let n = a.len();
    debug_assert!(n.is_power_of_two());

    // Bit-reversal permutation.
    let log_n = n.trailing_zeros() as usize;
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS as usize - log_n);
        if i < j {
            a.swap(i, j);
        }
    }

    // Butterfly passes.
    let mut half_len = 1;
    while half_len < n {
        let full_len = half_len * 2;
        // Step in the twiddle table: n / full_len.
        let tw_step = n / full_len;

        for start in (0..n).step_by(full_len) {
            for k in 0..half_len {
                let t = a[start + k + half_len] * twiddles[k * tw_step];
                let u = a[start + k];
                a[start + k] = u + t;
                a[start + k + half_len] = u - t;
            }
        }

        half_len = full_len;
    }
}

impl ErrorCorrectingCode for ReedSolomonCode {
    type Alphabet = Fr;

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn block_length(&self) -> usize {
        self.block_length
    }

    fn encode(&self, msg: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
        debug_assert_eq!(msg.len(), self.message_size);

        let mut coeffs = vec![Fr::from(0u64); self.block_length];
        coeffs[..self.message_size].copy_from_slice(msg);

        ntt_in_place(&mut coeffs, &self.twiddles);
        coeffs
    }
}
