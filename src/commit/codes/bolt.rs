//! Bolt's sketched-code constructions adapted to the secp256k1 scalar field.
//!
//! C(x) = x || BaseFold(Hx). H uses a compression-8 biregular configuration
//! model: degree 16 with independent nonzero coefficients for Bolt-min, or
//! degree 8 with all-one coefficients for Bolt-max. Parallel edges
//! are retained. Rate-1/2 BaseFold replaces upstream's binary-field additive RS;
//! this is an adapted encoder for the common interleaved IOPP, not Bolt's PCS.

use ark_ff::{BigInt, PrimeField};
use ark_secp256k1::Fr;
use rand::{Rng, seq::SliceRandom};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{BasefoldCode, BasefoldParams, ErrorCorrectingCode, FieldElement};

pub const BOLT_DEGREE: usize = 16;
pub const BOLT_MAX_DEGREE: usize = 8;
pub const BOLT_COMPRESSION: usize = 8;

/// Public sparse sketch and the code encoding its syndrome.
#[derive(Debug)]
pub struct BoltCode {
    message_size: usize,
    degree: usize,
    // Contiguous check rows, each with degree * BOLT_COMPRESSION edges. Separate arrays avoid
    // padding each 32-byte coefficient to the alignment of an index/value pair.
    indices: Vec<u32>,
    // None means all ones: no coefficient allocation or field multiplications.
    coefficients: Option<Vec<Fr>>,
    outer: BasefoldCode<Fr>,
}

fn uniform_nonzero(rng: &mut impl Rng) -> Fr {
    loop {
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);
        let limbs = std::array::from_fn(|i| {
            u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap())
        });
        if let Some(value) = Fr::from_bigint(BigInt(limbs))
            && !value.is_zero()
        {
            return value;
        }
    }
}

impl BoltCode {
    /// Setup follows the upstream configuration-model graph distribution, with
    /// coefficients sampled uniformly from the nonzero prime-field elements.
    #[must_use]
    pub fn new(message_size: usize, rng: &mut impl Rng) -> Self {
        Self::with_degree(message_size, BOLT_DEGREE, true, rng)
    }

    /// Degree-8 all-one Bolt-max sketch. Uses prime-field additions, not XOR.
    /// The upstream binary-field distance does not certify this adaptation;
    /// see docs/bolt-max-adaptation.md for the explicit experimental assumption.
    #[must_use]
    pub fn new_max(message_size: usize, rng: &mut impl Rng) -> Self {
        Self::with_degree(message_size, BOLT_MAX_DEGREE, false, rng)
    }

    fn with_degree(
        message_size: usize,
        degree: usize,
        random_coefficients: bool,
        rng: &mut impl Rng,
    ) -> Self {
        assert!(message_size.is_power_of_two() && message_size >= BOLT_COMPRESSION);
        assert!(u32::try_from(message_size).is_ok());
        let edge_count = message_size.checked_mul(degree).unwrap();
        let mut indices = Vec::with_capacity(edge_count);
        for input in 0..message_size {
            indices.extend(std::iter::repeat_n(input as u32, degree));
        }
        indices.shuffle(rng);
        // Sorting within each check improves locality without changing the
        // ensemble; independent coefficients are assigned after sorting.
        for check in indices.chunks_exact_mut(degree * BOLT_COMPRESSION) {
            check.sort_unstable();
        }
        let coefficients =
            random_coefficients.then(|| (0..edge_count).map(|_| uniform_nonzero(rng)).collect());
        let outer = BasefoldCode::new(
            message_size / BOLT_COMPRESSION,
            BasefoldParams { log_rate: 1 },
            rng,
        );
        Self {
            message_size,
            degree,
            indices,
            coefficients,
            outer,
        }
    }

    fn check(&self, check: usize, message: &[Fr]) -> Fr {
        let right_degree = self.degree * BOLT_COMPRESSION;
        let start = check * right_degree;
        let indices = &self.indices[start..start + right_degree];
        self.coefficients.as_ref().map_or_else(
            || {
                indices
                    .iter()
                    .fold(Fr::ZERO, |sum, &i| sum + message[i as usize])
            },
            |coefficients| {
                indices
                    .iter()
                    .zip(&coefficients[start..start + right_degree])
                    .fold(Fr::ZERO, |sum, (&i, &coefficient)| {
                        sum + message[i as usize] * coefficient
                    })
            },
        )
    }

    fn encode_impl(&self, message: &[Fr], sequential: bool) -> Vec<Fr> {
        assert_eq!(message.len(), self.message_size);
        let checks = self.message_size / BOLT_COMPRESSION;
        let syndrome: Vec<_>;
        #[cfg(feature = "parallel")]
        {
            syndrome = if sequential {
                (0..checks).map(|i| self.check(i, message)).collect()
            } else {
                (0..checks)
                    .into_par_iter()
                    .map(|i| self.check(i, message))
                    .collect()
            };
        }
        #[cfg(not(feature = "parallel"))]
        {
            syndrome = (0..checks).map(|i| self.check(i, message)).collect();
        }
        let parity = if sequential {
            self.outer.encode_sequential(&syndrome)
        } else {
            self.outer.encode(&syndrome)
        };
        let mut word = Vec::with_capacity(self.block_length());
        word.extend_from_slice(message);
        word.extend(parity);
        word
    }
}

impl ErrorCorrectingCode for BoltCode {
    type Alphabet = Fr;

    fn message_size(&self) -> usize {
        self.message_size
    }
    fn block_length(&self) -> usize {
        self.message_size + self.outer.codeword_length()
    }
    fn encode(&self, message: &[Fr]) -> Vec<Fr> {
        self.encode_impl(message, false)
    }
    fn encode_sequential(&self, message: &[Fr]) -> Vec<Fr> {
        self.encode_impl(message, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::SmallRng};

    #[test]
    fn graph_is_biregular_and_encoder_matches_dense_matrix() {
        let n = 128;
        let mut rng = SmallRng::seed_from_u64(2025);
        for code in [BoltCode::new(n, &mut rng), BoltCode::new_max(n, &mut rng)] {
            let mut degrees = vec![0; n];
            let mut dense = vec![vec![Fr::ZERO; n]; n / BOLT_COMPRESSION];
            for (edge, &index) in code.indices.iter().enumerate() {
                let coefficient = code.coefficients.as_ref().map_or(Fr::ONE, |c| c[edge]);
                assert!(!coefficient.is_zero());
                degrees[index as usize] += 1;
                dense[edge / (code.degree * BOLT_COMPRESSION)][index as usize] += coefficient;
            }
            assert!(degrees.into_iter().all(|d| d == code.degree));
            let message: Vec<_> = (0..n).map(|_| Fr::random(&mut rng)).collect();
            let syndrome: Vec<_> = dense
                .iter()
                .map(|row| {
                    row.iter()
                        .zip(&message)
                        .fold(Fr::ZERO, |sum, (&a, &b)| sum + a * b)
                })
                .collect();
            let word = code.encode(&message);
            assert_eq!(word.len(), n * 5 / 4);
            assert_eq!(&word[..n], &message);
            assert_eq!(&word[n..], code.outer.encode(&syndrome));
            assert_eq!(word, code.encode_sequential(&message));
        }
    }

    #[test]
    fn code_is_linear_and_preserves_every_input_coordinate() {
        let n = 32;
        let mut rng = SmallRng::seed_from_u64(19);
        for code in [BoltCode::new(n, &mut rng), BoltCode::new_max(n, &mut rng)] {
            let a: Vec<_> = (0..n).map(|_| Fr::random(&mut rng)).collect();
            let b: Vec<_> = (0..n).map(|_| Fr::random(&mut rng)).collect();
            let scale = Fr::from(7);
            let combined: Vec<_> = a.iter().zip(&b).map(|(&a, &b)| a + scale * b).collect();
            let expected: Vec<_> = code
                .encode(&a)
                .iter()
                .zip(code.encode(&b))
                .map(|(&a, b)| a + scale * b)
                .collect();
            assert_eq!(code.encode(&combined), expected);
            assert!(
                code.encode(&vec![Fr::ZERO; n])
                    .iter()
                    .all(FieldElement::is_zero)
            );
            for i in 0..n {
                let mut unit = vec![Fr::ZERO; n];
                unit[i] = Fr::ONE;
                assert_eq!(&code.encode(&unit)[..n], &unit);
            }
        }
    }

    #[test]
    fn max_uses_field_addition_and_retains_parallel_edges() {
        // At m=8 all edges land in one check, so every input occurs eight times.
        let code = BoltCode::new_max(8, &mut SmallRng::seed_from_u64(7));
        assert!(code.coefficients.is_none());
        assert_eq!(code.check(0, &[Fr::ONE; 8]), Fr::from(64));
        let mut unit = vec![Fr::ZERO; 8];
        unit[0] = Fr::ONE;
        assert_eq!(code.check(0, &unit), Fr::from(8));
        // Duplicate columns admit a weight-two kernel vector. Regular degrees
        // alone do not certify distance; tests of honest proofs cannot do so.
        unit[1] = -Fr::ONE;
        assert_eq!(code.check(0, &unit), Fr::ZERO);
        assert!(code.encode(&unit)[8..].iter().all(FieldElement::is_zero));
    }
}
