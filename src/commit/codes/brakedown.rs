//! Systematic Brakedown encoder with input-regular expanders and a systematic
//! Reed–Solomon base case. Setup stores edges by output for cache-friendly gathers.
use crate::{ErrorCorrectingCode, FieldElement};
use rand::{Rng, seq::index::sample};

#[derive(Debug, Clone, Copy)]
pub struct BrakedownParams {
    pub alpha: f64,
    pub inverse_rate: f64,
    pub cn: usize,
    pub dn: usize,
}

#[derive(Debug)]
struct Expander<F> {
    offsets: Vec<usize>,
    edges: Vec<(usize, F)>,
}

impl<F: FieldElement> Expander<F> {
    fn new(input: usize, output: usize, degree: usize, rng: &mut impl Rng) -> Self {
        assert!(degree <= output && degree > 0);
        let mut columns = vec![Vec::new(); output];
        for i in 0..input {
            // Distinct neighbours for every input, as in the expansion analysis.
            for j in sample(rng, output, degree) {
                let mut value = F::random(rng);
                while value.is_zero() {
                    value = F::random(rng);
                }
                columns[j].push((i, value));
            }
        }
        let mut offsets = Vec::with_capacity(output + 1);
        let mut edges = Vec::with_capacity(input * degree);
        offsets.push(0);
        for column in columns {
            edges.extend(column);
            offsets.push(edges.len());
        }
        Self { offsets, edges }
    }

    fn apply(&self, message: &[F]) -> Vec<F> {
        self.offsets
            .windows(2)
            .map(|range| {
                self.edges[range[0]..range[1]]
                    .iter()
                    .map(|&(i, weight)| message[i] * weight)
                    .fold(F::ZERO, |a, b| a + b)
            })
            .collect()
    }
}

#[derive(Debug)]
enum Layer<F> {
    Recursive {
        a: Expander<F>,
        b: Expander<F>,
        child: Box<BrakedownCode<F>>,
    },
    /// Row-major parity part of a systematic RS generator matrix.
    Base { parity: Vec<Vec<F>> },
}

#[derive(Debug)]
pub struct BrakedownCode<F> {
    message_size: usize,
    codeword_length: usize,
    layer: Layer<F>,
}

impl<F: FieldElement> BrakedownCode<F> {
    pub fn new(message_size: usize, params: BrakedownParams, rng: &mut impl Rng) -> Self {
        assert!(message_size > 0 && u32::try_from(message_size).is_ok());
        assert!(params.alpha > 0.0 && params.alpha < 1.0 && params.inverse_rate > 1.0);
        let codeword_length = (message_size as f64 * params.inverse_rate) as usize;
        let y = (message_size as f64 * params.alpha).ceil() as usize;
        let z = (y as f64 * params.inverse_rate) as usize;
        let v = codeword_length
            .checked_sub(message_size + z)
            .expect("invalid Brakedown rate/alpha");
        let layer = if y >= params.cn && v >= params.dn && message_size > 32 {
            Layer::Recursive {
                a: Expander::new(message_size, y, params.cn, rng),
                b: Expander::new(z, v, params.dn, rng),
                child: Box::new(Self::new(y, params, rng)),
            }
        } else {
            // Messages are evaluations at 0,...,k-1. Interpolate them at k,...,n-1.
            // This preserves the systematic layout and gives an MDS base code.
            assert!(u32::try_from(codeword_length).is_ok());
            let mut barycentric = Vec::with_capacity(message_size);
            for i in 0..message_size {
                let xi = F::from_u32(i as u32);
                let denominator = (0..message_size)
                    .filter(|&j| j != i)
                    .map(|j| xi - F::from_u32(j as u32))
                    .fold(F::ONE, |a, b| a * b);
                barycentric.push(
                    denominator
                        .inverse()
                        .expect("field too small for base code"),
                );
            }
            let parity = (message_size..codeword_length)
                .map(|j| {
                    let x = F::from_u32(j as u32);
                    let product = (0..message_size)
                        .map(|i| x - F::from_u32(i as u32))
                        .fold(F::ONE, |a, b| a * b);
                    (0..message_size)
                        .map(|i| {
                            product
                                * barycentric[i]
                                * (x - F::from_u32(i as u32)).inverse().unwrap()
                        })
                        .collect()
                })
                .collect();
            Layer::Base { parity }
        };
        Self {
            message_size,
            codeword_length,
            layer,
        }
    }

    #[must_use]
    pub const fn message_size(&self) -> usize {
        self.message_size
    }
    #[must_use]
    pub const fn codeword_length(&self) -> usize {
        self.codeword_length
    }

    pub fn encode(&self, message: &[F]) -> Vec<F> {
        assert_eq!(message.len(), self.message_size);
        let mut result = Vec::with_capacity(self.codeword_length);
        result.extend_from_slice(message);
        match &self.layer {
            Layer::Recursive { a, b, child } => {
                let z = child.encode(&a.apply(message));
                let v = b.apply(&z);
                result.extend(z);
                result.extend(v);
            }
            Layer::Base { parity } => {
                result.extend(parity.iter().map(|row| {
                    row.iter()
                        .zip(message)
                        .map(|(&a, &b)| a * b)
                        .fold(F::ZERO, |a, b| a + b)
                }));
            }
        }
        debug_assert_eq!(result.len(), self.codeword_length);
        result
    }

    pub fn encode_profiled(&self, message: &[F]) -> Vec<F> {
        let start = std::time::Instant::now();
        let codeword = self.encode(message);
        eprintln!("Brakedown encoding: {:?}", start.elapsed());
        codeword
    }
}

impl<F: FieldElement> ErrorCorrectingCode for BrakedownCode<F> {
    type Alphabet = F;
    fn message_size(&self) -> usize {
        self.message_size
    }
    fn block_length(&self) -> usize {
        self.codeword_length
    }
    fn encode(&self, message: &[F]) -> Vec<F> {
        self.encode(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_secp256k1::Fr as F;
    use rand::{SeedableRng, rngs::SmallRng};

    #[test]
    fn linear_systematic_and_input_regular() {
        let code = BrakedownCode::<F>::new(
            128,
            BrakedownParams {
                alpha: 0.3,
                inverse_rate: 2.0,
                cn: 10,
                dn: 20,
            },
            &mut SmallRng::seed_from_u64(2025),
        );
        assert!(
            code.encode(&vec![F::ZERO; 128])
                .iter()
                .all(FieldElement::is_zero)
        );
        let a: Vec<_> = (1..=128).map(F::from).collect();
        let b: Vec<_> = a.iter().map(|&x| x * x).collect();
        let combined: Vec<_> = a
            .iter()
            .zip(&b)
            .map(|(&x, &y)| x * F::from(7) + y * F::from(9))
            .collect();
        let ea = code.encode(&a);
        let eb = code.encode(&b);
        assert_eq!(&ea[..128], &a);
        assert_eq!(
            code.encode(&combined),
            ea.iter()
                .zip(&eb)
                .map(|(&x, &y)| x * F::from(7) + y * F::from(9))
                .collect::<Vec<_>>()
        );
        if let Layer::Recursive { a, .. } = &code.layer {
            let mut degrees = vec![0; 128];
            for &(i, _) in &a.edges {
                degrees[i] += 1;
            }
            assert!(degrees.iter().all(|&degree| degree == 10));
        } else {
            panic!("expected recursive test fixture");
        }
    }

    #[test]
    fn base_case_extends_a_known_polynomial() {
        let code = BrakedownCode::<F>::new(
            8,
            BrakedownParams {
                alpha: 0.3,
                inverse_rate: 2.0,
                cn: 10,
                dn: 20,
            },
            &mut SmallRng::seed_from_u64(1),
        );
        let polynomial = |x: F| x * x + F::from(3) * x + F::ONE;
        let msg: Vec<_> = (0..8).map(|i| polynomial(F::from(i))).collect();
        assert_eq!(
            code.encode(&msg),
            (0..16).map(|i| polynomial(F::from(i))).collect::<Vec<_>>()
        );
    }
}
