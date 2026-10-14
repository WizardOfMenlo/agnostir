//! Shared parameters and encoders for the interleaved IOPP demo and benchmarks.
//!
//! Distance values are inputs to the experiment's query-count model. This module
//! does not certify the distance of a sampled code or its setup failure probability.

use ark_secp256k1::Fr as SecpScalar;
use rand::{SeedableRng, rngs::SmallRng};

use crate::{
    BasefoldCode, BasefoldParams, BoltCode, BrakedownCode, BrakedownParams, EaCode, EaParams,
    EraCode, ErrorCorrectingCode, FieldElement, random_permutation,
};

pub const DEFAULT_MESSAGE_LOG: usize = 18;
pub const DEFAULT_ETA: usize = 5;
pub const DEFAULT_SEED: u64 = 2025;
pub const SECURITY_BITS: f64 = 100.0;
pub const ERA_REPETITION: usize = 4;

/// Encoder choices; Basefold here means its linear code, not its recursive IOPP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum CodeKind {
    Brakedown,
    Ea,
    Basefold,
    /// Bolt-min sketch with a BaseFold syndrome code over secp256k1 scalars.
    BoltMin,
    /// Bolt-max all-one sketch; prime-field kernel distance is an assumption.
    BoltMax,
    Era,
    ConjecturedEra,
}

impl CodeKind {
    pub const STANDARD: [Self; 6] = [
        Self::Brakedown,
        Self::Ea,
        Self::Basefold,
        Self::Era,
        Self::BoltMin,
        Self::BoltMax,
    ];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Brakedown => "brakedown",
            Self::Ea => "ea",
            Self::Basefold => "basefold",
            Self::BoltMin => "bolt-min",
            Self::BoltMax => "bolt-max",
            Self::Era => "era",
            Self::ConjecturedEra => "conjectured_era",
        }
    }

    /// Assumed relative distance used to choose the number of column queries.
    #[must_use]
    pub fn assumed_distance(self, segment_message_log: usize) -> f64 {
        match self {
            Self::Brakedown | Self::Ea => 0.1,
            // C(x)=x||B(Hx): d(C)>=min(d(ker H),d(B)). The kernel
            // ensemble bound is m/16, while B occupies 1/5 of the word.
            // B's estimates below round down the repository's BaseFold formula
            // at log2|F|=255 and setup budget 102. They remain conditional on
            // that analysis and setup model; see docs/bolt-adaptation.md.
            Self::BoltMin => {
                let outer_delta = match segment_message_log {
                    12 => 0.246,
                    13 => 0.240,
                    14 => 0.235,
                    15 => 0.229,
                    16 => 0.224,
                    17 => 0.219,
                    18 => 0.213,
                    19 => 0.208,
                    20 => 0.202,
                    21 => 0.197,
                    22 => 0.191,
                    _ => unreachable!("validate the configuration before looking up distance"),
                };
                outer_delta / 5.0
            }
            // Assumed kernel distance is relative to m, not the full 5m/4
            // word. The binary LDPC analysis does not prove this over Fr.
            // This is below the conditional outer distance / 5 throughout
            // the supported sizes. See docs/bolt-max-adaptation.md.
            Self::BoltMax => 0.013 / 1.25,
            Self::Basefold => match segment_message_log {
                10 => 0.246,
                11 => 0.240,
                12 => 0.235,
                13 => 0.230,
                14 => 0.224,
                15 => 0.219,
                16 => 0.213,
                17 => 0.208,
                18 => 0.202_586_068_445_465_9,
                19 => 0.197,
                20 => 0.192,
                21 => 0.186,
                22 => 0.181,
                _ => unreachable!("validate the configuration before looking up distance"),
            },
            Self::Era | Self::ConjecturedEra => match segment_message_log {
                12 => 0.204,
                13 => 0.226,
                14 => 0.227,
                18 => 0.224_403_355_646_751_46,
                _ => 0.228,
            },
        }
    }
}

/// `message_log` and `eta` are logarithms: there are `2^eta` contiguous rows.
#[derive(Debug, Clone, Copy)]
pub struct ExperimentConfig {
    pub message_log: usize,
    pub eta: usize,
    pub seed: u64,
}

impl Default for ExperimentConfig {
    fn default() -> Self {
        Self {
            message_log: DEFAULT_MESSAGE_LOG,
            eta: DEFAULT_ETA,
            seed: DEFAULT_SEED,
        }
    }
}

impl ExperimentConfig {
    /// Bind the deterministic setup recipe, dimensions and encoder version.
    #[must_use]
    pub fn code_id(self, kind: CodeKind) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("agnostir experimental code setup v2");
        h.update(kind.name().as_bytes());
        if kind == CodeKind::BoltMin {
            h.update(b"secp256k1-sketch-basefold-v1;degree=16;compression=8;outer-log-rate=1");
        }
        if kind == CodeKind::BoltMax {
            h.update(b"secp256k1-sketch-basefold-v1;degree=8;coefficients=all-one;compression=8;outer-log-rate=1");
        }
        h.update(&self.seed.to_le_bytes());
        h.update(&(self.message_log as u64).to_le_bytes());
        h.update(&(self.eta as u64).to_le_bytes());
        *h.finalize().as_bytes()
    }
    pub fn validate(self, kind: CodeKind) -> Result<(), String> {
        if self.message_log >= usize::BITS as usize || self.eta >= self.message_log {
            return Err(format!(
                "expected eta < message-log < {}, got eta={}, message-log={}",
                usize::BITS,
                self.eta,
                self.message_log
            ));
        }
        let log_segment = self.message_log - self.eta;
        let supported = if kind == CodeKind::Basefold {
            10..=22
        } else {
            12..=22
        };
        if !supported.contains(&log_segment) {
            return Err(format!(
                "{} requires message-log - eta in {supported:?}, got {log_segment}",
                kind.name()
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn message_size(self) -> usize {
        1usize << self.message_log
    }

    #[must_use]
    pub const fn rows(self) -> usize {
        1usize << self.eta
    }

    #[must_use]
    pub const fn segment_message_size(self) -> usize {
        1usize << (self.message_log - self.eta)
    }

    pub fn build_code(self, kind: CodeKind) -> Result<ExperimentalCode, String> {
        self.validate(kind)?;
        let mut rng = SmallRng::seed_from_u64(self.seed);
        let size = self.segment_message_size();
        let code = match kind {
            CodeKind::Brakedown => ExperimentalCode::Brakedown(BrakedownCode::new(
                size,
                BrakedownParams {
                    alpha: 0.3,
                    inverse_rate: 2.0,
                    cn: 10,
                    dn: 20,
                },
                &mut rng,
            )),
            CodeKind::Ea => ExperimentalCode::Ea(EaCode::new(
                size,
                EaParams {
                    inverse_rate: 2,
                    prob_multiplier: 18,
                },
                &mut rng,
            )),
            CodeKind::Basefold => ExperimentalCode::Basefold(BasefoldCode::new(
                size,
                BasefoldParams { log_rate: 1 },
                &mut rng,
            )),
            CodeKind::BoltMin => ExperimentalCode::BoltMin(BoltCode::new(size, &mut rng)),
            CodeKind::BoltMax => ExperimentalCode::BoltMax(BoltCode::new_max(size, &mut rng)),
            CodeKind::Era | CodeKind::ConjecturedEra => {
                let base_code = BrakedownCode::new(
                    size,
                    BrakedownParams {
                        alpha: 0.04,
                        inverse_rate: 1.05,
                        cn: 5,
                        dn: 42,
                    },
                    &mut rng,
                );
                let n = base_code.block_length() * ERA_REPETITION;
                let p1 = random_permutation(&mut rng, n);
                let p2 = random_permutation(&mut rng, n);
                let m1 = (0..n).map(|_| nonzero_scalar(&mut rng)).collect();
                let m2 = (0..n).map(|_| nonzero_scalar(&mut rng)).collect();
                let code = EraCode::new(base_code, ERA_REPETITION, p1, p2, m1, m2);
                if kind == CodeKind::Era {
                    ExperimentalCode::Era(code)
                } else {
                    ExperimentalCode::ConjecturedEra(code)
                }
            }
        };
        Ok(code)
    }

    /// Message and evaluation point use a separate stream from code setup.
    #[must_use]
    pub fn message_and_point(self) -> (Vec<SecpScalar>, Vec<SecpScalar>) {
        let mut rng = SmallRng::seed_from_u64(self.seed.wrapping_add(1));
        let message = (0..self.message_size())
            .map(|_| SecpScalar::random(&mut rng))
            .collect();
        let point = (0..self.message_log)
            .map(|_| SecpScalar::random(&mut rng))
            .collect();
        (message, point)
    }

    #[must_use]
    pub fn challenge_rng(self) -> SmallRng {
        SmallRng::seed_from_u64(self.seed.wrapping_add(2))
    }
}

#[derive(Debug)]
pub enum ExperimentalCode {
    Brakedown(BrakedownCode<SecpScalar>),
    Ea(EaCode<SecpScalar>),
    Basefold(BasefoldCode<SecpScalar>),
    BoltMin(BoltCode),
    BoltMax(BoltCode),
    Era(EraCode<BrakedownCode<SecpScalar>, SecpScalar>),
    ConjecturedEra(EraCode<BrakedownCode<SecpScalar>, SecpScalar>),
}

impl ExperimentalCode {
    /// Avoid nested parallel prefix sums when encoding many rows concurrently.
    #[must_use]
    pub fn encode_row(&self, message: &[SecpScalar], sequential_era: bool) -> Vec<SecpScalar> {
        match self {
            Self::Brakedown(code) => code.encode(message),
            Self::Ea(code) => code.encode(message),
            Self::Basefold(code) if sequential_era => code.encode_sequential(message),
            Self::Basefold(code) => code.encode(message),
            Self::BoltMin(code) | Self::BoltMax(code) if sequential_era => {
                code.encode_sequential(message)
            }
            Self::BoltMin(code) | Self::BoltMax(code) => code.encode(message),
            Self::Era(code) if sequential_era => code.encode_era_sequential(message),
            Self::Era(code) => code.encode_era(message),
            Self::ConjecturedEra(code) if sequential_era => {
                code.encode_conjectured_era_sequential(message)
            }
            Self::ConjecturedEra(code) => code.encode_conjectured_era(message),
        }
    }
}

impl ErrorCorrectingCode for ExperimentalCode {
    type Alphabet = SecpScalar;

    fn message_size(&self) -> usize {
        match self {
            Self::Brakedown(c) => c.message_size(),
            Self::Ea(c) => c.message_size(),
            Self::Basefold(c) => c.message_size(),
            Self::BoltMin(c) | Self::BoltMax(c) => c.message_size(),
            Self::Era(c) | Self::ConjecturedEra(c) => c.message_size(),
        }
    }

    fn block_length(&self) -> usize {
        match self {
            Self::Brakedown(c) => c.block_length(),
            Self::Ea(c) => c.codeword_length(),
            Self::Basefold(c) => c.codeword_length(),
            Self::BoltMin(c) | Self::BoltMax(c) => c.block_length(),
            Self::Era(c) | Self::ConjecturedEra(c) => c.block_length(),
        }
    }

    fn encode(&self, message: &[SecpScalar]) -> Vec<SecpScalar> {
        self.encode_row(message, false)
    }
}

/// Query soundness model: `q = ceil(-3 * SECURITY_BITS / log2(1 - delta))`.
#[must_use]
pub fn num_queries_from_delta(delta: f64) -> usize {
    assert!(
        delta.is_finite() && delta > 0.0 && delta < 1.0,
        "relative distance must be finite and strictly between zero and one"
    );
    (-3.0 * SECURITY_BITS / (1.0 - delta).log2()).ceil() as usize
}

/// Shared-path approximation using the padded tree's depth.
///
/// Returns `None` outside `2 <= queries <= block_length`, its supported regime.
/// Queries in the actual protocol are drawn with replacement; this model does
/// not account for collisions. The implementation sends independent paths.
/// Excludes the public root, evaluation point, indices, and serialization framing.
#[must_use]
pub fn shared_path_proof_size_kib(
    block_length: usize,
    config: ExperimentConfig,
    queries: usize,
) -> Option<f64> {
    if queries < 2
        || queries > block_length
        || config.eta > config.message_log
        || config.message_log >= usize::BITS as usize
    {
        return None;
    }
    let q = queries as f64;
    let depth = f64::from(block_length.checked_next_power_of_two()?.max(2).ilog2());
    let hashes = (q - 2.0) + (depth - q.log2()) * q;
    let fields = 1.0 + config.segment_message_size() as f64 + q * config.rows() as f64;
    Some((fields + hashes) * 32.0 / 1024.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paper_size_uses_expected_query_counts() {
        let config = ExperimentConfig {
            message_log: 22,
            eta: 6,
            seed: DEFAULT_SEED,
        };
        for (kind, queries) in [
            (CodeKind::Brakedown, 1974),
            (CodeKind::Ea, 1974),
            (CodeKind::Basefold, 869),
            (CodeKind::BoltMin, 4537),
            (CodeKind::BoltMax, 19891),
            (CodeKind::Era, 804),
            (CodeKind::ConjecturedEra, 804),
        ] {
            config.validate(kind).unwrap();
            assert_eq!(num_queries_from_delta(kind.assumed_distance(16)), queries);
        }
    }

    #[test]
    fn sketch_variants_have_distinct_setup_identifiers() {
        let config = ExperimentConfig::default();
        assert_ne!(
            config.code_id(CodeKind::BoltMin),
            config.code_id(CodeKind::BoltMax)
        );
    }

    #[test]
    fn unsupported_dimensions_are_rejected_before_setup() {
        for (message_log, eta) in [(12, 12), (10, 2), (usize::BITS as usize, 5), (28, 5)] {
            let config = ExperimentConfig {
                message_log,
                eta,
                seed: DEFAULT_SEED,
            };
            assert!(config.build_code(CodeKind::Era).is_err());
        }
    }

    #[test]
    fn query_model_and_override_reporting_have_valid_domains() {
        for delta in [0.0, 1.0, -0.1, f64::NAN, f64::INFINITY] {
            assert!(std::panic::catch_unwind(|| num_queries_from_delta(delta)).is_err());
        }
        let config = ExperimentConfig::default();
        assert!(shared_path_proof_size_kib(32768, config, 1).is_none());
        assert!(shared_path_proof_size_kib(32768, config, 32769).is_none());
        assert!(shared_path_proof_size_kib(32768, config, 804).unwrap() > 0.0);
    }
}

fn nonzero_scalar(rng: &mut impl rand::Rng) -> SecpScalar {
    loop {
        let value = SecpScalar::random(rng);
        if !value.is_zero() {
            return value;
        }
    }
}
