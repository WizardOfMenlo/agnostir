//! Shared presets for the four-code interleaved comparison.
//! Distance inputs are numerical ideal-ensemble bounds, not instance certificates.

use crate::{
    BasefoldCode, BasefoldParams, BrakedownCode, BrakedownParams, EaCode, EaParams, EraCode,
    ErrorCorrectingCode, FieldElement, random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use rand::{SeedableRng, rngs::SmallRng};

pub const DEFAULT_MESSAGE_LOG: usize = 22;
pub const DEFAULT_ETA: usize = 6;
pub const DEFAULT_SEED: u64 = 2025;
pub const SECURITY_BITS: f64 = 100.0;
pub const ERA_REPETITION: usize = 4;

/// These are encoders inside the common argument, not their native PCS protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum CodeKind {
    Brakedown,
    Ea,
    Basefold,
    Era,
}

impl CodeKind {
    pub const STANDARD: [Self; 4] = [Self::Brakedown, Self::Ea, Self::Basefold, Self::Era];

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Brakedown => "brakedown",
            Self::Ea => "ea",
            Self::Basefold => "basefold",
            Self::Era => "era",
        }
    }

    /// Distance inputs; EA retains its inherited assumption. See the calibration script.
    #[must_use]
    pub fn assumed_distance(self, segment_message_log: usize) -> f64 {
        assert_eq!(
            segment_message_log, 16,
            "only 65536-symbol rows are calibrated"
        );
        match self {
            Self::Brakedown => 0.1,
            Self::Ea => 0.1,
            // Total 102-bit setup budget: lambda=106 across 16 levels.
            Self::Basefold => 0.20106,
            Self::Era => 0.22037,
        }
    }
}

/// There are 2^eta contiguous rows, each containing 2^(message_log-eta) symbols.
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
    #[must_use]
    pub fn code_id(self, kind: CodeKind) -> [u8; 32] {
        // Setup identity is part of the wire format, independent of the crate name.
        let mut h = blake3::Hasher::new_derive_key("agnostir experimental code setup v3");
        h.update(kind.name().as_bytes());
        if kind == CodeKind::Brakedown {
            h.update(b"alpha=0.3;inverse-rate=2;cn=14;dn=28");
        }
        h.update(&self.seed.to_le_bytes());
        h.update(&(self.message_log as u64).to_le_bytes());
        h.update(&(self.eta as u64).to_le_bytes());
        *h.finalize().as_bytes()
    }

    pub fn validate(self, kind: CodeKind) -> Result<(), String> {
        self.validate_dimensions()?;
        let row_log = self.message_log - self.eta;
        if row_log != 16 {
            return Err(format!(
                "{} is calibrated for message-log - eta = 16, got {row_log}",
                kind.name()
            ));
        }
        Ok(())
    }

    /// Dimension checks only; a new row size needs an external distance bound.
    pub fn validate_dimensions(self) -> Result<(), String> {
        if self.message_log >= usize::BITS as usize || self.eta >= self.message_log {
            return Err(format!(
                "expected eta < message-log < {}, got eta={}, message-log={}",
                usize::BITS,
                self.eta,
                self.message_log
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
        self.build_code_with_external_distance(kind)
    }

    /// Build another row size; caller must supply its separately computed distance.
    pub fn build_code_with_external_distance(
        self,
        kind: CodeKind,
    ) -> Result<ExperimentalCode, String> {
        self.validate_dimensions()?;
        let mut rng = SmallRng::seed_from_u64(self.seed);
        let size = self.segment_message_size();
        Ok(match kind {
            CodeKind::Brakedown => ExperimentalCode::Brakedown(BrakedownCode::new(
                size,
                BrakedownParams {
                    alpha: 0.3,
                    inverse_rate: 2.0,
                    cn: 14,
                    dn: 28,
                },
                &mut rng,
            )),
            CodeKind::Basefold => ExperimentalCode::Basefold(BasefoldCode::new(
                size,
                BasefoldParams { log_rate: 1 },
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
            CodeKind::Era => {
                let base = BrakedownCode::new(
                    size,
                    BrakedownParams {
                        alpha: 0.04,
                        inverse_rate: 1.05,
                        cn: 5,
                        dn: 42,
                    },
                    &mut rng,
                );
                let n = base.block_length() * ERA_REPETITION;
                let p1 = random_permutation(&mut rng, n);
                let p2 = random_permutation(&mut rng, n);
                let m1 = (0..n).map(|_| nonzero_scalar(&mut rng)).collect();
                let m2 = (0..n).map(|_| nonzero_scalar(&mut rng)).collect();
                ExperimentalCode::Era(EraCode::new(base, ERA_REPETITION, p1, p2, m1, m2))
            }
        })
    }

    /// Reproducible public inputs, separately seeded from setup.
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
}

#[derive(Debug)]
pub enum ExperimentalCode {
    Brakedown(BrakedownCode<SecpScalar>),
    Ea(EaCode<SecpScalar>),
    Basefold(BasefoldCode<SecpScalar>),
    Era(EraCode<BrakedownCode<SecpScalar>, SecpScalar>),
}
impl ExperimentalCode {
    /// Use sequential inner scans when outer rows already occupy the workers.
    #[must_use]
    pub fn encode_row(&self, message: &[SecpScalar], sequential: bool) -> Vec<SecpScalar> {
        match self {
            Self::Brakedown(c) => c.encode(message),
            Self::Ea(c) => c.encode(message),
            Self::Basefold(c) if sequential => c.encode_sequential(message),
            Self::Basefold(c) => c.encode(message),
            Self::Era(c) if sequential => c.encode_era_sequential(message),
            Self::Era(c) => c.encode_era(message),
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
            Self::Era(c) => c.message_size(),
        }
    }
    fn block_length(&self) -> usize {
        match self {
            Self::Brakedown(c) => c.block_length(),
            Self::Ea(c) => c.codeword_length(),
            Self::Basefold(c) => c.codeword_length(),
            Self::Era(c) => c.block_length(),
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
/// not account for collisions. The serialized implementation deduplicates shared siblings.
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
            (CodeKind::Basefold, 927),
            (CodeKind::Era, 836),
        ] {
            config.validate(kind).unwrap();
            assert_eq!(num_queries_from_delta(kind.assumed_distance(16)), queries);
        }
    }

    #[test]
    fn encoders_have_distinct_setup_identifiers() {
        let config = ExperimentConfig::default();
        assert_ne!(
            config.code_id(CodeKind::Basefold),
            config.code_id(CodeKind::Era)
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
    fn other_row_sizes_require_explicit_external_distance_path() {
        let config = ExperimentConfig {
            message_log: 12,
            eta: 4,
            seed: DEFAULT_SEED,
        };
        assert!(config.build_code(CodeKind::Basefold).is_err());
        let code = config
            .build_code_with_external_distance(CodeKind::Basefold)
            .unwrap();
        assert_eq!(code.message_size(), 256);
        assert_eq!(code.block_length(), 512);
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
