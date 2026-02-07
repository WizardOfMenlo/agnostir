//! CodeswitchClaims API skeleton from `codeswitching.tex` / `CodeswitchClaims.tex`.
//!
//! TODO: implement protocol construction and claim generation logic.

use super::claims::{SplitIpClaim, SplitTipClaim};
use super::oracles::{CodeswitchOraclesOutput, SplitEncoding};
use crate::FieldElement;

/// One verifier spotcheck target used by `CodeswitchClaims`.
#[derive(Debug, Clone)]
pub struct CodeswitchSpotcheck<F> {
    pub alpha: usize,
    pub sigma_cs: F,
}

/// Input contract for `CodeswitchClaims`.
#[derive(Debug, Clone)]
pub struct CodeswitchClaimsInput<F> {
    /// Prover witness message `msg`.
    pub msg: Vec<F>,
    /// Split output-code commitments to `msg`: `VectorOracleOf{word}{ℓ_msg}`.
    pub message_oracles: SplitEncoding<F>,
    /// Spotcheck pairs `(alpha_j, sigma_cs_j)`.
    pub spotchecks: Vec<CodeswitchSpotcheck<F>>,
    /// Index-oracle families produced by `CodeswitchOracles`.
    pub index_oracles: CodeswitchOraclesOutput<F>,
    /// Output-code message size `k'`.
    pub k_prime: usize,
    /// ERA block length `n_ERA`.
    pub n_era: usize,
    /// Base-code block length `n_CodeB`.
    pub n_code_b: usize,
}

/// Output contract for `CodeswitchClaims`.
#[derive(Debug, Clone)]
pub struct CodeswitchClaimsOutput<F> {
    /// Auxiliary split-encoded oracles sent during the subprotocol.
    pub aux_oracles: Vec<SplitEncoding<F>>,
    /// Produced split inner-product claims.
    pub ip_claims: Vec<SplitIpClaim<F>>,
    /// Produced split triple-product claims.
    pub tip_claims: Vec<SplitTipClaim<F>>,
}

/// Build all claims/oracles required by the `CodeswitchClaims` subprotocol.
///
/// TODO: implement according to `codeswitching.tex`.
pub fn generate_codeswitch_claims<F: FieldElement>(
    _input: CodeswitchClaimsInput<F>,
) -> CodeswitchClaimsOutput<F> {
    todo!("implement CodeswitchClaims from codeswitching.tex")
}
