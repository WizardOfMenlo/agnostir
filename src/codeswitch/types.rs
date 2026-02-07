use crate::{FieldElement, poly_utils::multilinear::MultilinearPoint};

/// Public input tuple for the Reduce-IOR scaffold.
#[derive(Debug, Clone)]
pub struct ReduceIorInput<F: FieldElement> {
    /// Evaluation point `z` for the outer MEP instance.
    pub eval_point: MultilinearPoint<F>,
    /// Claimed value `H(z)`.
    pub eval_value: F,
    /// Start-code oracle word `word`.
    pub oracle_word: Vec<F>,
    /// Witness message `msg`.
    pub witness_message: Vec<F>,
}

/// Handle to an oracle participating in claim constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OracleReference {
    /// One of the base block oracles `[word_i]` from round-1.
    MessageBlock(usize),
    /// One of the auxiliary oracles introduced by `CodeswitchClaims`.
    Auxiliary(usize),
}

/// A single inner-product claim placeholder.
#[derive(Debug, Clone)]
pub struct IpClaim<F: FieldElement> {
    pub oracle: OracleReference,
    pub vector: Vec<F>,
    pub sigma: F,
    pub witness: Vec<F>,
}

/// A single double-inner-product claim placeholder.
#[derive(Debug, Clone)]
pub struct DipClaim<F: FieldElement> {
    pub left_oracle: OracleReference,
    pub right_oracle: OracleReference,
    pub vector: Vec<F>,
    pub sigma: F,
    pub left_witness: Vec<F>,
    pub right_witness: Vec<F>,
}

/// Aggregate output of the `CodeswitchClaims` subprotocol.
#[derive(Debug, Clone, Default)]
pub struct CodeswitchClaims<F: FieldElement> {
    pub auxiliary_oracles: Vec<Vec<F>>,
    pub ip_claims: Vec<IpClaim<F>>,
    pub dip_claims: Vec<DipClaim<F>>,
}

/// Data produced per message block in round-1.
#[derive(Debug, Clone)]
pub struct Round1Block<F: FieldElement> {
    pub message: Vec<F>,
    pub oracle_word: Vec<F>,
    pub y_eval: F,
    pub z_ood: MultilinearPoint<F>,
    pub y_ood: F,
}

/// A sampled spot-check against the start-code oracle.
#[derive(Debug, Clone)]
pub struct SpotCheck<F: FieldElement> {
    pub index: usize,
    pub value: F,
}

/// Current sumcheck scaffold output.
#[derive(Debug, Clone)]
pub struct SumcheckScaffold<F: FieldElement> {
    pub beta: F,
    pub sigma: F,
    pub r: MultilinearPoint<F>,
    pub y_r: F,
}

/// Claimed openings of all individual messages/claims at point `r`.
#[derive(Debug, Clone)]
pub struct EvaluationOpenings<F: FieldElement> {
    pub a_eval: Vec<F>,
    pub a_ood: Vec<F>,
    pub a_ip: Vec<F>,
    pub a_dip_left: Vec<F>,
    pub a_dip_right: Vec<F>,
}

/// Reduced MEP claim produced by batching.
#[derive(Debug, Clone)]
pub struct ReducedMepClaim<F: FieldElement> {
    pub point: MultilinearPoint<F>,
    pub value: F,
    pub oracle_word: Vec<F>,
    pub witness_message: Vec<F>,
}

/// Full scaffold transcript emitted by `run_reduce_ior_scaffold`.
#[derive(Debug, Clone)]
pub struct ReduceIorScaffoldOutput<F: FieldElement> {
    pub z1: MultilinearPoint<F>,
    pub z2: MultilinearPoint<F>,
    pub round1_blocks: Vec<Round1Block<F>>,
    pub spot_checks: Vec<SpotCheck<F>>,
    pub claims: CodeswitchClaims<F>,
    pub sumcheck: SumcheckScaffold<F>,
    pub openings: EvaluationOpenings<F>,
    pub gamma: F,
    pub reduced_claim: ReducedMepClaim<F>,
}
