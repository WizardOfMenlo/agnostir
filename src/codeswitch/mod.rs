//! Codeswitch protocol scaffolding for the Reduce IOR in `reduce-ior.tex`.
//!
//! The implementation is split by protocol phase:
//! - round-1 block/oracle preparation,
//! - codeswitch claim handling,
//! - sumcheck scaffold and opening checks,
//! - batching into a reduced MEP claim.
//!
//! This keeps each phase isolated so the current scaffold can be replaced
//! incrementally by the final interactive subprotocol implementations.

mod batching;
mod claims;
mod errors;
mod params;
mod protocol;
mod round1;
mod spotcheck;
mod sumcheck;
mod types;
mod utils;

#[cfg(test)]
mod tests;

pub use errors::{CodeswitchError, CodeswitchResult};
pub use params::CodeswitchParameters;
pub use protocol::{codeswitch, run_reduce_ior_scaffold};
pub use types::{
    CodeswitchClaims, DipClaim, EvaluationOpenings, IpClaim, OracleReference, ReduceIorInput,
    ReduceIorScaffoldOutput, ReducedMepClaim, Round1Block, SpotCheck, SumcheckScaffold,
};
