use super::types::OracleReference;

/// Error variants for the codeswitch Reduce-IOR scaffold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodeswitchError {
    InvalidLogSplit {
        log_start_code_message: usize,
        log_new_code_message: usize,
    },
    MessageInterleavingMismatch {
        expected: usize,
        found: usize,
    },
    WitnessLengthMismatch {
        expected: usize,
        found: usize,
    },
    EvalPointLengthMismatch {
        expected: usize,
        found: usize,
    },
    OracleLengthMismatch {
        expected: usize,
        found: usize,
    },
    NewCodeMessageSizeMismatch {
        expected: usize,
        found: usize,
    },
    ClaimVectorLengthMismatch {
        expected: usize,
        found: usize,
    },
    ClaimWitnessLengthMismatch {
        expected: usize,
        found: usize,
    },
    ClaimOracleLengthMismatch {
        expected: usize,
        found: usize,
    },
    InvalidOracleReference {
        reference: OracleReference,
        message_block_count: usize,
        auxiliary_count: usize,
    },
    EvalConsistencyCheckFailed,
    OpeningConsistencyCheckFailed,
}

pub type CodeswitchResult<T> = Result<T, CodeswitchError>;
