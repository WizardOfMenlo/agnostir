use crate::{ErrorCorrectingCode, FieldElement, OptimizedEraCode};

/// Static parameters for the codeswitch Reduce-IOR scaffold.
///
/// Mapping to paper notation (as currently modeled):
/// - `message_interleaving`      -> `\ell_msg`
/// - `base_code_interleaving`    -> `\ell_{n_B}`
/// - `era_interleaving`          -> `\ell_{n_{ERA}}`
/// - `repetition_parameter`      -> used as `numSpotChecks` in the scaffold
/// - `log_start_code_message`    -> `log k`
/// - `log_start_code_blocklength`-> `log n`
/// - `log_new_code_message`      -> `log k'`
#[derive(Debug, Clone)]
pub struct CodeswitchParameters<C, F> {
    message_interleaving: usize,
    base_code_interleaving: usize,
    era_interleaving: usize,
    repetition_parameter: usize,
    log_start_code_message: usize,
    log_start_code_blocklength: usize,
    log_new_code_message: usize,
    era_code: OptimizedEraCode<C, F>,
}

impl<C, F> CodeswitchParameters<C, F> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_interleaving: usize,
        base_code_interleaving: usize,
        era_interleaving: usize,
        repetition_parameter: usize,
        log_start_code_message: usize,
        log_start_code_blocklength: usize,
        log_new_code_message: usize,
        era_code: OptimizedEraCode<C, F>,
    ) -> Self {
        Self {
            message_interleaving,
            base_code_interleaving,
            era_interleaving,
            repetition_parameter,
            log_start_code_message,
            log_start_code_blocklength,
            log_new_code_message,
            era_code,
        }
    }

    pub const fn message_interleaving(&self) -> usize {
        self.message_interleaving
    }

    pub const fn base_code_interleaving(&self) -> usize {
        self.base_code_interleaving
    }

    pub const fn era_interleaving(&self) -> usize {
        self.era_interleaving
    }

    /// Number of spot checks sampled against the start-code oracle.
    pub const fn num_spot_checks(&self) -> usize {
        self.repetition_parameter
    }

    pub const fn log_start_code_message(&self) -> usize {
        self.log_start_code_message
    }

    pub const fn log_start_code_blocklength(&self) -> usize {
        self.log_start_code_blocklength
    }

    pub const fn log_new_code_message(&self) -> usize {
        self.log_new_code_message
    }

    pub fn z1_num_variables(&self) -> Option<usize> {
        self.log_start_code_message
            .checked_sub(self.log_new_code_message)
    }

    pub fn start_code_blocklength(&self) -> usize {
        1usize << self.log_start_code_blocklength
    }

    pub fn new_code_message_len(&self) -> usize {
        1usize << self.log_new_code_message
    }

    pub fn start_code_message_len(&self) -> usize {
        1usize << self.log_start_code_message
    }

    /// Access the full start-code (`ERA`) encoder used by the outer relation.
    pub const fn era_code(&self) -> &OptimizedEraCode<C, F> {
        &self.era_code
    }

    /// Access the inner/new code (`C'`) used per message block.
    pub fn new_code(&self) -> &C {
        self.era_code.base_code()
    }
}

impl<C, F> CodeswitchParameters<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F>,
    F: FieldElement,
{
    pub fn new_code_block_len(&self) -> usize {
        self.new_code().block_length()
    }
}
