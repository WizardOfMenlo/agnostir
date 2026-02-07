//! Claim-shape validation and oracle reference resolution for the
//! `CodeswitchClaims` subprotocol output.

use crate::{ErrorCorrectingCode, FieldElement};

use super::{
    errors::{CodeswitchError, CodeswitchResult},
    params::CodeswitchParameters,
    types::{CodeswitchClaims, OracleReference, Round1Block},
};

/// Validate dimensions and oracle references for all claim objects.
pub(crate) fn validate_claims<F: FieldElement, C: ErrorCorrectingCode<Alphabet = F>>(
    params: &CodeswitchParameters<C, F>,
    round1_blocks: &[Round1Block<F>],
    claims: &CodeswitchClaims<F>,
) -> CodeswitchResult<()> {
    let expected_message_len = params.new_code_message_len();
    let expected_oracle_len = params.new_code_block_len();

    for aux in &claims.auxiliary_oracles {
        if aux.len() != expected_oracle_len {
            return Err(CodeswitchError::ClaimOracleLengthMismatch {
                expected: expected_oracle_len,
                found: aux.len(),
            });
        }
    }

    for block in round1_blocks {
        if block.oracle_word.len() != expected_oracle_len {
            return Err(CodeswitchError::ClaimOracleLengthMismatch {
                expected: expected_oracle_len,
                found: block.oracle_word.len(),
            });
        }
    }

    for claim in &claims.ip_claims {
        validate_oracle_reference(claim.oracle, round1_blocks, &claims.auxiliary_oracles)?;

        if claim.vector.len() != expected_message_len {
            return Err(CodeswitchError::ClaimVectorLengthMismatch {
                expected: expected_message_len,
                found: claim.vector.len(),
            });
        }

        if claim.witness.len() != expected_message_len {
            return Err(CodeswitchError::ClaimWitnessLengthMismatch {
                expected: expected_message_len,
                found: claim.witness.len(),
            });
        }
    }

    for claim in &claims.dip_claims {
        validate_oracle_reference(claim.left_oracle, round1_blocks, &claims.auxiliary_oracles)?;
        validate_oracle_reference(claim.right_oracle, round1_blocks, &claims.auxiliary_oracles)?;

        if claim.vector.len() != expected_message_len {
            return Err(CodeswitchError::ClaimVectorLengthMismatch {
                expected: expected_message_len,
                found: claim.vector.len(),
            });
        }

        if claim.left_witness.len() != expected_message_len {
            return Err(CodeswitchError::ClaimWitnessLengthMismatch {
                expected: expected_message_len,
                found: claim.left_witness.len(),
            });
        }

        if claim.right_witness.len() != expected_message_len {
            return Err(CodeswitchError::ClaimWitnessLengthMismatch {
                expected: expected_message_len,
                found: claim.right_witness.len(),
            });
        }
    }

    Ok(())
}

fn validate_oracle_reference<F: FieldElement>(
    reference: OracleReference,
    round1_blocks: &[Round1Block<F>],
    auxiliary_oracles: &[Vec<F>],
) -> CodeswitchResult<()> {
    let is_valid = match reference {
        OracleReference::MessageBlock(index) => index < round1_blocks.len(),
        OracleReference::Auxiliary(index) => index < auxiliary_oracles.len(),
    };

    if is_valid {
        Ok(())
    } else {
        Err(CodeswitchError::InvalidOracleReference {
            reference,
            message_block_count: round1_blocks.len(),
            auxiliary_count: auxiliary_oracles.len(),
        })
    }
}

/// Resolve an [`OracleReference`] to a concrete oracle slice.
pub(crate) fn resolve_oracle<'a, F: FieldElement>(
    reference: OracleReference,
    round1_blocks: &'a [Round1Block<F>],
    auxiliary_oracles: &'a [Vec<F>],
) -> Option<&'a [F]> {
    match reference {
        OracleReference::MessageBlock(index) => round1_blocks
            .get(index)
            .map(|block| block.oracle_word.as_slice()),
        OracleReference::Auxiliary(index) => auxiliary_oracles.get(index).map(Vec::as_slice),
    }
}
