//! Expander-Accumulate (EA) linear-code encoding.
//!
//! This module contains only the encoding logic from the "ECC" polynomial
//! commitment scheme (sparse-matrix multiplication followed by a prefix-sum
//! accumulation), ported to work over any `p3_field::Field`.

use rand::Rng;

use crate::{FieldElement, SparseMatEntry, sparse_mat_vec};

/// Parameters that control the EA code construction.
#[derive(Debug, Clone, Copy)]
pub struct EaParams {
    /// Codeword-length / message-length ratio.
    pub inverse_rate: usize,
    /// Multiplier used to compute column degree from log2(codeword_length).
    pub prob_multiplier: usize,
}

/// Pre-computed code description for the EA (Expander-Accumulate) code.
#[derive(Debug)]
pub struct EaCode<F> {
    /// Message length.
    message_size: usize,
    /// Codeword length  (= inverse_rate * message_size).
    codeword_length: usize,
    /// Number of non-zeros per column in the sparse matrix.
    nnz_per_col: usize,
    /// Sparse matrix E stored as a flat array of entries
    /// (column-major, `nnz_per_col` entries per column).
    e: Vec<SparseMatEntry<F>>,
}

impl<F: FieldElement> EaCode<F> {
    /// Build a new EA code for a given `message_size` and `params`.
    pub fn new(message_size: usize, params: EaParams, rng: &mut impl Rng) -> Self {
        let codeword_length = params.inverse_rate * message_size;
        let log2 = (codeword_length as f64).log2() as usize;
        let nnz_per_col = log2 * params.prob_multiplier / params.inverse_rate;

        let mut e = Vec::with_capacity(codeword_length * nnz_per_col);
        for i in 0..codeword_length {
            for _ in 0..nnz_per_col {
                e.push(SparseMatEntry {
                    row: rng.random_range(0..message_size),
                    col: i,
                    val: F::random(rng),
                });
            }
        }

        Self {
            message_size,
            codeword_length,
            nnz_per_col,
            e,
        }
    }

    /// Returns the message size this code was built for.
    #[must_use]
    pub fn message_size(&self) -> usize {
        self.message_size
    }

    /// Returns the codeword length for this code.
    #[must_use]
    pub fn codeword_length(&self) -> usize {
        self.codeword_length
    }

    /// Encode a single message (row).
    ///
    /// 1. Multiply by sparse matrix E  ->  intermediate vector.
    /// 2. Prefix-sum (accumulate) the intermediate vector.
    pub fn encode(&self, msg: &[F]) -> Vec<F> {
        assert_eq!(msg.len(), self.message_size);

        // Step 1: sparse matrix-vector product
        let mut codeword = sparse_mat_vec(msg, &self.e, self.codeword_length, self.nnz_per_col);

        // Step 2: prefix-sum accumulation
        for i in 1..self.codeword_length {
            let prev = codeword[i - 1];
            codeword[i] += prev;
        }

        codeword
    }
}
