//! Brakedown linear-code encoding.
//!
//! This module contains only the encoding logic from the Brakedown polynomial
//! commitment scheme, ported to work over any `p3_field::Field`.

use rand::Rng;

use crate::{ErrorCorrectingCode, FieldElement, SparseMatEntry, sparse_mat_vec};

/// Parameters that control the Brakedown code construction.
#[derive(Debug, Clone, Copy)]
pub struct BrakedownParams {
    /// Fraction of the message length used for the intermediate vector y.
    pub alpha: f64,
    /// Codeword-length / message-length ratio.
    pub inverse_rate: f64,
    /// Column-degree multiplier for the E1 sparse matrix.
    pub cn: usize,
    /// Column-degree multiplier for the E2 sparse matrix.
    pub dn: usize,
}

/// Pre-computed code description for Brakedown (all sparse matrices at every
/// recursion level).
#[derive(Debug)]
pub struct BrakedownCode<F> {
    /// Message length (number of field elements in one row).
    message_size: usize,
    /// Code parameters.
    params: BrakedownParams,
    /// Sparse matrices E1 at each recursion depth.
    e1: Vec<Vec<SparseMatEntry<F>>>,
    /// Sparse matrices E2 at each recursion depth.
    e2: Vec<Vec<SparseMatEntry<F>>>,
    /// Cached "tail" constants for the base-case (depth where y_length < 1).
    base_vals: Vec<F>,
}

/// Compute the derived lengths for a given message length and parameters.
fn brakedown_code_lengths(cur_msg_length: usize, params: &BrakedownParams) -> (usize, usize, usize, usize) {
    let cur_codeword_length = (cur_msg_length as f64 * params.inverse_rate) as usize;
    let cur_y_length = (cur_msg_length as f64 * params.alpha) as usize;
    let cur_z_length = if cur_y_length >= 1 {
        (cur_y_length as f64 * params.inverse_rate) as usize
    } else {
        0
    };
    let cur_v_length = cur_codeword_length - cur_msg_length - cur_z_length;
    (cur_codeword_length, cur_y_length, cur_z_length, cur_v_length)
}

impl<F: FieldElement> BrakedownCode<F> {
    /// Build a new Brakedown code for a given `message_size` and `params`.
    ///
    /// This pre-generates all the random sparse matrices needed at every
    /// recursion level.
    pub fn new(message_size: usize, params: BrakedownParams, rng: &mut impl Rng) -> Self {
        let mut e1 = Vec::new();
        let mut e2 = Vec::new();
        let mut base_vals = Vec::new();
        let mut cur_msg_length = message_size;

        loop {
            let (_cw_len, cur_y_length, cur_z_length, cur_v_length) =
                brakedown_code_lengths(cur_msg_length, &params);

            let mut level_e1 = Vec::new();
            let mut level_e2 = Vec::new();

            if cur_y_length >= 1 {
                // E1: maps msg -> y
                for i in 0..cur_y_length {
                    let nnz = params.cn * cur_y_length / cur_msg_length + 1;
                    for _ in 0..nnz {
                        level_e1.push(SparseMatEntry {
                            row: rng.random_range(0..cur_msg_length),
                            col: i,
                            val: F::random(rng),
                        });
                    }
                }

                // E2: maps z -> v
                for i in 0..cur_v_length {
                    let nnz = params.dn * cur_v_length / cur_z_length + 1;
                    for _ in 0..nnz {
                        level_e2.push(SparseMatEntry {
                            row: rng.random_range(0..cur_z_length),
                            col: i,
                            val: F::random(rng),
                        });
                    }
                }
            } else {
                // Base case: just store random values
                for _ in 0..cur_v_length {
                    base_vals.push(F::random(rng));
                }
            }

            e1.push(level_e1);
            e2.push(level_e2);

            if cur_y_length < 1 {
                break;
            }
            cur_msg_length = cur_y_length;
        }

        Self {
            message_size,
            params,
            e1,
            e2,
            base_vals,
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
        let (codeword_length, _, _, _) = brakedown_code_lengths(self.message_size, &self.params);
        codeword_length
    }

    /// Encode a single message (row).
    pub fn encode(&self, msg: &[F]) -> Vec<F> {
        assert_eq!(msg.len(), self.message_size);
        self.encode_recursive(msg, 0)
    }

    // ── private helpers ──────────────────────────────────────────────────

    fn encode_recursive(&self, msg: &[F], depth: usize) -> Vec<F> {
        let cur_msg_length = msg.len();
        let (_cw_len, cur_y_length, cur_z_length, cur_v_length) =
            brakedown_code_lengths(cur_msg_length, &self.params);

        let mut x = msg.to_vec();

        if cur_y_length >= 1 {
            let nnz_e1 = self.params.cn * cur_y_length / cur_msg_length + 1;
            let y = sparse_mat_vec(msg, &self.e1[depth], cur_y_length, nnz_e1);

            let z = self.encode_recursive(&y, depth + 1);

            let nnz_e2 = self.params.dn * cur_v_length / cur_z_length + 1;
            let v = sparse_mat_vec(&z, &self.e2[depth], cur_v_length, nnz_e2);

            x.extend_from_slice(&z);
            x.extend_from_slice(&v);
        } else {
            x.extend_from_slice(&self.base_vals);
        }

        x
    }
}

impl<F: FieldElement> ErrorCorrectingCode for BrakedownCode<F> {
    type Alphabet = F;

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn block_length(&self) -> usize {
        self.codeword_length()
    }

    fn encode(&self, msg: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
        self.encode(msg)
    }
}
