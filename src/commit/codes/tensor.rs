//! Generic tensor (product) code.
//!
//! Given a code `C` with message size `k` and block length `n`, the tensor
//! code operates on messages of length `k²` by:
//!
//! 1. Arranging the message as a `k × k` grid (row-major).
//! 2. Encoding every **row** under `C`, producing a `k × n` grid.
//! 3. Encoding every **column** of that grid under `C`, producing an `n × n` grid.
//! 4. Concatenating all rows to yield a codeword of length `n²`.

use crate::ErrorCorrectingCode;

/// A tensor (product) code built from an inner code `C`.
///
/// The inner code `C` must have `message_size() == k` for some `k`; the tensor
/// code then has `message_size() == k²` and `block_length() == C.block_length()²`.
#[derive(Debug)]
pub struct TensorCode<C> {
    inner: C,
    /// `k` – the inner code's message size.
    k: usize,
    /// `n` – the inner code's block length.
    n: usize,
}

impl<C: ErrorCorrectingCode> TensorCode<C> {
    /// Build a new tensor code wrapping `inner`.
    pub fn new(inner: C) -> Self {
        let k = inner.message_size();
        let n = inner.block_length();
        Self { inner, k, n }
    }
}

impl<C> ErrorCorrectingCode for TensorCode<C>
where
    C: ErrorCorrectingCode,
    C::Alphabet: Clone,
{
    type Alphabet = C::Alphabet;

    fn message_size(&self) -> usize {
        self.k * self.k
    }

    fn block_length(&self) -> usize {
        self.n * self.n
    }

    fn encode(&self, msg: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
        assert_eq!(msg.len(), self.k * self.k);

        // Step 1: encode each row (k rows, each of length k -> n).
        let mut row_encoded: Vec<Vec<Self::Alphabet>> = Vec::with_capacity(self.k);
        for row in 0..self.k {
            let start = row * self.k;
            let row_codeword = self.inner.encode(&msg[start..start + self.k]);
            debug_assert_eq!(row_codeword.len(), self.n);
            row_encoded.push(row_codeword);
        }

        // Step 2: encode each column (n columns, each of length k -> n).
        // Build the result grid (n rows × n cols) directly.
        let mut result = Vec::with_capacity(self.n * self.n);

        // Collect each column, encode it, then scatter into result rows.
        // We build column-by-column and store the encoded columns, then
        // assemble row-major.
        let mut col_encoded: Vec<Vec<Self::Alphabet>> = Vec::with_capacity(self.n);
        for col in 0..self.n {
            let column: Vec<Self::Alphabet> = (0..self.k)
                .map(|row| row_encoded[row][col].clone())
                .collect();
            let col_codeword = self.inner.encode(&column);
            debug_assert_eq!(col_codeword.len(), self.n);
            col_encoded.push(col_codeword);
        }

        // Step 3: flatten to row-major order (row i, col j) = col_encoded[j][i].
        for row in 0..self.n {
            for col in 0..self.n {
                result.push(col_encoded[col][row].clone());
            }
        }

        result
    }
}
