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

#[cfg(feature = "parallel")]
use rayon::prelude::*;

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
    C: ErrorCorrectingCode + Sync,
    C::Alphabet: Clone + Send + Sync,
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

        // Step 1: encode each row in parallel (k rows, each of length k -> n).
        #[cfg(feature = "parallel")]
        let row_encoded: Vec<Vec<Self::Alphabet>> = (0..self.k)
            .into_par_iter()
            .map(|row| {
                let start = row * self.k;
                self.inner.encode(&msg[start..start + self.k])
            })
            .collect();
        #[cfg(not(feature = "parallel"))]
        let row_encoded: Vec<Vec<Self::Alphabet>> = (0..self.k)
            .map(|row| {
                let start = row * self.k;
                self.inner.encode(&msg[start..start + self.k])
            })
            .collect();

        // Step 2: encode each column in parallel (n columns, each of length k -> n).
        #[cfg(feature = "parallel")]
        let col_encoded: Vec<Vec<Self::Alphabet>> = (0..self.n)
            .into_par_iter()
            .map(|col| {
                let column: Vec<Self::Alphabet> = (0..self.k)
                    .map(|row| row_encoded[row][col].clone())
                    .collect();
                self.inner.encode(&column)
            })
            .collect();
        #[cfg(not(feature = "parallel"))]
        let col_encoded: Vec<Vec<Self::Alphabet>> = (0..self.n)
            .map(|col| {
                let column: Vec<Self::Alphabet> = (0..self.k)
                    .map(|row| row_encoded[row][col].clone())
                    .collect();
                self.inner.encode(&column)
            })
            .collect();

        // Step 3: flatten to row-major order (row i, col j) = col_encoded[j][i].
        let mut result = Vec::with_capacity(self.n * self.n);
        for row in 0..self.n {
            for col in 0..self.n {
                result.push(col_encoded[col][row].clone());
            }
        }

        result
    }
}
