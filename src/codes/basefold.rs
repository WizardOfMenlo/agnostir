//! Basefold linear-code encoding.
//!
//! This module contains only the encoding logic from the Basefold polynomial
//! commitment scheme, distilled into a simple struct that works over any
//! `FieldElement`.  The encoding is:
//!
//! 1. **Repetition base code** – each coefficient is repeated `rate` times.
//! 2. **Butterfly mixing** – `log2(message_size)` rounds of parallel butterfly
//!    passes, each using a pre-generated random table, transform the repeated
//!    coefficients into a codeword.
//! 3. **Bit-reversal** – a final bit-reversal permutation puts the codeword in
//!    the canonical (Type-1) order.

use rand::Rng;

use crate::FieldElement;

/// Parameters that control the Basefold code construction.
#[derive(Debug, Clone, Copy)]
pub struct BasefoldParams {
    /// log2 of the rate blow-up (codeword_length = message_size * 2^log_rate).
    pub log_rate: usize,
}

/// Pre-computed code description for Basefold (random butterfly tables).
#[derive(Debug)]
pub struct BasefoldCode<F> {
    /// Message length (number of field elements in one segment).
    message_size: usize,
    /// log2(message_size).
    log_message_size: usize,
    /// log2 of the rate blow-up.
    log_rate: usize,
    /// Rate = 2^log_rate.
    rate: usize,
    /// Codeword length = message_size * rate.
    codeword_length: usize,
    /// Butterfly table: one vector per level.
    /// Level `i` (for i in 0..log_message_size) has `rate * 2^i` entries (one
    /// per half-chunk element at that level).
    table: Vec<Vec<F>>,
}

/// In-place bit-reversal permutation on a slice whose length is a power of two.
fn reverse_index_bits_in_place<T>(data: &mut [T]) {
    let n = data.len();
    assert!(n.is_power_of_two(), "length must be a power of two");
    if n <= 1 {
        return;
    }
    let log_n = n.trailing_zeros();
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - log_n);
        if i < j {
            data.swap(i, j);
        }
    }
}

impl<F: FieldElement> BasefoldCode<F> {
    /// Build a new Basefold code for a given `message_size` and `params`.
    ///
    /// `message_size` must be a power of two.  Pre-generates the random
    /// butterfly tables needed for encoding.
    pub fn new(message_size: usize, params: BasefoldParams, rng: &mut impl Rng) -> Self {
        assert!(
            message_size.is_power_of_two(),
            "message_size must be a power of two"
        );
        let log_message_size = message_size.trailing_zeros() as usize;
        let log_rate = params.log_rate;
        let rate = 1usize << log_rate;
        let codeword_length = message_size * rate;

        // Build one table level per butterfly round.
        // Level i has size rate * 2^i  (= half the chunk size at that round).
        let mut table = Vec::with_capacity(log_message_size);
        for i in 0..log_message_size {
            let level_size = rate << i; // rate * 2^i
            let level: Vec<F> = (0..level_size)
                .map(|_| F::random(rng))
                .collect();
            table.push(level);
        }

        Self {
            message_size,
            log_message_size,
            log_rate,
            rate,
            codeword_length,
            table,
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

    /// Encode a single message (segment).
    ///
    /// 1. Repetition base code: each element repeated `rate` times.
    /// 2. Butterfly mixing: `log_message_size` rounds.
    /// 3. Bit-reversal permutation.
    pub fn encode(&self, msg: &[F]) -> Vec<F> {
        assert_eq!(msg.len(), self.message_size);

        // Step 1: repetition base code
        let mut codeword = Vec::with_capacity(self.codeword_length);
        for &coeff in msg {
            for _ in 0..self.rate {
                codeword.push(coeff);
            }
        }

        // Step 2: butterfly mixing passes
        let mut chunk_size = self.rate; // starts at base-code block length
        for i in 0..self.log_message_size {
            let level = &self.table[i];
            chunk_size <<= 1;
            debug_assert_eq!(level.len(), chunk_size >> 1);

            // Process each chunk independently.
            for chunk in codeword.chunks_mut(chunk_size) {
                let half = chunk_size >> 1;
                for j in half..chunk_size {
                    let rhs = chunk[j] * level[j - half];
                    let lhs = chunk[j - half];
                    chunk[j] = lhs + rhs;
                    chunk[j - half] = lhs + rhs + rhs;
                }
            }
        }

        // Step 3: bit-reversal permutation
        reverse_index_bits_in_place(&mut codeword);

        codeword
    }
}
