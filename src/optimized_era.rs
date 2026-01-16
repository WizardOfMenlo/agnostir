use p3_field::{Field, PackedValue};
use p3_maybe_rayon::prelude::*;
use std::sync::OnceLock;

use crate::ErrorCorrectingCode;

#[derive(Debug)]
pub struct OptimizedEraCode<C, F> {
    message_size: usize,
    block_length: usize,
    base_block_length: usize,
    repetition_parameter: usize,
    base_code: C,

    p1_vector: Vec<u32>,
    p2_vector: Vec<u32>,

    m1_vector: Vec<F>,
    m2_vector: Vec<F>,
}

impl<C, F> OptimizedEraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F> + Sync,
    F: Field,
{
    pub fn new(
        base_code: C,
        repetition_parameter: usize,
        p1_vector: Vec<usize>,
        p2_vector: Vec<usize>,
        m1_vector: Vec<F>,
        m2_vector: Vec<F>,
    ) -> Self {
        let message_size = base_code.message_size();
        let base_block_length = base_code.block_length();
        let block_length = repetition_parameter * base_block_length;

        assert!(
            block_length <= u32::MAX as usize,
            "block_length must fit in u32"
        );

        debug_assert!(Self::check_permutation(&p1_vector));
        debug_assert!(Self::check_permutation(&p2_vector));

        let p1_vector: Vec<u32> = p1_vector
            .into_iter()
            .map(|index| (index % base_block_length) as u32)
            .collect();
        let p2_vector: Vec<u32> = p2_vector.into_iter().map(|index| index as u32).collect();

        let code = Self {
            message_size,
            block_length,
            base_block_length,
            repetition_parameter,
            base_code,
            p1_vector,
            p2_vector,
            m1_vector,
            m2_vector,
        };

        debug_assert!(code.validate_parameters());
        code
    }

    // Check that a vector contains a permutation on 0..v.len()
    fn check_permutation(v: &[usize]) -> bool {
        let n = v.len();
        let mut seen = vec![false; n];

        for &x in v {
            if x >= n || seen[x] {
                return false;
            }
            seen[x] = true;
        }

        true
    }

    fn check_permutation_u32(v: &[u32]) -> bool {
        let n = v.len();
        let mut seen = vec![false; n];

        for &x in v {
            let idx = x as usize;
            if idx >= n || seen[idx] {
                return false;
            }
            seen[idx] = true;
        }

        true
    }

    fn validate_parameters(&self) -> bool {
        self.p1_vector.len() == self.block_length
            && self
                .p1_vector
                .iter()
                .all(|&x| (x as usize) < self.base_block_length)
            && self.p2_vector.len() == self.block_length
            && self.m1_vector.len() == self.block_length
            && self.m2_vector.len() == self.block_length
            && Self::check_permutation_u32(&self.p2_vector)
            && self.base_code.message_size() == self.message_size
            && self.repetition_parameter * self.base_code.block_length() == self.block_length()
    }

    pub fn encode_naive(&self, msg: &[C::Alphabet]) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let base_encoding = self.base_code.encode(msg);
        debug_assert_eq!(base_encoding.len(), self.base_block_length);

        let mut first_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        for i in 0..self.block_length {
            let base_idx = self.p1_vector[i] as usize;
            first_accumulate[i] = base_encoding[base_idx] * self.m1_vector[i];
        }

        let mut acc = F::ZERO;
        for value in first_accumulate.iter_mut() {
            acc += *value;
            *value = acc;
        }

        let mut second_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        for i in 0..self.block_length {
            let src_idx = self.p2_vector[i] as usize;
            second_accumulate[i] = first_accumulate[src_idx] * self.m2_vector[i];
        }

        let mut acc = F::ZERO;
        for value in second_accumulate.iter_mut() {
            acc += *value;
            *value = acc;
        }

        second_accumulate
    }

    fn add_const_in_place(slice: &mut [F], offset: F) {
        let (packed, suffix) = F::Packing::pack_slice_with_suffix_mut(slice);
        let packed_offset: F::Packing = offset.into();
        for value in packed.iter_mut() {
            *value += packed_offset;
        }
        for value in suffix.iter_mut() {
            *value += offset;
        }
    }

    fn chunk_len(len: usize) -> usize {
        if len <= 1 {
            return len;
        }
        if let Some(override_len) = chunk_len_override() {
            return override_len.min(len);
        }
        let tuned = 8192usize;
        if len >= tuned {
            return tuned;
        }
        let threads = current_num_threads().max(1);
        let mut chunk_len = len / (threads * 4).max(1);
        if chunk_len < tuned {
            chunk_len = tuned;
        }
        chunk_len.min(len)
    }

    fn prefix_sum_in_place(values: &mut [F], chunk_len: usize) {
        if values.is_empty() {
            return;
        }

        // Compute local prefix sums in parallel and collect each chunk's total.
        let mut totals: Vec<F> = values
            .par_chunks_mut(chunk_len)
            .map(|chunk| {
                let mut acc = F::ZERO;
                for value in chunk.iter_mut() {
                    acc += *value;
                    *value = acc;
                }
                acc
            })
            .collect();

        // Prefix-sum the chunk totals to get offsets.
        let mut running = F::ZERO;
        for total in totals.iter_mut() {
            let tmp = *total;
            *total = running;
            running += tmp;
        }

        // Add the offsets back into each chunk using packing (SIMD).
        values
            .par_chunks_mut(chunk_len)
            .zip(totals.into_par_iter())
            .for_each(|(chunk, offset)| {
                if !offset.is_zero() {
                    Self::add_const_in_place(chunk, offset);
                }
            });
    }

    pub fn encode_fast(&self, msg: &[C::Alphabet]) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let base_encoding = self.base_code.encode(msg);
        debug_assert_eq!(base_encoding.len(), self.base_block_length);

        let chunk_len = Self::chunk_len(self.block_length);
        let mut first_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];

        first_accumulate
            .par_chunks_mut(chunk_len)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * chunk_len;
                let base_ptr = base_encoding.as_ptr();
                let p1_ptr = self.p1_vector.as_ptr();
                let m1_ptr = self.m1_vector.as_ptr();
                let out_ptr = chunk.as_mut_ptr();
                let len = chunk.len();
                for offset in 0..len {
                    let idx = start + offset;
                    unsafe {
                        let base_idx = *p1_ptr.add(idx) as usize;
                        let base_val = *base_ptr.add(base_idx);
                        let mul = *m1_ptr.add(idx);
                        *out_ptr.add(offset) = base_val * mul;
                    }
                }
            });

        Self::prefix_sum_in_place(&mut first_accumulate, chunk_len);

        let mut second_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        second_accumulate
            .par_chunks_mut(chunk_len)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * chunk_len;
                let src_ptr = first_accumulate.as_ptr();
                let p2_ptr = self.p2_vector.as_ptr();
                let m2_ptr = self.m2_vector.as_ptr();
                let out_ptr = chunk.as_mut_ptr();
                let len = chunk.len();
                for offset in 0..len {
                    let idx = start + offset;
                    unsafe {
                        let src_idx = *p2_ptr.add(idx) as usize;
                        let src_val = *src_ptr.add(src_idx);
                        let mul = *m2_ptr.add(idx);
                        *out_ptr.add(offset) = src_val * mul;
                    }
                }
            });

        Self::prefix_sum_in_place(&mut second_accumulate, chunk_len);

        second_accumulate
    }
}

fn chunk_len_override() -> Option<usize> {
    static OVERRIDE: OnceLock<Option<usize>> = OnceLock::new();
    *OVERRIDE.get_or_init(|| {
        std::env::var("AGNOSTIR_CHUNK_LEN")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|&value| value > 0)
    })
}

impl<C, F> ErrorCorrectingCode for OptimizedEraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F> + Sync,
    F: Field,
{
    type Alphabet = C::Alphabet;

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn block_length(&self) -> usize {
        self.block_length
    }

    fn encode(&self, msg: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
        self.encode_fast(msg)
    }
}
