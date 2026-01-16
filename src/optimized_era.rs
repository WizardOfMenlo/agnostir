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

        let pack_width = F::Packing::WIDTH;
        let chunk_len = Self::chunk_len(self.block_length);
        let mut first_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];

        first_accumulate
            .par_chunks_mut(chunk_len)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * chunk_len;
                let len = chunk.len();
                let m1_slice = &self.m1_vector[start..start + len];
                let p1_slice = &self.p1_vector[start..start + len];

                let (out_packed, out_suffix) = F::Packing::pack_slice_with_suffix_mut(chunk);
                let (m1_packed, m1_suffix) = F::Packing::pack_slice_with_suffix(m1_slice);

                let base_ptr = base_encoding.as_ptr();
                let p1_ptr = p1_slice.as_ptr();

                for (pack_idx, (out, m1)) in out_packed.iter_mut().zip(m1_packed.iter()).enumerate()
                {
                    let base = F::Packing::from_fn(|lane| unsafe {
                        let idx = *p1_ptr.add(pack_idx * pack_width + lane) as usize;
                        *base_ptr.add(idx)
                    });
                    *out = base * *m1;
                }

                let suffix_start = out_packed.len() * pack_width;
                for (offset, out) in out_suffix.iter_mut().enumerate() {
                    let idx = suffix_start + offset;
                    let base_idx = unsafe { *p1_ptr.add(idx) as usize };
                    let mul = unsafe { *m1_suffix.get_unchecked(offset) };
                    let base_val = unsafe { *base_ptr.add(base_idx) };
                    *out = base_val * mul;
                }
            });

        Self::prefix_sum_in_place(&mut first_accumulate, chunk_len);

        let mut second_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        second_accumulate
            .par_chunks_mut(chunk_len)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * chunk_len;
                let len = chunk.len();
                let m2_slice = &self.m2_vector[start..start + len];
                let p2_slice = &self.p2_vector[start..start + len];

                let (out_packed, out_suffix) = F::Packing::pack_slice_with_suffix_mut(chunk);
                let (m2_packed, m2_suffix) = F::Packing::pack_slice_with_suffix(m2_slice);

                let src_ptr = first_accumulate.as_ptr();
                let p2_ptr = p2_slice.as_ptr();

                for (pack_idx, (out, m2)) in out_packed.iter_mut().zip(m2_packed.iter()).enumerate()
                {
                    let src = F::Packing::from_fn(|lane| unsafe {
                        let idx = *p2_ptr.add(pack_idx * pack_width + lane) as usize;
                        *src_ptr.add(idx)
                    });
                    *out = src * *m2;
                }

                let suffix_start = out_packed.len() * pack_width;
                for (offset, out) in out_suffix.iter_mut().enumerate() {
                    let idx = suffix_start + offset;
                    let src_idx = unsafe { *p2_ptr.add(idx) as usize };
                    let mul = unsafe { *m2_suffix.get_unchecked(offset) };
                    let src_val = unsafe { *src_ptr.add(src_idx) };
                    *out = src_val * mul;
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
