use voracious_radix_sort::{RadixSort, Radixable};
use p3_field::{Field, PackedValue};
use p3_maybe_rayon::prelude::*;
use std::{sync::OnceLock, time::Instant};

use crate::ErrorCorrectingCode;

const PERMUTE_CHUNK_SIZE: usize = 1 << 12;

#[derive(Debug)]
pub struct OptimizedEraCode<C, F> {
    message_size: usize,
    block_length: usize,
    block_length_segment: usize,
    base_block_length: usize,
    repetition_parameter: usize,
    interleaving_parameter: usize,
    segment_count: usize,
    base_code: C,

    p1_vector: Vec<u32>,
    p2_vector: Vec<u32>,

    m1_vector: Vec<F>,
    m2_vector: Vec<F>,

    first_accumulate: Vec<F>,
    second_accumulate: Vec<F>,
}

#[derive(Debug, Default)]
pub struct EncodeNaiveBuffers<F> {
    base_columns: Vec<Vec<F>>,
    first_accumulate: Vec<Vec<F>>,
    second_accumulate: Vec<Vec<F>>,
}

#[derive(Debug, Default)]
pub struct RadixSortBuffers<F: Copy> {
    entries: Vec<RadixEntry<F>>,
    first_accumulate: Vec<F>,
    second_accumulate: Vec<F>,
}

impl<F: Copy> RadixSortBuffers<F> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            first_accumulate: Vec::with_capacity(capacity),
            second_accumulate: Vec::with_capacity(capacity),
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RadixEntry<F: Copy> {
    key: u32,
    value: F,
}

impl<F: Copy> PartialEq for RadixEntry<F> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl<F: Copy> PartialOrd for RadixEntry<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.key.partial_cmp(&other.key)
    }
}

impl<F: Copy + Send + Sync> Radixable<u32> for RadixEntry<F> {
    type Key = u32;

    #[inline]
    fn key(&self) -> Self::Key {
        self.key
    }
}

impl<C, F> OptimizedEraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F> + Sync,
    F: Field,
{
    pub fn new(
        base_code: C,
        repetition_parameter: usize,
        interleaving_parameter: usize,
        p1_vector: Vec<usize>,
        p2_vector: Vec<usize>,
        m1_vector: Vec<F>,
        m2_vector: Vec<F>,
    ) -> Self {
        let segment_count = 1usize << interleaving_parameter;
        let message_size = base_code.message_size() * segment_count;
        let base_block_length = base_code.block_length();
        let block_length_segment = repetition_parameter * base_block_length;
        let block_length = block_length_segment * segment_count;

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
            block_length_segment,
            base_block_length,
            repetition_parameter,
            interleaving_parameter,
            segment_count,
            base_code,
            p1_vector,
            p2_vector,
            m1_vector,
            m2_vector,
            first_accumulate: vec![F::ZERO; block_length],
            second_accumulate: vec![F::ZERO; block_length],
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
        self.p1_vector.len() == self.block_length_segment
            && self
                .p1_vector
                .iter()
                .all(|&x| (x as usize) < self.base_block_length)
            && self.p2_vector.len() == self.block_length_segment
            && self.m1_vector.len() == self.block_length_segment
            && self.m2_vector.len() == self.block_length_segment
            && Self::check_permutation_u32(&self.p2_vector)
            && self.first_accumulate.len() == self.block_length_segment
            && self.second_accumulate.len() == self.block_length_segment
            && self.base_code.message_size() * self.segment_count == self.message_size
            && self.repetition_parameter * self.base_code.block_length()
                == self.block_length_segment
    }

    pub fn encode_naive(&self, msg: &[C::Alphabet]) -> Vec<C::Alphabet> {
        let mut buffers = EncodeNaiveBuffers::default();
        self.encode_naive_with_buffer(msg, &mut buffers)
    }

    pub fn encode_naive_with_buffer(
        &self,
        msg: &[C::Alphabet],
        buffers: &mut EncodeNaiveBuffers<C::Alphabet>,
    ) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let profiling = std::env::var("AGNOSTIR_PROFILE_ENCODE_NAIVE").is_ok();
        let mut t_encode_segments = 0.0f64;
        let mut t_first_perm_mul = 0.0f64;
        let mut t_first_prefix = 0.0f64;
        let mut t_second_perm_mul = 0.0f64;
        let mut t_second_prefix = 0.0f64;

        let segment_len = self.base_code.message_size();

        if buffers.base_columns.len() != self.base_block_length {
            buffers
                .base_columns
                .resize_with(self.base_block_length, || vec![F::ZERO; self.segment_count]);
        }
        for col in buffers.base_columns.iter_mut() {
            if col.len() != self.segment_count {
                col.resize(self.segment_count, F::ZERO);
            }
        }

        if buffers.first_accumulate.len() != self.block_length_segment {
            buffers
                .first_accumulate
                .resize_with(self.block_length_segment, || {
                    vec![F::ZERO; self.segment_count]
                });
        }
        for row in buffers.first_accumulate.iter_mut() {
            if row.len() != self.segment_count {
                row.resize(self.segment_count, F::ZERO);
            }
        }

        if buffers.second_accumulate.len() != self.block_length_segment {
            buffers
                .second_accumulate
                .resize_with(self.block_length_segment, || {
                    vec![F::ZERO; self.segment_count]
                });
        }
        for row in buffers.second_accumulate.iter_mut() {
            if row.len() != self.segment_count {
                row.resize(self.segment_count, F::ZERO);
            }
        }

        // Encode each segment using the base code
        let timer = if profiling { Some(Instant::now()) } else { None };
        for segment in 0..self.segment_count {
            let start = segment * segment_len;
            let end = start + segment_len;
            let enc = self.base_code.encode(&msg[start..end]);
            for i in 0..self.base_block_length {
                buffers.base_columns[i][segment] = enc[i];
            }
        }
        if let Some(start) = timer {
            t_encode_segments = start.elapsed().as_secs_f64();
        }

        // Apply first permutation (p1_vector)
        let timer = if profiling { Some(Instant::now()) } else { None };
        for i in 0..self.block_length_segment {
            let base_idx = self.p1_vector[i] as usize;
            buffers.first_accumulate[i].copy_from_slice(&buffers.base_columns[base_idx]);
        }
        if let Some(start) = timer {
            t_first_perm_mul = start.elapsed().as_secs_f64();
        }

        // Apply first accumulation
        let timer = if profiling { Some(Instant::now()) } else { None };
        let mut acc = vec![F::ZERO; self.segment_count];
        for i in 0..self.block_length_segment {
            for segment in 0..self.segment_count {
                acc[segment] += self.m1_vector[i] * buffers.first_accumulate[i][segment];
            }
            buffers.first_accumulate[i].copy_from_slice(&acc);
        }
        if let Some(start) = timer {
            t_first_prefix = start.elapsed().as_secs_f64();
        }

        // Apply second permutation (p2_vector)
        let timer = if profiling { Some(Instant::now()) } else { None };
        for i in 0..self.block_length_segment {
            let src_i = self.p2_vector[i] as usize;
            buffers
                .second_accumulate[i]
                .copy_from_slice(&buffers.first_accumulate[src_i]);
        }
        if let Some(start) = timer {
            t_second_perm_mul = start.elapsed().as_secs_f64();
        }

        // Apply second accumulation
        let timer = if profiling { Some(Instant::now()) } else { None };
        let mut acc = vec![F::ZERO; self.segment_count];
        for i in 0..self.block_length_segment {
            for segment in 0..self.segment_count {
                acc[segment] += self.m2_vector[i] * buffers.second_accumulate[i][segment];
            }
            buffers.second_accumulate[i].copy_from_slice(&acc);
        }
        if let Some(start) = timer {
            t_second_prefix = start.elapsed().as_secs_f64();
        }

        let mut out = Vec::with_capacity(self.block_length_segment * self.segment_count);
        for i in 0..self.block_length_segment {
            out.extend_from_slice(&buffers.second_accumulate[i]);
        }

        if profiling {
            eprintln!(
                "encode_naive timings (s): encode_segments={t_encode_segments:.6}, first_perm_mul={t_first_perm_mul:.6}, first_prefix={t_first_prefix:.6}, second_perm_mul={t_second_perm_mul:.6}, second_prefix={t_second_prefix:.6}"
            );
        }
        out
    }

    pub fn encode_blocked(&mut self, msg: &[C::Alphabet]) -> &[C::Alphabet] {
        debug_assert!(self.validate_parameters());
        debug_assert_eq!(self.block_length % PERMUTE_CHUNK_SIZE, 0);
        debug_assert_eq!(PERMUTE_CHUNK_SIZE % F::Packing::WIDTH, 0);
        debug_assert_eq!(self.first_accumulate.len(), self.block_length);
        debug_assert_eq!(self.second_accumulate.len(), self.block_length);

        let base_encoding = self.base_code.encode(msg);
        debug_assert_eq!(base_encoding.len(), self.base_block_length);

        let p1_vector = &self.p1_vector;
        let p2_vector = &self.p2_vector;
        let m1_vector = &self.m1_vector;
        let m2_vector = &self.m2_vector;

        let first_accumulate = &mut self.first_accumulate;
        let second_accumulate = &mut self.second_accumulate;

        //let first_permute_and_mult = Instant::now();
        first_accumulate
            .par_chunks_mut(PERMUTE_CHUNK_SIZE)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * PERMUTE_CHUNK_SIZE;
                let packed_out = F::Packing::pack_slice_mut(chunk);
                let width = F::Packing::WIDTH;

                for (pack_idx, out_pack) in packed_out.iter_mut().enumerate() {
                    let base = start + pack_idx * width;
                    let packed_in = F::Packing::from_fn(|lane| {
                        let i = base + lane;
                        let src_idx = p1_vector[i] as usize;
                        base_encoding[src_idx]
                    });
                    *out_pack = packed_in;
                }
            });

        //dbg!(first_permute_and_mult.elapsed());
        //let first_acc = Instant::now();

        Self::prefix_sum_in_place(
            first_accumulate,
            m1_vector,
            Self::chunk_len(self.block_length),
        );
        //dbg!(first_acc.elapsed());

        //let second_permute_and_mult = Instant::now();
        second_accumulate
            .par_chunks_mut(PERMUTE_CHUNK_SIZE)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * PERMUTE_CHUNK_SIZE;
                let packed_out = F::Packing::pack_slice_mut(chunk);
                let width = F::Packing::WIDTH;

                for (pack_idx, out_pack) in packed_out.iter_mut().enumerate() {
                    let base = start + pack_idx * width;
                    let packed_in = F::Packing::from_fn(|lane| {
                        let i = base + lane;
                        let src_idx = p2_vector[i] as usize;
                        first_accumulate[src_idx]
                    });
                    *out_pack = packed_in;
                }
            });
        //dbg!(second_permute_and_mult.elapsed());
        //let second_acc = Instant::now();
        Self::prefix_sum_in_place(
            second_accumulate,
            m2_vector,
            Self::chunk_len(self.block_length),
        );
        //dbg!(second_acc.elapsed());

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

    fn prefix_sum_in_place(values: &mut [F], weights: &[F], chunk_len: usize) {
        if values.is_empty() {
            return;
        }
        debug_assert_eq!(values.len(), weights.len());

        // Compute local prefix sums in parallel and collect each chunk's total.
        let mut totals: Vec<F> = values
            .par_chunks_mut(chunk_len)
            .zip(weights.par_chunks(chunk_len))
            .map(|(chunk, weights)| {
                let mut acc = F::ZERO;
                for (value, weight) in chunk.iter_mut().zip(weights.iter()) {
                    acc += *value * *weight;
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

    fn permute_radix_sort(
        &self,
        input: &[F],
        keys: &[u32],
        entries: &mut Vec<RadixEntry<F>>,
        out: &mut Vec<F>,
    ) {
        entries.clear();
        if entries.capacity() < keys.len() {
            entries.reserve(keys.len() - entries.capacity());
        }
        if out.len() != keys.len() {
            out.resize(keys.len(), F::ZERO);
        }
        for i in 0..keys.len() {
            let key = keys[i];
            let value = input[i / self.repetition_parameter];
            entries.push(RadixEntry { key, value });
        }

        entries.voracious_mt_sort(current_num_threads());

        out.iter_mut().zip(entries.iter()).for_each(|(out, entry)| {
            *out = entry.value;
        });
    }

    /// Encode using sort-based permutation of (key, value) pairs.
    pub fn encode_radix_sort_perm_with_buffer<'a>(
        &self,
        msg: &[C::Alphabet],
        buffers: &'a mut RadixSortBuffers<F>,
    ) -> &'a [C::Alphabet] {
        debug_assert!(self.validate_parameters());

        let base_encoding = self.base_code.encode(msg);
        debug_assert_eq!(base_encoding.len(), self.base_block_length);

        let chunk_len = Self::chunk_len(self.block_length);

        let RadixSortBuffers {
            entries,
            first_accumulate,
            second_accumulate,
        } = buffers;

        self.permute_radix_sort(
            &base_encoding,
            &self.p1_vector,
            entries,
            first_accumulate,
        );
        Self::prefix_sum_in_place(first_accumulate, &self.m1_vector, chunk_len);

        self.permute_radix_sort(
            first_accumulate.as_slice(),
            &self.p2_vector,
            entries,
            second_accumulate,
        );
        Self::prefix_sum_in_place(second_accumulate, &self.m2_vector, chunk_len);

        second_accumulate
    }

    /// Encode using sort-based permutation of (key, value) pairs.
    pub fn encode_radix_sort_perm(&self, msg: &[C::Alphabet]) -> Vec<C::Alphabet> {
        let mut buffers = RadixSortBuffers::default();
        self.encode_radix_sort_perm_with_buffer(msg, &mut buffers)
            .to_vec()
    }

    fn permute_sort(&self, input: &[F], keys: &[u32]) -> Vec<F> {

        #[derive(Clone, Copy)]
        struct Entry<F> {
            key: u32,
            value: F,
        }

        let mut entries: Vec<Entry<F>> = Vec::with_capacity(keys.len());
        for i in 0..keys.len() {
            let key = keys[i];
            let value = input[i / self.repetition_parameter];
            entries.push(Entry { key, value });
        }

        entries.par_sort_unstable_by_key(|entry| entry.key);

        entries.into_iter().map(|entry| entry.value).collect()
    }

    /// Encode using parallel unstable sort for permutation of (key, value) pairs.
    pub fn encode_sort_perm(&self, msg: &[C::Alphabet]) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let base_encoding = self.base_code.encode(msg);
        debug_assert_eq!(base_encoding.len(), self.base_block_length);

        let chunk_len = Self::chunk_len(self.block_length);

        let mut first_accumulate = self.permute_sort(&base_encoding, &self.p1_vector);
        Self::prefix_sum_in_place(&mut first_accumulate, &self.m1_vector, chunk_len);

        let mut second_accumulate = self.permute_sort(&first_accumulate, &self.p2_vector);
        Self::prefix_sum_in_place(&mut second_accumulate, &self.m2_vector, chunk_len);

        second_accumulate
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
                let p1_slice = &self.p1_vector[start..start + len];

                let (out_packed, out_suffix) = F::Packing::pack_slice_with_suffix_mut(chunk);
                let base_ptr = base_encoding.as_ptr();
                let p1_ptr = p1_slice.as_ptr();

                for (pack_idx, out) in out_packed.iter_mut().enumerate() {
                    let base = F::Packing::from_fn(|lane| unsafe {
                        let idx = *p1_ptr.add(pack_idx * pack_width + lane) as usize;
                        *base_ptr.add(idx)
                    });
                    *out = base;
                }

                let suffix_start = out_packed.len() * pack_width;
                for (offset, out) in out_suffix.iter_mut().enumerate() {
                    let idx = suffix_start + offset;
                    let base_idx = unsafe { *p1_ptr.add(idx) as usize };
                    let base_val = unsafe { *base_ptr.add(base_idx) };
                    *out = base_val;
                }
            });

        Self::prefix_sum_in_place(&mut first_accumulate, &self.m1_vector, chunk_len);

        let mut second_accumulate: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        second_accumulate
            .par_chunks_mut(chunk_len)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * chunk_len;
                let len = chunk.len();
                let p2_slice = &self.p2_vector[start..start + len];

                let (out_packed, out_suffix) = F::Packing::pack_slice_with_suffix_mut(chunk);
                let src_ptr = first_accumulate.as_ptr();
                let p2_ptr = p2_slice.as_ptr();

                for (pack_idx, out) in out_packed.iter_mut().enumerate() {
                    let src = F::Packing::from_fn(|lane| unsafe {
                        let idx = *p2_ptr.add(pack_idx * pack_width + lane) as usize;
                        *src_ptr.add(idx)
                    });
                    *out = src;
                }

                let suffix_start = out_packed.len() * pack_width;
                for (offset, out) in out_suffix.iter_mut().enumerate() {
                    let idx = suffix_start + offset;
                    let src_idx = unsafe { *p2_ptr.add(idx) as usize };
                    let src_val = unsafe { *src_ptr.add(src_idx) };
                    *out = src_val;
                }
            });

        Self::prefix_sum_in_place(&mut second_accumulate, &self.m2_vector, chunk_len);

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
