use std::{sync::OnceLock, time::Instant};

use rand_08::SeedableRng as _;
#[cfg(feature = "parallel")]
use rayon::{current_num_threads, prelude::*};
use rip_shuffle::RipShuffleSequential;

use crate::{ErrorCorrectingCode, FieldElement};

/// How many iterations ahead to issue prefetch hints during random gathers.
///
/// Guideline: `prefetch_distance ≈ memory_latency / cycles_per_iteration`.
///   • Apple M-series DRAM latency ≈ 100–120 ns ≈ 320–384 cycles @ 3.2 GHz.
///   • Each gather iteration ≈ 10–20 cycles (index lookup + 32-byte copy).
///   • → distance ≈ 320/15 ≈ 20; 16 is a good conservative choice.
/// Too low → prefetch hasn't arrived yet. Too high → data evicted before use
/// and extra instruction pressure. In practice 8–32 all work; 16 is the sweet
/// spot on most OoO cores.
const PREFETCH_AHEAD: usize = 16;

/// Issue a non-blocking read prefetch hint into the L1 cache.
///
/// This is purely advisory; the CPU may ignore it. Falls back to a no-op on
/// unsupported architectures.
#[inline(always)]
fn prefetch_read<T>(ptr: *const T) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // PRFM PLDL1KEEP — prefetch for load, L1, keep
        std::arch::asm!("prfm pldl1keep, [{0}]", in(reg) ptr, options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        std::arch::x86_64::_mm_prefetch(ptr as *const i8, std::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = ptr;
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

#[derive(Debug)]
pub struct EraCode<C, F> {
    message_size: usize,
    block_length: usize,
    repetition_parameter: usize,
    base_code: C,

    p1_vector: Vec<usize>,
    p2_vector: Vec<usize>,

    m1_vector: Vec<F>,
    m2_vector: Vec<F>,
}

impl<C, F> EraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F> + Sync,
    F: FieldElement,
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
        let block_length = repetition_parameter * base_code.block_length();

        let code = Self {
            message_size,
            block_length,
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

    fn validate_parameters(&self) -> bool {
        Self::check_permutation(&self.p1_vector)
            && Self::check_permutation(&self.p2_vector)
            && self.base_code.message_size() == self.message_size
            && self.repetition_parameter * self.base_code.block_length() == self.block_length()
    }

    fn add_const_in_place(slice: &mut [F], offset: F) {
        #[cfg(feature = "parallel")]
        slice.par_iter_mut().for_each(|value| *value += offset);
        #[cfg(not(feature = "parallel"))]
        for value in slice.iter_mut() {
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
        #[cfg(feature = "parallel")]
        let threads = current_num_threads().max(1);
        #[cfg(not(feature = "parallel"))]
        let threads = 1usize;
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

        // Add the offsets back into each chunk.
        values
            .par_chunks_mut(chunk_len)
            .zip(totals.into_par_iter())
            .for_each(|(chunk, offset)| {
                if !offset.is_zero() {
                    Self::add_const_in_place(chunk, offset);
                }
            });
    }

    pub fn encode_era(&self, msg: &[C::Alphabet]) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let n = self.block_length;
        let base_encoding = self.base_code.encode(msg);
        let base_bl = self.base_code.block_length();
        let chunk_len = Self::chunk_len(self.block_length);

        // Round 1: fused repetition + permutation gather, then prefix sum
        // SAFETY: every element is written by the gather before being read.
        let mut w1 = Vec::with_capacity(n);
        unsafe { w1.set_len(n) };
        w1.par_chunks_mut(chunk_len)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * chunk_len;
                let len = chunk.len();
                for i in 0..len {
                    if i + PREFETCH_AHEAD < len {
                        let idx = self.p1_vector[start + i + PREFETCH_AHEAD] % base_bl;
                        prefetch_read(base_encoding.as_ptr().wrapping_add(idx));
                    }
                    chunk[i] = base_encoding[self.p1_vector[start + i] % base_bl];
                }
            });
        Self::prefix_sum_in_place(&mut w1, &self.m1_vector, chunk_len);

        // SAFETY: every element is written by the gather before being read.
        let mut w2 = Vec::with_capacity(n);
        unsafe { w2.set_len(n) };
        w2.par_chunks_mut(chunk_len)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * chunk_len;
                let len = chunk.len();
                for i in 0..len {
                    if i + PREFETCH_AHEAD < len {
                        let idx = self.p2_vector[start + i + PREFETCH_AHEAD];
                        prefetch_read(w1.as_ptr().wrapping_add(idx));
                    }
                    chunk[i] = w1[self.p2_vector[start + i]];
                }
            });
        drop(w1); // free round-1 buffer early
        Self::prefix_sum_in_place(&mut w2, &self.m2_vector, chunk_len);

        w2
    }

    /// Like [`Self::encode`] but uses `rip_shuffle`'s in-place shuffle for the
    /// permutation steps instead of a pre-stored gather permutation.
    ///
    /// A fresh `SmallRng` (rand 0.8) is seeded from `seed` for the two shuffles.
    pub fn encode_rip(&self, msg: &[C::Alphabet], seed: u64) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let n = self.block_length;
        let base_encoding = self.base_code.encode(msg);

        let mut w0 = vec![F::ZERO; n];
        for i in 0..n {
            w0[i] = base_encoding[i % self.base_code.block_length()];
        }

        // Round 1: in-place shuffle, then mul, then prefix sum
        let mut m1 = w0;
        let mut rng = rand_08::rngs::SmallRng::seed_from_u64(seed);
        m1.seq_shuffle(&mut rng);

        for i in 0..n {
            m1[i] = m1[i] * self.m1_vector[i];
        }

        let mut w1 = vec![F::ZERO; n];
        let mut acc = F::ZERO;
        for i in 0..n {
            acc += m1[i];
            w1[i] = acc;
        }

        // Round 2: in-place shuffle, then mul, then prefix sum
        let mut m2 = w1;
        m2.seq_shuffle(&mut rng);

        for i in 0..n {
            m2[i] = m2[i] * self.m2_vector[i];
        }

        let mut w2 = vec![F::ZERO; n];
        let mut acc = F::ZERO;
        for i in 0..n {
            acc += m2[i];
            w2[i] = acc;
        }

        w2
    }

    /// Same as [`Self::encode_rip`] but prints per-step timings.
    pub fn encode_rip_profiled(&self, msg: &[C::Alphabet], seed: u64) -> Vec<C::Alphabet> {
        let n = self.block_length;

        let t0 = Instant::now();
        let base_encoding = self.base_code.encode(msg);
        let t_base = t0.elapsed();

        let t0 = Instant::now();
        let mut w0 = vec![F::ZERO; n];
        for i in 0..n {
            w0[i] = base_encoding[i % self.base_code.block_length()];
        }
        let t_repeat = t0.elapsed();

        let mut rng = rand_08::rngs::SmallRng::seed_from_u64(seed);

        // Round 1
        let t0 = Instant::now();
        let mut m1 = w0;
        m1.seq_shuffle(&mut rng);
        let t_perm1 = t0.elapsed();

        let t0 = Instant::now();
        for i in 0..n {
            m1[i] = m1[i] * self.m1_vector[i];
        }
        let t_mul1 = t0.elapsed();

        let t0 = Instant::now();
        let mut w1 = vec![F::ZERO; n];
        let mut acc = F::ZERO;
        for i in 0..n {
            acc += m1[i];
            w1[i] = acc;
        }
        let t_prefix1 = t0.elapsed();

        // Round 2
        let t0 = Instant::now();
        let mut m2 = w1;
        m2.seq_shuffle(&mut rng);
        let t_perm2 = t0.elapsed();

        let t0 = Instant::now();
        for i in 0..n {
            m2[i] = m2[i] * self.m2_vector[i];
        }
        let t_mul2 = t0.elapsed();

        let t0 = Instant::now();
        let mut w2 = vec![F::ZERO; n];
        let mut acc = F::ZERO;
        for i in 0..n {
            acc += m2[i];
            w2[i] = acc;
        }
        let t_prefix2 = t0.elapsed();

        let total = t_base + t_repeat + t_perm1 + t_mul1 + t_prefix1 + t_perm2 + t_mul2 + t_prefix2;

        eprintln!();
        eprintln!("┌──────────────────────────┬────────────┬─────────┐");
        eprintln!("│ Step                     │       Time │   % Tot │");
        eprintln!("├──────────────────────────┼────────────┼─────────┤");
        for (label, dur) in [
            ("1. Base-code encode", t_base),
            ("2. Repetition", t_repeat),
            ("3a. RipShuffle (round 1)", t_perm1),
            ("3b. Mul        (round 1)", t_mul1),
            ("3c. Prefix sum (round 1)", t_prefix1),
            ("4a. RipShuffle (round 2)", t_perm2),
            ("4b. Mul        (round 2)", t_mul2),
            ("4c. Prefix sum (round 2)", t_prefix2),
        ] {
            let pct = dur.as_secs_f64() / total.as_secs_f64() * 100.0;
            eprintln!(
                "│ {label:<24} │ {:>8.3} ms │ {:>5.1} % │",
                dur.as_secs_f64() * 1e3,
                pct
            );
        }
        eprintln!("├──────────────────────────┼────────────┼─────────┤");
        eprintln!(
            "│ Total                    │ {:>8.3} ms │ 100.0 % │",
            total.as_secs_f64() * 1e3
        );
        eprintln!("└──────────────────────────┴────────────┴─────────┘");

        w2
    }

    /// Same as [`Self::encode_era`] but prints a table with per-step timings.
    pub fn encode_profiled(&self, msg: &[C::Alphabet]) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let n = self.block_length;
        let chunk_len = Self::chunk_len(self.block_length);

        let t0 = Instant::now();
        let base_encoding = self.base_code.encode(msg);
        let t_base = t0.elapsed();
        let base_bl = self.base_code.block_length();

        // Round 1: fused repetition + permutation gather, then prefix sum
        let t0 = Instant::now();
        // SAFETY: every element is written by the gather before being read.
        let mut w1 = Vec::with_capacity(n);
        unsafe { w1.set_len(n) };
        w1.par_chunks_mut(chunk_len)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * chunk_len;
                let len = chunk.len();
                for i in 0..len {
                    if i + PREFETCH_AHEAD < len {
                        let idx = self.p1_vector[start + i + PREFETCH_AHEAD] % base_bl;
                        prefetch_read(base_encoding.as_ptr().wrapping_add(idx));
                    }
                    chunk[i] = base_encoding[self.p1_vector[start + i] % base_bl];
                }
            });
        let t_perm1 = t0.elapsed();

        let t0 = Instant::now();
        Self::prefix_sum_in_place(&mut w1, &self.m1_vector, chunk_len);
        let t_prefix1 = t0.elapsed();

        // Round 2: permutation, then fused mul + prefix sum
        let t0 = Instant::now();
        // SAFETY: every element is written by the gather before being read.
        let mut w2 = Vec::with_capacity(n);
        unsafe { w2.set_len(n) };
        w2.par_chunks_mut(chunk_len)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let start = chunk_idx * chunk_len;
                let len = chunk.len();
                for i in 0..len {
                    if i + PREFETCH_AHEAD < len {
                        let idx = self.p2_vector[start + i + PREFETCH_AHEAD];
                        prefetch_read(w1.as_ptr().wrapping_add(idx));
                    }
                    chunk[i] = w1[self.p2_vector[start + i]];
                }
            });
        drop(w1);
        let t_perm2 = t0.elapsed();

        let t0 = Instant::now();
        Self::prefix_sum_in_place(&mut w2, &self.m2_vector, chunk_len);
        let t_prefix2 = t0.elapsed();

        let total = t_base + t_perm1 + t_prefix1 + t_perm2 + t_prefix2;

        eprintln!();
        eprintln!("┌──────────────────────────┬────────────┬─────────┐");
        eprintln!("│ Step                     │       Time │   % Tot │");
        eprintln!("├──────────────────────────┼────────────┼─────────┤");
        for (label, dur) in [
            ("1. Base-code encode", t_base),
            ("2a. Rep+Perm   (round 1)", t_perm1),
            ("2b. Prefix sum (round 1)", t_prefix1),
            ("3a. Perm       (round 2)", t_perm2),
            ("3b. Prefix sum (round 2)", t_prefix2),
        ] {
            let pct = dur.as_secs_f64() / total.as_secs_f64() * 100.0;
            eprintln!(
                "│ {label:<24} │ {:>8.3} ms │ {:>5.1} % │",
                dur.as_secs_f64() * 1e3,
                pct
            );
        }
        eprintln!("├──────────────────────────┼────────────┼─────────┤");
        eprintln!(
            "│ Total                    │ {:>8.3} ms │ 100.0 % │",
            total.as_secs_f64() * 1e3
        );
        eprintln!("└──────────────────────────┴────────────┴─────────┘");

        w2
    }

    /// Encode `2^eta` messages of length `k` simultaneously.
    ///
    /// The input `msgs` has length `2^eta * k` — the `r`-th message occupies
    /// `msgs[r*k .. (r+1)*k]`.
    ///
    /// Base-code encoding, repetition, element-wise multiply, and prefix-sum
    /// are applied independently per row.  The permutation steps permute whole
    /// *columns* (groups of `2^eta` elements at the same position) in one pass,
    /// which is more cache-friendly than doing `2^eta` independent random gathers.
    ///
    /// The output has length `2^eta * block_length`, laid out in row-major order
    /// (row 0 first, then row 1, …).
    pub fn encode_interleaved(&self, msgs: &[F], eta: usize) -> Vec<F> {
        let rows = 1usize << eta;
        let k = self.message_size;
        let n = self.block_length;
        let base_n = self.base_code.block_length();
        debug_assert_eq!(msgs.len(), rows * k);

        // Column-major scratch: index (row, col) -> col * rows + row
        let total = rows * n;
        let mut w0 = vec![F::ZERO; total];
        let mut buf = vec![F::ZERO; total]; // reused for m1/w1/m2/w2 stages
        let mut tmp = vec![F::ZERO; total]; // second scratch for permute target

        // 1. Base-code encode + repetition (per row)
        for r in 0..rows {
            let msg = &msgs[r * k..(r + 1) * k];
            let base_enc = self.base_code.encode(msg);
            for i in 0..n {
                w0[i * rows + r] = base_enc[i % base_n];
            }
        }

        // 2. Permute columns by p1 (column-major: move entire column of `rows` elements)
        for i in 0..n {
            let src = self.p1_vector[i];
            let dst_off = i * rows;
            let src_off = src * rows;
            buf[dst_off..dst_off + rows].copy_from_slice(&w0[src_off..src_off + rows]);
        }

        // 3. Element-wise multiply by m1 (per row, sequential in column-major)
        for i in 0..n {
            let m1_i = self.m1_vector[i];
            let off = i * rows;
            for r in 0..rows {
                buf[off + r] = buf[off + r] * m1_i;
            }
        }

        // 4. Prefix sum (per row independently, column-major traversal)
        //    Keep one accumulator per row; iterate columns in the outer loop
        //    so that memory access is sequential in the column-major layout.
        let mut accs = vec![F::ZERO; rows];
        for i in 0..n {
            let off = i * rows;
            for r in 0..rows {
                accs[r] += buf[off + r];
                tmp[off + r] = accs[r];
            }
        }

        // 5. Permute columns by p2
        for i in 0..n {
            let src = self.p2_vector[i];
            let dst_off = i * rows;
            let src_off = src * rows;
            buf[dst_off..dst_off + rows].copy_from_slice(&tmp[src_off..src_off + rows]);
        }

        // 6. Element-wise multiply by m2
        for i in 0..n {
            let m2_i = self.m2_vector[i];
            let off = i * rows;
            for r in 0..rows {
                buf[off + r] = buf[off + r] * m2_i;
            }
        }

        // 7. Prefix sum (per row, column-major traversal)
        let mut accs = vec![F::ZERO; rows];
        for i in 0..n {
            let off = i * rows;
            for r in 0..rows {
                accs[r] += buf[off + r];
                tmp[off + r] = accs[r];
            }
        }

        // 8. Transpose to row-major output
        let mut out = vec![F::ZERO; total];
        for i in 0..n {
            let off = i * rows;
            for r in 0..rows {
                out[r * n + i] = tmp[off + r];
            }
        }

        out
    }

    /// Same as [`Self::encode_interleaved`] but prints per-step timings.
    pub fn encode_interleaved_profiled(&self, msgs: &[F], eta: usize) -> Vec<F> {
        let rows = 1usize << eta;
        let k = self.message_size;
        let n = self.block_length;
        let base_n = self.base_code.block_length();
        debug_assert_eq!(msgs.len(), rows * k);

        let total_elems = rows * n;
        let mut w0 = vec![F::ZERO; total_elems];
        let mut buf = vec![F::ZERO; total_elems];
        let mut tmp = vec![F::ZERO; total_elems];

        // 1. Base-code encode + repetition
        let t0 = Instant::now();
        for r in 0..rows {
            let msg = &msgs[r * k..(r + 1) * k];
            let base_enc = self.base_code.encode(msg);
            for i in 0..n {
                w0[i * rows + r] = base_enc[i % base_n];
            }
        }
        let t_base_repeat = t0.elapsed();

        // 2. Permute columns by p1
        let t0 = Instant::now();
        for i in 0..n {
            let src = self.p1_vector[i];
            let dst_off = i * rows;
            let src_off = src * rows;
            buf[dst_off..dst_off + rows].copy_from_slice(&w0[src_off..src_off + rows]);
        }
        let t_perm1 = t0.elapsed();

        // 3. Element-wise multiply by m1
        let t0 = Instant::now();
        for i in 0..n {
            let m1_i = self.m1_vector[i];
            let off = i * rows;
            for r in 0..rows {
                buf[off + r] = buf[off + r] * m1_i;
            }
        }
        let t_mul1 = t0.elapsed();

        // 4. Prefix sum round 1 (column-major traversal)
        let t0 = Instant::now();
        let mut accs = vec![F::ZERO; rows];
        for i in 0..n {
            let off = i * rows;
            for r in 0..rows {
                accs[r] += buf[off + r];
                tmp[off + r] = accs[r];
            }
        }
        let t_prefix1 = t0.elapsed();

        // 5. Permute columns by p2
        let t0 = Instant::now();
        for i in 0..n {
            let src = self.p2_vector[i];
            let dst_off = i * rows;
            let src_off = src * rows;
            buf[dst_off..dst_off + rows].copy_from_slice(&tmp[src_off..src_off + rows]);
        }
        let t_perm2 = t0.elapsed();

        // 6. Element-wise multiply by m2
        let t0 = Instant::now();
        for i in 0..n {
            let m2_i = self.m2_vector[i];
            let off = i * rows;
            for r in 0..rows {
                buf[off + r] = buf[off + r] * m2_i;
            }
        }
        let t_mul2 = t0.elapsed();

        // 7. Prefix sum round 2 (column-major traversal)
        let t0 = Instant::now();
        let mut accs = vec![F::ZERO; rows];
        for i in 0..n {
            let off = i * rows;
            for r in 0..rows {
                accs[r] += buf[off + r];
                tmp[off + r] = accs[r];
            }
        }
        let t_prefix2 = t0.elapsed();

        // 8. Transpose to row-major
        let t0 = Instant::now();
        let mut out = vec![F::ZERO; total_elems];
        for i in 0..n {
            let off = i * rows;
            for r in 0..rows {
                out[r * n + i] = tmp[off + r];
            }
        }
        let t_transpose = t0.elapsed();

        let total = t_base_repeat
            + t_perm1
            + t_mul1
            + t_prefix1
            + t_perm2
            + t_mul2
            + t_prefix2
            + t_transpose;

        eprintln!();
        eprintln!("┌──────────────────────────────┬────────────┬─────────┐");
        eprintln!("│ Step                         │       Time │   % Tot │");
        eprintln!("├──────────────────────────────┼────────────┼─────────┤");
        for (label, dur) in [
            ("1.  Base encode + repeat", t_base_repeat),
            ("2.  Perm columns  (rnd 1)", t_perm1),
            ("3.  Mul           (rnd 1)", t_mul1),
            ("4.  Prefix sum    (rnd 1)", t_prefix1),
            ("5.  Perm columns  (rnd 2)", t_perm2),
            ("6.  Mul           (rnd 2)", t_mul2),
            ("7.  Prefix sum    (rnd 2)", t_prefix2),
            ("8.  Transpose to row-maj", t_transpose),
        ] {
            let pct = dur.as_secs_f64() / total.as_secs_f64() * 100.0;
            eprintln!(
                "│ {label:<28} │ {:>8.3} ms │ {:>5.1} % │",
                dur.as_secs_f64() * 1e3,
                pct
            );
        }
        eprintln!("├──────────────────────────────┼────────────┼─────────┤");
        eprintln!(
            "│ Total                        │ {:>8.3} ms │ 100.0 % │",
            total.as_secs_f64() * 1e3
        );
        eprintln!("└──────────────────────────────┴────────────┴─────────┘");

        out
    }
}

impl<C, F> ErrorCorrectingCode for EraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F> + Sync,
    F: FieldElement,
{
    type Alphabet = C::Alphabet;

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn block_length(&self) -> usize {
        self.block_length
    }

    fn encode(&self, msg: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
        self.encode_era(msg)
    }
}
