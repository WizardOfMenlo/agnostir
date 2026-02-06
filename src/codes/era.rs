use std::time::Instant;

use crate::{ErrorCorrectingCode, FieldElement};

/// Pre-allocated scratch buffers for [`EraCode::encode`].
///
/// Create once with [`EraBuffers::new`] and reuse across repeated encode calls
/// to avoid re-allocating each time.
#[derive(Debug, Clone)]
pub struct EraBuffers<F> {
    pub w0: Vec<F>,
    pub m1: Vec<F>,
    pub w1: Vec<F>,
    pub m2: Vec<F>,
    pub w2: Vec<F>,
}

impl<F: FieldElement> EraBuffers<F> {
    /// Allocate buffers sized for the given `block_length`.
    #[must_use]
    pub fn new(block_length: usize) -> Self {
        Self {
            w0: vec![F::ZERO; block_length],
            m1: vec![F::ZERO; block_length],
            w1: vec![F::ZERO; block_length],
            m2: vec![F::ZERO; block_length],
            w2: vec![F::ZERO; block_length],
        }
    }

    /// Reset all buffers to zero (cheaper than re-allocating).
    pub fn clear(&mut self) {
        for v in [&mut self.w0, &mut self.m1, &mut self.w1, &mut self.m2, &mut self.w2] {
            v.fill(F::ZERO);
        }
    }
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
    C: ErrorCorrectingCode<Alphabet = F>,
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

    pub fn encode(&self, msg: &[C::Alphabet], buf: &mut EraBuffers<F>) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        buf.clear();

        let base_encoding = self.base_code.encode(msg);

        for i in 0..self.block_length {
            buf.w0[i] = base_encoding[i % self.base_code.block_length()];
        }

        for i in 0..self.block_length {
            buf.m1[i] = buf.w0[self.p1_vector[i]];
        }

        for i in 0..self.block_length {
            buf.m1[i] = buf.m1[i] * self.m1_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += buf.m1[i];
            buf.w1[i] = acc;
        }

        for i in 0..self.block_length {
            buf.m2[i] = buf.w1[self.p2_vector[i]];
        }

        for i in 0..self.block_length {
            buf.m2[i] = buf.m2[i] * self.m2_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += buf.m2[i];
            buf.w2[i] = acc;
        }

        buf.w2.clone()
    }

    /// Same as [`Self::encode`] but prints a table with per-step timings.
    pub fn encode_profiled(&self, msg: &[C::Alphabet], buf: &mut EraBuffers<F>) -> Vec<C::Alphabet> {
        buf.clear();

        let t0 = Instant::now();
        let base_encoding = self.base_code.encode(msg);
        let t_base = t0.elapsed();

        let t0 = Instant::now();
        for i in 0..self.block_length {
            buf.w0[i] = base_encoding[i % self.base_code.block_length()];
        }
        let t_repeat = t0.elapsed();

        // Round 1: permutation (random read), then element-wise multiply
        let t0 = Instant::now();
        for i in 0..self.block_length {
            buf.m1[i] = buf.w0[self.p1_vector[i]];
        }
        let t_perm1 = t0.elapsed();

        let t0 = Instant::now();
        for i in 0..self.block_length {
            buf.m1[i] = buf.m1[i] * self.m1_vector[i];
        }
        let t_mul1 = t0.elapsed();

        let t0 = Instant::now();
        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += buf.m1[i];
            buf.w1[i] = acc;
        }
        let t_prefix1 = t0.elapsed();

        // Round 2: permutation (random read), then element-wise multiply
        let t0 = Instant::now();
        for i in 0..self.block_length {
            buf.m2[i] = buf.w1[self.p2_vector[i]];
        }
        let t_perm2 = t0.elapsed();

        let t0 = Instant::now();
        for i in 0..self.block_length {
            buf.m2[i] = buf.m2[i] * self.m2_vector[i];
        }
        let t_mul2 = t0.elapsed();

        let t0 = Instant::now();
        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += buf.m2[i];
            buf.w2[i] = acc;
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
            ("3a. Perm       (round 1)", t_perm1),
            ("3b. Mul        (round 1)", t_mul1),
            ("4.  Prefix sum (round 1)", t_prefix1),
            ("5a. Perm       (round 2)", t_perm2),
            ("5b. Mul        (round 2)", t_mul2),
            ("6.  Prefix sum (round 2)", t_prefix2),
        ] {
            let pct = dur.as_secs_f64() / total.as_secs_f64() * 100.0;
            eprintln!("│ {label:<24} │ {:>8.3} ms │ {:>5.1} % │", dur.as_secs_f64() * 1e3, pct);
        }
        eprintln!("├──────────────────────────┼────────────┼─────────┤");
        eprintln!("│ Total                    │ {:>8.3} ms │ 100.0 % │", total.as_secs_f64() * 1e3);
        eprintln!("└──────────────────────────┴────────────┴─────────┘");

        buf.w2.clone()
    }
}

impl<C, F> ErrorCorrectingCode for EraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F>,
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
        let mut buf = EraBuffers::new(self.block_length);
        self.encode(msg, &mut buf)
    }
}
