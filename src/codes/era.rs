use crate::{ErrorCorrectingCode, FieldElement};

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

    pub fn encode_naive(&self, msg: &[C::Alphabet]) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let mut w0: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut m1: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut w1: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut m2: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];
        let mut w2: Vec<C::Alphabet> = vec![F::ZERO; self.block_length];

        let base_encoding = self.base_code.encode(msg);

        for i in 0..self.block_length {
            w0[i] = base_encoding[i % self.base_code.block_length()];
        }

        for i in 0..self.block_length {
            m1[i] = w0[self.p1_vector[i]] * self.m1_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += m1[i];
            w1[i] = acc;
        }

        for i in 0..self.block_length {
            m2[i] = w1[self.p2_vector[i]] * self.m2_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += m2[i];
            w2[i] = acc;
        }

        w2
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
        self.encode_naive(msg)
    }
}
