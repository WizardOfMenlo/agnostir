use std::marker::PhantomData;

use p3_field::Field;

pub trait ErrorCorrectingCode {
    type Alphabet;

    fn message_size(&self) -> usize;
    fn block_length(&self) -> usize;
    fn encode(&self, msg: Vec<Self::Alphabet>) -> Vec<Self::Alphabet>;
}

#[derive(Debug)]
pub struct IdentityCode<F> {
    message_size: usize,

    alphabet: PhantomData<F>,
}

impl<F> ErrorCorrectingCode for IdentityCode<F> {
    type Alphabet = F;

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn block_length(&self) -> usize {
        self.message_size
    }

    fn encode(&self, msg: Vec<Self::Alphabet>) -> Vec<Self::Alphabet> {
        msg
    }
}

#[derive(Debug)]
pub struct EraCode<C, F> {
    message_size: usize,
    block_length: usize,
    repetition_parameters: usize,
    base_code: C,

    p1_vector: Vec<usize>,
    p2_vector: Vec<usize>,

    m1_vector: Vec<F>,
    m2_vector: Vec<F>,
}

impl<C, F> EraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F>,
    F: Field,
{
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
            && self.repetition_parameters * self.base_code.block_length() == self.block_length()
    }

    fn encode_naive(&self, msg: Vec<C::Alphabet>) -> Vec<C::Alphabet> {
        debug_assert!(self.validate_parameters());

        let mut repeat_vector: Vec<C::Alphabet> = Vec::with_capacity(self.block_length);
        let mut first_permute: Vec<C::Alphabet> = Vec::with_capacity(self.block_length);
        let mut first_multiply: Vec<C::Alphabet> = Vec::with_capacity(self.block_length);
        let mut first_accumulate: Vec<C::Alphabet> = Vec::with_capacity(self.block_length);
        let mut second_permute: Vec<C::Alphabet> = Vec::with_capacity(self.block_length);
        let mut second_multiply: Vec<C::Alphabet> = Vec::with_capacity(self.block_length);
        let mut second_accumulate: Vec<C::Alphabet> = Vec::with_capacity(self.block_length);

        let base_encoding = self.base_code.encode(msg);

        for i in 0..self.block_length {
            repeat_vector[i] = base_encoding[i % self.base_code.block_length()];
        }

        for i in 0..self.block_length {
            first_permute[i] = repeat_vector[self.p1_vector[i]];
        }

        for i in 0..self.block_length {
            first_multiply[i] = first_permute[i] * self.m1_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += first_multiply[i];
            first_accumulate[i] = acc;
        }

        for i in 0..self.block_length {
            second_permute[i] = first_accumulate[self.p2_vector[i]];
        }

        for i in 0..self.block_length {
            second_multiply[i] = second_permute[i] * self.m2_vector[i];
        }

        let mut acc = F::ZERO;
        for i in 0..self.block_length {
            acc += second_multiply[i];
            second_accumulate[i] = acc;
        }

        second_accumulate
    }
}

impl<C, F> ErrorCorrectingCode for EraCode<C, F>
where
    C: ErrorCorrectingCode<Alphabet = F>,
    F: Field,
{
    type Alphabet = C::Alphabet;

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn block_length(&self) -> usize {
        self.block_length
    }

    fn encode(&self, msg: Vec<Self::Alphabet>) -> Vec<Self::Alphabet> {
        self.encode_naive(msg)
    }
}
