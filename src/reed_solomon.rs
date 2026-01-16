use std::marker::PhantomData;

use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::TwoAdicField;

use crate::ErrorCorrectingCode;

#[derive(Debug)]
pub struct ReedSolomonCode<F, D> {
    message_size: usize,
    block_length: usize,
    dft: D,
    alphabet: PhantomData<F>,
}

impl<F> ReedSolomonCode<F, Radix2DFTSmallBatch<F>>
where
    F: TwoAdicField,
{
    #[must_use]
    pub fn new(message_size: usize, block_length: usize) -> Self {
        Self::new_with_dft(message_size, block_length, Radix2DFTSmallBatch::default())
    }
}

impl<F, D> ReedSolomonCode<F, D>
where
    F: TwoAdicField,
    D: TwoAdicSubgroupDft<F>,
{
    pub fn new_with_dft(message_size: usize, block_length: usize, dft: D) -> Self {
        let code = Self {
            message_size,
            block_length,
            dft,
            alphabet: PhantomData,
        };

        debug_assert!(code.validate_parameters());
        code
    }

    const fn validate_parameters(&self) -> bool {
        if self.message_size > self.block_length {
            return false;
        }
        if !self.block_length.is_power_of_two() {
            return false;
        }

        let log_block_length = self.block_length.trailing_zeros() as usize;
        log_block_length <= F::TWO_ADICITY
    }
}

impl<F, D> ErrorCorrectingCode for ReedSolomonCode<F, D>
where
    F: TwoAdicField,
    D: TwoAdicSubgroupDft<F>,
{
    type Alphabet = F;

    fn message_size(&self) -> usize {
        self.message_size
    }

    fn block_length(&self) -> usize {
        self.block_length
    }

    fn encode(&self, msg: &[Self::Alphabet]) -> Vec<Self::Alphabet> {
        debug_assert!(self.validate_parameters());
        debug_assert_eq!(msg.len(), self.message_size);

        let mut coeffs = vec![F::ZERO; self.block_length];
        coeffs[..self.message_size].copy_from_slice(msg);

        self.dft.dft(coeffs)
    }
}
