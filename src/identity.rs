use std::marker::PhantomData;

use crate::ErrorCorrectingCode;

#[derive(Debug)]
pub struct IdentityCode<F> {
    message_size: usize,
    alphabet: PhantomData<F>,
}

impl<F> IdentityCode<F> {
    #[must_use]
    pub const fn new(message_size: usize) -> Self {
        Self {
            message_size,
            alphabet: PhantomData,
        }
    }
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
