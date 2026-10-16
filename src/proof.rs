//! Canonical proof transport and a domain-separated BLAKE3 Fiat–Shamir channel.
//!
//! Field elements are canonical, 32-byte little-endian secp256k1 scalars.
//! Lengths come from the public protocol parameters, never from untrusted bytes.
use ark_ff::{BigInt, PrimeField};
pub use ark_secp256k1::Fr as Scalar;
pub mod fractional;
pub mod merkle;
pub mod profile;
pub mod sumcheck;
pub(crate) mod weights;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    #[error("invalid proof or public parameters")]
    Invalid,
}

pub type ProofResult<T> = Result<T, ProofError>;

pub fn ensure(condition: bool) -> ProofResult<()> {
    if condition {
        Ok(())
    } else {
        Err(ProofError::Invalid)
    }
}

#[must_use]
pub fn scalar_bytes(value: Scalar) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, limb) in bytes.chunks_exact_mut(8).zip(value.into_bigint().0) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

fn decode_scalar(bytes: [u8; 32]) -> Option<Scalar> {
    let limbs =
        std::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * (i + 1)].try_into().unwrap()));
    Scalar::from_bigint(BigInt(limbs))
}

/// The verifier has only public inputs and a borrowed byte string. All prover
/// messages are absorbed before subsequent challenges are drawn.
#[derive(Debug)]
pub struct Channel<'a> {
    state: blake3::Hasher,
    input: Option<&'a [u8]>,
    output: Vec<u8>,
    cursor: usize,
    profile: Option<profile::Profile>,
}

impl<'a> Channel<'a> {
    pub fn new(domain: &[u8], input: Option<&'a [u8]>) -> Self {
        // Wire-format compatibility: keep this domain fixed for reference proofs.
        let mut channel = Self {
            state: blake3::Hasher::new_derive_key("agnostir Fiat-Shamir v1"),
            input,
            output: Vec::new(),
            cursor: 0,
            profile: None,
        };
        channel.bind(b"protocol", domain);
        channel
    }

    pub fn enable_profile(&mut self) {
        assert!(self.profile.is_none());
        self.profile = Some(profile::Profile::default());
    }

    fn position(&self) -> usize {
        if self.input.is_some() {
            self.cursor
        } else {
            self.output.len()
        }
    }

    pub fn profile_start(&mut self, name: &str) -> Option<usize> {
        let position = self.position();
        self.profile.as_mut().map(|p| p.start(name, position))
    }

    pub fn profile_end(&mut self, token: Option<usize>) {
        let position = self.position();
        if let Some(token) = token {
            self.profile.as_mut().unwrap().end(token, position);
        }
    }

    pub fn finish_profiled(self) -> ProofResult<(Vec<u8>, profile::Profile)> {
        ensure(self.input.is_none_or(|input| self.cursor == input.len()))?;
        let position = self.position();
        let profile = self.profile.unwrap_or_default();
        profile.assert_complete(position);
        Ok((self.output, profile))
    }

    pub fn bind(&mut self, label: &[u8], bytes: &[u8]) {
        self.state.update(&(label.len() as u64).to_le_bytes());
        self.state.update(label);
        self.state.update(&(bytes.len() as u64).to_le_bytes());
        self.state.update(bytes);
    }

    pub fn bind_usize(&mut self, label: &[u8], value: usize) {
        self.bind(label, &(value as u64).to_le_bytes());
    }

    pub fn bind_fields(&mut self, label: &[u8], values: &[Scalar]) {
        self.bind_usize(label, values.len());
        for &value in values {
            self.bind(b"field", &scalar_bytes(value));
        }
    }

    pub fn bytes<const N: usize>(&mut self, value: Option<[u8; N]>) -> ProofResult<[u8; N]> {
        let bytes = if let Some(input) = self.input {
            let end = self.cursor.checked_add(N).ok_or(ProofError::Invalid)?;
            let result = input.get(self.cursor..end).ok_or(ProofError::Invalid)?;
            self.cursor = end;
            result.try_into().map_err(|_| ProofError::Invalid)?
        } else {
            let result = value.ok_or(ProofError::Invalid)?;
            self.output.extend_from_slice(&result);
            result
        };
        self.bind(b"message", &bytes);
        Ok(bytes)
    }

    pub fn field(&mut self, value: Option<Scalar>) -> ProofResult<Scalar> {
        decode_scalar(self.bytes(value.map(scalar_bytes))?).ok_or(ProofError::Invalid)
    }

    pub fn fields(&mut self, values: Option<&[Scalar]>, len: usize) -> ProofResult<Vec<Scalar>> {
        if let Some(input) = self.input {
            ensure(len <= input.len().saturating_sub(self.cursor) / 32)?;
        } else {
            ensure(values.is_some_and(|v| v.len() == len))?;
        }
        (0..len).map(|i| self.field(values.map(|v| v[i]))).collect()
    }

    fn draw(&mut self, label: &[u8]) -> [u8; 32] {
        self.bind(b"challenge", label);
        let bytes = *self.state.finalize().as_bytes();
        self.bind(b"challenge-output", &bytes);
        bytes
    }

    pub fn challenge(&mut self, label: &[u8]) -> Scalar {
        loop {
            if let Some(value) = decode_scalar(self.draw(label)) {
                return value;
            }
        }
    }

    pub fn point(&mut self, label: &[u8], log_len: usize) -> Vec<Scalar> {
        self.bind_usize(label, log_len);
        (0..log_len)
            .map(|_| self.challenge(b"coordinate"))
            .collect()
    }

    /// Uniform sampling with replacement, using rejection instead of modulo bias.
    pub fn queries(&mut self, bound: usize, count: usize) -> ProofResult<Vec<usize>> {
        ensure(bound > 0 && count > 0)?;
        self.bind_usize(b"query-bound", bound);
        self.bind_usize(b"query-count", count);
        let bound = bound as u64;
        let threshold = bound.wrapping_neg() % bound;
        let mut result = Vec::with_capacity(count);
        while result.len() < count {
            let bytes = self.draw(b"query");
            let x = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            if x >= threshold {
                result.push((x % bound) as usize);
            }
        }
        Ok(result)
    }

    pub fn finish(self) -> ProofResult<Vec<u8>> {
        ensure(self.input.is_none_or(|input| self.cursor == input.len()))?;
        Ok(self.output)
    }
}
