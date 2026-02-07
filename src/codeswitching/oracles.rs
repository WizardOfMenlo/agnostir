use crate::{ErrorCorrectingCode, FieldElement};

/// A split message and the corresponding encoded chunks under the output code.
#[derive(Debug, Clone)]
pub struct SplitEncoding<F> {
    pub chunks: Vec<Vec<F>>,
    pub codewords: Vec<Vec<F>>,
}

impl<F> SplitEncoding<F> {
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    pub fn assert_shape(&self, chunk_len: usize, codeword_len: usize) {
        assert_eq!(
            self.chunks.len(),
            self.codewords.len(),
            "split encoding has mismatched chunk/codeword counts"
        );
        for chunk in &self.chunks {
            assert_eq!(
                chunk.len(),
                chunk_len,
                "split chunk length does not match output code message size"
            );
        }
        for codeword in &self.codewords {
            assert_eq!(
                codeword.len(),
                codeword_len,
                "split codeword length does not match output code block length"
            );
        }
    }
}

/// Split a vector into chunks of `output_code.message_size()` and encode each chunk.
///
/// Panics on shape mismatches.
pub fn split_and_encode<F, COut>(msg: &[F], output_code: &COut) -> SplitEncoding<F>
where
    F: FieldElement,
    COut: ErrorCorrectingCode<Alphabet = F>,
{
    let chunk_len = output_code.message_size();
    let codeword_len = output_code.block_length();

    assert!(chunk_len > 0, "output code message_size must be > 0");
    assert_eq!(
        msg.len() % chunk_len,
        0,
        "message length must be divisible by output code message_size"
    );

    let chunk_count = msg.len() / chunk_len;
    let mut chunks = Vec::with_capacity(chunk_count);
    let mut codewords = Vec::with_capacity(chunk_count);

    for i in 0..chunk_count {
        let start = i * chunk_len;
        let end = start + chunk_len;

        let chunk = msg[start..end].to_vec();
        let codeword = output_code.encode(&chunk);
        assert_eq!(
            codeword.len(),
            codeword_len,
            "output code returned wrong block length while encoding chunk"
        );

        chunks.push(chunk);
        codewords.push(codeword);
    }

    SplitEncoding { chunks, codewords }
}

/// Inputs for generating index oracles used by the codeswitch steps.
#[derive(Debug, Clone)]
pub struct CodeswitchOraclesInput<F> {
    /// ERA block length (`n_ERA`).
    pub n_era: usize,
    /// Flattened base-generator vector (`g`) used in base-code checks.
    pub generator_vector: Vec<F>,
    /// First permutation vector over `[0, n_era)`.
    pub permutation_1: Vec<usize>,
    /// Second permutation vector over `[0, n_era)`.
    pub permutation_2: Vec<usize>,
    /// First multiply vector (`v_1`) of length `n_era`.
    pub multiplier_1: Vec<F>,
    /// Second multiply vector (`v_2`) of length `n_era`.
    pub multiplier_2: Vec<F>,
}

impl<F> CodeswitchOraclesInput<F> {
    pub fn validate(&self) {
        assert!(self.n_era > 0, "n_era must be > 0");
        assert_is_permutation(&self.permutation_1, self.n_era, "permutation_1");
        assert_is_permutation(&self.permutation_2, self.n_era, "permutation_2");
        assert_eq!(
            self.multiplier_1.len(),
            self.n_era,
            "multiplier_1 length must equal n_era"
        );
        assert_eq!(
            self.multiplier_2.len(),
            self.n_era,
            "multiplier_2 length must equal n_era"
        );
    }
}

/// All split-encoded oracle families produced by `CodeswitchOracles`.
#[derive(Debug, Clone)]
pub struct CodeswitchOraclesOutput<F> {
    pub generator: SplitEncoding<F>,
    pub identity: SplitEncoding<F>,
    pub permutation_1: SplitEncoding<F>,
    pub permutation_2: SplitEncoding<F>,
    pub multiplier_1: SplitEncoding<F>,
    pub multiplier_2: SplitEncoding<F>,
}

impl<F: Clone> CodeswitchOraclesOutput<F> {
    /// Flatten index oracle codewords in a stable order.
    ///
    /// Order: `g`, `id`, `pi_1`, `pi_2`, `v_1`, `v_2`.
    pub fn flattened_index_oracles(&self) -> Vec<Vec<F>> {
        let mut out = Vec::new();
        out.extend(self.generator.codewords.iter().cloned());
        out.extend(self.identity.codewords.iter().cloned());
        out.extend(self.permutation_1.codewords.iter().cloned());
        out.extend(self.permutation_2.codewords.iter().cloned());
        out.extend(self.multiplier_1.codewords.iter().cloned());
        out.extend(self.multiplier_2.codewords.iter().cloned());
        out
    }
}

/// Build the split-encoded index oracles required by codeswitching.
///
/// This is an interface-first scaffolding function: it validates dimensions,
/// materializes the canonical vectors (`id`, `pi_1`, `pi_2`, `v_1`, `v_2`, `g`),
/// and split-encodes each under the output code.
///
/// Panics on any mismatch.
pub fn build_codeswitch_oracles<F, COut>(
    input: &CodeswitchOraclesInput<F>,
    output_code: &COut,
) -> CodeswitchOraclesOutput<F>
where
    F: FieldElement,
    COut: ErrorCorrectingCode<Alphabet = F>,
{
    input.validate();

    let k_prime = output_code.message_size();
    let n_prime = output_code.block_length();

    assert!(k_prime > 0, "output code message_size must be > 0");
    assert_eq!(
        input.n_era % k_prime,
        0,
        "n_era must be divisible by k_prime"
    );
    assert_eq!(
        input.generator_vector.len() % k_prime,
        0,
        "generator_vector length must be divisible by k_prime"
    );

    let n_era_u32 = input.n_era as u32;

    let identity_vector: Vec<F> = (0..n_era_u32).map(F::from_u32).collect();

    let permutation_1_vector: Vec<F> = input
        .permutation_1
        .iter()
        .copied()
        .map(|value| F::from_u32(value as u32))
        .collect();
    let permutation_2_vector: Vec<F> = input
        .permutation_2
        .iter()
        .copied()
        .map(|value| F::from_u32(value as u32))
        .collect();

    let generator = split_and_encode(&input.generator_vector, output_code);
    let identity = split_and_encode(&identity_vector, output_code);
    let permutation_1 = split_and_encode(&permutation_1_vector, output_code);
    let permutation_2 = split_and_encode(&permutation_2_vector, output_code);
    let multiplier_1 = split_and_encode(&input.multiplier_1, output_code);
    let multiplier_2 = split_and_encode(&input.multiplier_2, output_code);

    let l_era = input.n_era / k_prime;

    identity.assert_shape(k_prime, n_prime);
    permutation_1.assert_shape(k_prime, n_prime);
    permutation_2.assert_shape(k_prime, n_prime);
    multiplier_1.assert_shape(k_prime, n_prime);
    multiplier_2.assert_shape(k_prime, n_prime);

    assert_eq!(
        identity.chunk_count(),
        l_era,
        "identity split count does not match l_era"
    );
    assert_eq!(
        permutation_1.chunk_count(),
        l_era,
        "permutation_1 split count does not match l_era"
    );
    assert_eq!(
        permutation_2.chunk_count(),
        l_era,
        "permutation_2 split count does not match l_era"
    );
    assert_eq!(
        multiplier_1.chunk_count(),
        l_era,
        "multiplier_1 split count does not match l_era"
    );
    assert_eq!(
        multiplier_2.chunk_count(),
        l_era,
        "multiplier_2 split count does not match l_era"
    );

    CodeswitchOraclesOutput {
        generator,
        identity,
        permutation_1,
        permutation_2,
        multiplier_1,
        multiplier_2,
    }
}

fn assert_is_permutation(perm: &[usize], n: usize, label: &str) {
    assert_eq!(perm.len(), n, "{label} length must be exactly n_era");
    let mut seen = vec![false; n];
    for &value in perm {
        assert!(value < n, "{label} contains out-of-range value {value}");
        assert!(!seen[value], "{label} contains duplicate value {value}");
        seen[value] = true;
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::IdentityCode;

    fn f(x: u32) -> KoalaBear {
        <KoalaBear as FieldElement>::from_u32(x)
    }

    #[test]
    fn test_split_and_encode_with_identity_code() {
        let output_code = IdentityCode::<KoalaBear>::new(4);
        let msg: Vec<KoalaBear> = (0..8).map(f).collect();

        let split = split_and_encode(&msg, &output_code);

        assert_eq!(split.chunk_count(), 2);
        assert_eq!(split.chunks, split.codewords);
    }

    #[test]
    fn test_build_codeswitch_oracles_shapes() {
        let output_code = IdentityCode::<KoalaBear>::new(4);

        let input = CodeswitchOraclesInput {
            n_era: 8,
            generator_vector: (0..12).map(f).collect(),
            permutation_1: vec![3, 2, 1, 0, 7, 6, 5, 4],
            permutation_2: vec![0, 2, 4, 6, 1, 3, 5, 7],
            multiplier_1: (100..108).map(f).collect(),
            multiplier_2: (200..208).map(f).collect(),
        };

        let out = build_codeswitch_oracles(&input, &output_code);

        assert_eq!(out.identity.chunk_count(), 2);
        assert_eq!(out.permutation_1.chunk_count(), 2);
        assert_eq!(out.permutation_2.chunk_count(), 2);
        assert_eq!(out.multiplier_1.chunk_count(), 2);
        assert_eq!(out.multiplier_2.chunk_count(), 2);
        assert_eq!(out.generator.chunk_count(), 3);

        let flattened = out.flattened_index_oracles();
        assert_eq!(flattened.len(), 13);
    }

    #[test]
    #[should_panic]
    fn test_build_codeswitch_oracles_panics_on_bad_permutation() {
        let output_code = IdentityCode::<KoalaBear>::new(4);

        let input = CodeswitchOraclesInput {
            n_era: 8,
            generator_vector: (0..12).map(f).collect(),
            permutation_1: vec![0, 0, 1, 2, 3, 4, 5, 6], // duplicate 0
            permutation_2: vec![0, 1, 2, 3, 4, 5, 6, 7],
            multiplier_1: (100..108).map(f).collect(),
            multiplier_2: (200..208).map(f).collect(),
        };

        let _ = build_codeswitch_oracles(&input, &output_code);
    }
}
