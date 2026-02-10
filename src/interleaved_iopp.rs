use ark_ff::PrimeField;
use rand::Rng;

use crate::{
    FieldElement, blake3_merkle_open_interleaved, blake3_merkle_verify_interleaved_column,
    poly_utils::multilinear::MultilinearPoint,
};

/// Prover's first-round message: folded message and claimed evaluation y = m(z).
#[derive(Debug, Clone)]
pub struct ProverFirstMessage<F> {
    /// Folded message: Σ_r eq(z_1, r) · msg_row[r].  Length = 2^{k-eta}.
    pub folded_msg: Vec<F>,
    /// Claimed evaluation y = m(z).
    pub y: F,
}

/// Verifier's challenge: q uniformly random codeword column indices drawn from
/// [0, block_length).
#[derive(Debug, Clone)]
pub struct VerifierChallenge {
    pub query_indices: Vec<usize>,
}

/// Prover's second-round message: for each queried column, the full column
/// of 2^eta row values, plus its Merkle authentication path.
#[derive(Debug, Clone)]
pub struct ProverSecondMessage<F> {
    /// columns[i] has 2^eta elements – the values from every row at the
    /// queried column index.
    pub columns: Vec<Vec<F>>,
    /// Merkle authentication path for `columns[i]`.
    pub merkle_paths: Vec<Vec<[u8; 32]>>,
}

/// Prover's first round: fold the interleaved message rows and compute y = m(z).
///
/// Given evaluation point `z ∈ F^k`, split as `z = (z_1, z_2)` where
/// `z_1 ∈ F^eta` and `z_2 ∈ F^{k-eta}`.
pub fn prover_first_round<F>(message: &[F], z: &[F], eta: usize, k: usize) -> ProverFirstMessage<F>
where
    F: FieldElement,
{
    assert_eq!(z.len(), k, "evaluation point must have k={k} coordinates");

    let rows = 1usize << eta;
    let seg_msg_size = 1usize << (k - eta);

    let z_1 = &z[..eta];
    let z1_point = MultilinearPoint(z_1.to_vec());
    let eq_weights = z1_point.eq_weights();
    assert_eq!(eq_weights.len(), rows);

    let mut folded_msg = vec![F::ZERO; seg_msg_size];
    for (r, &w) in eq_weights.iter().enumerate() {
        let row_start = r * seg_msg_size;
        for i in 0..seg_msg_size {
            folded_msg[i] += w * message[row_start + i];
        }
    }

    let z_2 = &z[eta..];
    let z2_point = MultilinearPoint(z_2.to_vec());
    let eq2_weights = z2_point.eq_weights();
    assert_eq!(eq2_weights.len(), seg_msg_size);

    let y = folded_msg
        .iter()
        .zip(eq2_weights.iter())
        .fold(F::ZERO, |acc, (&fm, &e)| acc + fm * e);

    ProverFirstMessage { folded_msg, y }
}

/// Verifier picks q random codeword column indices from [0, block_length).
pub fn verifier_challenge(
    block_length: usize,
    num_queries: usize,
    rng: &mut impl Rng,
) -> VerifierChallenge {
    let query_indices = (0..num_queries)
        .map(|_| rng.random_range(0..block_length))
        .collect();
    VerifierChallenge { query_indices }
}

/// Prover's second round: open queried codeword columns (all 2^eta row values)
/// and include their Merkle authentication paths.
pub fn prover_second_round<F>(
    segments: &[Vec<F>],
    merkle_leaves: &[[u8; 32]],
    merkle_levels: &[Vec<[u8; 32]>],
    challenge: &VerifierChallenge,
    eta: usize,
) -> ProverSecondMessage<F>
where
    F: PrimeField,
{
    let rows = 1usize << eta;
    assert_eq!(segments.len(), rows, "unexpected interleaving row count");

    let columns: Vec<Vec<F>> = challenge
        .query_indices
        .iter()
        .map(|&cw_idx| (0..rows).map(|r| segments[r][cw_idx]).collect())
        .collect();

    let merkle_paths =
        blake3_merkle_open_interleaved(merkle_leaves, merkle_levels, &challenge.query_indices);

    ProverSecondMessage {
        columns,
        merkle_paths,
    }
}

/// Verifier checks:
/// 1. Each opened column is consistent with its Merkle path and commitment root.
/// 2. Verifier recomputes folded_cw = Enc(folded_msg), then each opened
///    column folds (with eq(z_1, ·)) to the matching entry in folded_cw.
/// 3. The folded message evaluated at z_2 equals y.
pub fn verify<F, EncodeFn>(
    z: &[F],
    eta: usize,
    k: usize,
    commitment_root: &[u8; 32],
    first_msg: &ProverFirstMessage<F>,
    challenge: &VerifierChallenge,
    second_msg: &ProverSecondMessage<F>,
    encode_fn: EncodeFn,
) -> bool
where
    F: FieldElement + PrimeField,
    EncodeFn: Fn(&[F]) -> Vec<F>,
{
    let rows = 1usize << eta;
    let seg_msg_size = 1usize << (k - eta);
    let folded_cw = encode_fn(&first_msg.folded_msg);

    if second_msg.columns.len() != challenge.query_indices.len()
        || second_msg.merkle_paths.len() != challenge.query_indices.len()
    {
        return false;
    }

    let z_1 = &z[..eta];
    let z1_point = MultilinearPoint(z_1.to_vec());
    let eq_weights = z1_point.eq_weights();

    for ((col, path), &cw_idx) in second_msg
        .columns
        .iter()
        .zip(second_msg.merkle_paths.iter())
        .zip(challenge.query_indices.iter())
    {
        if col.len() != rows {
            return false;
        }

        if !blake3_merkle_verify_interleaved_column(col, cw_idx, path, commitment_root) {
            return false;
        }

        if cw_idx >= folded_cw.len() {
            return false;
        }

        let folded_val = col
            .iter()
            .zip(eq_weights.iter())
            .fold(<F as FieldElement>::ZERO, |acc, (&c, &w)| acc + c * w);

        if folded_val != folded_cw[cw_idx] {
            return false;
        }
    }

    let z_2 = &z[eta..];
    let z2_point = MultilinearPoint(z_2.to_vec());
    let eq2_weights = z2_point.eq_weights();
    assert_eq!(eq2_weights.len(), seg_msg_size);

    let eval = first_msg
        .folded_msg
        .iter()
        .zip(eq2_weights.iter())
        .fold(<F as FieldElement>::ZERO, |acc, (&fm, &e)| acc + fm * e);

    eval == first_msg.y
}
