//! Interactive proximity check for a column-committed interleaving of a linear code.
//!
//! Here `k` and `eta` are logarithms: the message has `2^k` field elements,
//! arranged as `2^eta` contiguous rows of length `2^(k - eta)`. Each row is
//! encoded with the same linear encoder. A Merkle leaf commits to one column
//! containing a value from every encoded row; the tree is padded to a power of
//! two with at least two leaves.
//!
//! For `z = (z_1, z_2)`, the prover first sends the rows folded with the
//! multilinear equality weights `eq(z_1, row)` and the claimed evaluation
//! `y = m(z)`. The verifier then samples codeword columns, and the prover opens
//! those columns. The verifier authenticates each opening, checks that the
//! folded columns equal the encoding of the folded message, and evaluates that
//! message at `z_2` to check `y`.
//!
//! The caller supplies the committed code, evaluation point, and verifier
//! randomness. In particular, query challenges must be sampled independently
//! after the first message; accepting prover-selected challenges would not
//! implement this protocol. These functions do not provide a Fiat–Shamir
//! transcript or choose a query count for a desired soundness level.

use ark_ff::PrimeField;
use rand::Rng;

pub mod fs;

use crate::{
    FieldElement, blake3_merkle_open_interleaved, blake3_merkle_verify_interleaved_column,
    poly_utils::multilinear::MultilinearPoint,
};

const fn dimensions(eta: usize, k: usize) -> Option<(usize, usize, usize)> {
    if eta > k || k >= usize::BITS as usize {
        return None;
    }
    Some((1usize << eta, 1usize << (k - eta), 1usize << k))
}

fn padded_leaf_count(block_length: usize) -> Option<usize> {
    if block_length == 0 {
        return None;
    }
    block_length.checked_next_power_of_two().map(|n| n.max(2))
}

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
///
/// Panics if `eta > k`, `2^k` does not fit in `usize`, `z` has a different
/// length from `k`, or `message` has a different length from `2^k`.
pub fn prover_first_round<F>(message: &[F], z: &[F], eta: usize, k: usize) -> ProverFirstMessage<F>
where
    F: FieldElement,
{
    let (rows, seg_msg_size, message_size) = dimensions(eta, k)
        .expect("require eta <= k and k < usize::BITS for interleaved dimensions");
    assert_eq!(z.len(), k, "evaluation point must have k={k} coordinates");
    assert_eq!(
        message.len(),
        message_size,
        "message must have 2^k={message_size} elements"
    );

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
/// Queries are sampled with replacement, so duplicate indices are valid.
///
/// Panics if `block_length` or `num_queries` is zero.
pub fn verifier_challenge(
    block_length: usize,
    num_queries: usize,
    rng: &mut impl Rng,
) -> VerifierChallenge {
    assert!(block_length > 0, "block_length must be positive");
    assert!(num_queries > 0, "num_queries must be positive");
    let query_indices = (0..num_queries)
        .map(|_| rng.random_range(0..block_length))
        .collect();
    VerifierChallenge { query_indices }
}

/// Prover's second round: open queried codeword columns (all 2^eta row values)
/// and include their Merkle authentication paths.
///
/// Panics on inconsistent row/tree dimensions, an empty challenge, or queries
/// outside the unpadded codeword. The supplied tree must have been built from
/// `segments`; this function validates its shape without recomputing its hashes.
#[must_use]
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
    let (rows, _, _) =
        dimensions(eta, eta).expect("require eta < usize::BITS for interleaved row count");
    assert_eq!(segments.len(), rows, "unexpected interleaving row count");
    let block_length = segments[0].len();
    assert!(
        segments.iter().all(|row| row.len() == block_length),
        "encoded rows must have the same block length"
    );
    let leaf_count = padded_leaf_count(block_length)
        .expect("codeword block length must be positive and have representable Merkle padding");
    assert_eq!(
        merkle_leaves.len(),
        leaf_count,
        "unexpected padded leaf count"
    );
    let path_length = leaf_count.ilog2() as usize;
    assert_eq!(
        merkle_levels.len(),
        path_length + 1,
        "unexpected Merkle level count"
    );
    assert!(
        merkle_levels
            .iter()
            .enumerate()
            .all(|(level, hashes)| hashes.len() == leaf_count >> level),
        "unexpected Merkle level width"
    );
    assert!(
        !challenge.query_indices.is_empty(),
        "query challenge must be non-empty"
    );
    assert!(
        challenge
            .query_indices
            .iter()
            .all(|&index| index < block_length),
        "query index must be within the unpadded codeword"
    );

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
///
/// Returns `false` for malformed dimensions, messages, openings, and empty
/// challenges. `encode_fn` must be the same linear encoder used for the
/// committed rows and accept messages of length `2^(k - eta)`. It is called
/// only after validating that length and the shapes of the supplied openings.
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
    let Some((rows, seg_msg_size, _)) = dimensions(eta, k) else {
        return false;
    };

    if z.len() != k
        || first_msg.folded_msg.len() != seg_msg_size
        || challenge.query_indices.is_empty()
        || second_msg.columns.len() != challenge.query_indices.len()
        || second_msg.merkle_paths.len() != challenge.query_indices.len()
        || second_msg.columns.iter().any(|column| column.len() != rows)
    {
        return false;
    }

    let folded_cw = encode_fn(&first_msg.folded_msg);
    let Some(leaf_count) = padded_leaf_count(folded_cw.len()) else {
        return false;
    };
    let path_length = leaf_count.ilog2() as usize;
    if challenge
        .query_indices
        .iter()
        .any(|&index| index >= folded_cw.len())
        || second_msg
            .merkle_paths
            .iter()
            .any(|path| path.len() != path_length)
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
        if !blake3_merkle_verify_interleaved_column(col, cw_idx, path, commitment_root) {
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

#[cfg(test)]
mod tests {
    use ark_secp256k1::Fr as Scalar;
    use rand::{SeedableRng, rngs::SmallRng};

    use super::*;
    use crate::{
        EraCode, ErrorCorrectingCode, IdentityCode, blake3_merkle_interleaved_leaves,
        blake3_merkle_precompute_levels, blake3_merkle_root_from_levels,
    };

    fn f(value: u32) -> Scalar {
        <Scalar as FieldElement>::from_u32(value)
    }

    // Evaluate by interpolating adjacent Boolean entries, independently of the
    // equality-weight calculation used by the protocol.
    fn evaluate(message: &[Scalar], z: &[Scalar]) -> Scalar {
        let mut values = message.to_vec();
        for &coordinate in z.iter().rev() {
            values = values
                .chunks_exact(2)
                .map(|pair| pair[0] + coordinate * (pair[1] - pair[0]))
                .collect();
        }
        assert_eq!(values.len(), 1);
        values[0]
    }

    struct Fixture {
        k: usize,
        eta: usize,
        message: Vec<Scalar>,
        z: Vec<Scalar>,
        code: EraCode<IdentityCode<Scalar>, Scalar>,
        segments: Vec<Vec<Scalar>>,
        leaves: Vec<[u8; 32]>,
        levels: Vec<Vec<[u8; 32]>>,
        root: [u8; 32],
        first: ProverFirstMessage<Scalar>,
        challenge: VerifierChallenge,
        second: ProverSecondMessage<Scalar>,
    }

    impl Fixture {
        fn new(eta: usize) -> Self {
            let k = 4;
            let segment_size = 1usize << (k - eta);
            let block_length = segment_size * 3;
            let code = EraCode::new(
                IdentityCode::new(segment_size),
                3,
                (0..block_length).rev().collect(),
                (0..block_length).map(|i| (i + 1) % block_length).collect(),
                (0..block_length as u32).map(|i| f(i + 1)).collect(),
                (0..block_length as u32).map(|i| f(i + 5)).collect(),
            );
            let message: Vec<_> = (0..1u32 << k).map(|i| f(i * i + 3 * i + 7)).collect();
            let z = vec![f(2), f(3), f(5), f(7)];
            let segments: Vec<_> = message
                .chunks_exact(segment_size)
                .map(|row| code.encode(row))
                .collect();
            let leaves = blake3_merkle_interleaved_leaves(&segments);
            let levels = blake3_merkle_precompute_levels(&leaves);
            let root = blake3_merkle_root_from_levels(&levels);
            let first = prover_first_round(&message, &z, eta, k);
            let mut query_indices: Vec<_> = (0..block_length).collect();
            query_indices.push(0); // Repeated queries are permitted.
            let challenge = VerifierChallenge { query_indices };
            let second = prover_second_round(&segments, &leaves, &levels, &challenge, eta);

            Self {
                k,
                eta,
                message,
                z,
                code,
                segments,
                leaves,
                levels,
                root,
                first,
                challenge,
                second,
            }
        }

        fn verify_messages(
            &self,
            first: &ProverFirstMessage<Scalar>,
            challenge: &VerifierChallenge,
            second: &ProverSecondMessage<Scalar>,
        ) -> bool {
            verify(
                &self.z,
                self.eta,
                self.k,
                &self.root,
                first,
                challenge,
                second,
                |msg| self.code.encode(msg),
            )
        }

        fn reject_before_encoding(
            &self,
            z: &[Scalar],
            eta: usize,
            k: usize,
            first: &ProverFirstMessage<Scalar>,
            challenge: &VerifierChallenge,
            second: &ProverSecondMessage<Scalar>,
        ) {
            assert!(!verify(
                z,
                eta,
                k,
                &self.root,
                first,
                challenge,
                second,
                |_| panic!("malformed input reached encoder")
            ));
        }
    }

    #[test]
    fn era_roundtrip_with_non_power_of_two_blocks_and_boundary_interleavings() {
        for eta in [0, 2, 4] {
            let fixture = Fixture::new(eta);
            assert!(!fixture.code.block_length().is_power_of_two());
            assert_eq!(fixture.first.y, evaluate(&fixture.message, &fixture.z));
            assert!(fixture.verify_messages(&fixture.first, &fixture.challenge, &fixture.second));
        }
    }

    #[test]
    fn zero_variable_message_roundtrip() {
        let segments = vec![vec![f(7)]];
        let leaves = blake3_merkle_interleaved_leaves(&segments);
        let levels = blake3_merkle_precompute_levels(&leaves);
        let root = blake3_merkle_root_from_levels(&levels);
        let first = prover_first_round(&segments[0], &[], 0, 0);
        let challenge = VerifierChallenge {
            query_indices: vec![0],
        };
        let second = prover_second_round(&segments, &leaves, &levels, &challenge, 0);

        assert!(verify(
            &[],
            0,
            0,
            &root,
            &first,
            &challenge,
            &second,
            <[Scalar]>::to_vec
        ));
    }

    #[test]
    fn rejects_tampered_messages_commitment_and_openings() {
        let fixture = Fixture::new(2);
        let mut first = fixture.first.clone();
        first.y += f(1);
        assert!(!fixture.verify_messages(&first, &fixture.challenge, &fixture.second));

        first = fixture.first.clone();
        first.folded_msg[0] += f(1);
        first.y = evaluate(&first.folded_msg, &fixture.z[fixture.eta..]);
        assert!(!fixture.verify_messages(&first, &fixture.challenge, &fixture.second));

        let mut second = fixture.second.clone();
        second.columns[0][0] += f(1);
        assert!(!fixture.verify_messages(&fixture.first, &fixture.challenge, &second));

        second = fixture.second.clone();
        second.merkle_paths[0][0][0] ^= 1;
        assert!(!fixture.verify_messages(&fixture.first, &fixture.challenge, &second));

        let mut root = fixture.root;
        root[0] ^= 1;
        assert!(!verify(
            &fixture.z,
            fixture.eta,
            fixture.k,
            &root,
            &fixture.first,
            &fixture.challenge,
            &fixture.second,
            |msg| fixture.code.encode(msg)
        ));
    }

    #[test]
    fn rejects_invalid_dimensions_and_points_before_calling_encoder() {
        let fixture = Fixture::new(2);
        for (eta, k) in [(5, 4), (0, usize::BITS as usize), (usize::MAX, usize::MAX)] {
            fixture.reject_before_encoding(
                &fixture.z,
                eta,
                k,
                &fixture.first,
                &fixture.challenge,
                &fixture.second,
            );
        }
        fixture.reject_before_encoding(
            &fixture.z[..3],
            2,
            4,
            &fixture.first,
            &fixture.challenge,
            &fixture.second,
        );
        let mut z = fixture.z.clone();
        z.push(f(11));
        fixture.reject_before_encoding(
            &z,
            2,
            4,
            &fixture.first,
            &fixture.challenge,
            &fixture.second,
        );
    }

    #[test]
    fn rejects_malformed_message_and_opening_shapes_before_calling_encoder() {
        let fixture = Fixture::new(2);
        let mut first = fixture.first.clone();
        first.folded_msg.pop();
        fixture.reject_before_encoding(
            &fixture.z,
            2,
            4,
            &first,
            &fixture.challenge,
            &fixture.second,
        );
        first = fixture.first.clone();
        first.folded_msg.push(f(0));
        fixture.reject_before_encoding(
            &fixture.z,
            2,
            4,
            &first,
            &fixture.challenge,
            &fixture.second,
        );

        let mut second = fixture.second.clone();
        second.columns.pop();
        fixture.reject_before_encoding(
            &fixture.z,
            2,
            4,
            &fixture.first,
            &fixture.challenge,
            &second,
        );
        second = fixture.second.clone();
        second.merkle_paths.pop();
        fixture.reject_before_encoding(
            &fixture.z,
            2,
            4,
            &fixture.first,
            &fixture.challenge,
            &second,
        );
        for oversized in [false, true] {
            second = fixture.second.clone();
            if oversized {
                second.columns[0].push(f(0));
            } else {
                second.columns[0].pop();
            }
            fixture.reject_before_encoding(
                &fixture.z,
                2,
                4,
                &fixture.first,
                &fixture.challenge,
                &second,
            );
        }

        let empty_challenge = VerifierChallenge {
            query_indices: vec![],
        };
        let empty_second = ProverSecondMessage {
            columns: vec![],
            merkle_paths: vec![],
        };
        fixture.reject_before_encoding(
            &fixture.z,
            2,
            4,
            &fixture.first,
            &empty_challenge,
            &empty_second,
        );
    }

    #[test]
    fn rejects_invalid_query_indices_merkle_depths_and_empty_encoding() {
        let fixture = Fixture::new(2);
        for index in [
            fixture.code.block_length(),
            fixture.leaves.len(),
            usize::MAX,
        ] {
            let mut challenge = fixture.challenge.clone();
            challenge.query_indices[0] = index;
            assert!(!fixture.verify_messages(&fixture.first, &challenge, &fixture.second));
        }
        for oversized in [false, true] {
            let mut second = fixture.second.clone();
            if oversized {
                second.merkle_paths[0].push([0; 32]);
            } else {
                second.merkle_paths[0].pop();
            }
            assert!(!fixture.verify_messages(&fixture.first, &fixture.challenge, &second));
        }
        assert!(!verify(
            &fixture.z,
            fixture.eta,
            fixture.k,
            &fixture.root,
            &fixture.first,
            &fixture.challenge,
            &fixture.second,
            |_| vec![]
        ));
    }

    #[test]
    fn prover_rejects_bad_dimensions_and_tree_shapes() {
        for (message, z, eta, k) in [
            (vec![f(1)], vec![f(2)], 2, 1),
            (vec![f(1)], vec![], 0, usize::BITS as usize),
            (vec![f(1); 4], vec![f(2)], 1, 2),
            (vec![f(1); 3], vec![f(2); 2], 1, 2),
            (vec![f(1); 5], vec![f(2); 2], 1, 2),
        ] {
            assert!(std::panic::catch_unwind(|| prover_first_round(&message, &z, eta, k)).is_err());
        }

        let fixture = Fixture::new(2);
        let mut segments = fixture.segments.clone();
        segments[0].pop();
        assert!(
            std::panic::catch_unwind(|| prover_second_round(
                &segments,
                &fixture.leaves,
                &fixture.levels,
                &fixture.challenge,
                fixture.eta
            ))
            .is_err()
        );
        let mut levels = fixture.levels.clone();
        levels[1].pop();
        assert!(
            std::panic::catch_unwind(|| prover_second_round(
                &fixture.segments,
                &fixture.leaves,
                &levels,
                &fixture.challenge,
                fixture.eta
            ))
            .is_err()
        );
        let challenge = VerifierChallenge {
            query_indices: vec![fixture.code.block_length()],
        };
        assert!(
            std::panic::catch_unwind(|| prover_second_round(
                &fixture.segments,
                &fixture.leaves,
                &fixture.levels,
                &challenge,
                fixture.eta
            ))
            .is_err()
        );
    }

    #[test]
    fn challenge_samples_valid_columns_and_requires_nonzero_sizes() {
        let mut rng = SmallRng::seed_from_u64(19);
        let challenge = verifier_challenge(12, 30, &mut rng);
        assert_eq!(challenge.query_indices.len(), 30);
        assert!(challenge.query_indices.iter().all(|&index| index < 12));
        for (block_length, num_queries) in [(0, 1), (12, 0)] {
            assert!(
                std::panic::catch_unwind(|| {
                    let mut rng = SmallRng::seed_from_u64(19);
                    verifier_challenge(block_length, num_queries, &mut rng)
                })
                .is_err()
            );
        }
    }
}
