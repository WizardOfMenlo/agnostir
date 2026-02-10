use ark_ff::PrimeField;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Compute a Merkle root sequentially (used for small subtrees).
fn merkle_root_sequential(leaves: &[[u8; 32]]) -> [u8; 32] {
    let n = leaves.len();
    debug_assert!(n.is_power_of_two() && n >= 2);

    let mut level: Vec<[u8; 32]> = leaves
        .chunks_exact(2)
        .map(|pair| {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            *blake3::hash(&buf).as_bytes()
        })
        .collect();

    while level.len() > 1 {
        level = level
            .chunks_exact(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                *blake3::hash(&buf).as_bytes()
            })
            .collect();
    }

    level[0]
}

/// Build a Blake3 Merkle tree over `leaves` (each a 32-byte hash) and return
/// the root hash.  When the `parallel` feature is enabled, uses divide-and-
/// conquer via `rayon::join` so each thread computes its subtree independently
/// with no level-by-level synchronisation barriers.  Subtrees ≤ SEQ_CUTOFF
/// leaves are handled sequentially to avoid task-spawning overhead.
pub fn blake3_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    const SEQ_CUTOFF: usize = 1024;

    let n = leaves.len();
    assert!(n.is_power_of_two() && n >= 2);

    if n <= SEQ_CUTOFF {
        return merkle_root_sequential(leaves);
    }

    let mid = n / 2;

    #[cfg(feature = "parallel")]
    let (left, right) = rayon::join(
        || blake3_merkle_root(&leaves[..mid]),
        || blake3_merkle_root(&leaves[mid..]),
    );
    #[cfg(not(feature = "parallel"))]
    let (left, right) = (
        blake3_merkle_root(&leaves[..mid]),
        blake3_merkle_root(&leaves[mid..]),
    );

    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&left);
    buf[32..].copy_from_slice(&right);
    *blake3::hash(&buf).as_bytes()
}

/// Hash a field element's canonical limbs directly into a `blake3::Hasher`,
/// avoiding the `Vec<u8>` allocation of `to_bytes_le()`.
#[inline]
fn hash_field_element<F: PrimeField>(hasher: &mut blake3::Hasher, elem: &F) {
    let bigint = elem.into_bigint();
    let limbs: &[u64] = bigint.as_ref();
    for &limb in limbs {
        hasher.update(&limb.to_le_bytes());
    }
}

#[inline]
fn hash_merkle_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(left);
    buf[32..].copy_from_slice(right);
    *blake3::hash(&buf).as_bytes()
}

#[inline]
fn hash_interleaved_column<F: PrimeField>(segments: &[Vec<F>], col: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for seg in segments {
        hash_field_element(&mut hasher, &seg[col]);
    }
    *hasher.finalize().as_bytes()
}

#[inline]
fn hash_column_values<F: PrimeField>(column_values: &[F]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for value in column_values {
        hash_field_element(&mut hasher, value);
    }
    *hasher.finalize().as_bytes()
}

pub fn blake3_merkle_interleaved_leaves<F: PrimeField>(segments: &[Vec<F>]) -> Vec<[u8; 32]> {
    assert!(!segments.is_empty());
    let block_len = segments[0].len();
    assert!(segments.iter().all(|s| s.len() == block_len));

    // Hash each column (one element per segment) into a 32-byte leaf.
    #[cfg(feature = "parallel")]
    let mut leaves: Vec<[u8; 32]> = (0..block_len)
        .into_par_iter()
        .map(|col| hash_interleaved_column(segments, col))
        .collect();
    #[cfg(not(feature = "parallel"))]
    let mut leaves: Vec<[u8; 32]> = (0..block_len)
        .map(|col| hash_interleaved_column(segments, col))
        .collect();

    let n = leaves.len().next_power_of_two().max(2);
    leaves.resize(n, [0u8; 32]);
    leaves
}

pub fn blake3_merkle_precompute_levels(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    assert!(leaves.len().is_power_of_two());
    assert!(leaves.len() >= 2);

    let mut levels = Vec::with_capacity(leaves.len().ilog2() as usize + 1);
    levels.push(leaves.to_vec());
    while levels.last().is_some_and(|level| level.len() > 1) {
        let next = levels
            .last()
            .expect("levels is non-empty")
            .chunks_exact(2)
            .map(|pair| hash_merkle_node(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }

    levels
}

pub fn blake3_merkle_root_from_levels(levels: &[Vec<[u8; 32]>]) -> [u8; 32] {
    assert!(!levels.is_empty());
    let root_level = levels.last().expect("levels is non-empty");
    assert_eq!(root_level.len(), 1);
    root_level[0]
}

/// Hash each field element to a 32-byte Blake3 digest, pad to a power-of-two,
/// then compute the Merkle root.
pub fn blake3_merkle_commit<F: PrimeField>(codeword: &[F]) -> [u8; 32] {
    // Hash each element into a 32-byte leaf
    #[cfg(feature = "parallel")]
    let mut leaves: Vec<[u8; 32]> = codeword
        .par_iter()
        .map(|elem| {
            let mut hasher = blake3::Hasher::new();
            hash_field_element(&mut hasher, elem);
            *hasher.finalize().as_bytes()
        })
        .collect();
    #[cfg(not(feature = "parallel"))]
    let mut leaves: Vec<[u8; 32]> = codeword
        .iter()
        .map(|elem| {
            let mut hasher = blake3::Hasher::new();
            hash_field_element(&mut hasher, elem);
            *hasher.finalize().as_bytes()
        })
        .collect();

    // Pad to the next power of two with zero-hashes
    let n = leaves.len().next_power_of_two().max(2);
    leaves.resize(n, [0u8; 32]);

    blake3_merkle_root(&leaves)
}

/// Commit to an interleaved codeword.
///
/// `segments` is a slice of rows, one per interleaved copy.  All rows must
/// have the same length (the block length of the code).  Each Merkle leaf is
/// formed by hashing the *column* — the concatenation of the `i`-th element
/// from every segment — so there are `block_length` leaves total.
pub fn blake3_merkle_commit_interleaved<F: PrimeField>(segments: &[Vec<F>]) -> [u8; 32] {
    let leaves = blake3_merkle_interleaved_leaves(segments);
    blake3_merkle_root(&leaves)
}

/// For each queried codeword column, return its Merkle authentication path.
///
/// `leaves` must be the padded interleaved leaves (power-of-two length), and
/// `merkle_levels` must be the output of `blake3_merkle_precompute_levels`.
/// Returned paths are in the same order as queries.
pub fn blake3_merkle_open_interleaved(
    leaves: &[[u8; 32]],
    merkle_levels: &[Vec<[u8; 32]>],
    query_indices: &[usize],
) -> Vec<Vec<[u8; 32]>> {
    assert!(!merkle_levels.is_empty());
    assert_eq!(merkle_levels[0].len(), leaves.len());
    assert!(leaves.len().is_power_of_two() && leaves.len() >= 2);
    let path_len = leaves.len().ilog2() as usize;
    assert_eq!(merkle_levels.len(), path_len + 1);

    query_indices
        .iter()
        .map(|&idx| {
            assert!(idx < leaves.len(), "query index out of range");
            let mut cur_idx = idx;
            let mut path = Vec::with_capacity(path_len);
            for level in merkle_levels.iter().take(path_len) {
                let sibling = if cur_idx.is_multiple_of(2) {
                    cur_idx + 1
                } else {
                    cur_idx - 1
                };
                path.push(level[sibling]);
                cur_idx /= 2;
            }
            path
        })
        .collect()
}

/// Verify that an opened interleaved column is consistent with a Merkle root.
pub fn blake3_merkle_verify_interleaved_column<F: PrimeField>(
    column_values: &[F],
    query_index: usize,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    let mut acc = hash_column_values(column_values);
    let mut idx = query_index;

    for sibling in path {
        acc = if idx.is_multiple_of(2) {
            hash_merkle_node(&acc, sibling)
        } else {
            hash_merkle_node(sibling, &acc)
        };
        idx /= 2;
    }

    acc == *root
}

#[cfg(test)]
mod tests {
    use super::{
        blake3_merkle_interleaved_leaves, blake3_merkle_open_interleaved,
        blake3_merkle_precompute_levels, blake3_merkle_root_from_levels,
        blake3_merkle_verify_interleaved_column,
    };
    use ark_secp256k1::Fr as SecpScalar;
    use rand::{SeedableRng, rngs::SmallRng};

    #[test]
    fn interleaved_open_and_verify_roundtrip() {
        let mut rng = SmallRng::seed_from_u64(7);

        let rows = 4;
        let block_len = 5; // Deliberately not a power of two to test padding.
        let segments: Vec<Vec<SecpScalar>> = (0..rows)
            .map(|_| {
                (0..block_len)
                    .map(|_| <SecpScalar as crate::FieldElement>::random(&mut rng))
                    .collect()
            })
            .collect();

        let leaves = blake3_merkle_interleaved_leaves(&segments);
        let levels = blake3_merkle_precompute_levels(&leaves);
        let root = blake3_merkle_root_from_levels(&levels);
        let queries = vec![0, 2, 4];
        let paths = blake3_merkle_open_interleaved(&leaves, &levels, &queries);

        for (path, &query_idx) in paths.iter().zip(queries.iter()) {
            let column: Vec<SecpScalar> = (0..rows).map(|r| segments[r][query_idx]).collect();
            assert!(blake3_merkle_verify_interleaved_column(
                &column, query_idx, path, &root
            ));
        }

        let mut tampered_path = paths[0].clone();
        tampered_path[0][0] ^= 1;
        let column: Vec<SecpScalar> = (0..rows).map(|r| segments[r][queries[0]]).collect();
        assert!(!blake3_merkle_verify_interleaved_column(
            &column,
            queries[0],
            &tampered_path,
            &root
        ));
    }
}
