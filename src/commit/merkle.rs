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
    assert!(!segments.is_empty());
    let block_len = segments[0].len();
    assert!(segments.iter().all(|s| s.len() == block_len));

    // Hash each column (one element per segment) into a 32-byte leaf
    #[cfg(feature = "parallel")]
    let mut leaves: Vec<[u8; 32]> = (0..block_len)
        .into_par_iter()
        .map(|col| {
            let mut hasher = blake3::Hasher::new();
            for seg in segments {
                hash_field_element(&mut hasher, &seg[col]);
            }
            *hasher.finalize().as_bytes()
        })
        .collect();
    #[cfg(not(feature = "parallel"))]
    let mut leaves: Vec<[u8; 32]> = (0..block_len)
        .map(|col| {
            let mut hasher = blake3::Hasher::new();
            for seg in segments {
                hash_field_element(&mut hasher, &seg[col]);
            }
            *hasher.finalize().as_bytes()
        })
        .collect();

    let n = leaves.len().next_power_of_two().max(2);
    leaves.resize(n, [0u8; 32]);

    blake3_merkle_root(&leaves)
}
