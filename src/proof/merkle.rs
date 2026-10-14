//! Deterministic Merkle multiproofs: repeated queries and shared siblings occur once.
use super::{Channel, ProofResult, Scalar, ensure};
use crate::commit::merkle::{
    blake3_merkle_interleaved_leaves, hash_column_values, hash_merkle_node, merkle_levels_owned,
};

#[derive(Debug)]
pub struct Commitment {
    pub rows: Vec<Vec<Scalar>>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl Commitment {
    pub fn new(rows: Vec<Vec<Scalar>>) -> Self {
        assert!(!rows.is_empty() && !rows[0].is_empty());
        let levels = merkle_levels_owned(blake3_merkle_interleaved_leaves(&rows));
        Self { rows, levels }
    }

    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.levels.last().unwrap()[0]
    }
}

/// Return columns in sorted, deduplicated query order, checking the entire
/// authentication frontier. The schedule and all dimensions are public.
pub fn open(
    channel: &mut Channel<'_>,
    commitment: Option<&Commitment>,
    root: [u8; 32],
    row_count: usize,
    block_len: usize,
    queries: &[usize],
) -> ProofResult<Vec<(usize, Vec<Scalar>)>> {
    ensure(row_count > 0 && block_len > 0 && !queries.is_empty())?;
    let leaves = block_len
        .checked_next_power_of_two()
        .ok_or(super::ProofError::Invalid)?
        .max(2);
    let mut indices = queries.to_vec();
    indices.sort_unstable();
    indices.dedup();
    ensure(indices.last().is_some_and(|&index| index < block_len))?;
    let mut columns = Vec::with_capacity(indices.len());
    let mut frontier = Vec::with_capacity(indices.len());
    for &index in &indices {
        let values = commitment.map(|tree| tree.rows.iter().map(|r| r[index]).collect::<Vec<_>>());
        let values = channel.fields(values.as_deref(), row_count)?;
        frontier.push((
            index,
            commitment.map_or_else(|| hash_column_values(&values), |tree| tree.levels[0][index]),
        ));
        columns.push((index, values));
    }
    for level in 0..leaves.ilog2() as usize {
        let mut parents = Vec::with_capacity(frontier.len());
        let mut position = 0;
        while position < frontier.len() {
            let (index, hash) = frontier[position];
            let sibling =
                if index % 2 == 0 && frontier.get(position + 1).is_some_and(|p| p.0 == index + 1) {
                    position += 1;
                    frontier[position].1
                } else {
                    channel.bytes(commitment.map(|tree| tree.levels[level][index ^ 1]))?
                };
            let parent = if let Some(tree) = commitment {
                tree.levels[level + 1][index / 2]
            } else if index % 2 == 0 {
                hash_merkle_node(&hash, &sibling)
            } else {
                hash_merkle_node(&sibling, &hash)
            };
            parents.push((index / 2, parent));
            position += 1;
        }
        frontier = parents;
    }
    ensure(frontier.len() == 1 && frontier[0] == (0, root))?;
    Ok(columns)
}
