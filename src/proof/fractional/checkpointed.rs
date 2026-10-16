//! Fractional GKR split at committed checkpoints. Each batch advances every
//! unfinished segment by one circuit layer. Short sumchecks use constant
//! extension and explicit normalization, never padded witness allocations.
//!
//! The caller MUST commit `Witness::pack(layout)` before this reduction and
//! authenticate EVERY returned checkpoint evaluation against that commitment.
//! Leaf denominators and the public numerator mask must also be authenticated.
use super::{FractionLayer, prefix_weight, tree};
use crate::{
    FieldElement,
    proof::{Channel, ProofResult, Scalar, ensure, sumcheck},
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry {
    pub depth: usize,
    pub tree: usize,
    pub denominator: bool,
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug)]
pub(crate) struct Layout {
    pub cuts: Vec<usize>,
    pub log_len: usize,
    pub entries: Vec<Entry>,
    pub len: usize,
}

impl Layout {
    pub(crate) fn new(log_len: usize, cuts: &[usize]) -> ProofResult<Self> {
        ensure(log_len < usize::BITS as usize && !cuts.is_empty())?;
        ensure(cuts.iter().all(|&d| d > 0 && d < log_len))?;
        ensure(cuts.windows(2).all(|w| w[0] < w[1]))?;
        let mut entries = Vec::new();
        let mut offset = 0usize;
        // Largest arrays first: full-width arrays align with rows, and all
        // small checkpoints share the tail instead of each consuming a row.
        for &depth in cuts.iter().rev() {
            for tree in 0..4 {
                for denominator in [false, true] {
                    let len = 1 << depth;
                    entries.push(Entry {
                        depth,
                        tree,
                        denominator,
                        offset,
                        len,
                    });
                    offset = offset
                        .checked_add(len)
                        .ok_or(crate::proof::ProofError::Invalid)?;
                }
            }
        }
        Ok(Self {
            cuts: cuts.to_vec(),
            log_len,
            entries,
            len: offset,
        })
    }

    fn entry(&self, depth: usize, tree: usize, denominator: bool) -> usize {
        self.entries
            .iter()
            .position(|e| e.depth == depth && e.tree == tree && e.denominator == denominator)
            .unwrap()
    }
}

#[derive(Debug)]
pub(crate) struct Witness {
    trees: Vec<Vec<FractionLayer>>,
}

impl Witness {
    pub(crate) fn new(denominators: Vec<Vec<Scalar>>, real_len: usize) -> ProofResult<Self> {
        let padded = real_len
            .checked_next_power_of_two()
            .ok_or(crate::proof::ProofError::Invalid)?;
        ensure(
            real_len > 1
                && denominators.len() == 4
                && denominators.iter().all(|d| d.len() == padded),
        )?;
        Ok(Self {
            trees: denominators
                .into_iter()
                .map(|d| tree(d, real_len))
                .collect(),
        })
    }

    fn values(&self, e: &Entry) -> &[Scalar] {
        let layer = &self.trees[e.tree][e.depth];
        if e.denominator { &layer.1 } else { &layer.0 }
    }

    pub(crate) fn pack(&self, layout: &Layout) -> Vec<Scalar> {
        let mut values = Vec::with_capacity(layout.len);
        for e in &layout.entries {
            values.extend_from_slice(self.values(e));
        }
        values
    }
}

#[derive(Debug)]
pub(crate) struct Evaluation {
    pub entry: usize,
    pub point: Vec<Scalar>,
    pub value: Scalar,
}

#[derive(Debug)]
pub(crate) struct Output {
    pub point: Vec<Scalar>,
    pub denominators: Vec<Scalar>,
    pub evaluations: Vec<Evaluation>,
}

#[derive(Debug)]
struct Segment {
    depth: usize,
    end: usize,
    point: Vec<Scalar>,
    claims: Vec<Scalar>,
}

pub(crate) fn prove_or_verify(
    channel: &mut Channel<'_>,
    witness: Option<&Witness>,
    layout: &Layout,
    real_len: usize,
) -> ProofResult<Output> {
    ensure(real_len > 1 && real_len.next_power_of_two().ilog2() as usize == layout.log_len)?;
    let span = channel.profile_start("boundary_claims");
    let roots = witness.map(|w| {
        w.trees
            .iter()
            .flat_map(|t| [t[0].0[0], t[0].1[0]])
            .collect::<Vec<_>>()
    });
    let roots = channel.fields(roots.as_deref(), 8)?;
    ensure(roots.iter().skip(1).step_by(2).all(|x| !x.is_zero()))?;
    ensure(
        roots[0] * roots[3] == roots[2] * roots[1] && roots[4] * roots[7] == roots[6] * roots[5],
    )?;
    let mut evaluations = Vec::new();
    let mut segments = vec![Segment {
        depth: 0,
        end: layout.cuts[0],
        point: Vec::new(),
        claims: roots,
    }];
    for (i, &depth) in layout.cuts.iter().enumerate() {
        channel.bind_usize(b"checkpoint-depth", depth);
        let point = channel.point(b"checkpoint-point", depth);
        let values = witness.map(|w| {
            (0..8)
                .map(|k| {
                    sumcheck::evaluate(
                        w.values(&layout.entries[layout.entry(depth, k / 2, k % 2 == 1)]),
                        &point,
                    )
                })
                .collect::<Vec<_>>()
        });
        let values = channel.fields(values.as_deref(), 8)?;
        for (k, &value) in values.iter().enumerate() {
            evaluations.push(Evaluation {
                entry: layout.entry(depth, k / 2, k % 2 == 1),
                point: point.clone(),
                value,
            });
        }
        segments.push(Segment {
            depth,
            end: layout.cuts.get(i + 1).copied().unwrap_or(layout.log_len),
            point,
            claims: values,
        });
    }
    channel.profile_end(span);
    let mut batch = 0;
    while segments.iter().any(|s| s.depth < s.end) {
        let active: Vec<_> = segments
            .iter()
            .enumerate()
            .filter(|(_, s)| s.depth < s.end)
            .map(|(i, _)| i)
            .collect();
        let log = active.iter().map(|&i| segments[i].depth).max().unwrap();
        let batch_span = channel.profile_start(&format!("batch_{batch}_d{log}"));
        let beta = channel.challenge(b"checkpoint-gkr-layer-batch");
        let mut power = Scalar::ONE;
        let mut weights = Vec::new();
        let mut groups = Vec::new();
        let mut claim = Scalar::ZERO;
        for &i in &active {
            let w: Vec<_> = (0..8)
                .map(|_| {
                    let v = power;
                    power *= beta;
                    v
                })
                .collect();
            claim += sumcheck::dot(&segments[i].claims, &w);
            let scale =
                FieldElement::inverse(Scalar::from(1u64 << (log - segments[i].depth))).unwrap();
            groups.push(sumcheck::Group {
                log_len: segments[i].depth,
                terms: (0..4)
                    .flat_map(|t| {
                        [
                            (scale * w[2 * t], vec![4 * t, 4 * t + 3, 16]),
                            (scale * w[2 * t], vec![4 * t + 1, 4 * t + 2, 16]),
                            (scale * w[2 * t + 1], vec![4 * t + 2, 4 * t + 3, 16]),
                        ]
                    })
                    .collect(),
            });
            weights.push((w, scale));
        }
        let span = channel.profile_start("layer_tables");
        let tables = witness.map(|w| {
            active
                .iter()
                .map(|&i| {
                    let s = &segments[i];
                    let mut rows = Vec::with_capacity(17);
                    for t in &w.trees {
                        let (n, d) = &t[s.depth + 1];
                        rows.push(n.iter().step_by(2).copied().collect());
                        rows.push(n.iter().skip(1).step_by(2).copied().collect());
                        rows.push(d.iter().step_by(2).copied().collect());
                        rows.push(d.iter().skip(1).step_by(2).copied().collect());
                    }
                    rows.push(sumcheck::eq_weights(&s.point));
                    rows
                })
                .collect()
        });
        channel.profile_end(span);
        let span = channel.profile_start("sumcheck");
        let (r, final_claim, values) = sumcheck::ragged_sumcheck(channel, tables, &groups, claim)?;
        channel.profile_end(span);
        let span = channel.profile_start("child_claims");
        let mut children = Vec::new();
        let mut expected = Scalar::ZERO;
        for (j, &i) in active.iter().enumerate() {
            let child = channel.fields(values.as_ref().map(|v| &v[j][..16]), 16)?;
            let (w, scale) = &weights[j];
            let rhs: Scalar = (0..4)
                .map(|t| {
                    let v = &child[4 * t..4 * t + 4];
                    w[2 * t] * (v[0] * v[3] + v[1] * v[2]) + w[2 * t + 1] * v[2] * v[3]
                })
                .sum();
            expected += *scale * sumcheck::eq(&segments[i].point, &r[..segments[i].depth]) * rhs;
            children.push(child);
        }
        ensure(expected == final_claim)?;
        // All child evaluations precede the shared child-folding challenge.
        let bit = channel.challenge(b"checkpoint-gkr-child");
        for (&i, child) in active.iter().zip(children) {
            let s = &mut segments[i];
            s.point = r[..s.depth].to_vec();
            s.point.push(bit);
            s.depth += 1;
            s.claims = child
                .chunks_exact(4)
                .flat_map(|v| [v[0] + bit * (v[1] - v[0]), v[2] + bit * (v[3] - v[2])])
                .collect();
            if s.depth == s.end && s.end < layout.log_len {
                for (k, &value) in s.claims.iter().enumerate() {
                    evaluations.push(Evaluation {
                        entry: layout.entry(s.end, k / 2, k % 2 == 1),
                        point: s.point.clone(),
                        value,
                    });
                }
            }
        }
        channel.profile_end(span);
        channel.profile_end(batch_span);
        batch += 1;
    }
    let leaf = segments.pop().unwrap();
    let mask = prefix_weight(&leaf.point, real_len);
    ensure(leaf.claims.iter().step_by(2).all(|&v| v == mask))?;
    Ok(Output {
        point: leaf.point,
        denominators: leaf.claims.into_iter().skip(1).step_by(2).collect(),
        evaluations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_layout_rejects_invalid_cuts_and_packs_without_gaps() {
        for cuts in [vec![], vec![0], vec![8], vec![3, 3], vec![5, 3]] {
            assert!(Layout::new(8, &cuts).is_err());
        }
        let layout = Layout::new(19, &[3, 7, 11, 15]).unwrap();
        assert_eq!(layout.len, 279616);
        assert_eq!(layout.len.div_ceil(32768), 9);
        let mut end = 0;
        for e in layout.entries {
            assert_eq!(e.offset, end);
            end += e.len;
        }
        assert_eq!(end, layout.len);
    }

    #[test]
    fn checkpoint_gkr_authenticates_both_boundaries_and_leaf_claims() {
        for (log, real_len, cuts) in [
            (4, 11, vec![1, 3]),
            (8, 239, vec![1, 3, 5]),
            (8, 256, vec![3, 7]),
            (5, 29, vec![1, 2, 3, 4]),
        ] {
            let a: Vec<_> = (0..1 << log)
                .map(|i| {
                    if i < real_len {
                        Scalar::from((i + 3) as u64)
                    } else {
                        Scalar::ONE
                    }
                })
                .collect();
            let mut b = a.clone();
            b[..real_len].reverse();
            let denominators = vec![a.clone(), b.clone(), a, b];
            let witness = Witness::new(denominators.clone(), real_len).unwrap();
            let layout = Layout::new(log, &cuts).unwrap();
            let packed = witness.pack(&layout);
            let authenticate = |output: &Output, commitment: &[Scalar]| -> ProofResult<()> {
                ensure(output.evaluations.len() == 16 * cuts.len())?;
                let mut counts = vec![0; layout.entries.len()];
                for e in &output.evaluations {
                    let entry = &layout.entries[e.entry];
                    counts[e.entry] += 1;
                    ensure(
                        e.value
                            == sumcheck::evaluate(
                                &commitment[entry.offset..entry.offset + entry.len],
                                &e.point,
                            ),
                    )?;
                }
                ensure(counts.iter().all(|&c| c == 2))?;
                for (row, &value) in denominators.iter().zip(&output.denominators) {
                    ensure(value == sumcheck::evaluate(row, &output.point))?;
                }
                Ok(())
            };
            let mut prover = Channel::new(b"checkpoint-unit-test", None);
            let output = prove_or_verify(&mut prover, Some(&witness), &layout, real_len).unwrap();
            authenticate(&output, &packed).unwrap();
            let proof = prover.finish().unwrap();
            let check = |bytes: &[u8]| -> ProofResult<()> {
                let mut verifier = Channel::new(b"checkpoint-unit-test", Some(bytes));
                let output = prove_or_verify(&mut verifier, None, &layout, real_len)?;
                authenticate(&output, &packed)?;
                verifier.finish()?;
                Ok(())
            };
            check(&proof).unwrap();
            // GKR alone is a reduction. Changing a committed checkpoint must
            // be rejected when its returned boundary evaluations are checked.
            for entry in &layout.entries {
                let mut changed = packed.clone();
                changed[entry.offset] += Scalar::ONE;
                assert!(authenticate(&output, &changed).is_err());
            }
            for offset in (0..proof.len()).step_by(32) {
                let mut bad = proof.clone();
                bad[offset] ^= 1;
                assert!(check(&bad).is_err(), "offset {offset}");
            }
            let mut false_witness = Witness::new(denominators, real_len).unwrap();
            false_witness.trees[0][0].0[0] += Scalar::ONE;
            assert!(
                prove_or_verify(
                    &mut Channel::new(b"checkpoint-unit-test", None),
                    Some(&false_witness),
                    &layout,
                    real_len
                )
                .is_err()
            );
        }
    }
}
