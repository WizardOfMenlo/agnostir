//! Batched logUp-GKR for two permutation checks. Every layer transmits its
//! child evaluations before the next batching/folding challenge is sampled.
use super::{Channel, ProofResult, Scalar, ensure, sumcheck};
use crate::FieldElement;
use p3_maybe_rayon::prelude::*;

pub(crate) mod checkpointed;

type FractionLayer = (Vec<Scalar>, Vec<Scalar>);

fn tree(denominators: Vec<Scalar>, real_len: usize) -> Vec<FractionLayer> {
    let numerators: Vec<Scalar> = (0..denominators.len())
        .into_par_iter()
        .map(|i| {
            if i < real_len {
                Scalar::ONE
            } else {
                Scalar::ZERO
            }
        })
        .collect();
    let mut layers = vec![(numerators, denominators)];
    while layers.last().unwrap().0.len() > 1 {
        let (n, d) = layers.last().unwrap();
        let pair = n
            .par_chunks_exact(2)
            .zip(d.par_chunks_exact(2))
            .map(|(n, d)| (n[0] * d[1] + n[1] * d[0], d[0] * d[1]))
            .unzip();
        layers.push(pair);
    }
    layers.reverse();
    layers
}

pub fn prove_or_verify(
    channel: &mut Channel<'_>,
    denominators: Option<Vec<Vec<Scalar>>>,
    real_len: usize,
) -> ProofResult<(Vec<Scalar>, Vec<Scalar>)> {
    ensure(real_len > 1)?;
    let padded = real_len
        .checked_next_power_of_two()
        .ok_or(super::ProofError::Invalid)?;
    let log_len = padded.ilog2() as usize;
    if let Some(denominators) = &denominators {
        ensure(denominators.len() == 4 && denominators.iter().all(|d| d.len() == padded))?;
    }
    let span = channel.profile_start("fraction_trees");
    let mut trees = denominators.map(|d| {
        d.into_par_iter()
            .map(|d| tree(d, real_len))
            .collect::<Vec<_>>()
    });
    channel.profile_end(span);
    let roots = trees.as_ref().map(|trees| {
        trees
            .iter()
            .flat_map(|tree| [tree[0].0[0], tree[0].1[0]])
            .collect::<Vec<_>>()
    });
    let roots = channel.fields(roots.as_deref(), 8)?;
    ensure(roots.iter().skip(1).step_by(2).all(|x| !x.is_zero()))?;
    ensure(
        roots[0] * roots[3] == roots[2] * roots[1] && roots[4] * roots[7] == roots[6] * roots[5],
    )?;
    let mut claims = roots;
    let mut point = Vec::new();
    for layer in 0..log_len {
        let beta = channel.challenge(b"logup-gkr-layer-batch");
        let mut weights = Vec::new();
        let mut power = Scalar::ONE;
        for _ in 0..8 {
            weights.push(power);
            power *= beta;
        }
        let claim = sumcheck::dot(&claims, &weights);
        let span = channel.profile_start("layer_tables");
        let tables = trees.as_mut().map(|trees| {
            // A layer is used exactly once. Split its numerator/denominator
            // tables in parallel, then free the original storage immediately.
            // Indexed collection preserves the old transcript's factor order.
            let parts: Vec<_> = trees
                .par_iter_mut()
                .map(|tree| {
                    let (n, d) = std::mem::take(&mut tree[layer + 1]);
                    let (n0, n1): (Vec<_>, Vec<_>) =
                        n.par_chunks_exact(2).map(|v| (v[0], v[1])).unzip();
                    drop(n);
                    let (d0, d1): (Vec<_>, Vec<_>) =
                        d.par_chunks_exact(2).map(|v| (v[0], v[1])).unzip();
                    [n0, n1, d0, d1]
                })
                .collect();
            let mut tables: Vec<_> = parts.into_iter().flatten().collect();
            tables.push(sumcheck::eq_weights(&point));
            tables
        });
        let terms: Vec<_> = (0..4)
            .flat_map(|i| {
                [
                    (weights[2 * i], vec![4 * i, 4 * i + 3, 16]),
                    (weights[2 * i], vec![4 * i + 1, 4 * i + 2, 16]),
                    (weights[2 * i + 1], vec![4 * i + 2, 4 * i + 3, 16]),
                ]
            })
            .collect();
        channel.profile_end(span);
        let span = channel.profile_start("layer_sumchecks");
        let (r, final_claim, evaluations) =
            sumcheck::sumcheck(channel, tables, &terms, layer, claim)?;
        channel.profile_end(span);
        let children = channel.fields(evaluations.as_ref().map(|e| &e[..16]), 16)?;
        let expected: Scalar = (0..4)
            .map(|i| {
                let v = &children[4 * i..4 * i + 4];
                weights[2 * i] * (v[0] * v[3] + v[1] * v[2]) + weights[2 * i + 1] * v[2] * v[3]
            })
            .sum();
        ensure(sumcheck::eq(&point, &r) * expected == final_claim)?;
        let child_bit = channel.challenge(b"logup-gkr-child");
        claims = children
            .chunks_exact(4)
            .flat_map(|v| {
                [
                    v[0] + child_bit * (v[1] - v[0]),
                    v[2] + child_bit * (v[3] - v[2]),
                ]
            })
            .collect();
        point = r;
        point.push(child_bit);
    }
    let mask = prefix_weight(&point, real_len);
    ensure(claims.iter().step_by(2).all(|&v| v == mask))?;
    Ok((point, claims.into_iter().skip(1).step_by(2).collect()))
}

/// Sum of equality weights at the first `end` Boolean indices, in O(log n).
#[must_use]
pub fn prefix_weight(point: &[Scalar], end: usize) -> Scalar {
    if end >= 1usize << point.len() {
        return Scalar::ONE;
    }
    let mut prefix = Scalar::ONE;
    let mut sum = Scalar::ZERO;
    for (i, &r) in point.iter().enumerate() {
        if end & (1 << (point.len() - i - 1)) != 0 {
            sum += prefix * (Scalar::ONE - r);
            prefix *= r;
        } else {
            prefix *= Scalar::ONE - r;
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fractional_checks_honest_permutations_and_rejects_false_sum() {
        let first: Vec<_> = [3, 5, 9, 17, 11, 1, 1, 1]
            .into_iter()
            .map(Scalar::from)
            .collect();
        let mut second = first.clone();
        second[..5].reverse();
        let input = vec![first.clone(), second.clone(), first.clone(), second];
        let mut prover = Channel::new(b"fractional-test", None);
        let (r, d) = prove_or_verify(&mut prover, Some(input.clone()), 5).unwrap();
        assert_eq!(
            d,
            input
                .iter()
                .map(|v| sumcheck::evaluate(v, &r))
                .collect::<Vec<_>>()
        );
        let proof = prover.finish().unwrap();
        let check = |bytes: &[u8]| {
            let mut verifier = Channel::new(b"fractional-test", Some(bytes));
            let output = prove_or_verify(&mut verifier, None, 5)?;
            ensure(output == (r.clone(), d.clone()))?;
            verifier.finish()
        };
        assert!(check(&proof).is_ok());
        for i in (0..proof.len()).step_by(32) {
            let mut bad = proof.clone();
            bad[i] ^= 1;
            assert!(check(&bad).is_err());
        }
        let mut bad_input = input;
        bad_input[1][0] += Scalar::ONE;
        assert!(
            prove_or_verify(
                &mut Channel::new(b"fractional-test", None),
                Some(bad_input),
                5
            )
            .is_err()
        );
    }
}
