//! Multilinear sumchecks in MSB-first variable order.
use super::{Channel, ProofResult, Scalar, ensure};
use crate::{FieldElement, poly_utils::multilinear::MultilinearPoint};
use p3_maybe_rayon::prelude::*;

#[must_use]
pub fn eq_weights(point: &[Scalar]) -> Vec<Scalar> {
    if point.len() < 14 {
        return MultilinearPoint(point.to_vec()).eq_weights();
    }
    // Disjoint suffix blocks preserve MSB order and avoid a sequential O(2^n)
    // expansion on large tables. Each node uses one multiplication.
    let split = point.len() - 10;
    let prefixes = MultilinearPoint(point[..split].to_vec()).eq_weights();
    let mut weights = vec![Scalar::ZERO; 1 << point.len()];
    weights
        .par_chunks_mut(1024)
        .zip(prefixes.par_iter())
        .for_each(|(block, &prefix)| {
            block[0] = prefix;
            let mut active = 1;
            for &coordinate in &point[split..] {
                for i in (0..active).rev() {
                    let parent = block[i];
                    let right = parent * coordinate;
                    block[2 * i] = parent - right;
                    block[2 * i + 1] = right;
                }
                active *= 2;
            }
        });
    weights
}

#[must_use]
pub fn eq(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b)
        .map(|(&x, &y)| x * y + (Scalar::ONE - x) * (Scalar::ONE - y))
        .product()
}

pub fn fold(values: &mut Vec<Scalar>, r: Scalar) {
    let half = values.len() / 2;
    let (lo, hi) = values.split_at_mut(half);
    if half < 1024 {
        lo.iter_mut()
            .zip(hi.iter())
            .for_each(|(a, b)| *a += r * (*b - *a));
    } else {
        lo.par_iter_mut()
            .zip(hi.par_iter())
            .for_each(|(a, b)| *a += r * (*b - *a));
    }
    values.truncate(half);
}

#[must_use]
pub fn dot(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len());
    // Merkle columns often have only a few dozen entries. Scheduling a parallel
    // reduction for every opened column costs more than these multiplications.
    if a.len() < 1024 {
        a.iter().zip(b).map(|(&x, &y)| x * y).sum()
    } else {
        a.par_iter().zip(b.par_iter()).map(|(&x, &y)| x * y).sum()
    }
}

#[must_use]
pub fn evaluate(values: &[Scalar], point: &[Scalar]) -> Scalar {
    dot(values, &eq_weights(point))
}

#[must_use]
pub fn interpolate(values: &[Scalar], r: Scalar) -> Scalar {
    assert!((2..=4).contains(&values.len()));
    static INVERSES: std::sync::OnceLock<(Scalar, Scalar)> = std::sync::OnceLock::new();
    let &(half, sixth) = INVERSES.get_or_init(|| {
        (
            FieldElement::inverse(Scalar::from(2)).unwrap(),
            FieldElement::inverse(Scalar::from(6)).unwrap(),
        )
    });
    let mut answer = values[0] + r * (values[1] - values[0]);
    let r2 = r * (r - Scalar::ONE);
    if values.len() >= 3 {
        answer += r2 * (values[2] - values[1] - values[1] + values[0]) * half;
    }
    if values.len() == 4 {
        let third =
            values[3] - values[2] - values[2] - values[2] + values[1] + values[1] + values[1]
                - values[0];
        answer += r2 * (r - Scalar::from(2)) * third * sixth;
    }
    answer
}

/// Evaluate at 0, 2, and (for cubic expressions) 3 in one tiled pass.
/// The caller recovers g(1) from the current sumcheck claim. This is only a
/// prover optimization: the verifier still receives/checks every old message.
fn round_samples(
    tables: &[Vec<Scalar>],
    terms: &[(Scalar, Vec<usize>)],
    degree: usize,
) -> [Scalar; 3] {
    let half = tables[0].len() / 2;
    let block = |start: usize, end: usize| {
        let mut samples = vec![[Scalar::ZERO; 3]; tables.len()];
        let mut total = [Scalar::ZERO; 3];
        for j in start..end {
            for (sample, row) in samples.iter_mut().zip(tables) {
                let lo = row[j];
                let hi = row[j + half];
                let delta = hi - lo;
                *sample = [lo, hi + delta, hi + delta + delta];
            }
            for (coefficient, factors) in terms {
                for k in 0..degree {
                    let mut value = samples[factors[0]][k];
                    if factors.len() >= 2 {
                        value *= samples[factors[1]][k];
                    }
                    if factors.len() == 3 {
                        value *= samples[factors[2]][k];
                    }
                    if *coefficient != Scalar::ONE {
                        value *= coefficient;
                    }
                    total[k] += value;
                }
            }
        }
        total
    };
    if half < 1024 {
        return block(0, half);
    }
    let partials: Vec<_> = (0..half.div_ceil(256))
        .into_par_iter()
        .map(|i| block(i * 256, ((i + 1) * 256).min(half)))
        .collect();
    let mut total = [Scalar::ZERO; 3];
    for part in partials {
        for (a, b) in total.iter_mut().zip(part) {
            *a += b;
        }
    }
    total
}

/// Sumcheck for a public sum of products. Each term lists table indices and a
/// coefficient. The verifier evaluates the final polynomial independently.
pub fn sumcheck(
    channel: &mut Channel<'_>,
    mut tables: Option<Vec<Vec<Scalar>>>,
    terms: &[(Scalar, Vec<usize>)],
    log_len: usize,
    mut claim: Scalar,
) -> ProofResult<(Vec<Scalar>, Scalar, Option<Vec<Scalar>>)> {
    let degree = terms.iter().map(|t| t.1.len()).max().unwrap_or(0);
    ensure((1..=3).contains(&degree))?;
    let mut point = Vec::with_capacity(log_len);
    for _ in 0..log_len {
        let span = channel.profile_start("polynomial_evaluation");
        let poly = tables.as_ref().map(|tables| {
            let samples = round_samples(tables, terms, degree);
            let mut poly = vec![samples[0], claim - samples[0]];
            poly.extend_from_slice(&samples[1..degree]);
            poly
        });
        let poly = channel.fields(poly.as_deref(), degree + 1)?;
        ensure(poly[0] + poly[1] == claim)?;
        channel.profile_end(span);
        let r = channel.challenge(b"sumcheck-round");
        claim = interpolate(&poly, r);
        let span = channel.profile_start("table_folding");
        if let Some(tables) = &mut tables {
            for table in tables {
                fold(table, r);
            }
        }
        channel.profile_end(span);
        point.push(r);
    }
    let evaluations = tables.map(|tables| tables.into_iter().map(|t| t[0]).collect());
    Ok((point, claim, evaluations))
}

/// A sumcheck component on a prefix of the common variable list. Its expression
/// is constant in the remaining variables. Callers normalize coefficients by
/// 2^-(common_log - log_len) when batching claims on differently sized cubes.
#[derive(Debug)]
pub(crate) struct Group {
    pub log_len: usize,
    pub terms: Vec<(Scalar, Vec<usize>)>,
}

/// Batched cubic sumcheck without materializing the dummy coordinates of short
/// components. This uses the same interpolation arithmetic as `sumcheck`.
pub(crate) fn ragged_sumcheck(
    channel: &mut Channel<'_>,
    mut tables: Option<Vec<Vec<Vec<Scalar>>>>,
    groups: &[Group],
    mut claim: Scalar,
) -> ProofResult<(Vec<Scalar>, Scalar, Option<Vec<Vec<Scalar>>>)> {
    ensure(!groups.is_empty())?;
    let log_len = groups.iter().map(|g| g.log_len).max().unwrap();
    ensure(log_len < usize::BITS as usize)?;
    ensure(
        groups
            .iter()
            .all(|g| !g.terms.is_empty() && g.terms.iter().all(|t| (1..=3).contains(&t.1.len()))),
    )?;
    if let Some(tables) = &tables {
        ensure(tables.len() == groups.len())?;
        for (rows, group) in tables.iter().zip(groups) {
            ensure(!rows.is_empty() && rows.iter().all(|r| r.len() == 1 << group.log_len))?;
            ensure(
                group
                    .terms
                    .iter()
                    .all(|t| t.1.iter().all(|&i| i < rows.len())),
            )?;
        }
    }
    let mut point = Vec::with_capacity(log_len);
    for round in 0..log_len {
        let span = channel.profile_start("polynomial_evaluation");
        let poly = tables.as_ref().map(|tables| {
            let mut total = [Scalar::ZERO; 3];
            for (rows, group) in tables.iter().zip(groups) {
                let remaining = group.log_len.saturating_sub(round);
                let (samples, free) = if remaining == 0 {
                    let value: Scalar = group
                        .terms
                        .iter()
                        .map(|(c, factors)| factors.iter().fold(*c, |v, &i| v * rows[i][0]))
                        .sum();
                    ([value; 3], log_len - round - 1)
                } else {
                    (
                        round_samples(rows, &group.terms, 3),
                        log_len - round - remaining,
                    )
                };
                let scale = Scalar::from(1u64 << free);
                for (dst, value) in total.iter_mut().zip(samples) {
                    *dst += value * scale;
                }
            }
            vec![total[0], claim - total[0], total[1], total[2]]
        });
        let poly = channel.fields(poly.as_deref(), 4)?;
        ensure(poly[0] + poly[1] == claim)?;
        channel.profile_end(span);
        let r = channel.challenge(b"sumcheck-round");
        claim = interpolate(&poly, r);
        let span = channel.profile_start("table_folding");
        if let Some(tables) = &mut tables {
            for rows in tables {
                for row in rows {
                    if row.len() > 1 {
                        fold(row, r);
                    }
                }
            }
        }
        channel.profile_end(span);
        point.push(r);
    }
    let evaluations = tables.map(|tables| {
        tables
            .into_iter()
            .map(|rows| rows.into_iter().map(|row| row[0]).collect())
            .collect()
    });
    Ok((point, claim, evaluations))
}

#[cfg(test)]
mod ragged_tests {
    use super::*;

    #[test]
    fn ragged_matches_explicit_constant_extension_including_zero_dimensional_group() {
        for lengths in [vec![0, 1, 3], vec![3], vec![2, 4, 1, 0], vec![0]] {
            let max_log = *lengths.iter().max().unwrap();
            let mut groups = Vec::new();
            let mut tables = Vec::new();
            let mut dense = Vec::new();
            let mut dense_terms = Vec::new();
            for (g, &log) in lengths.iter().enumerate() {
                let rows: Vec<Vec<_>> = (0..3)
                    .map(|k| {
                        (0..1 << log)
                            .map(|j| Scalar::from((j * j + 7 * k + 13 * g + 2) as u64))
                            .collect()
                    })
                    .collect();
                let normalization =
                    FieldElement::inverse(Scalar::from(1u64 << (max_log - log))).unwrap();
                let terms = vec![
                    (normalization * Scalar::from((g + 1) as u64), vec![0, 1, 2]),
                    (normalization * Scalar::from(9), vec![0, 2]),
                ];
                for (c, indices) in &terms {
                    dense_terms.push((
                        *c,
                        indices.iter().map(|i| i + dense.len()).collect::<Vec<_>>(),
                    ));
                }
                dense.extend(rows.iter().map(|r| {
                    r.iter()
                        .flat_map(|&v| std::iter::repeat_n(v, 1 << (max_log - log)))
                        .collect::<Vec<_>>()
                }));
                groups.push(Group {
                    log_len: log,
                    terms,
                });
                tables.push(rows);
            }
            let claim: Scalar = (0..1 << max_log)
                .map(|j| {
                    dense_terms
                        .iter()
                        .map(|(c, indices)| indices.iter().fold(*c, |v, &i| v * dense[i][j]))
                        .sum::<Scalar>()
                })
                .sum();
            let mut old = Channel::new(b"ragged-test", None);
            let (r0, c0, e0) = optimization_tests::reference_sumcheck(
                &mut old,
                Some(dense),
                &dense_terms,
                max_log,
                claim,
            )
            .unwrap();
            let old_bytes = old.finish().unwrap();
            let mut new = Channel::new(b"ragged-test", None);
            let (r1, c1, e1) = ragged_sumcheck(&mut new, Some(tables), &groups, claim).unwrap();
            assert_eq!(new.finish().unwrap(), old_bytes);
            assert_eq!(
                (r0, c0, e0.unwrap()),
                (r1, c1, e1.unwrap().into_iter().flatten().collect())
            );
            let mut verifier = Channel::new(b"ragged-test", Some(&old_bytes));
            ragged_sumcheck(&mut verifier, None, &groups, claim).unwrap();
            verifier.finish().unwrap();
        }
    }
}

#[cfg(test)]
mod optimization_tests {
    use super::*;
    pub(super) fn reference_sumcheck(
        channel: &mut Channel<'_>,
        mut tables: Option<Vec<Vec<Scalar>>>,
        terms: &[(Scalar, Vec<usize>)],
        log_len: usize,
        mut claim: Scalar,
    ) -> ProofResult<(Vec<Scalar>, Scalar, Option<Vec<Scalar>>)> {
        let degree = terms.iter().map(|t| t.1.len()).max().unwrap_or(0);
        ensure((1..=3).contains(&degree))?;
        let mut point = Vec::with_capacity(log_len);
        for _ in 0..log_len {
            let span = channel.profile_start("polynomial_evaluation");
            let poly = tables.as_ref().map(|tables| {
                let half = tables[0].len() / 2;
                (0..=degree)
                    .map(|t| {
                        let t = Scalar::from(t as u64);
                        (0..half)
                            .into_par_iter()
                            .map(|j| {
                                terms
                                    .iter()
                                    .map(|(coefficient, factors)| {
                                        factors.iter().fold(*coefficient, |product, &index| {
                                            let row = &tables[index];
                                            product * (row[j] + t * (row[j + half] - row[j]))
                                        })
                                    })
                                    .sum::<Scalar>()
                            })
                            .sum()
                    })
                    .collect::<Vec<_>>()
            });
            let poly = channel.fields(poly.as_deref(), degree + 1)?;
            ensure(poly[0] + poly[1] == claim)?;
            channel.profile_end(span);
            let r = channel.challenge(b"sumcheck-round");
            claim = interpolate(&poly, r);
            let span = channel.profile_start("table_folding");
            if let Some(tables) = &mut tables {
                for table in tables {
                    fold(table, r);
                }
            }
            channel.profile_end(span);
            point.push(r);
        }
        let evaluations = tables.map(|tables| tables.into_iter().map(|t| t[0]).collect());
        Ok((point, claim, evaluations))
    }

    #[test]
    fn optimized_sumcheck_matches_original_messages_for_all_degrees() {
        for log in [0, 1, 4, 11] {
            for degree in 1..=3 {
                let rows: Vec<Vec<_>> = (0..4)
                    .map(|k| {
                        (0..1 << log)
                            .map(|i| Scalar::from((i * i + 13 * k + 11) as u64))
                            .collect()
                    })
                    .collect();
                let terms = vec![
                    (Scalar::ONE, (0..degree).collect::<Vec<_>>()),
                    (Scalar::from(7), (1..=degree).collect()),
                ];
                let claim: Scalar = (0..1 << log)
                    .map(|i| {
                        terms
                            .iter()
                            .map(|(c, idx)| idx.iter().fold(*c, |v, &j| v * rows[j][i]))
                            .sum::<Scalar>()
                    })
                    .sum();
                let mut reference = Channel::new(b"fused-kernel-test", None);
                let expected =
                    reference_sumcheck(&mut reference, Some(rows.clone()), &terms, log, claim)
                        .unwrap();
                let bytes = reference.finish().unwrap();
                for threads in [1, 8] {
                    let pool = rayon::ThreadPoolBuilder::new()
                        .num_threads(threads)
                        .build()
                        .unwrap();
                    pool.install(|| {
                        let mut channel = Channel::new(b"fused-kernel-test", None);
                        let actual =
                            sumcheck(&mut channel, Some(rows.clone()), &terms, log, claim).unwrap();
                        assert_eq!(actual, expected);
                        assert_eq!(channel.finish().unwrap(), bytes);
                    });
                }
                let mut verifier = Channel::new(b"fused-kernel-test", Some(&bytes));
                sumcheck(&mut verifier, None, &terms, log, claim).unwrap();
                verifier.finish().unwrap();
            }
        }
    }

    #[test]
    fn parallel_equality_weights_match_definition_including_binary_coordinates() {
        for log in [0, 5, 14, 16] {
            let point: Vec<_> = (0..log).map(|i| Scalar::from((i % 7) as u64)).collect();
            let weights = eq_weights(&point);
            for (i, &weight) in weights.iter().enumerate() {
                let expected: Scalar = point
                    .iter()
                    .enumerate()
                    .map(|(j, &r)| {
                        if (i >> (log - 1 - j)) & 1 == 1 {
                            r
                        } else {
                            Scalar::ONE - r
                        }
                    })
                    .product();
                assert_eq!(weight, expected);
            }
        }
    }
}
