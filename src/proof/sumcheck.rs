//! Multilinear sumchecks in MSB-first variable order.
use super::{Channel, ProofResult, Scalar, ensure};
use crate::{FieldElement, poly_utils::multilinear::MultilinearPoint};
use p3_maybe_rayon::prelude::*;

#[must_use]
pub fn eq_weights(point: &[Scalar]) -> Vec<Scalar> {
    MultilinearPoint(point.to_vec()).eq_weights()
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
        let r = channel.challenge(b"sumcheck-round");
        claim = interpolate(&poly, r);
        if let Some(tables) = &mut tables {
            for table in tables {
                fold(table, r);
            }
        }
        point.push(r);
    }
    let evaluations = tables.map(|tables| tables.into_iter().map(|t| t[0]).collect());
    Ok((point, claim, evaluations))
}
