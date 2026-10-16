//! Public weight descriptions for packed ERA claims. Verification never expands
//! an oracle-sized equality table. Indices and coordinates are MSB first.
//!
//! Shifted equality products and cumulative weights use binary carry/borrow
//! dynamic programs (constant state, logarithmic time). A tightly packed tensor
//! with a non-power-of-two stride uses one such evaluation per touched tensor
//! row: O(inner dimension * log width), NOT a polylogarithmic verifier claim.
use super::{Scalar, fractional::prefix_weight, sumcheck};
use crate::FieldElement;
use p3_maybe_rayon::prelude::*;
use std::sync::Arc;

#[derive(Debug)]
enum Kind {
    Equality(Vec<Scalar>),
    Tensor {
        left: Vec<Scalar>,
        right: Vec<Scalar>,
        columns: usize,
    },
    Repeat {
        point: Vec<Scalar>,
        copies: usize,
    },
    Suffix(Vec<Scalar>),
    SparseSuffix(Vec<(usize, Scalar)>),
}

/// A slice of a public vector, placed at `offset` in a zero-padded oracle row.
/// Only the prover carries a dense backing array; splits share that array.
#[derive(Debug, Clone)]
pub(crate) struct Weights {
    kind: Arc<Kind>,
    dense: Option<Arc<Vec<Scalar>>>,
    total: usize,
    start: usize,
    len: usize,
    offset: usize,
}

impl Weights {
    fn new(kind: Kind, len: usize, prover: bool) -> Self {
        let dense = prover.then(|| {
            Arc::new(match &kind {
                Kind::Equality(p) => {
                    let mut w = sumcheck::eq_weights(p);
                    w.truncate(len);
                    w
                }
                Kind::Tensor {
                    left,
                    right,
                    columns,
                } => {
                    let a = sumcheck::eq_weights(left);
                    let b = sumcheck::eq_weights(right);
                    (0..len)
                        .into_par_iter()
                        .map(|i| a[i / columns] * b[i % columns])
                        .collect()
                }
                Kind::Repeat { point, copies } => {
                    let w = sumcheck::eq_weights(point);
                    (0..len)
                        .into_par_iter()
                        .map(|i| (0..*copies).map(|j| w[i + j * len]).sum())
                        .collect()
                }
                Kind::Suffix(p) => {
                    let mut w = sumcheck::eq_weights(p);
                    w.truncate(len);
                    suffix_sum(&mut w);
                    w
                }
                Kind::SparseSuffix(entries) => {
                    let mut w = vec![Scalar::ZERO; len];
                    for &(i, v) in entries {
                        w[i] += v;
                    }
                    suffix_sum(&mut w);
                    w
                }
            })
        });
        Self {
            kind: Arc::new(kind),
            dense,
            total: len,
            start: 0,
            len,
            offset: 0,
        }
    }

    pub(crate) fn equality(point: &[Scalar], len: usize, prover: bool) -> Self {
        assert!(len <= 1usize << point.len());
        Self::new(Kind::Equality(point.to_vec()), len, prover)
    }
    pub(crate) fn tensor(
        left: &[Scalar],
        right: &[Scalar],
        rows: usize,
        columns: usize,
        prover: bool,
    ) -> Self {
        assert!(rows <= 1usize << left.len() && columns <= 1usize << right.len());
        // Power-of-two strides are just concatenated equality points, even
        // when the number of physical rows is not a power of two.
        if columns == 1usize << right.len() {
            return Self::equality(&[left, right].concat(), rows * columns, prover);
        }
        Self::new(
            Kind::Tensor {
                left: left.to_vec(),
                right: right.to_vec(),
                columns,
            },
            rows * columns,
            prover,
        )
    }
    pub(crate) fn repeat(point: &[Scalar], period: usize, copies: usize, prover: bool) -> Self {
        assert!(period * copies <= 1usize << point.len());
        Self::new(
            Kind::Repeat {
                point: point.to_vec(),
                copies,
            },
            period,
            prover,
        )
    }
    pub(crate) fn suffix(point: &[Scalar], len: usize, prover: bool) -> Self {
        assert!(len <= 1usize << point.len());
        Self::new(Kind::Suffix(point.to_vec()), len, prover)
    }
    pub(crate) fn sparse_suffix(entries: Vec<(usize, Scalar)>, len: usize, prover: bool) -> Self {
        assert!(entries.iter().all(|&(i, _)| i < len));
        Self::new(Kind::SparseSuffix(entries), len, prover)
    }
    pub(crate) const fn len(&self) -> usize {
        self.len
    }
    pub(crate) fn slice(&self, start: usize, len: usize, offset: usize) -> Self {
        assert!(start + len <= self.len);
        Self {
            start: self.start + start,
            len,
            offset,
            ..self.clone()
        }
    }
    pub(crate) fn discard_dense(&mut self) {
        self.dense = None;
    }
    pub(crate) fn dense(&self) -> &[Scalar] {
        &self.dense.as_ref().unwrap()[self.start..self.start + self.len]
    }
    pub(crate) fn dot(&self, a: &[Scalar], b: Option<&[Scalar]>) -> Scalar {
        let a = &a[self.offset..self.offset + self.len];
        if let Some(b) = b {
            let b = &b[self.offset..self.offset + self.len];
            a.par_iter()
                .zip(b.par_iter())
                .zip(self.dense().par_iter())
                .map(|((&a, &b), &w)| a * b * w)
                .sum()
        } else {
            sumcheck::dot(a, self.dense())
        }
    }
    pub(crate) fn add_scaled(&self, target: &mut [Scalar], scale: Scalar) {
        target[self.offset..self.offset + self.len]
            .par_iter_mut()
            .zip(self.dense().par_iter())
            .for_each(|(v, &w)| {
                if !w.is_zero() {
                    *v += scale * w;
                }
            });
    }
    pub(crate) fn evaluate(&self, point: &[Scalar]) -> Scalar {
        assert!(self.offset + self.len <= 1usize << point.len());
        match self.kind.as_ref() {
            Kind::Equality(p) => shifted_product(p, self.start, point, self.offset, self.len),
            Kind::Repeat { point: p, copies } => (0..*copies)
                .map(|i| {
                    shifted_product(p, self.start + i * self.total, point, self.offset, self.len)
                })
                .sum(),
            Kind::Suffix(p) => {
                suffix_product(p, self.total, self.start, point, self.offset, self.len)
            }
            Kind::SparseSuffix(entries) => entries
                .iter()
                .map(|&(i, w)| {
                    let end = (i + 1).saturating_sub(self.start).min(self.len);
                    w * (prefix_weight(point, self.offset + end)
                        - prefix_weight(point, self.offset))
                })
                .sum(),
            Kind::Tensor {
                left,
                right,
                columns,
            } => {
                let end = self.start + self.len;
                (self.start / columns..end.div_ceil(*columns))
                    .into_par_iter()
                    .map(|row| {
                        let lo = self.start.max(row * columns);
                        let hi = end.min((row + 1) * columns);
                        boolean_weight(left, row)
                            * shifted_product(
                                right,
                                lo - row * columns,
                                point,
                                self.offset + lo - self.start,
                                hi - lo,
                            )
                    })
                    .sum()
            }
        }
    }
}

/// Parallel block scans preserve the exact field sum, including duplicates.
fn suffix_sum(values: &mut [Scalar]) {
    const BLOCK: usize = 4096;
    let totals: Vec<_> = values
        .par_chunks_mut(BLOCK)
        .map(|block| {
            let mut sum = Scalar::ZERO;
            for x in block.iter_mut().rev() {
                sum += *x;
                *x = sum;
            }
            sum
        })
        .collect();
    let mut carry = vec![Scalar::ZERO; totals.len()];
    let mut sum = Scalar::ZERO;
    for (c, t) in carry.iter_mut().zip(&totals).rev() {
        *c = sum;
        sum += t;
    }
    values
        .par_chunks_mut(BLOCK)
        .zip(carry.par_iter())
        .for_each(|(block, &c)| {
            if !c.is_zero() {
                for x in block {
                    *x += c;
                }
            }
        });
}

fn bit_weight(point: &[Scalar], bit: usize, value: usize) -> Scalar {
    if bit >= point.len() {
        if value == 0 {
            Scalar::ONE
        } else {
            Scalar::ZERO
        }
    } else {
        let r = point[point.len() - bit - 1];
        if value == 0 { Scalar::ONE - r } else { r }
    }
}
fn boolean_weight(point: &[Scalar], index: usize) -> Scalar {
    (0..point.len())
        .map(|b| bit_weight(point, b, (index >> b) & 1))
        .product()
}
const fn bits(n: usize) -> usize {
    (usize::BITS - n.leading_zeros()) as usize
}

/// Sum_{0 <= t < len} eq(p,a+t) eq(q,b+t). LSB-first addition with
/// two carry bits and the borrow bit of t-len; no field divisions.
fn shifted_product(p: &[Scalar], a: usize, q: &[Scalar], b: usize, len: usize) -> Scalar {
    if len == 0 {
        return Scalar::ZERO;
    }
    let m = p.len().max(q.len()).max(bits(a + len)).max(bits(b + len)) + 1;
    let mut dp = [Scalar::ZERO; 8];
    dp[0] = Scalar::ONE;
    for bit in 0..m {
        let mut next = [Scalar::ZERO; 8];
        for (state, &v) in dp.iter().enumerate() {
            if v.is_zero() {
                continue;
            }
            for t in 0..2 {
                let x = t + ((a >> bit) & 1) + (state & 1);
                let y = t + ((b >> bit) & 1) + ((state >> 1) & 1);
                let borrow = usize::from(t < ((len >> bit) & 1) + (state >> 2));
                next[(x >> 1) | ((y >> 1) << 1) | (borrow << 2)] +=
                    v * bit_weight(p, bit, x & 1) * bit_weight(q, bit, y & 1);
            }
        }
        dp = next;
    }
    dp[4]
}

/// Sum_{t<len, a+t<=j<end} eq(p,j) eq(q,b+t). The five state bits
/// are carries for a+t,b+t and borrows for t-len,j-end,j-(a+t).
fn suffix_product(
    p: &[Scalar],
    end: usize,
    a: usize,
    q: &[Scalar],
    b: usize,
    len: usize,
) -> Scalar {
    let m = p
        .len()
        .max(q.len())
        .max(bits(a + len))
        .max(bits(b + len))
        .max(bits(end))
        + 1;
    let mut dp = [Scalar::ZERO; 32];
    dp[0] = Scalar::ONE;
    for bit in 0..m {
        let mut next = [Scalar::ZERO; 32];
        for (state, &v) in dp.iter().enumerate() {
            if v.is_zero() {
                continue;
            }
            for t in 0..2 {
                let x = t + ((a >> bit) & 1) + (state & 1);
                let y = t + ((b >> bit) & 1) + ((state >> 1) & 1);
                let bt = usize::from(t < ((len >> bit) & 1) + ((state >> 2) & 1));
                for j in 0..2 {
                    let bj = usize::from(j < ((end >> bit) & 1) + ((state >> 3) & 1));
                    let bx = usize::from(j < (x & 1) + ((state >> 4) & 1));
                    let s = (x >> 1) | ((y >> 1) << 1) | (bt << 2) | (bj << 3) | (bx << 4);
                    next[s] += v * bit_weight(p, bit, j) * bit_weight(q, bit, y & 1);
                }
            }
        }
        dp = next;
    }
    dp[12]
}

/// First moment of the truncated Boolean equality distribution, O(log n).
pub(crate) fn prefix_index_moment(point: &[Scalar], end: usize) -> Scalar {
    assert!(end <= 1usize << point.len());
    let mut suffix_mean = vec![Scalar::ZERO; point.len() + 1];
    for i in (0..point.len()).rev() {
        suffix_mean[i] =
            suffix_mean[i + 1] + point[i] * Scalar::from(1u64 << (point.len() - i - 1));
    }
    if end == 1usize << point.len() {
        return suffix_mean[0];
    }
    let mut prefix = Scalar::ONE;
    let mut integer = 0usize;
    let mut sum = Scalar::ZERO;
    for (i, &r) in point.iter().enumerate() {
        let place = 1usize << (point.len() - i - 1);
        if end & place != 0 {
            sum += prefix * (Scalar::ONE - r) * (Scalar::from(integer as u64) + suffix_mean[i + 1]);
            prefix *= r;
            integer += place;
        } else {
            prefix *= Scalar::ONE - r;
        }
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    fn point(n: usize) -> Vec<Scalar> {
        (0..n).map(|i| Scalar::from((i * 7 + 3) as u64)).collect()
    }
    fn check(w: &Weights, q: &[Scalar]) {
        let dense = w.dense();
        let eq = sumcheck::eq_weights(q);
        assert_eq!(
            w.evaluate(q),
            sumcheck::dot(dense, &eq[w.offset..w.offset + w.len])
        );
    }
    #[test]
    fn compact_weights_match_dense_for_packing_truncation_and_boolean_challenges() {
        for p in [point(5), vec![Scalar::ZERO; 5], vec![Scalar::ONE; 5]] {
            for end in [1, 7, 16, 27, 32] {
                let eq = sumcheck::eq_weights(&p);
                assert_eq!(
                    prefix_index_moment(&p, end),
                    (0..end).map(|i| Scalar::from(i as u64) * eq[i]).sum()
                );
                for w in [
                    Weights::equality(&p, end, true),
                    Weights::suffix(&p, end, true),
                    Weights::sparse_suffix(
                        vec![
                            (0, Scalar::from(2)),
                            (end - 1, Scalar::from(3)),
                            (end - 1, Scalar::from(5)),
                        ],
                        end,
                        true,
                    ),
                ] {
                    for start in 0..end {
                        for len in 1..=end - start {
                            for offset in [0, 1, 32 - len] {
                                check(&w.slice(start, len, offset), &point(6));
                            }
                        }
                    }
                }
            }
        }
        for cols in [3, 5, 8] {
            let w = Weights::tensor(&point(3), &point(3), 5, cols, true);
            for start in 0..w.len() {
                check(&w.slice(start, (w.len() - start).min(11), 3), &point(4));
            }
        }
        for period in [1, 3, 7, 8] {
            let w = Weights::repeat(&point(5), period, 4, true);
            for start in 0..period {
                check(&w.slice(start, period - start, 1), &point(4));
            }
        }
    }
    #[test]
    fn parallel_suffix_scan_matches_serial() {
        let mut v: Vec<_> = (0..10003).map(|i| Scalar::from(i * i + 9)).collect();
        let mut expected = v.clone();
        let mut sum = Scalar::ZERO;
        for x in expected.iter_mut().rev() {
            sum += *x;
            *x = sum;
        }
        suffix_sum(&mut v);
        assert_eq!(v, expected);
    }
}
