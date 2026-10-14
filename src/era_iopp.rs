//! One ERA codeswitch followed by recursive BaseFold. Uses two independent
//! multiplier vectors, batched logUp-GKR, early stack commitments and unique
//! per-oracle batching coefficients. Packed non-power-of-two vectors are padded
//! only inside split messages, never inside the ERA code's physical word.
use crate::{
    BasefoldCode, BasefoldParams, BrakedownCode, BrakedownParams, EraCode, ErrorCorrectingCode,
    FieldElement, TensorCode,
    basefold_iopp::{self, FoldingSetup, Source},
    interleaved_iopp::fs::fold_rows,
    proof::{
        Channel, ProofResult, Scalar, ensure, fractional,
        merkle::{self, Commitment},
        sumcheck,
    },
    random_permutation,
};
use p3_maybe_rayon::prelude::*;
use rand::{SeedableRng, rngs::SmallRng};

#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    pub message_log: usize,
    pub eta: usize,
    pub output_log: usize,
    pub output_log_rate: usize,
    pub terminal_log: usize,
    pub era_queries: usize,
    pub basefold_queries: usize,
    pub seed: u64,
}

#[derive(Debug, Clone, Copy)]
struct Family {
    start: usize,
    len: usize,
    rows: usize,
}

fn family(cursor: &mut usize, len: usize, width: usize) -> Family {
    let f = Family {
        start: *cursor,
        len,
        rows: len.div_ceil(width),
    };
    *cursor += f.rows;
    f
}

#[derive(Debug)]
struct Layout {
    generator: Family,
    pi1: Family,
    pi2: Family,
    mult1: Family,
    mult2: Family,
    message: Family,
    base: Family,
    perm1: Family,
    perm2: Family,
    index_rows: usize,
    rows: usize,
}

#[derive(Debug)]
pub struct Setup {
    pub parameters: Parameters,
    pub era: EraCode<TensorCode<BrakedownCode<Scalar>>, Scalar>,
    pub output: FoldingSetup,
    pub index: Commitment,
    index_messages: Vec<Vec<Scalar>>,
    layout: Layout,
}

fn split(values: &[Scalar], width: usize) -> Vec<Vec<Scalar>> {
    values
        .chunks(width)
        .map(|chunk| {
            let mut v = chunk.to_vec();
            v.resize(width, Scalar::ZERO);
            v
        })
        .collect()
}

impl Setup {
    pub fn new(parameters: Parameters) -> ProofResult<Self> {
        let p = parameters;
        ensure(p.eta < p.message_log && p.message_log < 32)?;
        let row_log = p.message_log - p.eta;
        ensure(
            row_log.is_multiple_of(2) && p.output_log < row_log && p.terminal_log < p.output_log,
        )?;
        ensure(p.output_log_rate <= 5 && p.era_queries > 0 && p.basefold_queries > 0)?;
        let width = 1usize << p.output_log;
        let mut rng = SmallRng::seed_from_u64(p.seed);
        let inner = BrakedownCode::new(
            1 << (row_log / 2),
            BrakedownParams {
                alpha: 0.05,
                inverse_rate: 1.1,
                cn: 6,
                dn: 40,
            },
            &mut rng,
        );
        let k = inner.message_size();
        let n = inner.block_length();
        let columns: Vec<_> = (0..k)
            .into_par_iter()
            .map(|j| {
                let mut unit = vec![Scalar::ZERO; k];
                unit[j] = Scalar::ONE;
                inner.encode(&unit)
            })
            .collect();
        let generator: Vec<_> = (0..n)
            .flat_map(|i| columns.iter().map(move |col| col[i]))
            .collect();
        let length = 4 * n * n;
        let pi1 = random_permutation(&mut rng, length);
        let pi2 = random_permutation(&mut rng, length);
        let mut nonzero = || loop {
            let v = Scalar::random(&mut rng);
            if !v.is_zero() {
                break v;
            }
        };
        let mult1: Vec<_> = (0..length).map(|_| nonzero()).collect();
        let mult2: Vec<_> = (0..length).map(|_| nonzero()).collect();
        let mut cursor = 0;
        let g_family = family(&mut cursor, generator.len(), width);
        let p1_family = family(&mut cursor, length, width);
        let p2_family = family(&mut cursor, length, width);
        let m1_family = family(&mut cursor, length, width);
        let m2_family = family(&mut cursor, length, width);
        let index_rows = cursor;
        let message_family = family(&mut cursor, k * k, width);
        let base_family = family(&mut cursor, n * n, width);
        let perm1_family = family(&mut cursor, length, width);
        let perm2_family = family(&mut cursor, length, width);
        let mut index_messages = split(&generator, width);
        index_messages.extend(split(
            &pi1.iter()
                .map(|&i| Scalar::from(i as u64))
                .collect::<Vec<_>>(),
            width,
        ));
        index_messages.extend(split(
            &pi2.iter()
                .map(|&i| Scalar::from(i as u64))
                .collect::<Vec<_>>(),
            width,
        ));
        index_messages.extend(split(&mult1, width));
        index_messages.extend(split(&mult2, width));
        let output = FoldingSetup::new(BasefoldCode::new(
            width,
            BasefoldParams {
                log_rate: p.output_log_rate,
            },
            &mut rng,
        ));
        let index = Commitment::new(
            index_messages
                .par_iter()
                .map(|m| output.code.encode_sequential(m))
                .collect(),
        );
        let era = EraCode::new(TensorCode::new(inner), 4, pi1, pi2, mult1, mult2);
        let layout = Layout {
            generator: g_family,
            pi1: p1_family,
            pi2: p2_family,
            mult1: m1_family,
            mult2: m2_family,
            message: message_family,
            base: base_family,
            perm1: perm1_family,
            perm2: perm2_family,
            index_rows,
            rows: cursor,
        };
        Ok(Self {
            parameters,
            era,
            output,
            index,
            index_messages,
            layout,
        })
    }

    pub fn commit(&self, message: &[Scalar]) -> ProofResult<Commitment> {
        ensure(message.len() == 1usize << self.parameters.message_log)?;
        Ok(Commitment::new(
            message
                .par_chunks(self.era.message_size())
                .map(|row| self.era.encode_era_sequential(row))
                .collect(),
        ))
    }

    fn bind(
        &self,
        channel: &mut Channel<'_>,
        root: [u8; 32],
        point: &[Scalar],
        value: Scalar,
    ) -> ProofResult<()> {
        let p = self.parameters;
        ensure(point.len() == p.message_log)?;
        ensure(channel.bytes(Some(*b"AGNERAv1"))? == *b"AGNERAv1")?;
        for value in [
            p.message_log,
            p.eta,
            p.output_log,
            p.output_log_rate,
            p.terminal_log,
            p.era_queries,
            p.basefold_queries,
        ] {
            channel.bind_usize(b"parameter", value);
        }
        channel.bind(b"seed", &p.seed.to_le_bytes());
        channel.bind(b"initial-root", &root);
        channel.bind(b"index-root", &self.index.root());
        channel.bind_fields(b"evaluation-point", point);
        ensure(channel.field(Some(value))? == value)
    }

    pub fn prove(
        &self,
        tree: &Commitment,
        message: &[Scalar],
        point: &[Scalar],
    ) -> ProofResult<(Scalar, Vec<u8>)> {
        ensure(
            point.len() == self.parameters.message_log
                && message.len() == 1usize << self.parameters.message_log,
        )?;
        let value = sumcheck::evaluate(message, point);
        let mut channel = Channel::new(b"era-codeswitch-v1", None);
        self.execute(
            &mut channel,
            tree.root(),
            point,
            value,
            Some((message, tree)),
        )?;
        Ok((value, channel.finish()?))
    }

    pub fn verify(
        &self,
        root: [u8; 32],
        point: &[Scalar],
        value: Scalar,
        bytes: &[u8],
    ) -> ProofResult<()> {
        let mut channel = Channel::new(b"era-codeswitch-v1", Some(bytes));
        self.execute(&mut channel, root, point, value, None)?;
        channel.finish().map(|_| ())
    }

    fn execute(
        &self,
        channel: &mut Channel<'_>,
        root: [u8; 32],
        point: &[Scalar],
        value: Scalar,
        witness: Option<(&[Scalar], &Commitment)>,
    ) -> ProofResult<()> {
        self.bind(channel, root, point, value)?;
        let p = self.parameters;
        let l = &self.layout;
        let width = 1 << p.output_log;
        let (r, final_claim, _) = sumcheck::sumcheck(
            channel,
            witness.map(|(m, _)| vec![m.to_vec(), sumcheck::eq_weights(point)]),
            &[(Scalar::ONE, vec![0, 1])],
            p.message_log,
            value,
        )?;
        let eq = sumcheck::eq(point, &r);
        let reduced_value =
            final_claim * FieldElement::inverse(eq).ok_or(crate::proof::ProofError::Invalid)?;
        let row_weights = sumcheck::eq_weights(&r[..p.eta]);
        let folded = witness.map(|(m, _)| fold_rows(m, &row_weights));
        let online_values = folded.as_ref().map(|message| {
            let base = self.era.base_code().encode(message);
            let (pi1, pi2) = self.era.permutations();
            let (m1, _) = self.era.multipliers();
            let perm1: Vec<_> = pi1.iter().map(|&i| base[i % base.len()]).collect();
            let mut acc = Scalar::ZERO;
            let accum1: Vec<_> = perm1
                .iter()
                .zip(m1)
                .map(|(&w, &m)| {
                    acc += w * m;
                    acc
                })
                .collect();
            let perm2: Vec<_> = pi2.iter().map(|&i| accum1[i]).collect();
            (base, perm1, accum1, perm2)
        });
        let online_messages = folded.as_ref().map(|message| {
            let (base, perm1, _, perm2) = online_values.as_ref().unwrap();
            let mut rows = split(message, width);
            rows.extend(split(base, width));
            rows.extend(split(perm1, width));
            rows.extend(split(perm2, width));
            rows
        });
        // All auxiliary vectors are bound before OODs, spot queries, permutation
        // challenges, and every subsequent random combination.
        let online_tree = online_messages.as_ref().map(|rows| {
            Commitment::new(
                rows.par_iter()
                    .map(|m| self.output.code.encode_sequential(m))
                    .collect(),
            )
        });
        let online_root = channel.bytes(online_tree.as_ref().map(Commitment::root))?;
        let all_messages = online_messages.as_ref().map(|rows| {
            let mut all = self.index_messages.clone();
            all.extend(rows.clone());
            all
        });
        let mut claims = Claims::new(width, all_messages.as_deref());
        claims.ip(
            channel,
            l.message,
            sumcheck::eq_weights(&r[p.eta..]),
            reduced_value,
        )?;
        // One OOD evaluation per split online oracle avoids relying on unproved
        // uniqueness of a packed family's zero-padded representation.
        for row in l.index_rows..l.rows {
            let z = channel.point(b"online-ood", p.output_log);
            let weights = sumcheck::eq_weights(&z);
            let y = channel.field(
                all_messages
                    .as_ref()
                    .map(|rows| sumcheck::dot(&rows[row], &weights)),
            )?;
            claims.terms.push(Claim {
                row1: row,
                row2: None,
                weights,
                value: y,
            });
        }
        let queries = channel.queries(self.era.block_length(), p.era_queries)?;
        let columns = merkle::open(
            channel,
            witness.map(|(_, t)| t),
            root,
            1 << p.eta,
            self.era.block_length(),
            &queries,
        )?;
        let answers: Vec<_> = queries
            .iter()
            .map(|i| {
                sumcheck::dot(
                    &columns[columns.binary_search_by_key(i, |c| c.0).unwrap()].1,
                    &row_weights,
                )
            })
            .collect();
        self.tensor_check(
            channel,
            &mut claims,
            online_values.as_ref().map(|v| v.0.as_slice()),
            folded.as_deref(),
        )?;
        self.permutation_checks(channel, &mut claims, online_values.as_ref())?;
        // Directly emulate the queried final accumulator. Duplicate query
        // coefficients ADD; overwriting would break honest repeated queries.
        let beta = channel.challenge(b"codeswitch-query-batch");
        let mut power = Scalar::ONE;
        let mut target = Scalar::ZERO;
        let mut weights = vec![Scalar::ZERO; self.era.block_length()];
        for (&index, &answer) in queries.iter().zip(&answers) {
            weights[index] += power;
            target += power * answer;
            power *= beta;
        }
        suffix_sum(&mut weights);
        claims.tip(channel, l.perm2, l.mult2, weights, target)?;
        claims.close(
            channel,
            &self.output,
            l.index_rows,
            &self.index,
            online_tree.as_ref(),
            online_root,
            p.terminal_log,
            p.basefold_queries,
        )
    }

    fn tensor_check(
        &self,
        channel: &mut Channel<'_>,
        claims: &mut Claims<'_>,
        base: Option<&[Scalar]>,
        message: Option<&[Scalar]>,
    ) -> ProofResult<()> {
        let l = &self.layout;
        let inner = self.era.base_code().inner();
        let k = inner.message_size();
        let n = inner.block_length();
        let rx = channel.point(b"tensor-row", n.next_power_of_two().ilog2() as usize);
        let ry = channel.point(b"tensor-column", rx.len());
        let ex = sumcheck::eq_weights(&rx);
        let ey = sumcheck::eq_weights(&ry);
        let base_weights: Vec<_> = (0..n)
            .flat_map(|i| {
                ey[..n].iter().map({
                    let ex = &ex;
                    move |&y| ex[i] * y
                })
            })
            .collect();
        let base_value = channel.field(base.map(|b| sumcheck::dot(b, &base_weights)))?;
        claims.ip(channel, l.base, base_weights, base_value)?;
        let tables = message.map(|m| {
            let g = flatten_family(claims.rows.unwrap(), l.generator);
            let g1: Vec<_> = (0..k)
                .map(|j| (0..n).map(|i| ex[i] * g[i * k + j]).sum::<Scalar>())
                .collect();
            let g2: Vec<_> = (0..k)
                .map(|j| (0..n).map(|i| ey[i] * g[i * k + j]).sum::<Scalar>())
                .collect();
            vec![
                g1.iter().flat_map(|&v| std::iter::repeat_n(v, k)).collect(),
                (0..k).flat_map(|_| g2.iter().copied()).collect(),
                m.to_vec(),
            ]
        });
        let (r, claim, evals) = sumcheck::sumcheck(
            channel,
            tables,
            &[(Scalar::ONE, vec![0, 1, 2])],
            2 * k.ilog2() as usize,
            base_value,
        )?;
        let values = channel.fields(evals.as_deref(), 3)?;
        ensure(values.iter().copied().product::<Scalar>() == claim)?;
        let e1 = sumcheck::eq_weights(&r[..r.len() / 2]);
        let e2 = sumcheck::eq_weights(&r[r.len() / 2..]);
        let g1_weights: Vec<_> = (0..n)
            .flat_map(|i| {
                e1.iter().map({
                    let ex = &ex;
                    move |&e| ex[i] * e
                })
            })
            .collect();
        let g2_weights: Vec<_> = (0..n)
            .flat_map(|i| {
                e2.iter().map({
                    let ey = &ey;
                    move |&e| ey[i] * e
                })
            })
            .collect();
        claims.ip(channel, l.generator, g1_weights, values[0])?;
        claims.ip(channel, l.generator, g2_weights, values[1])?;
        claims.ip(channel, l.message, sumcheck::eq_weights(&r), values[2])
    }

    fn permutation_checks(
        &self,
        channel: &mut Channel<'_>,
        claims: &mut Claims<'_>,
        online: Option<&(Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>)>,
    ) -> ProofResult<()> {
        let l = &self.layout;
        let n = self.era.block_length();
        let base_len = self.era.base_code().block_length();
        // Independent affine label compression and pole challenges. Squaring
        // one challenge is not the logarithmic derivative of a linear product.
        let alpha1 = channel.challenge(b"permutation-1-pole");
        let beta1 = channel.challenge(b"permutation-1-label");
        let alpha2 = channel.challenge(b"permutation-2-pole");
        let beta2 = channel.challenge(b"permutation-2-label");
        let denominators = online.map(|(base, p1, a1, p2)| {
            let (pi1, pi2) = self.era.permutations();
            let mut d = vec![vec![Scalar::ONE; n.next_power_of_two()]; 4];
            for i in 0..n {
                d[0][i] = alpha1 + beta1 * Scalar::from(i as u64) + base[i % base_len];
                d[1][i] = alpha1 + beta1 * Scalar::from(pi1[i] as u64) + p1[i];
                d[2][i] = alpha2 + beta2 * Scalar::from(i as u64) + a1[i];
                d[3][i] = alpha2 + beta2 * Scalar::from(pi2[i] as u64) + p2[i];
            }
            d
        });
        let (r, d) = fractional::prove_or_verify(channel, denominators, n)?;
        let weights = sumcheck::eq_weights(&r);
        let weights = &weights[..n];
        let mask = fractional::prefix_weight(&r, n);
        let id: Scalar = weights
            .iter()
            .enumerate()
            .map(|(i, &w)| Scalar::from(i as u64) * w)
            .sum();
        let values = online.map(|(base, p1, a1, p2)| {
            let (pi1, pi2) = self.era.permutations();
            vec![
                weights
                    .iter()
                    .enumerate()
                    .map(|(i, &w)| w * base[i % base_len])
                    .sum(),
                sumcheck::dot(p1, weights),
                sumcheck::dot(a1, weights),
                sumcheck::dot(p2, weights),
                weights
                    .iter()
                    .zip(pi1)
                    .map(|(&w, &i)| w * Scalar::from(i as u64))
                    .sum(),
                weights
                    .iter()
                    .zip(pi2)
                    .map(|(&w, &i)| w * Scalar::from(i as u64))
                    .sum(),
            ]
        });
        let v = channel.fields(values.as_deref(), 6)?;
        for (j, (alpha, beta, label)) in [
            (alpha1, beta1, id),
            (alpha1, beta1, v[4]),
            (alpha2, beta2, id),
            (alpha2, beta2, v[5]),
        ]
        .into_iter()
        .enumerate()
        {
            ensure(d[j] == alpha * mask + beta * label + v[j] + Scalar::ONE - mask)?;
        }
        let mut repeat = vec![Scalar::ZERO; base_len];
        for (i, &w) in weights.iter().enumerate() {
            repeat[i % base_len] += w;
        }
        claims.ip(channel, l.base, repeat, v[0])?;
        claims.ip(channel, l.perm1, weights.to_vec(), v[1])?;
        let mut acc_weights = weights.to_vec();
        suffix_sum(&mut acc_weights);
        claims.tip(channel, l.perm1, l.mult1, acc_weights, v[2])?;
        claims.ip(channel, l.perm2, weights.to_vec(), v[3])?;
        claims.ip(channel, l.pi1, weights.to_vec(), v[4])?;
        claims.ip(channel, l.pi2, weights.to_vec(), v[5])
    }
}

fn flatten_family(rows: &[Vec<Scalar>], family: Family) -> Vec<Scalar> {
    rows[family.start..family.start + family.rows]
        .iter()
        .flatten()
        .take(family.len)
        .copied()
        .collect()
}
fn suffix_sum(weights: &mut [Scalar]) {
    let mut sum = Scalar::ZERO;
    for w in weights.iter_mut().rev() {
        sum += *w;
        *w = sum;
    }
}

#[derive(Debug)]
struct Claim {
    row1: usize,
    row2: Option<usize>,
    weights: Vec<Scalar>,
    value: Scalar,
}
#[derive(Debug)]
struct Claims<'a> {
    width: usize,
    rows: Option<&'a [Vec<Scalar>]>,
    terms: Vec<Claim>,
}
impl<'a> Claims<'a> {
    fn new(width: usize, rows: Option<&'a [Vec<Scalar>]>) -> Self {
        Self {
            width,
            rows,
            terms: Vec::new(),
        }
    }
    fn ip(
        &mut self,
        ch: &mut Channel<'_>,
        family: Family,
        weights: Vec<Scalar>,
        value: Scalar,
    ) -> ProofResult<()> {
        self.split_claim(ch, family, None, weights, value)
    }
    fn tip(
        &mut self,
        ch: &mut Channel<'_>,
        a: Family,
        b: Family,
        weights: Vec<Scalar>,
        value: Scalar,
    ) -> ProofResult<()> {
        ensure(a.len == b.len)?;
        self.split_claim(ch, a, Some(b), weights, value)
    }
    fn split_claim(
        &mut self,
        ch: &mut Channel<'_>,
        a: Family,
        b: Option<Family>,
        weights: Vec<Scalar>,
        value: Scalar,
    ) -> ProofResult<()> {
        ensure(weights.len() == a.len)?;
        let mut sum = Scalar::ZERO;
        for (i, weights) in split(&weights, self.width).into_iter().enumerate() {
            let part = ch.field(self.rows.map(|rows| {
                weights
                    .iter()
                    .enumerate()
                    .map(|(j, &w)| {
                        w * rows[a.start + i][j] * b.map_or(Scalar::ONE, |b| rows[b.start + i][j])
                    })
                    .sum()
            }))?;
            sum += part;
            self.terms.push(Claim {
                row1: a.start + i,
                row2: b.map(|b| b.start + i),
                weights,
                value: part,
            });
        }
        ensure(sum == value)
    }
    fn close(
        self,
        ch: &mut Channel<'_>,
        setup: &FoldingSetup,
        index_rows: usize,
        index: &Commitment,
        online: Option<&Commitment>,
        online_root: [u8; 32],
        terminal_log: usize,
        queries: usize,
    ) -> ProofResult<()> {
        let row_count = self
            .terms
            .iter()
            .map(|t| t.row1.max(t.row2.unwrap_or(0)))
            .max()
            .unwrap_or(0)
            + 1;
        let beta = ch.challenge(b"constraint-batch");
        let mut power = Scalar::ONE;
        let mut claim = Scalar::ZERO;
        let mut terms = Vec::new();
        for (i, t) in self.terms.iter().enumerate() {
            claim += power * t.value;
            let mut indices = vec![t.row1, row_count + i];
            if let Some(row) = t.row2 {
                indices.push(row);
            }
            terms.push((power, indices));
            power *= beta;
        }
        let tables = self.rows.map(|rows| {
            let mut tables = rows.to_vec();
            tables.extend(self.terms.iter().map(|t| t.weights.clone()));
            tables
        });
        let (r, final_claim, evals) =
            sumcheck::sumcheck(ch, tables, &terms, self.width.ilog2() as usize, claim)?;
        let values = ch.fields(evals.as_ref().map(|v| &v[..row_count]), row_count)?;
        let mut expected = Scalar::ZERO;
        power = Scalar::ONE;
        for t in &self.terms {
            expected += power
                * values[t.row1]
                * t.row2.map_or(Scalar::ONE, |row| values[row])
                * sumcheck::evaluate(&t.weights, &r);
            power *= beta;
        }
        ensure(expected == final_claim)?;
        // Every UNIQUE oracle has its own power. Both factors of a TIP can
        // never cancel under a shared coefficient as in the original figure.
        let gamma = ch.challenge(b"oracle-evaluation-batch");
        power = Scalar::ONE;
        let weights: Vec<_> = (0..row_count)
            .map(|_| {
                let w = power;
                power *= gamma;
                w
            })
            .collect();
        let reduced_value = sumcheck::dot(&values, &weights);
        let message = self.rows.map(|rows| {
            (0..self.width)
                .into_par_iter()
                .map(|j| rows.iter().zip(&weights).map(|(row, &w)| row[j] * w).sum())
                .collect::<Vec<_>>()
        });
        basefold_iopp::prove_or_verify(
            ch,
            setup,
            &[
                Source {
                    root: index.root(),
                    weights: weights[..index_rows].to_vec(),
                    commitment: self.rows.map(|_| index),
                },
                Source {
                    root: online_root,
                    weights: weights[index_rows..].to_vec(),
                    commitment: online,
                },
            ],
            message.as_deref(),
            &r,
            reduced_value,
            terminal_log,
            queries,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_era_iopp_roundtrip_nonpower_shapes_and_tampering() {
        let setup = Setup::new(Parameters {
            message_log: 10,
            eta: 2,
            output_log: 6,
            output_log_rate: 1,
            terminal_log: 2,
            era_queries: 32,
            basefold_queries: 32,
            seed: 42,
        })
        .unwrap();
        let message: Vec<_> = (0..1024).map(|i| Scalar::from(i * i + 17)).collect();
        let point = vec![Scalar::from(5); 10];
        let tree = setup.commit(&message).unwrap();
        let (value, proof) = setup.prove(&tree, &message, &point).unwrap();
        assert!(setup.verify(tree.root(), &point, value, &proof).is_ok());
        for i in (0..proof.len()).step_by((proof.len() / 20).max(1)) {
            let mut bad = proof.clone();
            bad[i] ^= 1;
            assert!(
                setup.verify(tree.root(), &point, value, &bad).is_err(),
                "offset {i}"
            );
        }
        assert!(
            setup
                .verify(tree.root(), &point, value + Scalar::ONE, &proof)
                .is_err()
        );
        assert!(
            setup
                .verify(tree.root(), &point, value, &proof[..proof.len() - 1])
                .is_err()
        );
        let mut extra = proof;
        extra.push(0);
        assert!(setup.verify(tree.root(), &point, value, &extra).is_err());
    }
}
