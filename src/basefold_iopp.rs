//! Recursive BaseFold over the repository's nested Type-1 code family.
//! This is the terminal IOPP for codeswitching, not an upstream Plonky3 fork.
use crate::{
    BasefoldCode, FieldElement,
    proof::{
        Channel, ProofResult, Scalar, ensure,
        merkle::{self, Commitment},
        sumcheck,
    },
};
use p3_maybe_rayon::prelude::*;

#[derive(Debug)]
pub struct FoldingSetup {
    pub code: BasefoldCode<Scalar>,
    inverse_tables: Vec<Vec<Scalar>>,
    inverse_two: Scalar,
}

impl FoldingSetup {
    pub fn new(code: BasefoldCode<Scalar>) -> Self {
        let inverse_tables = (1..=code.message_size().ilog2() as usize)
            .map(|log| {
                let mut table = code.folding_table(log);
                ark_ff::batch_inversion(&mut table);
                table
            })
            .collect();
        Self {
            code,
            inverse_tables,
            inverse_two: FieldElement::inverse(Scalar::from(2)).unwrap(),
        }
    }

    pub fn fold_pair(
        &self,
        log_message: usize,
        index: usize,
        a: Scalar,
        b: Scalar,
        r: Scalar,
    ) -> Scalar {
        let half = self.inverse_two;
        ((Scalar::ONE - r) * (a + b) + r * (a - b) * self.inverse_tables[log_message - 1][index])
            * half
    }
}

/// A virtual oracle is a linear combination of columns of independently
/// committed stacks. Weights are sampled only after the claims are fixed.
#[derive(Debug)]
pub struct Source<'a> {
    pub root: [u8; 32],
    pub weights: Vec<Scalar>,
    pub commitment: Option<&'a Commitment>,
}

pub fn prove_or_verify(
    channel: &mut Channel<'_>,
    setup: &FoldingSetup,
    sources: &[Source<'_>],
    message: Option<&[Scalar]>,
    point: &[Scalar],
    mut claim: Scalar,
    terminal_log: usize,
    query_count: usize,
) -> ProofResult<()> {
    let log_message = setup.code.message_size().ilog2() as usize;
    ensure(point.len() == log_message && terminal_log < log_message && query_count > 0)?;
    let rounds = log_message - terminal_log;
    let mut msg = message.map(<[Scalar]>::to_vec);
    let mut eq_table = message.map(|_| sumcheck::eq_weights(point));
    let mut word = message.map(|_| {
        (0..setup.code.codeword_length())
            .into_par_iter()
            .map(|i| {
                sources
                    .iter()
                    .map(|s| {
                        s.commitment
                            .unwrap()
                            .rows
                            .iter()
                            .zip(&s.weights)
                            .map(|(row, &w)| row[i] * w)
                            .sum::<Scalar>()
                    })
                    .sum::<Scalar>()
            })
            .collect::<Vec<_>>()
    });
    let mut trees = Vec::with_capacity(rounds - 1);
    let mut roots = Vec::with_capacity(rounds - 1);
    let mut challenges = Vec::with_capacity(rounds);
    for round in 0..rounds {
        let poly = msg.as_ref().map(|msg| {
            let weights = eq_table.as_ref().unwrap();
            let half = msg.len() / 2;
            (0..3)
                .map(|t| {
                    let t = Scalar::from(t as u64);
                    (0..half)
                        .into_par_iter()
                        .map(|i| {
                            (msg[i] + t * (msg[i + half] - msg[i]))
                                * (weights[i] + t * (weights[i + half] - weights[i]))
                        })
                        .sum::<Scalar>()
                })
                .collect::<Vec<_>>()
        });
        let poly = channel.fields(poly.as_deref(), 3)?;
        ensure(poly[0] + poly[1] == claim)?;
        let r = channel.challenge(b"basefold-fold");
        challenges.push(r);
        claim = sumcheck::interpolate(&poly, r);
        if let Some(msg) = &mut msg {
            sumcheck::fold(msg, r);
        }
        if let Some(eq) = &mut eq_table {
            sumcheck::fold(eq, r);
        }
        if round + 1 < rounds {
            if let Some(old_word) = word.take() {
                let inverse = &setup.inverse_tables[log_message - round - 1];
                let inv_two = FieldElement::inverse(Scalar::from(2)).unwrap();
                let next: Vec<_> = old_word
                    .par_chunks_exact(2)
                    .zip(inverse.par_iter())
                    .map(|(pair, &t_inv)| {
                        ((Scalar::ONE - r) * (pair[0] + pair[1]) + r * (pair[0] - pair[1]) * t_inv)
                            * inv_two
                    })
                    .collect();
                let tree = Commitment::new(vec![next.clone()]);
                word = Some(next);
                roots.push(channel.bytes(Some(tree.root()))?);
                trees.push(tree);
            } else {
                roots.push(channel.bytes(None)?);
            }
        }
    }
    let terminal = channel.fields(msg.as_deref(), 1 << terminal_log)?;
    ensure(
        sumcheck::eq(&point[..rounds], &challenges)
            * sumcheck::evaluate(&terminal, &point[rounds..])
            == claim,
    )?;
    let mut indices = channel.queries(setup.code.codeword_length() / 2, query_count)?;
    let mut expected: Vec<(usize, Scalar)> = Vec::new();
    for round in 0..rounds {
        let length = setup.code.codeword_length() >> round;
        let mut pair_indices: Vec<_> = indices.iter().flat_map(|&i| [2 * i, 2 * i + 1]).collect();
        pair_indices.sort_unstable();
        pair_indices.dedup();
        let values = if round == 0 {
            let mut values = vec![Scalar::ZERO; pair_indices.len()];
            for source in sources {
                let columns = merkle::open(
                    channel,
                    source.commitment,
                    source.root,
                    source.weights.len(),
                    length,
                    &pair_indices,
                )?;
                for (v, (_, column)) in values.iter_mut().zip(columns) {
                    *v += sumcheck::dot(&column, &source.weights);
                }
            }
            values
        } else {
            merkle::open(
                channel,
                trees.get(round - 1),
                roots[round - 1],
                1,
                length,
                &pair_indices,
            )?
            .into_iter()
            .map(|(_, c)| c[0])
            .collect()
        };
        for (index, value) in expected {
            ensure(
                values[pair_indices
                    .binary_search(&index)
                    .map_err(|_| crate::proof::ProofError::Invalid)?]
                    == value,
            )?;
        }
        expected = pair_indices
            .chunks_exact(2)
            .zip(values.chunks_exact(2))
            .map(|(indices, pair)| {
                (
                    indices[0] / 2,
                    setup.fold_pair(
                        log_message - round,
                        indices[0] / 2,
                        pair[0],
                        pair[1],
                        challenges[round],
                    ),
                )
            })
            .collect();
        for index in &mut indices {
            *index /= 2;
        }
    }
    let encoded_terminal = setup.code.encode_lower(&terminal);
    ensure(
        expected
            .iter()
            .all(|&(i, value)| encoded_terminal[i] == value),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BasefoldParams;
    use rand::{SeedableRng, rngs::SmallRng};

    #[test]
    fn folding_matches_independent_encoding_and_rejects_tampering() {
        let setup = FoldingSetup::new(BasefoldCode::new(
            32,
            BasefoldParams { log_rate: 2 },
            &mut SmallRng::seed_from_u64(1),
        ));
        let message: Vec<_> = (1..=32).map(Scalar::from).collect();
        let encoded = setup.code.encode(&message);
        let r = Scalar::from(19);
        let mut folded = message.clone();
        sumcheck::fold(&mut folded, r);
        assert_eq!(
            setup.code.encode_lower(&folded),
            encoded
                .chunks_exact(2)
                .enumerate()
                .map(|(i, p)| setup.fold_pair(5, i, p[0], p[1], r))
                .collect::<Vec<_>>()
        );
        let tree = Commitment::new(vec![encoded]);
        let point = vec![Scalar::from(7); 5];
        let value = sumcheck::evaluate(&message, &point);
        let mut prover = Channel::new(b"basefold-test", None);
        prove_or_verify(
            &mut prover,
            &setup,
            &[Source {
                root: tree.root(),
                weights: vec![Scalar::ONE],
                commitment: Some(&tree),
            }],
            Some(&message),
            &point,
            value,
            2,
            30,
        )
        .unwrap();
        let bytes = prover.finish().unwrap();
        let verify = |bytes: &[u8]| {
            let mut verifier = Channel::new(b"basefold-test", Some(bytes));
            prove_or_verify(
                &mut verifier,
                &setup,
                &[Source {
                    root: tree.root(),
                    weights: vec![Scalar::ONE],
                    commitment: None,
                }],
                None,
                &point,
                value,
                2,
                30,
            )?;
            verifier.finish()
        };
        assert!(verify(&bytes).is_ok());
        for i in (0..bytes.len()).step_by(32) {
            let mut bad = bytes.clone();
            bad[i] ^= 1;
            assert!(verify(&bad).is_err(), "offset {i}");
        }
    }
}

/// Interleaving and early termination are the optimizations in the paper's
/// baseline. This local implementation is also useful as an ERA component test.
#[derive(Debug, Clone, Copy)]
pub struct InterleavedParameters {
    pub message_log: usize,
    pub eta: usize,
    pub terminal_log: usize,
    pub queries: usize,
    pub code_id: [u8; 32],
}

fn interleaved_execute(
    channel: &mut Channel<'_>,
    setup: &FoldingSetup,
    parameters: InterleavedParameters,
    root: [u8; 32],
    point: &[Scalar],
    value: Scalar,
    witness: Option<(&[Scalar], &Commitment)>,
) -> ProofResult<()> {
    let p = parameters;
    ensure(
        p.eta < p.message_log
            && p.message_log < usize::BITS as usize
            && point.len() == p.message_log,
    )?;
    ensure(setup.code.message_size() == 1usize << (p.message_log - p.eta))?;
    ensure(channel.bytes(Some(*b"AGNBFIv1"))? == *b"AGNBFIv1")?;
    channel.bind(b"code-id", &p.code_id);
    channel.bind(b"root", &root);
    for v in [p.message_log, p.eta, p.terminal_log, p.queries] {
        channel.bind_usize(b"parameter", v);
    }
    channel.bind_fields(b"point", point);
    ensure(channel.field(Some(value))? == value)?;
    let (r, claim, _) = sumcheck::sumcheck(
        channel,
        witness.map(|(m, _)| vec![m.to_vec(), sumcheck::eq_weights(point)]),
        &[(Scalar::ONE, vec![0, 1])],
        p.message_log,
        value,
    )?;
    let weights = sumcheck::eq_weights(&r[..p.eta]);
    let message = witness.map(|(m, _)| crate::interleaved_iopp::fs::fold_rows(m, &weights));
    let value = claim
        * FieldElement::inverse(sumcheck::eq(point, &r))
            .ok_or(crate::proof::ProofError::Invalid)?;
    prove_or_verify(
        channel,
        setup,
        &[Source {
            root,
            weights,
            commitment: witness.map(|(_, t)| t),
        }],
        message.as_deref(),
        &r[p.eta..],
        value,
        p.terminal_log,
        p.queries,
    )
}

pub fn prove_interleaved(
    setup: &FoldingSetup,
    parameters: InterleavedParameters,
    tree: &Commitment,
    message: &[Scalar],
    point: &[Scalar],
) -> ProofResult<(Scalar, Vec<u8>)> {
    ensure(
        parameters.message_log < usize::BITS as usize
            && point.len() == parameters.message_log
            && message.len() == 1usize << parameters.message_log,
    )?;
    let value = sumcheck::evaluate(message, point);
    let mut channel = Channel::new(b"basefold-local-interleaved-v1", None);
    interleaved_execute(
        &mut channel,
        setup,
        parameters,
        tree.root(),
        point,
        value,
        Some((message, tree)),
    )?;
    Ok((value, channel.finish()?))
}

pub fn verify_interleaved(
    setup: &FoldingSetup,
    parameters: InterleavedParameters,
    root: [u8; 32],
    point: &[Scalar],
    value: Scalar,
    proof: &[u8],
) -> ProofResult<()> {
    let mut channel = Channel::new(b"basefold-local-interleaved-v1", Some(proof));
    interleaved_execute(&mut channel, setup, parameters, root, point, value, None)?;
    channel.finish().map(|_| ())
}
