//! Noninteractive evaluation argument, with StartingIOR randomization and exact
//! wire transport. Unlike folding directly at a caller-selected point, the
//! initial sumcheck supplies random row weights even at Boolean public points.
use crate::{
    FieldElement,
    proof::{
        Channel, ProofError, ProofResult, Scalar, ensure,
        merkle::{self, Commitment},
        sumcheck,
    },
};
use p3_maybe_rayon::prelude::*;

#[derive(Debug, Clone, Copy)]
pub struct Parameters {
    pub message_log: usize,
    pub eta: usize,
    pub block_len: usize,
    pub queries: usize,
    /// Public, verifier-selected identifier of the exact code and setup.
    pub code_id: [u8; 32],
}

impl Parameters {
    fn validate(self, point: &[Scalar]) -> ProofResult<()> {
        ensure(self.eta <= self.message_log && self.message_log < usize::BITS as usize)?;
        ensure(point.len() == self.message_log && self.block_len > 0 && self.queries > 0)?;
        ensure(self.block_len.checked_next_power_of_two().is_some())
    }
}

/// Parallelize over disjoint message-column tiles; the row loop retains locality.
#[must_use]
pub fn fold_rows(message: &[Scalar], weights: &[Scalar]) -> Vec<Scalar> {
    assert!(message.len().is_multiple_of(weights.len()));
    let width = message.len() / weights.len();
    let mut result = vec![Scalar::ZERO; width];
    result
        .par_chunks_mut(256)
        .enumerate()
        .for_each(|(tile, output)| {
            let start = tile * 256;
            let end = start + output.len();
            for (row, &weight) in message.chunks_exact(width).zip(weights) {
                for (value, &input) in output.iter_mut().zip(&row[start..end]) {
                    *value += weight * input;
                }
            }
        });
    result
}

fn execute(
    channel: &mut Channel<'_>,
    parameters: Parameters,
    root: [u8; 32],
    point: &[Scalar],
    claimed_value: Scalar,
    witness: Option<(&[Scalar], &Commitment)>,
    encode: impl Fn(&[Scalar]) -> Vec<Scalar>,
) -> ProofResult<()> {
    parameters.validate(point)?;
    let rows = 1usize << parameters.eta;
    let width = 1usize << (parameters.message_log - parameters.eta);
    if let Some((message, tree)) = witness {
        ensure(message.len() == rows * width && tree.rows.len() == rows)?;
        ensure(tree.rows.iter().all(|r| r.len() == parameters.block_len))?;
        ensure(tree.root() == root)?;
    }
    ensure(channel.bytes(Some(*b"AGNIFSv1"))? == *b"AGNIFSv1")?;
    channel.bind(b"code", &parameters.code_id);
    channel.bind_usize(b"message-log", parameters.message_log);
    channel.bind_usize(b"eta", parameters.eta);
    channel.bind_usize(b"block-len", parameters.block_len);
    channel.bind_usize(b"queries", parameters.queries);
    channel.bind(b"root", &root);
    channel.bind_fields(b"point", point);
    ensure(channel.field(Some(claimed_value))? == claimed_value)?;
    let (random_point, final_claim, _) = sumcheck::sumcheck(
        channel,
        witness.map(|(message, _)| vec![message.to_vec(), sumcheck::eq_weights(point)]),
        &[(Scalar::ONE, vec![0, 1])],
        parameters.message_log,
        claimed_value,
    )?;
    let weights = sumcheck::eq_weights(&random_point[..parameters.eta]);
    let folded = witness.map(|(message, _)| fold_rows(message, &weights));
    let folded = channel.fields(folded.as_deref(), width)?;
    ensure(
        sumcheck::eq(point, &random_point)
            * sumcheck::evaluate(&folded, &random_point[parameters.eta..])
            == final_claim,
    )?;
    let queries = channel.queries(parameters.block_len, parameters.queries)?;
    let columns = merkle::open(
        channel,
        witness.map(|(_, tree)| tree),
        root,
        rows,
        parameters.block_len,
        &queries,
    )?;
    // Proving does not repeat the verifier's encoding work.
    if witness.is_none() {
        let codeword = encode(&folded);
        ensure(codeword.len() == parameters.block_len)?;
        ensure(
            columns
                .par_iter()
                .all(|(index, column)| sumcheck::dot(column, &weights) == codeword[*index]),
        )?;
    }
    Ok(())
}

pub fn prove(
    parameters: Parameters,
    commitment: &Commitment,
    message: &[Scalar],
    point: &[Scalar],
) -> ProofResult<(Scalar, Vec<u8>)> {
    parameters.validate(point)?;
    ensure(message.len() == 1usize << parameters.message_log)?;
    let value = sumcheck::evaluate(message, point);
    let mut channel = Channel::new(b"interleaved-evaluation-v1", None);
    execute(
        &mut channel,
        parameters,
        commitment.root(),
        point,
        value,
        Some((message, commitment)),
        |_| unreachable!(),
    )?;
    Ok((value, channel.finish()?))
}

pub fn verify(
    parameters: Parameters,
    root: [u8; 32],
    point: &[Scalar],
    value: Scalar,
    proof: &[u8],
    encode: impl Fn(&[Scalar]) -> Vec<Scalar>,
) -> ProofResult<()> {
    // The minimum proof length prevents malformed large parameters allocating
    // large tables before the parser can reject a tiny adversarial proof.
    parameters.validate(point)?;
    let width = 1usize << (parameters.message_log - parameters.eta);
    ensure(width <= proof.len() / 32)?;
    ensure((1usize << parameters.eta) <= proof.len() / 32)?;
    ensure(parameters.queries <= 1 << 20)?;
    let mut channel = Channel::new(b"interleaved-evaluation-v1", Some(proof));
    execute(&mut channel, parameters, root, point, value, None, encode)?;
    channel
        .finish()
        .map(|_| ())
        .map_err(|_| ProofError::Invalid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EraCode, ErrorCorrectingCode, IdentityCode};

    #[test]
    fn adapted_bolt_uses_the_shared_serialized_argument() {
        use crate::BoltCode;
        use rand::{SeedableRng, rngs::SmallRng};
        for code in [
            BoltCode::new(32, &mut SmallRng::seed_from_u64(2025)),
            BoltCode::new_max(32, &mut SmallRng::seed_from_u64(2025)),
        ] {
            let message: Vec<_> = (0..128).map(|i| Scalar::from(i * i + 3)).collect();
            let parameters = Parameters {
                message_log: 7,
                eta: 2,
                block_len: code.block_length(),
                queries: 96,
                code_id: [42; 32],
            };
            let tree = Commitment::new(message.chunks_exact(32).map(|m| code.encode(m)).collect());
            for point in [vec![Scalar::ZERO; 7], vec![Scalar::from(9); 7]] {
                let (value, proof) = prove(parameters, &tree, &message, &point).unwrap();
                let check = |bytes: &[u8]| {
                    verify(parameters, tree.root(), &point, value, bytes, |m| {
                        code.encode(m)
                    })
                };
                check(&proof).unwrap();
                for index in [0, 8, 40, proof.len() / 2, proof.len() - 1] {
                    let mut bad = proof.clone();
                    bad[index] ^= 1;
                    assert!(check(&bad).is_err());
                }
                assert!(check(&proof[..proof.len() - 1]).is_err());
                let mut trailing = proof.clone();
                trailing.push(0);
                assert!(check(&trailing).is_err());
                let mut wrong_setup = parameters;
                wrong_setup.code_id[0] ^= 1;
                assert!(
                    verify(wrong_setup, tree.root(), &point, value, &proof, |m| code
                        .encode(m))
                    .is_err()
                );
                assert!(
                    verify(
                        parameters,
                        tree.root(),
                        &point,
                        value + Scalar::ONE,
                        &proof,
                        |m| code.encode(m)
                    )
                    .is_err()
                );
                #[cfg(feature = "parallel")]
                {
                    let run = |threads| {
                        rayon::ThreadPoolBuilder::new()
                            .num_threads(threads)
                            .build()
                            .unwrap()
                            .install(|| {
                                let tree = Commitment::new(
                                    message.chunks_exact(32).map(|m| code.encode(m)).collect(),
                                );
                                (
                                    tree.root(),
                                    prove(parameters, &tree, &message, &point).unwrap().1,
                                )
                            })
                    };
                    assert_eq!(run(1), run(4));
                }
            }
        }
    }

    #[test]
    fn fiat_shamir_roundtrip_and_adversarial_transport() {
        let code = EraCode::new(
            IdentityCode::new(4),
            3,
            (0..12).rev().collect(),
            (0..12).map(|i| (i + 1) % 12).collect(),
            vec![Scalar::from(2); 12],
            vec![Scalar::from(3); 12],
        );
        let message: Vec<_> = (1..=16).map(Scalar::from).collect();
        let tree = Commitment::new(
            message
                .chunks_exact(4)
                .map(|row| code.encode(row))
                .collect(),
        );
        let parameters = Parameters {
            message_log: 4,
            eta: 2,
            block_len: 12,
            queries: 100,
            code_id: [7; 32],
        };
        for point in [vec![Scalar::ZERO; 4], vec![Scalar::from(3); 4]] {
            let (value, proof) = prove(parameters, &tree, &message, &point).unwrap();
            let check = |bytes: &[u8]| {
                verify(parameters, tree.root(), &point, value, bytes, |m| {
                    code.encode(m)
                })
            };
            assert!(check(&proof).is_ok());
            assert_eq!(prove(parameters, &tree, &message, &point).unwrap().1, proof);
            for i in [0, 8, 40, proof.len() / 2, proof.len() - 1] {
                let mut tampered = proof.clone();
                tampered[i] ^= 1;
                assert!(check(&tampered).is_err());
            }
            for len in [0, 8, 40, proof.len() - 1] {
                assert!(check(&proof[..len]).is_err());
            }
            let mut trailing = proof.clone();
            trailing.push(0);
            assert!(check(&trailing).is_err());
            let mut noncanonical = proof.clone();
            noncanonical[8..40].fill(255);
            assert!(check(&noncanonical).is_err());
            assert!(
                verify(
                    parameters,
                    tree.root(),
                    &point,
                    value + Scalar::ONE,
                    &proof,
                    |m| code.encode(m)
                )
                .is_err()
            );
            let mut changed = parameters;
            changed.code_id[0] ^= 1;
            assert!(
                verify(changed, tree.root(), &point, value, &proof, |m| code
                    .encode(m))
                .is_err()
            );
        }
    }

    #[cfg(feature = "parallel")]
    #[test]
    fn proof_is_identical_across_thread_counts() {
        let message: Vec<_> = (0..1024).map(Scalar::from).collect();
        let point = vec![Scalar::from(11); 10];
        let parameters = Parameters {
            message_log: 10,
            eta: 2,
            block_len: 256,
            queries: 50,
            code_id: [3; 32],
        };
        let run = |threads| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap()
                .install(|| {
                    let tree = Commitment::new(
                        message.chunks_exact(256).map(<[Scalar]>::to_vec).collect(),
                    );
                    let (value, proof) = prove(parameters, &tree, &message, &point).unwrap();
                    verify(
                        parameters,
                        tree.root(),
                        &point,
                        value,
                        &proof,
                        <[Scalar]>::to_vec,
                    )
                    .unwrap();
                    (tree.root(), proof)
                })
        };
        assert_eq!(run(1), run(4));
    }
}
