//! One ERA codeswitch followed by recursive BaseFold. Uses two independent
//! multiplier vectors, batched logUp-GKR, early stack commitments and unique
//! per-oracle batching coefficients. Packed non-power-of-two vectors are padded
//! only inside split messages, never inside the ERA code's physical word.
use crate::{
    BasefoldCode, BasefoldParams, BrakedownBaseCase, BrakedownCode, BrakedownParams, EraCode,
    ErrorCorrectingCode, FieldElement, TensorCode,
    basefold_iopp::{self, FoldingSetup, Source},
    interleaved_iopp::fs::fold_rows,
    proof::{
        Channel, ProofResult, Scalar, ensure, fractional,
        merkle::{self, Commitment},
        sumcheck,
        weights::{Weights, prefix_index_moment},
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
    gkr_checkpoints: Vec<usize>,
}

#[derive(Debug)]
struct CheckpointCommitment {
    root: [u8; 32],
    tree: Option<Commitment>,
    rows: usize,
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

enum CommitmentWitness<'a> {
    Borrowed(&'a Commitment),
    Owned(Commitment),
}

impl CommitmentWitness<'_> {
    fn tree(&self) -> &Commitment {
        match self {
            Self::Borrowed(tree) => tree,
            Self::Owned(tree) => tree,
        }
    }
}

impl Setup {
    pub fn new(parameters: Parameters) -> ProofResult<Self> {
        Self::new_with_checkpoints(parameters, Vec::new())
    }

    /// Opt-in checkpointed GKR. An empty list preserves the original transcript.
    pub fn new_with_checkpoints(
        parameters: Parameters,
        gkr_checkpoints: Vec<usize>,
    ) -> ProofResult<Self> {
        Self::new_with_base_code(
            parameters,
            gkr_checkpoints,
            BrakedownParams {
                alpha: 0.05,
                inverse_rate: 1.1,
                cn: 6,
                dn: 40,
            },
            BrakedownBaseCase::ReedSolomon,
        )
    }

    /// Explicit alternative base code. The trusted index commitment binds its
    /// actual generator matrix. Callers must recalibrate distance/query bounds.
    pub fn new_with_base_code(
        parameters: Parameters,
        gkr_checkpoints: Vec<usize>,
        base_parameters: BrakedownParams,
        base_case: BrakedownBaseCase,
    ) -> ProofResult<Self> {
        let p = parameters;
        ensure(p.eta < p.message_log && p.message_log < 32)?;
        let row_log = p.message_log - p.eta;
        ensure(
            row_log.is_multiple_of(2) && p.output_log < row_log && p.terminal_log < p.output_log,
        )?;
        ensure(p.output_log_rate <= 5 && p.era_queries > 0 && p.basefold_queries > 0)?;
        ensure(
            base_parameters.alpha.is_finite()
                && base_parameters.inverse_rate.is_finite()
                && base_parameters.alpha > 0.0
                && base_parameters.alpha < 1.0
                && base_parameters.inverse_rate > 1.0
                && base_parameters.cn > 0
                && base_parameters.dn > 0,
        )?;
        // Reject invalid rounded recursive shapes before the encoder's asserts.
        let mut size = 1usize << (row_log / 2);
        loop {
            let length = size as f64 * base_parameters.inverse_rate;
            ensure(length <= f64::from(u32::MAX))?;
            let child = (size as f64 * base_parameters.alpha).ceil() as usize;
            let child_length = (child as f64 * base_parameters.inverse_rate) as usize;
            let parity = (length as usize)
                .checked_sub(size + child_length)
                .ok_or(crate::proof::ProofError::Invalid)?;
            if size <= 32 || child < base_parameters.cn || parity < base_parameters.dn {
                break;
            }
            ensure(child < size)?;
            size = child;
        }
        let width = 1usize << p.output_log;
        let mut rng = SmallRng::seed_from_u64(p.seed);
        let inner = BrakedownCode::new_with_base_case(
            1 << (row_log / 2),
            base_parameters,
            base_case,
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
        if !gkr_checkpoints.is_empty() {
            fractional::checkpointed::Layout::new(
                length.next_power_of_two().ilog2() as usize,
                &gkr_checkpoints,
            )?;
        }
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
        let index = Commitment::new(output.code.encode_batch(&index_messages));
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
            gkr_checkpoints,
        })
    }

    pub fn checkpoint_rows(&self) -> usize {
        if self.gkr_checkpoints.is_empty() {
            return 0;
        }
        fractional::checkpointed::Layout::new(
            self.era.block_length().next_power_of_two().ilog2() as usize,
            &self.gkr_checkpoints,
        )
        .unwrap()
        .len
        .div_ceil(1 << self.parameters.output_log)
    }

    fn domain(&self) -> &'static [u8] {
        if self.gkr_checkpoints.is_empty() {
            b"era-codeswitch-v1"
        } else {
            b"era-codeswitch-checkpoints-v1"
        }
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
        let magic = if self.gkr_checkpoints.is_empty() {
            *b"AGNERAv1"
        } else {
            *b"AGNERAc1"
        };
        ensure(channel.bytes(Some(magic))? == magic)?;
        if !self.gkr_checkpoints.is_empty() {
            channel.bind_usize(b"checkpoint-count", self.gkr_checkpoints.len());
            for &depth in &self.gkr_checkpoints {
                channel.bind_usize(b"checkpoint-depth", depth);
            }
        }
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
        let (value, proof, _) = self.prove_with_profile(tree, message, point, false)?;
        Ok((value, proof))
    }

    /// Same proof and transcript as `prove`, with optional stage measurements.
    pub fn prove_with_profile(
        &self,
        tree: &Commitment,
        message: &[Scalar],
        point: &[Scalar],
        enabled: bool,
    ) -> ProofResult<(Scalar, Vec<u8>, crate::proof::profile::Profile)> {
        self.prove_witness(CommitmentWitness::Borrowed(tree), message, point, enabled)
    }

    /// Consume the original commitment and release it after its last opening.
    /// The caller can retain `tree.root()` for verification. Proof bytes are
    /// identical to the borrowed API, including when profiling is enabled.
    pub fn prove_consuming_with_profile(
        &self,
        tree: Commitment,
        message: &[Scalar],
        point: &[Scalar],
        enabled: bool,
    ) -> ProofResult<(Scalar, Vec<u8>, crate::proof::profile::Profile)> {
        self.prove_witness(CommitmentWitness::Owned(tree), message, point, enabled)
    }

    fn prove_witness(
        &self,
        tree: CommitmentWitness<'_>,
        message: &[Scalar],
        point: &[Scalar],
        enabled: bool,
    ) -> ProofResult<(Scalar, Vec<u8>, crate::proof::profile::Profile)> {
        let mut channel = Channel::new(self.domain(), None);
        if enabled {
            channel.enable_profile();
        }
        let total = channel.profile_start("prove");
        ensure(
            point.len() == self.parameters.message_log
                && message.len() == 1usize << self.parameters.message_log,
        )?;
        let span = channel.profile_start("public_evaluation");
        let evaluation_weights = sumcheck::eq_weights(point);
        let value = sumcheck::dot(message, &evaluation_weights);
        channel.profile_end(span);
        self.execute(
            &mut channel,
            tree.tree().root(),
            point,
            value,
            Some((message, tree)),
            Some(evaluation_weights),
        )?;
        channel.profile_end(total);
        let (proof, profile) = channel.finish_profiled()?;
        Ok((value, proof, profile))
    }

    pub fn verify(
        &self,
        root: [u8; 32],
        point: &[Scalar],
        value: Scalar,
        bytes: &[u8],
    ) -> ProofResult<()> {
        self.verify_with_profile(root, point, value, bytes, false)
            .map(|_| ())
    }

    /// Profile verifier work separately; it reads exactly the same proof bytes.
    pub fn verify_with_profile(
        &self,
        root: [u8; 32],
        point: &[Scalar],
        value: Scalar,
        bytes: &[u8],
        enabled: bool,
    ) -> ProofResult<crate::proof::profile::Profile> {
        let mut channel = Channel::new(self.domain(), Some(bytes));
        if enabled {
            channel.enable_profile();
        }
        let total = channel.profile_start("verify");
        self.execute(&mut channel, root, point, value, None, None)?;
        channel.profile_end(total);
        channel.finish_profiled().map(|(_, profile)| profile)
    }

    fn execute(
        &self,
        channel: &mut Channel<'_>,
        root: [u8; 32],
        point: &[Scalar],
        value: Scalar,
        witness: Option<(&[Scalar], CommitmentWitness<'_>)>,
        evaluation_weights: Option<Vec<Scalar>>,
    ) -> ProofResult<()> {
        let span = channel.profile_start("header");
        self.bind(channel, root, point, value)?;
        channel.profile_end(span);
        let p = self.parameters;
        let l = &self.layout;
        let width = 1 << p.output_log;
        let span = channel.profile_start("starting_sumcheck");
        let (r, final_claim, _) = sumcheck::sumcheck(
            channel,
            witness.as_ref().map(|(m, _)| {
                vec![
                    m.to_vec(),
                    evaluation_weights.unwrap_or_else(|| sumcheck::eq_weights(point)),
                ]
            }),
            &[(Scalar::ONE, vec![0, 1])],
            p.message_log,
            value,
        )?;
        channel.profile_end(span);
        let span = channel.profile_start("interleaved_row_fold");
        let eq = sumcheck::eq(point, &r);
        let reduced_value =
            final_claim * FieldElement::inverse(eq).ok_or(crate::proof::ProofError::Invalid)?;
        let row_weights = sumcheck::eq_weights(&r[..p.eta]);
        let folded = witness.as_ref().map(|(m, _)| fold_rows(m, &row_weights));
        channel.profile_end(span);
        let span = channel.profile_start("auxiliary_witness");
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
        channel.profile_end(span);
        let span = channel.profile_start("online_commitment");
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
            let encoding = channel.profile_start("encode");
            let encoded = self.output.code.encode_batch(rows);
            channel.profile_end(encoding);
            let hashing = channel.profile_start("merkle");
            let tree = Commitment::new(encoded);
            channel.profile_end(hashing);
            tree
        });
        let online_root = channel.bytes(online_tree.as_ref().map(Commitment::root))?;
        channel.profile_end(span);
        let span = channel.profile_start("initial_claims_and_oods");
        let all_messages = online_messages.as_ref().map(|rows| {
            self.index_messages
                .iter()
                .chain(rows)
                .map(Vec::as_slice)
                .collect::<Vec<_>>()
        });
        let mut claims = Claims::new(width, all_messages.as_deref());
        claims.ip(
            channel,
            l.message,
            Weights::equality(&r[p.eta..], l.message.len, claims.rows.is_some()),
            reduced_value,
        )?;
        // One OOD evaluation per split online oracle avoids relying on unproved
        // uniqueness of a packed family's zero-padded representation.
        for row in l.index_rows..l.rows {
            let z = channel.point(b"online-ood", p.output_log);
            let weights = Weights::equality(&z, width, claims.rows.is_some());
            let y = channel.field(
                all_messages
                    .as_ref()
                    .map(|rows| weights.dot(rows[row], None)),
            )?;
            claims.terms.push(Claim {
                row1: row,
                row2: None,
                weights,
                value: y,
            });
        }
        channel.profile_end(span);
        let span = channel.profile_start("era_openings");
        let queries = channel.queries(self.era.block_length(), p.era_queries)?;
        let columns = merkle::open(
            channel,
            witness.as_ref().map(|(_, t)| t.tree()),
            root,
            1 << p.eta,
            self.era.block_length(),
            &queries,
        )?;
        // No subsequent step reads the original commitment or message. In the
        // consuming API, free the encoded rows and Merkle nodes before GKR and
        // the terminal BaseFold proof allocate their large working tables.
        drop(witness);
        let answers: Vec<_> = queries
            .iter()
            .map(|i| {
                sumcheck::dot(
                    &columns[columns.binary_search_by_key(i, |c| c.0).unwrap()].1,
                    &row_weights,
                )
            })
            .collect();
        channel.profile_end(span);
        let span = channel.profile_start("tensor_check");
        self.tensor_check(
            channel,
            &mut claims,
            online_values.as_ref().map(|v| v.0.as_slice()),
            folded.as_deref(),
        )?;
        channel.profile_end(span);
        let span = channel.profile_start("permutation_checks");
        let checkpoint = self.permutation_checks(channel, &mut claims, online_values.as_ref())?;
        channel.profile_end(span);
        let span = channel.profile_start("accumulator_claims");
        // Directly emulate the queried final accumulator. Duplicate query
        // coefficients ADD; overwriting would break honest repeated queries.
        let beta = channel.challenge(b"codeswitch-query-batch");
        let mut power = Scalar::ONE;
        let mut target = Scalar::ZERO;
        let mut entries = Vec::with_capacity(queries.len());
        for (&index, &answer) in queries.iter().zip(&answers) {
            entries.push((index, power));
            target += power * answer;
            power *= beta;
        }
        let weights =
            Weights::sparse_suffix(entries, self.era.block_length(), claims.rows.is_some());
        claims.tip(channel, l.perm2, l.mult2, weights, target)?;
        channel.profile_end(span);
        let span = channel.profile_start("claim_reduction");
        claims.close(
            channel,
            &self.output,
            l.index_rows,
            &self.index,
            online_tree.as_ref(),
            online_root,
            checkpoint.as_ref(),
            p.terminal_log,
            p.basefold_queries,
        )?;
        channel.profile_end(span);
        Ok(())
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
        let base_weights = Weights::tensor(&rx, &ry, n, n, claims.rows.is_some());
        let base_value = channel.field(base.map(|b| base_weights.dot(b, None)))?;
        claims.ip(channel, l.base, base_weights, base_value)?;
        let tables = message.map(|m| {
            let ex = sumcheck::eq_weights(&rx);
            let ey = sumcheck::eq_weights(&ry);
            let g = flatten_family(claims.rows.unwrap(), l.generator);
            let g1: Vec<_> = (0..k)
                .into_par_iter()
                .map(|j| (0..n).map(|i| ex[i] * g[i * k + j]).sum::<Scalar>())
                .collect();
            let g2: Vec<_> = (0..k)
                .into_par_iter()
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
        let prover = claims.rows.is_some();
        let g1_weights = Weights::tensor(&rx, &r[..r.len() / 2], n, k, prover);
        let g2_weights = Weights::tensor(&ry, &r[r.len() / 2..], n, k, prover);
        claims.ip(channel, l.generator, g1_weights, values[0])?;
        claims.ip(channel, l.generator, g2_weights, values[1])?;
        claims.ip(
            channel,
            l.message,
            Weights::equality(&r, l.message.len, prover),
            values[2],
        )
    }

    fn permutation_checks(
        &self,
        channel: &mut Channel<'_>,
        claims: &mut Claims<'_>,
        online: Option<&(Vec<Scalar>, Vec<Scalar>, Vec<Scalar>, Vec<Scalar>)>,
    ) -> ProofResult<Option<CheckpointCommitment>> {
        let l = &self.layout;
        let n = self.era.block_length();
        let base_len = self.era.base_code().block_length();
        // Independent affine label compression and pole challenges. Squaring
        // one challenge is not the logarithmic derivative of a linear product.
        let alpha1 = channel.challenge(b"permutation-1-pole");
        let beta1 = channel.challenge(b"permutation-1-label");
        let alpha2 = channel.challenge(b"permutation-2-pole");
        let beta2 = channel.challenge(b"permutation-2-label");
        let span = channel.profile_start("denominators");
        let denominators = online.map(|(base, p1, a1, p2)| {
            let (pi1, pi2) = self.era.permutations();
            (0..4)
                .into_par_iter()
                .map(|j| {
                    (0..n.next_power_of_two())
                        .into_par_iter()
                        .map(|i| {
                            if i >= n {
                                return Scalar::ONE;
                            }
                            match j {
                                0 => alpha1 + beta1 * Scalar::from(i as u64) + base[i % base_len],
                                1 => alpha1 + beta1 * Scalar::from(pi1[i] as u64) + p1[i],
                                2 => alpha2 + beta2 * Scalar::from(i as u64) + a1[i],
                                _ => alpha2 + beta2 * Scalar::from(pi2[i] as u64) + p2[i],
                            }
                        })
                        .collect()
                })
                .collect()
        });
        channel.profile_end(span);
        let span = channel.profile_start("logup_gkr");
        let (r, d, checkpoint) = if self.gkr_checkpoints.is_empty() {
            let (r, d) = fractional::prove_or_verify(channel, denominators, n)?;
            (r, d, None)
        } else {
            let layout = fractional::checkpointed::Layout::new(
                n.next_power_of_two().ilog2() as usize,
                &self.gkr_checkpoints,
            )?;
            let phase = channel.profile_start("fraction_trees");
            let witness = denominators
                .map(|d| fractional::checkpointed::Witness::new(d, n))
                .transpose()?;
            channel.profile_end(phase);
            let phase = channel.profile_start("checkpoint_commitment");
            let pack = channel.profile_start("pack");
            let messages = witness
                .as_ref()
                .map(|w| split(&w.pack(&layout), claims.width));
            channel.profile_end(pack);
            let encode = channel.profile_start("encode");
            let words = messages
                .as_ref()
                .map(|rows| self.output.code.encode_batch(rows));
            channel.profile_end(encode);
            let hash = channel.profile_start("merkle");
            let tree = words.map(Commitment::new);
            channel.profile_end(hash);
            let root = channel.bytes(tree.as_ref().map(Commitment::root))?;
            let count = layout.len.div_ceil(claims.width);
            claims.extra_rows = messages.unwrap_or_default();
            channel.profile_end(phase);
            // Checkpoint oracles are committed after the permutation challenges,
            // but before OODs, checkpoint points, batching or child challenges.
            let phase = channel.profile_start("checkpoint_oods");
            for row in l.rows..l.rows + count {
                let z = channel.point(b"checkpoint-ood", self.parameters.output_log);
                let weights = Weights::equality(&z, claims.width, claims.rows.is_some());
                let value =
                    channel.field(claims.rows.map(|_| weights.dot(claims.row(row), None)))?;
                claims.terms.push(Claim {
                    row1: row,
                    row2: None,
                    weights,
                    value,
                });
            }
            channel.profile_end(phase);
            let output =
                fractional::checkpointed::prove_or_verify(channel, witness.as_ref(), &layout, n)?;
            let phase = channel.profile_start("checkpoint_authentication_claims");
            // Both ends of EVERY segment must be tied to the SAME committed
            // checkpoint arrays. GKR's boundary claims alone are insufficient.
            ensure(output.evaluations.len() == 16 * self.gkr_checkpoints.len())?;
            for evaluation in output.evaluations {
                let entry = &layout.entries[evaluation.entry];
                claims.packed_ip(
                    channel,
                    l.rows,
                    entry.offset,
                    Weights::equality(
                        &evaluation.point,
                        1 << evaluation.point.len(),
                        claims.rows.is_some(),
                    ),
                    evaluation.value,
                )?;
            }
            channel.profile_end(phase);
            (
                output.point,
                output.denominators,
                Some(CheckpointCommitment {
                    root,
                    tree,
                    rows: count,
                }),
            )
        };
        channel.profile_end(span);
        let span = channel.profile_start("terminal_linear_claims");
        let prover = online.is_some();
        let weights = Weights::equality(&r, n, prover);
        let mask = fractional::prefix_weight(&r, n);
        let id = prefix_index_moment(&r, n);
        let values = online.map(|(base, p1, a1, p2)| {
            let (pi1, pi2) = self.era.permutations();
            let w = weights.dense();
            vec![
                w.par_iter()
                    .enumerate()
                    .map(|(i, &w)| w * base[i % base_len])
                    .sum(),
                sumcheck::dot(p1, w),
                sumcheck::dot(a1, w),
                sumcheck::dot(p2, w),
                w.par_iter()
                    .zip(pi1.par_iter())
                    .map(|(&w, &i)| w * Scalar::from(i as u64))
                    .sum(),
                w.par_iter()
                    .zip(pi2.par_iter())
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
        claims.ip(
            channel,
            l.base,
            Weights::repeat(&r, base_len, 4, prover),
            v[0],
        )?;
        claims.ip(channel, l.perm1, weights.clone(), v[1])?;
        claims.tip(
            channel,
            l.perm1,
            l.mult1,
            Weights::suffix(&r, n, prover),
            v[2],
        )?;
        claims.ip(channel, l.perm2, weights.clone(), v[3])?;
        claims.ip(channel, l.pi1, weights.clone(), v[4])?;
        claims.ip(channel, l.pi2, weights, v[5])?;
        channel.profile_end(span);
        Ok(checkpoint)
    }
}

fn flatten_family(rows: &[&[Scalar]], family: Family) -> Vec<Scalar> {
    rows[family.start..family.start + family.rows]
        .iter()
        .flat_map(|row| row.iter())
        .take(family.len)
        .copied()
        .collect()
}
#[derive(Debug)]
struct Claim {
    row1: usize,
    row2: Option<usize>,
    weights: Weights,
    value: Scalar,
}
#[derive(Debug)]
struct Claims<'a> {
    width: usize,
    rows: Option<&'a [&'a [Scalar]]>,
    extra_rows: Vec<Vec<Scalar>>,
    terms: Vec<Claim>,
}
impl<'a> Claims<'a> {
    fn new(width: usize, rows: Option<&'a [&'a [Scalar]]>) -> Self {
        Self {
            width,
            rows,
            extra_rows: Vec::new(),
            terms: Vec::new(),
        }
    }
    fn row(&self, index: usize) -> &[Scalar] {
        let rows = self.rows.unwrap();
        if index < rows.len() {
            rows[index]
        } else {
            &self.extra_rows[index - rows.len()]
        }
    }

    /// Evaluation of a subarray of the tightly packed checkpoint stack.
    /// Only touched rows contribute claims; a one-row claim needs no extra
    /// scalar because its claimed value is already in the GKR transcript.
    fn packed_ip(
        &mut self,
        ch: &mut Channel<'_>,
        start_row: usize,
        offset: usize,
        weights: Weights,
        value: Scalar,
    ) -> ProofResult<()> {
        ensure(weights.len() > 0)?;
        let first = offset / self.width;
        let last = (offset + weights.len() - 1) / self.width;
        let mut sum = Scalar::ZERO;
        for row in first..=last {
            let begin = offset.max(row * self.width);
            let end = (offset + weights.len()).min((row + 1) * self.width);
            let w = weights.slice(begin - offset, end - begin, begin - row * self.width);
            let part = if first == last {
                value
            } else {
                ch.field(self.rows.map(|_| w.dot(self.row(start_row + row), None)))?
            };
            sum += part;
            self.terms.push(Claim {
                row1: start_row + row,
                row2: None,
                weights: w,
                value: part,
            });
        }
        ensure(sum == value)
    }

    fn ip(
        &mut self,
        ch: &mut Channel<'_>,
        family: Family,
        weights: Weights,
        value: Scalar,
    ) -> ProofResult<()> {
        self.split_claim(ch, family, None, weights, value)
    }
    fn tip(
        &mut self,
        ch: &mut Channel<'_>,
        a: Family,
        b: Family,
        weights: Weights,
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
        weights: Weights,
        value: Scalar,
    ) -> ProofResult<()> {
        ensure(weights.len() == a.len)?;
        let mut sum = Scalar::ZERO;
        for i in 0..a.rows {
            let start = i * self.width;
            let weights = weights.slice(start, self.width.min(a.len - start), 0);
            let part = ch.field(
                self.rows
                    .map(|rows| weights.dot(rows[a.start + i], b.map(|b| rows[b.start + i]))),
            )?;
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
        checkpoint: Option<&CheckpointCommitment>,
        terminal_log: usize,
        queries: usize,
    ) -> ProofResult<()> {
        let span = ch.profile_start("build_tables");
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
        // Linearity of the MLE lets claims with the same witness factors
        // share a public weight table, without changing the batched polynomial.
        let mut grouped =
            std::collections::BTreeMap::<(usize, Option<usize>), Vec<(Scalar, Weights)>>::new();
        for t in self.terms {
            claim += power * t.value;
            grouped
                .entry((t.row1, t.row2))
                .or_default()
                .push((power, t.weights));
            power *= beta;
        }
        let mut grouped: Vec<_> = grouped.into_iter().collect();
        let terms: Vec<_> = grouped
            .iter()
            .enumerate()
            .map(|(i, ((a, b), _))| {
                let mut indices = vec![*a, row_count + i];
                if let Some(b) = b {
                    indices.push(*b);
                }
                (Scalar::ONE, indices)
            })
            .collect();
        let tables = self.rows.map(|rows| {
            let mut tables: Vec<_> = rows.par_iter().map(|r| r.to_vec()).collect();
            tables.extend(self.extra_rows.iter().cloned());
            // Move each dense combined weight into sumcheck; keep only shared
            // source descriptions for the independent compact endpoint check.
            tables.extend(
                grouped
                    .par_iter()
                    .map(|(_, entries)| {
                        let mut w = vec![Scalar::ZERO; self.width];
                        for (scale, weights) in entries {
                            weights.add_scaled(&mut w, *scale);
                        }
                        w
                    })
                    .collect::<Vec<_>>(),
            );
            tables
        });
        for (_, entries) in &mut grouped {
            for (_, weight) in entries {
                weight.discard_dense();
            }
        }
        ch.profile_end(span);
        let span = ch.profile_start("batched_sumcheck");
        let (r, final_claim, evals) =
            sumcheck::sumcheck(ch, tables, &terms, self.width.ilog2() as usize, claim)?;
        ch.profile_end(span);
        let span = ch.profile_start("endpoint_checks");
        let values = ch.fields(evals.as_ref().map(|v| &v[..row_count]), row_count)?;
        let expected: Scalar = grouped
            .iter()
            .map(|((a, b), entries)| {
                values[*a]
                    * b.map_or(Scalar::ONE, |b| values[b])
                    * entries
                        .iter()
                        .map(|(scale, w)| *scale * w.evaluate(&r))
                        .sum::<Scalar>()
            })
            .sum();
        ensure(expected == final_claim)?;
        ch.profile_end(span);
        let span = ch.profile_start("oracle_fold");
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
                .map(|j| {
                    rows.iter()
                        .copied()
                        .chain(self.extra_rows.iter().map(Vec::as_slice))
                        .zip(&weights)
                        .map(|(row, &w)| row[j] * w)
                        .sum()
                })
                .collect::<Vec<_>>()
        });
        ch.profile_end(span);
        let span = ch.profile_start("terminal_basefold");
        let checkpoint_start = row_count - checkpoint.map_or(0, |c| c.rows);
        let mut sources = vec![
            Source {
                root: index.root(),
                weights: weights[..index_rows].to_vec(),
                commitment: self.rows.map(|_| index),
            },
            Source {
                root: online_root,
                weights: weights[index_rows..checkpoint_start].to_vec(),
                commitment: online,
            },
        ];
        if let Some(c) = checkpoint {
            sources.push(Source {
                root: c.root,
                weights: weights[checkpoint_start..].to_vec(),
                commitment: c.tree.as_ref(),
            });
        }
        basefold_iopp::prove_or_verify(
            ch,
            setup,
            &sources,
            message.as_deref(),
            &r,
            reduced_value,
            terminal_log,
            queries,
        )?;
        ch.profile_end(span);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compact_verifier_and_parallel_gkr_preserve_preoptimization_proofs() {
        // Captured from the unchanged binary before compact weights/GKR edits.
        let config = crate::iopp_experiment::ExperimentConfig {
            message_log: 10,
            eta: 2,
            seed: 2025,
        };
        let (message, point) = config.message_and_point();
        for (checkpoints, expected) in [
            (
                vec![],
                "74d0d8e00d471360769f6870f8744bfe1c4725d1e271e351e4ade05967da170e",
            ),
            (
                vec![3, 7],
                "e6887a9acbad0373ad5c6881421d54763e4fe2730a0aa8843b3f8302b03cfcf3",
            ),
        ] {
            let setup = Setup::new_with_checkpoints(
                Parameters {
                    message_log: 10,
                    eta: 2,
                    output_log: 6,
                    output_log_rate: 3,
                    terminal_log: 2,
                    era_queries: 24,
                    basefold_queries: 24,
                    seed: 2025,
                },
                checkpoints,
            )
            .unwrap();
            let tree = setup.commit(&message).unwrap();
            let (value, proof) = setup.prove(&tree, &message, &point).unwrap();
            assert_eq!(blake3::hash(&proof).to_hex().as_str(), expected);
            setup
                .verify_with_profile(tree.root(), &point, value, &proof, true)
                .unwrap()
                .assert_complete(proof.len());
        }
    }
    #[test]
    fn consuming_commitment_preserves_bytes_across_output_rates() {
        for (output_log, rate, checkpoints) in [(6, 1, vec![]), (7, 2, vec![]), (7, 3, vec![3, 7])]
        {
            let setup = Setup::new_with_checkpoints(
                Parameters {
                    message_log: 10,
                    eta: 2,
                    output_log,
                    output_log_rate: rate,
                    terminal_log: 2,
                    era_queries: 24,
                    basefold_queries: 24,
                    seed: 42,
                },
                checkpoints,
            )
            .unwrap();
            let message: Vec<_> = (0..1024).map(|i| Scalar::from(i * i + 17)).collect();
            let point = vec![Scalar::from(5); 10];
            let tree = setup.commit(&message).unwrap();
            let root = tree.root();
            let (value, proof) = setup.prove(&tree, &message, &point).unwrap();
            let (owned_value, owned_proof, profile) = setup
                .prove_consuming_with_profile(tree, &message, &point, true)
                .unwrap();
            assert_eq!((owned_value, &owned_proof), (value, &proof));
            profile.assert_complete(owned_proof.len());
            setup.verify(root, &point, value, &owned_proof).unwrap();
            setup
                .verify_with_profile(root, &point, value, &owned_proof, true)
                .unwrap()
                .assert_complete(owned_proof.len());
        }
    }

    #[test]
    fn zero_padding_base_roundtrip_binds_generator() {
        let parameters = Parameters {
            message_log: 12,
            eta: 0,
            output_log: 6,
            output_log_rate: 1,
            terminal_log: 2,
            era_queries: 24,
            basefold_queries: 24,
            seed: 42,
        };
        let base = BrakedownParams {
            alpha: 0.25,
            inverse_rate: 2.0,
            cn: 4,
            dn: 5,
        };
        for invalid in [
            BrakedownParams { cn: 0, ..base },
            BrakedownParams {
                alpha: 0.99,
                ..base
            },
            BrakedownParams {
                inverse_rate: f64::INFINITY,
                ..base
            },
        ] {
            assert!(
                Setup::new_with_base_code(
                    parameters,
                    vec![],
                    invalid,
                    BrakedownBaseCase::ZeroPadding
                )
                .is_err()
            );
        }
        let setup =
            Setup::new_with_base_code(parameters, vec![], base, BrakedownBaseCase::ZeroPadding)
                .unwrap();
        let other =
            Setup::new_with_base_code(parameters, vec![], base, BrakedownBaseCase::ReedSolomon)
                .unwrap();
        assert_ne!(setup.index.root(), other.index.root());
        let message: Vec<_> = (0..4096).map(|i| Scalar::from(i * i + 7)).collect();
        let point = vec![Scalar::from(3); 12];
        let tree = setup.commit(&message).unwrap();
        let (value, proof) = setup.prove(&tree, &message, &point).unwrap();
        assert!(setup.verify(tree.root(), &point, value, &proof).is_ok());
        assert!(other.verify(tree.root(), &point, value, &proof).is_err());
        let mut bad = proof.clone();
        bad[proof.len() / 2] ^= 1;
        assert!(setup.verify(tree.root(), &point, value, &bad).is_err());
    }

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
        let (profiled_value, profiled_proof, profile) = setup
            .prove_with_profile(&tree, &message, &point, true)
            .unwrap();
        assert_eq!((profiled_value, profiled_proof), (value, proof.clone()));
        profile.assert_complete(proof.len());
        assert_eq!(profile.measurements[0].inclusive_bytes, proof.len());
        assert_eq!(
            profile
                .measurements
                .iter()
                .map(|m| m.exclusive)
                .sum::<std::time::Duration>(),
            profile.measurements[0].inclusive
        );
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
    #[test]
    fn checkpoint_era_roundtrip_context_tampering_and_thread_determinism() {
        let parameters = Parameters {
            message_log: 10,
            eta: 2,
            output_log: 6,
            output_log_rate: 1,
            terminal_log: 2,
            era_queries: 32,
            basefold_queries: 32,
            seed: 42,
        };
        let setup = Setup::new_with_checkpoints(parameters.clone(), vec![3, 7]).unwrap();
        let message: Vec<_> = (0..1024).map(|i| Scalar::from(i * i + 17)).collect();
        let point = vec![Scalar::from(5); 10];
        let tree = setup.commit(&message).unwrap();
        let one = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let eight = rayon::ThreadPoolBuilder::new()
            .num_threads(8)
            .build()
            .unwrap();
        let (value, proof) = one
            .install(|| setup.prove(&tree, &message, &point))
            .unwrap();
        let (profiled_value, profiled_proof, profile) = eight
            .install(|| setup.prove_with_profile(&tree, &message, &point, true))
            .unwrap();
        assert_eq!((value, &proof), (profiled_value, &profiled_proof));
        profile.assert_complete(proof.len());
        setup.verify(tree.root(), &point, value, &proof).unwrap();
        // Probe all transcript regions, including the third source's Merkle openings.
        for offset in (0..proof.len()).step_by((proof.len() / 64).max(1)) {
            let mut bad = proof.clone();
            bad[offset] ^= 1;
            assert!(
                setup.verify(tree.root(), &point, value, &bad).is_err(),
                "offset {offset}"
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
        let mut trailing = proof.clone();
        trailing.push(0);
        assert!(setup.verify(tree.root(), &point, value, &trailing).is_err());
        let other = Setup::new_with_checkpoints(parameters.clone(), vec![3, 8]).unwrap();
        assert!(other.verify(tree.root(), &point, value, &proof).is_err());
        let old = Setup::new(parameters).unwrap();
        assert!(old.verify(tree.root(), &point, value, &proof).is_err());
    }
}
