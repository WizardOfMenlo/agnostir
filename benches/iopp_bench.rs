mod iopp_params;

use agnostir::{
    BasefoldCode, BasefoldParams, BrakedownCode, BrakedownParams, EaCode, EaParams, EraCode,
    ErrorCorrectingCode, FieldElement, TensorCode,
    blake3_merkle_commit_interleaved,
    poly_utils::multilinear::MultilinearPoint,
    random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use iopp_params::*;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use rayon::prelude::*;
use std::sync::Arc;

const MESSAGE_SIZE: usize = 1 << 22;
const ETA: usize = 8;

// ═══════════════════════════════════════════════════════════════════════════
// IOPP protocol helpers
// ═══════════════════════════════════════════════════════════════════════════

struct ProverFirstMessage {
    folded_msg: Vec<SecpScalar>,
    y: SecpScalar,
}

struct VerifierChallenge {
    query_indices: Vec<usize>,
}

struct ProverSecondMessage {
    columns: Vec<Vec<SecpScalar>>,
}

fn prover_first_round(
    message: &[SecpScalar],
    z: &[SecpScalar],
    eta: usize,
    k: usize,
) -> ProverFirstMessage {
    let seg_msg_size = 1usize << (k - eta);

    let z_1 = &z[..eta];
    let z1_point = MultilinearPoint(z_1.to_vec());
    let eq_weights = z1_point.eq_weights();

    let mut folded_msg = vec![SecpScalar::ZERO; seg_msg_size];
    for (r, &w) in eq_weights.iter().enumerate() {
        let row_start = r * seg_msg_size;
        for i in 0..seg_msg_size {
            folded_msg[i] += w * message[row_start + i];
        }
    }

    let z_2 = &z[eta..];
    let z2_point = MultilinearPoint(z_2.to_vec());
    let eq2_weights = z2_point.eq_weights();
    let y = folded_msg
        .iter()
        .zip(eq2_weights.iter())
        .fold(SecpScalar::ZERO, |acc, (&fm, &e)| acc + fm * e);

    ProverFirstMessage { folded_msg, y }
}

fn verifier_challenge(
    block_length: usize,
    num_queries: usize,
    rng: &mut impl Rng,
) -> VerifierChallenge {
    let query_indices: Vec<usize> = (0..num_queries)
        .map(|_| rng.random_range(0..block_length))
        .collect();
    VerifierChallenge { query_indices }
}

fn prover_second_round(
    segments: &[Vec<SecpScalar>],
    challenge: &VerifierChallenge,
    eta: usize,
) -> ProverSecondMessage {
    let rows = 1usize << eta;
    let columns: Vec<Vec<SecpScalar>> = challenge
        .query_indices
        .iter()
        .map(|&cw_idx| (0..rows).map(|r| segments[r][cw_idx]).collect())
        .collect();
    ProverSecondMessage { columns }
}

fn verify_via_segments(
    z: &[SecpScalar],
    eta: usize,
    k: usize,
    first_msg: &ProverFirstMessage,
    challenge: &VerifierChallenge,
    second_msg: &ProverSecondMessage,
    segments: &[Vec<SecpScalar>],
) -> bool {
    let rows = 1usize << eta;
    let seg_msg_size = 1usize << (k - eta);
    let block_length = segments[0].len();

    let z_1 = &z[..eta];
    let z1_point = MultilinearPoint(z_1.to_vec());
    let eq_weights = z1_point.eq_weights();

    let mut folded_cw = vec![SecpScalar::ZERO; block_length];
    for (r, &w) in eq_weights.iter().enumerate() {
        let seg = &segments[r];
        for j in 0..block_length {
            folded_cw[j] += w * seg[j];
        }
    }

    for (col, &cw_idx) in second_msg
        .columns
        .iter()
        .zip(challenge.query_indices.iter())
    {
        if col.len() != rows {
            return false;
        }

        let folded_val: SecpScalar = col
            .iter()
            .zip(eq_weights.iter())
            .fold(SecpScalar::ZERO, |acc, (&c, &w)| acc + c * w);

        if folded_val != folded_cw[cw_idx] {
            return false;
        }
    }

    let z_2 = &z[eta..];
    let z2_point = MultilinearPoint(z_2.to_vec());
    let eq2_weights = z2_point.eq_weights();
    assert_eq!(eq2_weights.len(), seg_msg_size);

    let eval: SecpScalar = first_msg
        .folded_msg
        .iter()
        .zip(eq2_weights.iter())
        .fold(SecpScalar::ZERO, |acc, (&fm, &e)| acc + fm * e);

    eval == first_msg.y
}

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark
// ═══════════════════════════════════════════════════════════════════════════

fn build_message(rng: &mut impl Rng) -> Vec<SecpScalar> {
    (0..MESSAGE_SIZE).map(|_| SecpScalar::random(rng)).collect()
}

fn bench_iopp(c: &mut Criterion) {
    let k = MESSAGE_SIZE.ilog2() as usize;
    let eta = ETA;
    let log_seg_msg = k - eta;
    let seg_msg_size = 1usize << log_seg_msg;
    let seg_count = 1usize << eta;
    let num_queries = 40;

    let mut rng = SmallRng::seed_from_u64(2025);
    let msg = Arc::new(build_message(&mut rng));
    let z: Vec<SecpScalar> = (0..k).map(|_| SecpScalar::random(&mut rng)).collect();

    // Print proof sizes for each code.
    {
        let bd_code = BrakedownCode::<SecpScalar>::new(
            seg_msg_size,
            BrakedownParams {
                alpha: BRAKEDOWN_ALPHA,
                inverse_rate: BRAKEDOWN_INV_RATE,
                cn: BRAKEDOWN_CN,
                dn: BRAKEDOWN_DN,
            },
            &mut SmallRng::seed_from_u64(0),
        );
        let ea_code_tmp = EaCode::<SecpScalar>::new(
            seg_msg_size,
            EaParams {
                inverse_rate: EA_INV_RATE,
                prob_multiplier: EA_PROB_MUL,
            },
            &mut SmallRng::seed_from_u64(0),
        );
        let bf_code = BasefoldCode::<SecpScalar>::new(
            seg_msg_size,
            BasefoldParams { log_rate: BASEFOLD_LOG_RATE },
            &mut SmallRng::seed_from_u64(0),
        );

        let k_inner = (seg_msg_size as f64).sqrt() as usize;
        let (a, ir, cn, dn) = era_inner_params(k_inner.ilog2());
        let inner_tmp = BrakedownCode::<SecpScalar>::new(
            k_inner, BrakedownParams { alpha: a, inverse_rate: ir, cn, dn },
            &mut SmallRng::seed_from_u64(0),
        );
        let base_tmp: TensorCode<BrakedownCode<SecpScalar>> = TensorCode::new(inner_tmp);
        let bl_seg_tmp = base_tmp.block_length() * ERA_REPETITION;
        let p1 = random_permutation(&mut SmallRng::seed_from_u64(0), bl_seg_tmp);
        let p2 = random_permutation(&mut SmallRng::seed_from_u64(1), bl_seg_tmp);
        let m1: Vec<SecpScalar> = (0..bl_seg_tmp).map(|_| SecpScalar::random(&mut SmallRng::seed_from_u64(2))).collect();
        let m2: Vec<SecpScalar> = (0..bl_seg_tmp).map(|_| SecpScalar::random(&mut SmallRng::seed_from_u64(3))).collect();
        let era_tmp = EraCode::new(base_tmp, ERA_REPETITION, p1, p2, m1, m2);

        let bd_delta = BRAKEDOWN_DELTA;
        let ea_delta = EA_DELTA;
        let bf_delta = basefold_delta(log_seg_msg);
        let er_delta = era_delta(log_seg_msg);

        eprintln!("  Proof sizes (k={k}, eta={eta}, seg_msg=2^{log_seg_msg}):");
        eprintln!("    Brakedown  delta={bd_delta:.3}  q={}  proof={:.1} KiB",
            num_queries_from_delta(SECPARAM, bd_delta),
            proof_size_kib(bd_code.block_length(), k, eta, bd_delta));
        eprintln!("    EA         delta={ea_delta:.3}  q={}  proof={:.1} KiB",
            num_queries_from_delta(SECPARAM, ea_delta),
            proof_size_kib(ea_code_tmp.codeword_length(), k, eta, ea_delta));
        eprintln!("    Basefold   delta={bf_delta:.3}  q={}  proof={:.1} KiB",
            num_queries_from_delta(SECPARAM, bf_delta),
            proof_size_kib(bf_code.codeword_length(), k, eta, bf_delta));
        eprintln!("    ERA        delta={er_delta:.3}  q={}  proof={:.1} KiB",
            num_queries_from_delta(SECPARAM, er_delta),
            proof_size_kib(era_tmp.block_length(), k, eta, er_delta));
    }

    // ── Brakedown ──
    let brakedown_code = BrakedownCode::<SecpScalar>::new(
        seg_msg_size,
        BrakedownParams {
            alpha: BRAKEDOWN_ALPHA,
            inverse_rate: BRAKEDOWN_INV_RATE,
            cn: BRAKEDOWN_CN,
            dn: BRAKEDOWN_DN,
        },
        &mut rng,
    );
    let brakedown_bl = brakedown_code.block_length();

    c.bench_function("brakedown_commit", |b| {
        let msg = Arc::clone(&msg);
        b.iter_batched(
            || (*msg).clone(),
            |input| {
                let segments: Vec<Vec<_>> = (0..seg_count)
                    .into_par_iter()
                    .map(|seg| {
                        let start = seg * seg_msg_size;
                        brakedown_code.encode(&input[start..start + seg_msg_size])
                    })
                    .collect();
                blake3_merkle_commit_interleaved(&segments)
            },
            BatchSize::LargeInput,
        );
    });

    let brakedown_segments: Arc<Vec<Vec<SecpScalar>>> = Arc::new(
        (0..seg_count)
            .into_par_iter()
            .map(|seg| {
                let start = seg * seg_msg_size;
                brakedown_code.encode(&msg[start..start + seg_msg_size])
            })
            .collect(),
    );

    c.bench_function("brakedown_eval_prover", |b| {
        let msg = Arc::clone(&msg);
        let segments = Arc::clone(&brakedown_segments);
        let z = z.clone();
        b.iter(|| {
            let first_msg = prover_first_round(&msg, &z, eta, k);
            let mut rng = SmallRng::seed_from_u64(999);
            let challenge = verifier_challenge(brakedown_bl, num_queries, &mut rng);
            let _second_msg = prover_second_round(&segments, &challenge, eta);
            first_msg
        });
    });

    c.bench_function("brakedown_verify", |b| {
        let msg = Arc::clone(&msg);
        let segments = Arc::clone(&brakedown_segments);
        let z = z.clone();
        let first_msg = prover_first_round(&msg, &z, eta, k);
        let mut ch_rng = SmallRng::seed_from_u64(999);
        let challenge = verifier_challenge(brakedown_bl, num_queries, &mut ch_rng);
        let second_msg = prover_second_round(&segments, &challenge, eta);
        b.iter(|| {
            let mut rng = SmallRng::seed_from_u64(888);
            let _vc = verifier_challenge(brakedown_bl, num_queries, &mut rng);
            assert!(verify_via_segments(&z, eta, k, &first_msg, &challenge, &second_msg, &segments));
        });
    });

    // ── EA ──
    let ea_code = EaCode::<SecpScalar>::new(
        seg_msg_size,
        EaParams {
            inverse_rate: EA_INV_RATE,
            prob_multiplier: EA_PROB_MUL,
        },
        &mut rng,
    );
    let ea_bl = ea_code.codeword_length();

    c.bench_function("ea_commit", |b| {
        let msg = Arc::clone(&msg);
        b.iter_batched(
            || (*msg).clone(),
            |input| {
                let segments: Vec<Vec<_>> = (0..seg_count)
                    .into_par_iter()
                    .map(|seg| {
                        let start = seg * seg_msg_size;
                        ea_code.encode(&input[start..start + seg_msg_size])
                    })
                    .collect();
                blake3_merkle_commit_interleaved(&segments)
            },
            BatchSize::LargeInput,
        );
    });

    let ea_segments: Arc<Vec<Vec<SecpScalar>>> = Arc::new(
        (0..seg_count)
            .into_par_iter()
            .map(|seg| {
                let start = seg * seg_msg_size;
                ea_code.encode(&msg[start..start + seg_msg_size])
            })
            .collect(),
    );

    c.bench_function("ea_eval_prover", |b| {
        let msg = Arc::clone(&msg);
        let segments = Arc::clone(&ea_segments);
        let z = z.clone();
        b.iter(|| {
            let first_msg = prover_first_round(&msg, &z, eta, k);
            let mut rng = SmallRng::seed_from_u64(999);
            let challenge = verifier_challenge(ea_bl, num_queries, &mut rng);
            let _second_msg = prover_second_round(&segments, &challenge, eta);
            first_msg
        });
    });

    c.bench_function("ea_verify", |b| {
        let msg = Arc::clone(&msg);
        let segments = Arc::clone(&ea_segments);
        let z = z.clone();
        let first_msg = prover_first_round(&msg, &z, eta, k);
        let mut ch_rng = SmallRng::seed_from_u64(999);
        let challenge = verifier_challenge(ea_bl, num_queries, &mut ch_rng);
        let second_msg = prover_second_round(&segments, &challenge, eta);
        b.iter(|| {
            let mut rng = SmallRng::seed_from_u64(888);
            let _vc = verifier_challenge(ea_bl, num_queries, &mut rng);
            assert!(verify_via_segments(&z, eta, k, &first_msg, &challenge, &second_msg, &segments));
        });
    });

    // ── Basefold ──
    let basefold_code = BasefoldCode::<SecpScalar>::new(
        seg_msg_size,
        BasefoldParams {
            log_rate: BASEFOLD_LOG_RATE,
        },
        &mut rng,
    );
    let basefold_bl = basefold_code.codeword_length();

    c.bench_function("basefold_commit", |b| {
        let msg = Arc::clone(&msg);
        b.iter_batched(
            || (*msg).clone(),
            |input| {
                let segments: Vec<Vec<_>> = (0..seg_count)
                    .into_par_iter()
                    .map(|seg| {
                        let start = seg * seg_msg_size;
                        basefold_code.encode(&input[start..start + seg_msg_size])
                    })
                    .collect();
                blake3_merkle_commit_interleaved(&segments)
            },
            BatchSize::LargeInput,
        );
    });

    let basefold_segments: Arc<Vec<Vec<SecpScalar>>> = Arc::new(
        (0..seg_count)
            .into_par_iter()
            .map(|seg| {
                let start = seg * seg_msg_size;
                basefold_code.encode(&msg[start..start + seg_msg_size])
            })
            .collect(),
    );

    c.bench_function("basefold_eval_prover", |b| {
        let msg = Arc::clone(&msg);
        let segments = Arc::clone(&basefold_segments);
        let z = z.clone();
        b.iter(|| {
            let first_msg = prover_first_round(&msg, &z, eta, k);
            let mut rng = SmallRng::seed_from_u64(999);
            let challenge = verifier_challenge(basefold_bl, num_queries, &mut rng);
            let _second_msg = prover_second_round(&segments, &challenge, eta);
            first_msg
        });
    });

    c.bench_function("basefold_verify", |b| {
        let msg = Arc::clone(&msg);
        let segments = Arc::clone(&basefold_segments);
        let z = z.clone();
        let first_msg = prover_first_round(&msg, &z, eta, k);
        let mut ch_rng = SmallRng::seed_from_u64(999);
        let challenge = verifier_challenge(basefold_bl, num_queries, &mut ch_rng);
        let second_msg = prover_second_round(&segments, &challenge, eta);
        b.iter(|| {
            let mut rng = SmallRng::seed_from_u64(888);
            let _vc = verifier_challenge(basefold_bl, num_queries, &mut rng);
            assert!(verify_via_segments(&z, eta, k, &first_msg, &challenge, &second_msg, &segments));
        });
    });

    // ── ERA ──
    let k_inner = (seg_msg_size as f64).sqrt() as usize;
    assert_eq!(k_inner * k_inner, seg_msg_size);
    let (alpha, inverse_rate, cn, dn) = era_inner_params(k_inner.ilog2());
    let inner = BrakedownCode::<SecpScalar>::new(
        k_inner,
        BrakedownParams {
            alpha,
            inverse_rate,
            cn,
            dn,
        },
        &mut rng,
    );
    let base_code: TensorCode<BrakedownCode<SecpScalar>> = TensorCode::new(inner);
    let bl_seg = base_code.block_length() * ERA_REPETITION;
    let p1 = random_permutation(&mut rng, bl_seg);
    let p2 = random_permutation(&mut rng, bl_seg);
    let m1: Vec<SecpScalar> = (0..bl_seg).map(|_| SecpScalar::random(&mut rng)).collect();
    let m2: Vec<SecpScalar> = (0..bl_seg).map(|_| SecpScalar::random(&mut rng)).collect();
    let era_code = EraCode::new(base_code, ERA_REPETITION, p1, p2, m1, m2);
    let era_bl = era_code.block_length();

    c.bench_function("era_commit", |b| {
        let msg = Arc::clone(&msg);
        b.iter_batched(
            || (*msg).clone(),
            |input| {
                let segment_msg = era_code.message_size();
                let segments: Vec<Vec<_>> = (0..seg_count)
                    .into_par_iter()
                    .map(|seg| {
                        let start = seg * segment_msg;
                        era_code.encode_era(&input[start..start + segment_msg])
                    })
                    .collect();
                blake3_merkle_commit_interleaved(&segments)
            },
            BatchSize::LargeInput,
        );
    });

    let era_segment_msg = era_code.message_size();
    let era_segments: Arc<Vec<Vec<SecpScalar>>> = Arc::new(
        (0..seg_count)
            .into_par_iter()
            .map(|seg| {
                let start = seg * era_segment_msg;
                era_code.encode_era(&msg[start..start + era_segment_msg])
            })
            .collect(),
    );

    c.bench_function("era_eval_prover", |b| {
        let msg = Arc::clone(&msg);
        let segments = Arc::clone(&era_segments);
        let z = z.clone();
        b.iter(|| {
            let first_msg = prover_first_round(&msg, &z, eta, k);
            let mut rng = SmallRng::seed_from_u64(999);
            let challenge = verifier_challenge(era_bl, num_queries, &mut rng);
            let _second_msg = prover_second_round(&segments, &challenge, eta);
            first_msg
        });
    });

    c.bench_function("era_verify", |b| {
        let msg = Arc::clone(&msg);
        let segments = Arc::clone(&era_segments);
        let z = z.clone();
        let first_msg = prover_first_round(&msg, &z, eta, k);
        let mut ch_rng = SmallRng::seed_from_u64(999);
        let challenge = verifier_challenge(era_bl, num_queries, &mut ch_rng);
        let second_msg = prover_second_round(&segments, &challenge, eta);
        b.iter(|| {
            let mut rng = SmallRng::seed_from_u64(888);
            let _vc = verifier_challenge(era_bl, num_queries, &mut rng);
            assert!(verify_via_segments(&z, eta, k, &first_msg, &challenge, &second_msg, &segments));
        });
    });
}

criterion_group! {
    name = iopp;
    config = Criterion::default().sample_size(10);
    targets = bench_iopp
}

criterion_main!(iopp);
