mod iopp_params;

use agnostir::{
    BasefoldCode, BasefoldParams, BrakedownCode, BrakedownParams, EaCode, EaParams, EraCode,
    ErrorCorrectingCode, FieldElement, blake3_merkle_commit_interleaved,
    blake3_merkle_interleaved_leaves, blake3_merkle_precompute_levels,
    blake3_merkle_root_from_levels,
    interleaved_iopp::{prover_first_round, prover_second_round, verifier_challenge, verify},
    random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use iopp_params::*;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use rayon::prelude::*;
use std::sync::Arc;

const MESSAGE_SIZE: usize = 1 << 20;
const ETA: usize = 5;

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
            BasefoldParams {
                log_rate: BASEFOLD_LOG_RATE,
            },
            &mut SmallRng::seed_from_u64(0),
        );

        let (a, ir, cn, dn) = era_inner_params(seg_msg_size.ilog2());
        let base_tmp = BrakedownCode::<SecpScalar>::new(
            seg_msg_size,
            BrakedownParams {
                alpha: a,
                inverse_rate: ir,
                cn,
                dn,
            },
            &mut SmallRng::seed_from_u64(0),
        );
        let bl_seg_tmp = base_tmp.block_length() * ERA_REPETITION;
        let p1 = random_permutation(&mut SmallRng::seed_from_u64(0), bl_seg_tmp);
        let p2 = random_permutation(&mut SmallRng::seed_from_u64(1), bl_seg_tmp);
        let m1: Vec<SecpScalar> = (0..bl_seg_tmp)
            .map(|_| SecpScalar::random(&mut SmallRng::seed_from_u64(2)))
            .collect();
        let m2: Vec<SecpScalar> = (0..bl_seg_tmp)
            .map(|_| SecpScalar::random(&mut SmallRng::seed_from_u64(3)))
            .collect();
        let era_tmp = EraCode::new(base_tmp, ERA_REPETITION, p1, p2, m1, m2);

        let bd_delta = BRAKEDOWN_DELTA;
        let ea_delta = EA_DELTA;
        let bf_delta = basefold_4_delta(log_seg_msg);
        let er_delta = era_delta(log_seg_msg);

        eprintln!("  Proof sizes (k={k}, eta={eta}, seg_msg=2^{log_seg_msg}):");
        eprintln!(
            "    Brakedown  delta={bd_delta:.3}  q={}  proof={:.1} KiB",
            num_queries_from_delta(SECPARAM, bd_delta),
            proof_size_kib(bd_code.block_length(), k, eta, bd_delta)
        );
        eprintln!(
            "    EA         delta={ea_delta:.3}  q={}  proof={:.1} KiB",
            num_queries_from_delta(SECPARAM, ea_delta),
            proof_size_kib(ea_code_tmp.codeword_length(), k, eta, ea_delta)
        );
        eprintln!(
            "    Basefold   delta={bf_delta:.3}  q={}  proof={:.1} KiB",
            num_queries_from_delta(SECPARAM, bf_delta),
            proof_size_kib(bf_code.codeword_length(), k, eta, bf_delta)
        );
        eprintln!(
            "    ERA        delta={er_delta:.3}  q={}  proof={:.1} KiB",
            num_queries_from_delta(SECPARAM, er_delta),
            proof_size_kib(era_tmp.block_length(), k, eta, er_delta)
        );
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
    let brakedown_leaves = blake3_merkle_interleaved_leaves(&brakedown_segments);
    let brakedown_levels = blake3_merkle_precompute_levels(&brakedown_leaves);
    let brakedown_root = blake3_merkle_root_from_levels(&brakedown_levels);

    {
        let mut ch_rng = SmallRng::seed_from_u64(999);
        let brakedown_challenge = verifier_challenge(brakedown_bl, num_queries, &mut ch_rng);

        c.bench_function("brakedown_eval_prover", |b| {
            let msg = Arc::clone(&msg);
            let segments = Arc::clone(&brakedown_segments);
            let z = z.clone();
            b.iter(|| {
                let first_msg = prover_first_round(&msg, &z, eta, k);
                let _second_msg = prover_second_round(
                    &segments,
                    &brakedown_leaves,
                    &brakedown_levels,
                    &brakedown_challenge,
                    eta,
                );
                first_msg
            });
        });

        let first_msg = prover_first_round(&msg, &z, eta, k);
        let second_msg = prover_second_round(
            &brakedown_segments,
            &brakedown_leaves,
            &brakedown_levels,
            &brakedown_challenge,
            eta,
        );

        c.bench_function("brakedown_verify", |b| {
            let z = z.clone();
            b.iter(|| {
                assert!(verify(
                    &z,
                    eta,
                    k,
                    &brakedown_root,
                    &first_msg,
                    &brakedown_challenge,
                    &second_msg,
                    |m| brakedown_code.encode(m)
                ));
            });
        });
    }

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
    let ea_leaves = blake3_merkle_interleaved_leaves(&ea_segments);
    let ea_levels = blake3_merkle_precompute_levels(&ea_leaves);
    let ea_root = blake3_merkle_root_from_levels(&ea_levels);

    {
        let mut ch_rng = SmallRng::seed_from_u64(999);
        let ea_challenge = verifier_challenge(ea_bl, num_queries, &mut ch_rng);

        c.bench_function("ea_eval_prover", |b| {
            let msg = Arc::clone(&msg);
            let segments = Arc::clone(&ea_segments);
            let z = z.clone();
            b.iter(|| {
                let first_msg = prover_first_round(&msg, &z, eta, k);
                let _second_msg =
                    prover_second_round(&segments, &ea_leaves, &ea_levels, &ea_challenge, eta);
                first_msg
            });
        });

        let first_msg = prover_first_round(&msg, &z, eta, k);
        let second_msg =
            prover_second_round(&ea_segments, &ea_leaves, &ea_levels, &ea_challenge, eta);

        c.bench_function("ea_verify", |b| {
            let z = z.clone();
            b.iter(|| {
                assert!(verify(
                    &z,
                    eta,
                    k,
                    &ea_root,
                    &first_msg,
                    &ea_challenge,
                    &second_msg,
                    |m| ea_code.encode(m)
                ));
            });
        });
    }

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
    let basefold_leaves = blake3_merkle_interleaved_leaves(&basefold_segments);
    let basefold_levels = blake3_merkle_precompute_levels(&basefold_leaves);
    let basefold_root = blake3_merkle_root_from_levels(&basefold_levels);

    {
        let mut ch_rng = SmallRng::seed_from_u64(999);
        let basefold_challenge = verifier_challenge(basefold_bl, num_queries, &mut ch_rng);

        c.bench_function("basefold_eval_prover", |b| {
            let msg = Arc::clone(&msg);
            let segments = Arc::clone(&basefold_segments);
            let z = z.clone();
            b.iter(|| {
                let first_msg = prover_first_round(&msg, &z, eta, k);
                let _second_msg = prover_second_round(
                    &segments,
                    &basefold_leaves,
                    &basefold_levels,
                    &basefold_challenge,
                    eta,
                );
                first_msg
            });
        });

        let first_msg = prover_first_round(&msg, &z, eta, k);
        let second_msg = prover_second_round(
            &basefold_segments,
            &basefold_leaves,
            &basefold_levels,
            &basefold_challenge,
            eta,
        );

        c.bench_function("basefold_verify", |b| {
            let z = z.clone();
            b.iter(|| {
                assert!(verify(
                    &z,
                    eta,
                    k,
                    &basefold_root,
                    &first_msg,
                    &basefold_challenge,
                    &second_msg,
                    |m| basefold_code.encode(m)
                ));
            });
        });
    }

    // ── ERA ──
    let (alpha, inverse_rate, cn, dn) = era_inner_params(seg_msg_size.ilog2());
    let base_code = BrakedownCode::<SecpScalar>::new(
        seg_msg_size,
        BrakedownParams {
            alpha,
            inverse_rate,
            cn,
            dn,
        },
        &mut rng,
    );
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
    let era_leaves = blake3_merkle_interleaved_leaves(&era_segments);
    let era_levels = blake3_merkle_precompute_levels(&era_leaves);
    let era_root = blake3_merkle_root_from_levels(&era_levels);

    {
        let mut ch_rng = SmallRng::seed_from_u64(999);
        let era_challenge = verifier_challenge(era_bl, num_queries, &mut ch_rng);

        c.bench_function("era_eval_prover", |b| {
            let msg = Arc::clone(&msg);
            let segments = Arc::clone(&era_segments);
            let z = z.clone();
            b.iter(|| {
                let first_msg = prover_first_round(&msg, &z, eta, k);
                let _second_msg =
                    prover_second_round(&segments, &era_leaves, &era_levels, &era_challenge, eta);
                first_msg
            });
        });

        let first_msg = prover_first_round(&msg, &z, eta, k);
        let second_msg =
            prover_second_round(&era_segments, &era_leaves, &era_levels, &era_challenge, eta);

        c.bench_function("era_verify", |b| {
            let z = z.clone();
            b.iter(|| {
                assert!(verify(
                    &z,
                    eta,
                    k,
                    &era_root,
                    &first_msg,
                    &era_challenge,
                    &second_msg,
                    |m| era_code.encode_era(m)
                ));
            });
        });
    }
}

criterion_group! {
    name = iopp;
    config = Criterion::default().sample_size(10).without_plots();
    targets = bench_iopp
}

criterion_main!(iopp);
