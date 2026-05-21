mod iopp_params;

use agnostir::{
    BrakedownCode, BrakedownParams, EaCode, EaParams, EraCode, ErrorCorrectingCode,
    FieldElement, blake3_merkle_commit_interleaved,
    blake3_merkle_interleaved_leaves, blake3_merkle_precompute_levels,
    blake3_merkle_root_from_levels,
    interleaved_iopp::{prover_first_round, prover_second_round, verifier_challenge, verify},
    random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use iopp_params::*;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use rayon::{current_num_threads, prelude::*};
use std::env;
use std::sync::Arc;

const DEFAULT_MESSAGE_LOG: usize = 18;
const DEFAULT_ETA: usize = 5;

// ═══════════════════════════════════════════════════════════════════════════
// Benchmark
// ═══════════════════════════════════════════════════════════════════════════

fn env_usize(name: &str, default: usize) -> usize {
    match env::var(name) {
        Ok(raw) => raw
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("invalid {name}='{raw}', expected usize")),
        Err(_) => default,
    }
}

fn env_bool(name: &str) -> bool {
    match env::var(name) {
        Ok(raw) => matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "y" | "on"
        ),
        Err(_) => false,
    }
}

fn build_message(message_size: usize, rng: &mut impl Rng) -> Vec<SecpScalar> {
    (0..message_size).map(|_| SecpScalar::random(rng)).collect()
}

fn build_era_code(
    rng: &mut impl Rng,
    segment_msg_size: usize,
) -> EraCode<BrakedownCode<SecpScalar>, SecpScalar> {
    let (alpha, inverse_rate, cn, dn) = era_inner_params_normal(segment_msg_size.ilog2());
    let base_code = BrakedownCode::<SecpScalar>::new(
        segment_msg_size,
        BrakedownParams {
            alpha,
            inverse_rate,
            cn,
            dn,
        },
        rng,
    );
    let bl_seg = base_code.block_length() * ERA_REPETITION;
    let p1 = random_permutation(rng, bl_seg);
    let p2 = random_permutation(rng, bl_seg);
    let m1: Vec<SecpScalar> = (0..bl_seg).map(|_| SecpScalar::random(rng)).collect();
    let m2: Vec<SecpScalar> = (0..bl_seg).map(|_| SecpScalar::random(rng)).collect();

    EraCode::new(base_code, ERA_REPETITION, p1, p2, m1, m2)
}

fn encode_segments_conditional<EncodeFn>(
    input: &[SecpScalar],
    seg_count: usize,
    segment_msg_size: usize,
    encode_fn: EncodeFn,
) -> Vec<Vec<SecpScalar>>
where
    EncodeFn: Fn(&[SecpScalar]) -> Vec<SecpScalar> + Sync,
{
    (0..seg_count)
        .into_par_iter()
        .map(|seg| {
            let start = seg * segment_msg_size;
            encode_fn(&input[start..start + segment_msg_size])
        })
        .collect()
}

fn bench_iopp(c: &mut Criterion) {
    let k = env_usize("IOPP_MESSAGE_LOG", DEFAULT_MESSAGE_LOG);
    let eta = env_usize("IOPP_ETA", DEFAULT_ETA);
    assert!(eta < k, "expected eta < k, got eta={eta}, k={k}");
    let message_size = 1usize << k;
    let log_seg_msg = k - eta;
    let seg_msg_size = 1usize << log_seg_msg;
    let seg_count = 1usize << eta;
    let use_sequential_encode = current_num_threads() < seg_count;
    let bd_delta = BRAKEDOWN_DELTA;
    let ea_delta = EA_DELTA;
    let er_delta = era_delta_r4(log_seg_msg);
    let brakedown_num_queries = num_queries_from_delta(SECPARAM, bd_delta);
    let ea_num_queries = num_queries_from_delta(SECPARAM, ea_delta);
    let era_num_queries = num_queries_from_delta(SECPARAM, er_delta);
    let run_all_codes = !env_bool("IOPP_ONLY_CONJECTURED_ERA");
    let include_conjectured_era = env_bool("IOPP_INCLUDE_CONJECTURED_ERA") || !run_all_codes;
    let skip_ea = env_bool("IOPP_SKIP_EA");

    let mut rng = SmallRng::seed_from_u64(2025);
    let msg = Arc::new(build_message(message_size, &mut rng));
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
        let era_tmp = build_era_code(&mut SmallRng::seed_from_u64(0), seg_msg_size);

        eprintln!("  Proof sizes (k={k}, eta={eta}, seg_msg=2^{log_seg_msg}):");
        eprintln!(
            "    Brakedown  delta={bd_delta:.3}  q={}  proof={:.1} KiB",
            brakedown_num_queries,
            proof_size_kib(bd_code.block_length(), k, eta, bd_delta)
        );
        if !skip_ea {
            eprintln!(
                "    EA         delta={ea_delta:.3}  q={}  proof={:.1} KiB",
                ea_num_queries,
                proof_size_kib(ea_code_tmp.codeword_length(), k, eta, ea_delta)
            );
        }
        eprintln!(
            "    ERA        delta={er_delta:.3}  q={}  proof={:.1} KiB",
            era_num_queries,
            proof_size_kib(era_tmp.block_length(), k, eta, er_delta)
        );
        if include_conjectured_era {
            eprintln!(
                "    Conj. ERA  delta={er_delta:.3}  q={}  proof={:.1} KiB",
                era_num_queries,
                proof_size_kib(era_tmp.block_length(), k, eta, er_delta)
            );
        }
    }

    if run_all_codes {
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
                    let segments =
                        encode_segments_conditional(&input, seg_count, seg_msg_size, |segment| {
                            brakedown_code.encode(segment)
                        });
                    blake3_merkle_commit_interleaved(&segments)
                },
                BatchSize::LargeInput,
            );
        });

        let brakedown_segments: Arc<Vec<Vec<SecpScalar>>> = Arc::new(encode_segments_conditional(
            msg.as_ref(),
            seg_count,
            seg_msg_size,
            |segment| brakedown_code.encode(segment),
        ));
        let brakedown_leaves = blake3_merkle_interleaved_leaves(&brakedown_segments);
        let brakedown_levels = blake3_merkle_precompute_levels(&brakedown_leaves);
        let brakedown_root = blake3_merkle_root_from_levels(&brakedown_levels);

        {
            let mut ch_rng = SmallRng::seed_from_u64(999);
            let brakedown_challenge =
                verifier_challenge(brakedown_bl, brakedown_num_queries, &mut ch_rng);

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

        if !skip_ea {
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
                        let segments = encode_segments_conditional(
                            &input,
                            seg_count,
                            seg_msg_size,
                            |segment| ea_code.encode(segment),
                        );
                        blake3_merkle_commit_interleaved(&segments)
                    },
                    BatchSize::LargeInput,
                );
            });

            let ea_segments: Arc<Vec<Vec<SecpScalar>>> = Arc::new(encode_segments_conditional(
                msg.as_ref(),
                seg_count,
                seg_msg_size,
                |segment| ea_code.encode(segment),
            ));
            let ea_leaves = blake3_merkle_interleaved_leaves(&ea_segments);
            let ea_levels = blake3_merkle_precompute_levels(&ea_leaves);
            let ea_root = blake3_merkle_root_from_levels(&ea_levels);

            {
                let mut ch_rng = SmallRng::seed_from_u64(999);
                let ea_challenge = verifier_challenge(ea_bl, ea_num_queries, &mut ch_rng);

                c.bench_function("ea_eval_prover", |b| {
                    let msg = Arc::clone(&msg);
                    let segments = Arc::clone(&ea_segments);
                    let z = z.clone();
                    b.iter(|| {
                        let first_msg = prover_first_round(&msg, &z, eta, k);
                        let _second_msg = prover_second_round(
                            &segments,
                            &ea_leaves,
                            &ea_levels,
                            &ea_challenge,
                            eta,
                        );
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
        }

        // ── ERA ──
        let era_code = build_era_code(&mut rng, seg_msg_size);
        let era_bl = era_code.block_length();

        c.bench_function("era_commit", |b| {
            let msg = Arc::clone(&msg);
            b.iter_batched(
                || (*msg).clone(),
                |input| {
                    let segment_msg = era_code.message_size();
                    let segments =
                        encode_segments_conditional(&input, seg_count, segment_msg, |segment| {
                            if use_sequential_encode {
                                era_code.encode_era_sequential(segment)
                            } else {
                                era_code.encode_era(segment)
                            }
                        });
                    blake3_merkle_commit_interleaved(&segments)
                },
                BatchSize::LargeInput,
            );
        });

        let era_segment_msg = era_code.message_size();
        let era_segments: Arc<Vec<Vec<SecpScalar>>> = Arc::new(encode_segments_conditional(
            msg.as_ref(),
            seg_count,
            era_segment_msg,
            |segment| {
                if use_sequential_encode {
                    era_code.encode_era_sequential(segment)
                } else {
                    era_code.encode_era(segment)
                }
            },
        ));
        let era_leaves = blake3_merkle_interleaved_leaves(&era_segments);
        let era_levels = blake3_merkle_precompute_levels(&era_leaves);
        let era_root = blake3_merkle_root_from_levels(&era_levels);

        {
            let mut ch_rng = SmallRng::seed_from_u64(999);
            let era_challenge = verifier_challenge(era_bl, era_num_queries, &mut ch_rng);

            c.bench_function("era_eval_prover", |b| {
                let msg = Arc::clone(&msg);
                let segments = Arc::clone(&era_segments);
                let z = z.clone();
                b.iter(|| {
                    let first_msg = prover_first_round(&msg, &z, eta, k);
                    let _second_msg = prover_second_round(
                        &segments,
                        &era_leaves,
                        &era_levels,
                        &era_challenge,
                        eta,
                    );
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
                        |m| {
                            if use_sequential_encode {
                                era_code.encode_era_sequential(m)
                            } else {
                                era_code.encode_era(m)
                            }
                        }
                    ));
                });
            });
        }
    }

    if include_conjectured_era {
        // ── Conjectured ERA (no multiplication in prefix rounds) ──
        let conjectured_era_code = build_era_code(&mut rng, seg_msg_size);
        let conjectured_era_bl = conjectured_era_code.block_length();

        c.bench_function("conjectured_era_commit", |b| {
            let msg = Arc::clone(&msg);
            b.iter_batched(
                || (*msg).clone(),
                |input| {
                    let segment_msg = conjectured_era_code.message_size();
                    let segments =
                        encode_segments_conditional(&input, seg_count, segment_msg, |segment| {
                            if use_sequential_encode {
                                conjectured_era_code.encode_conjectured_era_sequential(segment)
                            } else {
                                conjectured_era_code.encode_conjectured_era(segment)
                            }
                        });
                    blake3_merkle_commit_interleaved(&segments)
                },
                BatchSize::LargeInput,
            );
        });

        let conjectured_era_segment_msg = conjectured_era_code.message_size();
        let conjectured_era_segments: Arc<Vec<Vec<SecpScalar>>> =
            Arc::new(encode_segments_conditional(
                msg.as_ref(),
                seg_count,
                conjectured_era_segment_msg,
                |segment| {
                    if use_sequential_encode {
                        conjectured_era_code.encode_conjectured_era_sequential(segment)
                    } else {
                        conjectured_era_code.encode_conjectured_era(segment)
                    }
                },
            ));
        let conjectured_era_leaves = blake3_merkle_interleaved_leaves(&conjectured_era_segments);
        let conjectured_era_levels = blake3_merkle_precompute_levels(&conjectured_era_leaves);
        let conjectured_era_root = blake3_merkle_root_from_levels(&conjectured_era_levels);

        {
            let mut ch_rng = SmallRng::seed_from_u64(999);
            let conjectured_era_challenge =
                verifier_challenge(conjectured_era_bl, era_num_queries, &mut ch_rng);

            c.bench_function("conjectured_era_eval_prover", |b| {
                let msg = Arc::clone(&msg);
                let segments = Arc::clone(&conjectured_era_segments);
                let z = z.clone();
                b.iter(|| {
                    let first_msg = prover_first_round(&msg, &z, eta, k);
                    let _second_msg = prover_second_round(
                        &segments,
                        &conjectured_era_leaves,
                        &conjectured_era_levels,
                        &conjectured_era_challenge,
                        eta,
                    );
                    first_msg
                });
            });

            let first_msg = prover_first_round(&msg, &z, eta, k);
            let second_msg = prover_second_round(
                &conjectured_era_segments,
                &conjectured_era_leaves,
                &conjectured_era_levels,
                &conjectured_era_challenge,
                eta,
            );

            c.bench_function("conjectured_era_verify", |b| {
                let z = z.clone();
                b.iter(|| {
                    assert!(verify(
                        &z,
                        eta,
                        k,
                        &conjectured_era_root,
                        &first_msg,
                        &conjectured_era_challenge,
                        &second_msg,
                        |m| {
                            if use_sequential_encode {
                                conjectured_era_code.encode_conjectured_era_sequential(m)
                            } else {
                                conjectured_era_code.encode_conjectured_era(m)
                            }
                        }
                    ));
                });
            });
        }
    }
}

criterion_group! {
    name = iopp;
    config = Criterion::default().sample_size(10).without_plots();
    targets = bench_iopp
}

criterion_main!(iopp);
