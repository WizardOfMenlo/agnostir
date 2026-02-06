use agnostir::{
    BasefoldCode, BasefoldParams, BrakedownCode, BrakedownParams, EaCode, EaParams, EraBuffers,
    EraCode, ErrorCorrectingCode, FieldElement, ReedSolomonCode, TensorCode,
    encode_interleaved, random_permutation,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use ark_secp256k1::Fr as SecpScalar;
use rand::{Rng, SeedableRng, rngs::SmallRng};

type BlsScalar = ark_bls12_381::Fr;

const MESSAGE_SIZE: usize = 1 << 20;
const RS_INV_RATE: usize = 1;
const INTERLEAVING_FACTOR: usize = 4;
const ERA_REPETITION: usize = 6;

fn build_message(rng: &mut impl Rng) -> Vec<SecpScalar> {
    (0..MESSAGE_SIZE)
        .map(|_| SecpScalar::random(rng))
        .collect()
}

fn build_bls_message(rng: &mut impl Rng) -> Vec<BlsScalar> {
    (0..MESSAGE_SIZE)
        .map(|_| BlsScalar::random(rng))
        .collect()
}

fn build_era_code(
    rng: &mut impl Rng,
    interleaving_factor: usize,
) -> EraCode<TensorCode<BrakedownCode<SecpScalar>>, SecpScalar> {
    let segment_msg_size = MESSAGE_SIZE >> interleaving_factor;

    // The tensor code's message_size is k^2 where k is the inner code's
    // message_size.  We need k^2 == segment_msg_size, so k = sqrt(segment_msg_size).
    let k = (segment_msg_size as f64).sqrt() as usize;
    assert_eq!(k * k, segment_msg_size, "segment message size must be a perfect square");

    let inner_brakedown_params = BrakedownParams {
        alpha: 0.045,
        inverse_rate: 1.1,
        cn: 7,
        dn: 11,
    };
    let inner_brakedown = BrakedownCode::new(k, inner_brakedown_params, rng);
    let base_code: TensorCode<BrakedownCode<SecpScalar>> = TensorCode::new(inner_brakedown);

    let block_length_segment = base_code.block_length() * ERA_REPETITION;

    let p1 = random_permutation(rng, block_length_segment);
    let p2 = random_permutation(rng, block_length_segment);
    let m1: Vec<SecpScalar> = (0..block_length_segment)
        .map(|_| SecpScalar::random(rng))
        .collect();
    let m2: Vec<SecpScalar> = (0..block_length_segment)
        .map(|_| SecpScalar::random(rng))
        .collect();

    EraCode::new(base_code, ERA_REPETITION, p1, p2, m1, m2)
}

fn build_brakedown_code(
    rng: &mut impl Rng,
    message_size: usize,
    params: BrakedownParams,
) -> BrakedownCode<SecpScalar> {
    BrakedownCode::new(message_size, params, rng)
}


fn build_ea_code(
    rng: &mut impl Rng,
    message_size: usize,
    params: EaParams,
) -> EaCode<SecpScalar> {
    EaCode::new(message_size, params, rng)
}

fn build_basefold_code(
    rng: &mut impl Rng,
    message_size: usize,
    params: BasefoldParams,
) -> BasefoldCode<SecpScalar> {
    BasefoldCode::new(message_size, params, rng)
}


fn bench_compare_interleaved(c: &mut Criterion) {
    let mut rng = SmallRng::seed_from_u64(2025);
    let sc_msg = build_message(&mut rng);
    let bls_msg = build_bls_message(&mut rng);

    let rs_code =
        ReedSolomonCode::new(MESSAGE_SIZE >> INTERLEAVING_FACTOR, (MESSAGE_SIZE >> INTERLEAVING_FACTOR) << RS_INV_RATE);

    c.bench_function("reed_solomon_interleaved_rate_half", |b| {
        b.iter_batched(
            || bls_msg.clone(),
            |input| encode_interleaved(&input, &rs_code, INTERLEAVING_FACTOR),
            BatchSize::LargeInput,
        );
    });

    let era_code = build_era_code(&mut rng, INTERLEAVING_FACTOR);
    let mut era_buf = EraBuffers::new(era_code.block_length());
    c.bench_function("era_interleaved_repetition_6", |b| {
        b.iter_batched(
            || sc_msg.clone(),
            |input| {
                let segment_msg = era_code.message_size();
                let seg_count = 1usize << INTERLEAVING_FACTOR;
                let mut out = Vec::with_capacity(era_code.block_length() * seg_count);
                for seg in 0..seg_count {
                    let start = seg * segment_msg;
                    out.extend(era_code.encode(&input[start..start + segment_msg], &mut era_buf));
                }
                out
            },
            BatchSize::LargeInput,
        );
    });

    let segment_size = MESSAGE_SIZE >> INTERLEAVING_FACTOR;
    let segment_count = 1usize << INTERLEAVING_FACTOR;

    let brakedown_params = BrakedownParams {
        alpha: 0.238,
        inverse_rate: 1.72,
        cn: 9,
        dn: 12,
    };
    let brakedown_code = build_brakedown_code(&mut rng, segment_size, brakedown_params);
    c.bench_function("brakedown_interleaved_encoding", |b| {
        b.iter_batched(
            || sc_msg.clone(),
            |input| {
                let mut out = Vec::with_capacity(brakedown_code.codeword_length() * segment_count);
                for seg in 0..segment_count {
                    let start = seg * segment_size;
                    out.extend(brakedown_code.encode(&input[start..start + segment_size]));
                }
                out
            },
            BatchSize::LargeInput,
        );
    });

    // let ea_params = EaParams {
    //     inverse_rate: 2,
    //     prob_multiplier: 18,
    // };
    // let ea_code = build_ea_code(&mut rng, segment_size, ea_params);
    // c.bench_function("ea_interleaved_encoding", |b| {
    //     b.iter_batched(
    //         || sc_msg.clone(),
    //         |input| {
    //             let mut out = Vec::with_capacity(ea_code.codeword_length() * segment_count);
    //             for seg in 0..segment_count {
    //                 let start = seg * segment_size;
    //                 out.extend(ea_code.encode(&input[start..start + segment_size]));
    //             }
    //             out
    //         },
    //         BatchSize::LargeInput,
    //     );
    // });

    let basefold_params = BasefoldParams { log_rate: 2 };
    let basefold_code = build_basefold_code(&mut rng, segment_size, basefold_params);
    c.bench_function("basefold_interleaved_encoding", |b| {
        b.iter_batched(
            || sc_msg.clone(),
            |input| {
                let mut out = Vec::with_capacity(basefold_code.codeword_length() * segment_count);
                for seg in 0..segment_count {
                    let start = seg * segment_size;
                    out.extend(basefold_code.encode(&input[start..start + segment_size]));
                }
                out
            },
            BatchSize::LargeInput,
        );
    });
}


// fn bench_compare(c: &mut Criterion) {
//     let mut rng = SmallRng::seed_from_u64(2025);
//     let sc_msg = build_message(&mut rng);
//     let bls_msg = build_bls_message(&mut rng);

//     let rs_code = ReedSolomonCode::new(MESSAGE_SIZE, MESSAGE_SIZE << RS_INV_RATE);
//     c.bench_function("reed_solomon_rate_half", |b| {
//         b.iter_batched(
//             || bls_msg.clone(),
//             |input| rs_code.encode(&input),
//             BatchSize::LargeInput,
//         );
//     });

//     let era_code = build_era_code(&mut rng, 0);
//     let mut era_buf = EraBuffers::new(era_code.block_length());
//     c.bench_function("era_repetition_6", |b| {
//         b.iter_batched(
//             || sc_msg.clone(),
//             |input| era_code.encode(&input, &mut era_buf),
//             BatchSize::LargeInput,
//         );
//     });

//     let brakedown_params = BrakedownParams {
//         alpha: 0.238,
//         inverse_rate: 1.72,
//         cn: 9,
//         dn: 12,
//     };
//     let brakedown_code = build_brakedown_code(&mut rng, MESSAGE_SIZE, brakedown_params);
//     c.bench_function("brakedown_encoding", |b| {
//         b.iter_batched(
//             || sc_msg.clone(),
//             |input| brakedown_code.encode(&input),
//             BatchSize::LargeInput,
//         );
//     });

//     let ea_params = EaParams {
//         inverse_rate: 2,
//         prob_multiplier: 18,
//     };
//     let ea_code = build_ea_code(&mut rng, MESSAGE_SIZE, ea_params);
//     c.bench_function("ea_encoding", |b| {
//         b.iter_batched(
//             || sc_msg.clone(),
//             |input| ea_code.encode(&input),
//             BatchSize::LargeInput,
//         );
//     });
// }

fn bench_field_ops(c: &mut Criterion) {
    let mut rng = SmallRng::seed_from_u64(42);

    let a_secp = SecpScalar::random(&mut rng);
    let b_secp = SecpScalar::random(&mut rng);

    let a_bls = BlsScalar::random(&mut rng);
    let b_bls = BlsScalar::random(&mut rng);

    c.bench_function("secp256k1_mul", |b| {
        b.iter(|| black_box(black_box(a_secp) * black_box(b_secp)))
    });

    c.bench_function("secp256k1_add", |b| {
        b.iter(|| black_box(black_box(a_secp) + black_box(b_secp)))
    });

    c.bench_function("bls12_381_mul", |b| {
        b.iter(|| black_box(black_box(a_bls) * black_box(b_bls)))
    });

    c.bench_function("bls12_381_add", |b| {
        b.iter(|| black_box(black_box(a_bls) + black_box(b_bls)))
    });
}

criterion_group! {
    name = interleaved_encoding;
    config = Criterion::default().sample_size(10);
    targets = bench_compare_interleaved
}

criterion_group! {
    name = field_ops;
    config = Criterion::default();
    targets = bench_field_ops
}

criterion_main!(interleaved_encoding);
