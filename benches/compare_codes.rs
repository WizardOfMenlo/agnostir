use agnostir::{
    BasefoldCode, BasefoldParams, BrakedownCode, BrakedownParams, EaCode, EaParams,
    EraCode, ErrorCorrectingCode, FieldElement, ReedSolomonCode, TensorCode,
    random_permutation, blake3_merkle_commit, blake3_merkle_commit_interleaved,
};
use ark_ff::{BigInteger, PrimeField};
use ark_secp256k1::Fr as SecpScalar;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rand::{Rng, SeedableRng, rngs::SmallRng};
use rayon::prelude::*;
use std::hint::black_box;

type BlsScalar = ark_bls12_381::Fr;

const MESSAGE_SIZE: usize = 1 << 20;
const RS_INV_RATE: usize = 1;
const INTERLEAVING_FACTOR: usize = 4;
const ERA_REPETITION: usize = 6;

fn build_message(rng: &mut impl Rng) -> Vec<SecpScalar> {
    (0..MESSAGE_SIZE).map(|_| SecpScalar::random(rng)).collect()
}

fn build_bls_message(rng: &mut impl Rng) -> Vec<BlsScalar> {
    (0..MESSAGE_SIZE).map(|_| BlsScalar::random(rng)).collect()
}

fn build_era_code(
    rng: &mut impl Rng,
    interleaving_factor: usize,
) -> EraCode<TensorCode<BrakedownCode<SecpScalar>>, SecpScalar> {
    let segment_msg_size = MESSAGE_SIZE >> interleaving_factor;

    // The tensor code's message_size is k^2 where k is the inner code's
    // message_size.  We need k^2 == segment_msg_size, so k = sqrt(segment_msg_size).
    let k = (segment_msg_size as f64).sqrt() as usize;
    assert_eq!(
        k * k,
        segment_msg_size,
        "segment message size must be a perfect square"
    );

    let inner_brakedown_params = BrakedownParams {
        alpha: 0.085,
        inverse_rate: 1.154,
        cn: 5,
        dn: 32,
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

fn build_ea_code(rng: &mut impl Rng, message_size: usize, params: EaParams) -> EaCode<SecpScalar> {
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

    let rs_code = ReedSolomonCode::new(
        MESSAGE_SIZE >> INTERLEAVING_FACTOR,
        (MESSAGE_SIZE >> INTERLEAVING_FACTOR) << RS_INV_RATE,
    );

    c.bench_function("reed_solomon_interleaved_inv_rate_2", |b| {
        b.iter_batched(
            || bls_msg.clone(),
            |input| {
                let base_msg_size = rs_code.message_size();
                let segments: Vec<Vec<_>> = input
                    .par_chunks(base_msg_size)
                    .map(|chunk| rs_code.encode(chunk))
                    .collect();
                blake3_merkle_commit_interleaved(&segments)
            },
            BatchSize::LargeInput,
        );
    });

    let era_code = build_era_code(&mut rng, INTERLEAVING_FACTOR);
    c.bench_function("era_interleaved_inv_rate_8", |b| {
        b.iter_batched(
            || sc_msg.clone(),
            |input| {
                let segment_msg = era_code.message_size();
                let seg_count = 1usize << INTERLEAVING_FACTOR;
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

    let segment_size = MESSAGE_SIZE >> INTERLEAVING_FACTOR;
    let segment_count = 1usize << INTERLEAVING_FACTOR;

    let brakedown_params = BrakedownParams {
        alpha: 0.238,
        inverse_rate: 1.72,
        cn: 9,
        dn: 12,
    };
    let brakedown_code = build_brakedown_code(&mut rng, segment_size, brakedown_params);
    c.bench_function("brakedown_interleaved_inv_rate_1_72", |b| {
        b.iter_batched(
            || sc_msg.clone(),
            |input| {
                let segments: Vec<Vec<_>> = (0..segment_count)
                    .into_par_iter()
                    .map(|seg| {
                        let start = seg * segment_size;
                        brakedown_code.encode(&input[start..start + segment_size])
                    })
                    .collect();
                blake3_merkle_commit_interleaved(&segments)
            },
            BatchSize::LargeInput,
        );
    });

    // let ea_params = EaParams {
    //     inverse_rate: 2,
    //     prob_multiplier: 18,
    // };
    // let ea_code = build_ea_code(&mut rng, segment_size, ea_params);
    // c.bench_function("ea_interleaved_inv_rate_2", |b| {
    //     b.iter_batched(
    //         || sc_msg.clone(),
    //         |input| {
    //             let segments: Vec<Vec<_>> = (0..segment_count)
    //                 .map(|seg| {
    //                     let start = seg * segment_size;
    //                     ea_code.encode(&input[start..start + segment_size])
    //                 })
    //                 .collect();
    //             blake3_merkle_commit_interleaved(&segments)
    //         },
    //         BatchSize::LargeInput,
    //     );
    // });

    let basefold_params = BasefoldParams { log_rate: 1 };
    let basefold_code = build_basefold_code(&mut rng, segment_size, basefold_params);
    c.bench_function("basefold_interleaved_inv_rate_2", |b| {
        b.iter_batched(
            || sc_msg.clone(),
            |input| {
                let segments: Vec<Vec<_>> = (0..segment_count)
                    .into_par_iter()
                    .map(|seg| {
                        let start = seg * segment_size;
                        basefold_code.encode(&input[start..start + segment_size])
                    })
                    .collect();
                blake3_merkle_commit_interleaved(&segments)
            },
            BatchSize::LargeInput,
        );
    });
}

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

    let secp_bytes = a_secp.into_bigint().to_bytes_le();
    let bls_bytes = a_bls.into_bigint().to_bytes_le();

    c.bench_function("blake3_hash_secp256k1", |b| {
        b.iter(|| black_box(blake3::hash(black_box(&secp_bytes))))
    });

    c.bench_function("blake3_hash_bls12_381", |b| {
        b.iter(|| black_box(blake3::hash(black_box(&bls_bytes))))
    });

    let h1 = *blake3::hash(&secp_bytes).as_bytes();
    let h2 = *blake3::hash(&bls_bytes).as_bytes();
    let mut two_hashes = [0u8; 64];
    two_hashes[..32].copy_from_slice(&h1);
    two_hashes[32..].copy_from_slice(&h2);

    c.bench_function("blake3_compress_two_digests", |b| {
        b.iter(|| black_box(blake3::hash(black_box(&two_hashes))))
    });

    let secp_vec: Vec<u8> = (0..16)
        .flat_map(|i| {
            let s = SecpScalar::from(i as u64) + a_secp;
            s.into_bigint().to_bytes_le()
        })
        .collect();
    let bls_vec: Vec<u8> = (0..16)
        .flat_map(|i| {
            let s = BlsScalar::from(i as u64) + a_bls;
            s.into_bigint().to_bytes_le()
        })
        .collect();

    c.bench_function("blake3_hash_16_secp256k1", |b| {
        b.iter(|| black_box(blake3::hash(black_box(&secp_vec))))
    });

    c.bench_function("blake3_hash_16_bls12_381", |b| {
        b.iter(|| black_box(blake3::hash(black_box(&bls_vec))))
    });

    let raw_512 = [0xABu8; 512];
    c.bench_function("blake3_hash_512_bytes_raw", |b| {
        b.iter(|| black_box(blake3::hash(black_box(&raw_512))))
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
