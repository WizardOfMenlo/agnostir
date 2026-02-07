use agnostir::{
    BasefoldCode, BasefoldParams, BrakedownCode, BrakedownParams, EaCode, EaParams,
    EraCode, ErrorCorrectingCode, FieldElement, ReedSolomonCode, TensorCode,
    random_permutation,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use ark_secp256k1::Fr as SecpScalar;
use rand::{Rng, SeedableRng, rngs::SmallRng};
use rayon::prelude::*;

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

        c.bench_function("reed_solomon_interleaved_inv_rate_2", |b| {
            b.iter_batched(
            || bls_msg.clone(),
            |input| {
                let base_msg_size = rs_code.message_size();
                input
                    .par_chunks(base_msg_size)
                    .flat_map(|chunk| rs_code.encode(chunk))
                    .collect::<Vec<_>>()
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
                (0..seg_count)
                    .into_par_iter()
                    .flat_map(|seg| {
                        let start = seg * segment_msg;
                        era_code.encode_era(&input[start..start + segment_msg])
                    })
                    .collect::<Vec<_>>()
            },
            BatchSize::LargeInput,
        );
    });

    let segment_size = MESSAGE_SIZE >> INTERLEAVING_FACTOR;
    let segment_count = 1usize << INTERLEAVING_FACTOR;

    let brakedown_params = BrakedownParams {
        alpha: 0.54,
        inverse_rate: 4.0,
        cn: 5,
        dn: 47,
    };
    let brakedown_code = build_brakedown_code(&mut rng, segment_size, brakedown_params);
    c.bench_function("brakedown_interleaved_inv_rate_4", |b| {
        b.iter_batched(
            || sc_msg.clone(),
            |input| {
                (0..segment_count)
                    .into_par_iter()
                    .flat_map(|seg| {
                        let start = seg * segment_size;
                        brakedown_code.encode(&input[start..start + segment_size])
                    })
                    .collect::<Vec<_>>()
            },
            BatchSize::LargeInput,
        );
    });

    let ea_params = EaParams {
        inverse_rate: 2,
        prob_multiplier: 18,
    };
    let ea_code = build_ea_code(&mut rng, segment_size, ea_params);
    c.bench_function("ea_interleaved_inv_rate_2", |b| {
        b.iter_batched(
            || sc_msg.clone(),
            |input| {
                let mut out = Vec::with_capacity(ea_code.codeword_length() * segment_count);
                for seg in 0..segment_count {
                    let start = seg * segment_size;
                    out.extend(ea_code.encode(&input[start..start + segment_size]));
                }
                out
            },
            BatchSize::LargeInput,
        );
    });

    let basefold_params = BasefoldParams { log_rate: 2 };
    let basefold_code = build_basefold_code(&mut rng, segment_size, basefold_params);
    c.bench_function("basefold_interleaved_inv_rate_4", |b| {
        b.iter_batched(
            || sc_msg.clone(),
            |input| {
                (0..segment_count)
                    .into_par_iter()
                    .flat_map(|seg| {
                        let start = seg * segment_size;
                        basefold_code.encode(&input[start..start + segment_size])
                    })
                    .collect::<Vec<_>>()
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

// ── Merkle-tree commitment benchmark (Blake3) ─────────────────────────────

use ark_ff::{BigInteger, PrimeField};

const MERKLE_VECTOR_SIZE: usize = 1 << 23;

/// Build a Blake3 Merkle tree over `leaves` (each a 32-byte hash) and return
/// the root hash.  Internal nodes are computed bottom-up with rayon.
fn blake3_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let n = leaves.len();
    assert!(n.is_power_of_two() && n >= 2);

    // Level 0: hash pairs of leaves → n/2 parent hashes
    let mut level: Vec<[u8; 32]> = leaves
        .par_chunks_exact(2)
        .map(|pair| {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            *blake3::hash(&buf).as_bytes()
        })
        .collect();

    // Repeatedly halve until a single root remains
    while level.len() > 1 {
        level = level
            .par_chunks_exact(2)
            .map(|pair| {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(&pair[0]);
                buf[32..].copy_from_slice(&pair[1]);
                *blake3::hash(&buf).as_bytes()
            })
            .collect();
    }

    level[0]
}

fn bench_merkle_commit(c: &mut Criterion) {
    let mut rng = SmallRng::seed_from_u64(2025);

    // Pre-hash 2^23 SecpScalars into 32-byte Blake3 leaf digests
    let leaves: Vec<[u8; 32]> = (0..MERKLE_VECTOR_SIZE)
        .map(|_| {
            let s = SecpScalar::random(&mut rng);
            let bytes = s.into_bigint().to_bytes_le();
            *blake3::hash(&bytes).as_bytes()
        })
        .collect();

    c.bench_function("merkle_blake3_commit_2_23_secp_scalars", |b| {
        b.iter_batched(
            || leaves.clone(),
            |lvs| black_box(blake3_merkle_root(&lvs)),
            BatchSize::LargeInput,
        );
    });
}

criterion_group! {
    name = merkle_commitment;
    config = Criterion::default().sample_size(10);
    targets = bench_merkle_commit
}

criterion_main!(merkle_commitment);
