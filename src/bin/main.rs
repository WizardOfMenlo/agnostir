use std::{hint::black_box, time::Instant};

use agnostir::{
    ErrorCorrectingCode, IdentityCode, OptimizedEraCode, ReedSolomonCode, random_permutation,
};
use rand::{Rng, SeedableRng, rngs::SmallRng};

use p3_koala_bear::KoalaBear;

fn random_field_vector(rng: &mut impl Rng, n: usize) -> Vec<KoalaBear> {
    (0..n).map(|_| KoalaBear::new(rng.random())).collect()
}

fn random_message(rng: &mut impl Rng, n: usize) -> Vec<KoalaBear> {
    (0..n).map(|_| KoalaBear::new(rng.random())).collect()
}

fn main() {
    let message_size = 1 << 23;
    let rs_block_size = 1 << 24;
    let repetition = 6;
    let block_length = message_size * repetition;

    let mut rng = SmallRng::seed_from_u64(12345);

    let reed_solomon_code: ReedSolomonCode<KoalaBear, p3_dft::Radix2DFTSmallBatch<KoalaBear>> =
        ReedSolomonCode::new(message_size, rs_block_size);

    let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);
    let p1 = random_permutation(&mut rng, block_length);
    let p2 = random_permutation(&mut rng, block_length);
    let m1 = random_field_vector(&mut rng, block_length);
    let m2 = random_field_vector(&mut rng, block_length);

    let mut era_code = OptimizedEraCode::new(base_code, repetition, p1, p2, m1, m2);
    let msg = random_message(&mut rng, message_size);

    let rs_encode_time = Instant::now();
    for _ in 0..100 {
        let encoding = reed_solomon_code.encode(&msg);

        black_box(encoding);
    }
    dbg!(rs_encode_time.elapsed());

    let encode_blocked_time = Instant::now();
    for _ in 0..100 {
        let encoding = era_code.encode_blocked(&msg);

        black_box(encoding);
    }
    dbg!(encode_blocked_time.elapsed());
}
