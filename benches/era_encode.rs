use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use agnostir::{EraCode, IdentityCode, random_permutation};
use p3_koala_bear::KoalaBear;
use rand::{Rng, SeedableRng, rngs::SmallRng};

fn random_field_vector(rng: &mut impl Rng, n: usize) -> Vec<KoalaBear> {
    (0..n).map(|_| KoalaBear::new(rng.random())).collect()
}

fn random_message(rng: &mut impl Rng, n: usize) -> Vec<KoalaBear> {
    (0..n).map(|_| KoalaBear::new(rng.random())).collect()
}

fn bench_encode_naive(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_naive");

    for log_size in 20..=26 {
        let message_size = 1 << log_size;
        let repetition = 1;
        let block_length = message_size * repetition;

        let mut rng = SmallRng::seed_from_u64(12345);

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);
        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);
        let msg = random_message(&mut rng, message_size);

        group.throughput(Throughput::Elements(message_size as u64));
        group.bench_with_input(
            BenchmarkId::new("size", format!("2^{log_size}")),
            &msg,
            |b, msg| {
                b.iter(|| era_code.encode_naive(msg.clone()));
            },
        );
    }

    group.finish();
}

fn bench_encode_fused(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_fused");

    for log_size in 20..=26 {
        let message_size = 1 << log_size;
        let repetition = 1;
        let block_length = message_size * repetition;

        let mut rng = SmallRng::seed_from_u64(12345);

        let base_code: IdentityCode<KoalaBear> = IdentityCode::new(message_size);
        let p1 = random_permutation(&mut rng, block_length);
        let p2 = random_permutation(&mut rng, block_length);
        let m1 = random_field_vector(&mut rng, block_length);
        let m2 = random_field_vector(&mut rng, block_length);

        let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);
        let msg = random_message(&mut rng, message_size);

        group.throughput(Throughput::Elements(message_size as u64));
        group.bench_with_input(
            BenchmarkId::new("size", format!("2^{log_size}")),
            &msg,
            |b, msg| {
                b.iter(|| era_code.encode_fused(msg.clone()));
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_encode_naive, bench_encode_fused);
criterion_main!(benches);
