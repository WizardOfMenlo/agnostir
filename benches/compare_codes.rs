use agnostir::{
    EraCode, ErrorCorrectingCode, IdentityCode, OptimizedEraCode, ReedSolomonCode,
    random_permutation,
};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use p3_koala_bear::KoalaBear;
use rand::{Rng, SeedableRng, rngs::SmallRng};

const MESSAGE_SIZE: usize = 1 << 23;
const RS_BLOCK_LENGTH: usize = 1 << 24;
const ERA_REPETITION: usize = 6;

fn build_message() -> Vec<KoalaBear> {
    (0..MESSAGE_SIZE as u32).map(KoalaBear::new).collect()
}

fn build_era_code(rng: &mut impl Rng) -> EraCode<IdentityCode<KoalaBear>, KoalaBear> {
    let base_code: IdentityCode<KoalaBear> = IdentityCode::new(MESSAGE_SIZE);
    let block_length = MESSAGE_SIZE * ERA_REPETITION;

    let p1 = random_permutation(rng, block_length);
    let p2 = random_permutation(rng, block_length);
    let m1: Vec<KoalaBear> = (0..block_length)
        .map(|_| KoalaBear::new(rng.random()))
        .collect();
    let m2: Vec<KoalaBear> = (0..block_length)
        .map(|_| KoalaBear::new(rng.random()))
        .collect();

    EraCode::new(base_code, ERA_REPETITION, p1, p2, m1, m2)
}

fn build_optimized_era_code(
    rng: &mut impl Rng,
) -> OptimizedEraCode<IdentityCode<KoalaBear>, KoalaBear> {
    let base_code: IdentityCode<KoalaBear> = IdentityCode::new(MESSAGE_SIZE);
    let block_length = MESSAGE_SIZE * ERA_REPETITION;

    let p1 = random_permutation(rng, block_length);
    let p2 = random_permutation(rng, block_length);
    let m1: Vec<KoalaBear> = (0..block_length)
        .map(|_| KoalaBear::new(rng.random()))
        .collect();
    let m2: Vec<KoalaBear> = (0..block_length)
        .map(|_| KoalaBear::new(rng.random()))
        .collect();

    OptimizedEraCode::new(base_code, ERA_REPETITION, p1, p2, m1, m2)
}

fn bench_compare(c: &mut Criterion) {
    let msg = build_message();
    let mut rng = SmallRng::seed_from_u64(2025);

    let rs_code: ReedSolomonCode<KoalaBear, _> =
        ReedSolomonCode::new(MESSAGE_SIZE, RS_BLOCK_LENGTH);
    let era_code = build_era_code(&mut rng);
    let optimized_era_code = build_optimized_era_code(&mut rng);

    c.bench_function("reed_solomon_rate_half", |b| {
        b.iter_batched(
            || msg.clone(),
            |input| rs_code.encode(&input),
            BatchSize::LargeInput,
        );
    });

    c.bench_function("era_repetition_6", |b| {
        b.iter_batched(
            || msg.clone(),
            |input| era_code.encode(&input),
            BatchSize::LargeInput,
        );
    });

    c.bench_function("optimized_era_repetition_6", |b| {
        b.iter_batched(
            || msg.clone(),
            |input| optimized_era_code.encode(&input),
            BatchSize::LargeInput,
        );
    });

    c.bench_function("optimized_era_blocked_repetition_6", |b| {
        b.iter_batched(
            || msg.clone(),
            |input| optimized_era_code.encode_blocked(&input),
            BatchSize::LargeInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_compare
}
criterion_main!(benches);
