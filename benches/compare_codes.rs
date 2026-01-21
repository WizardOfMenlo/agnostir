use agnostir::{
    EncodeNaiveBuffers, EraCode, ErrorCorrectingCode, IdentityCode, OptimizedEraCode,
    RadixSortBuffers, ReedSolomonCode, encode_interleaved, random_permutation,
};
use criterion::{BatchSize, Criterion, black_box, criterion_group, criterion_main};
use p3_koala_bear::KoalaBear;
use rand::{Rng, SeedableRng, rngs::SmallRng};

const MESSAGE_SIZE: usize = 1 << 23;
const RS_INV_RATE: usize = 1;
const INTERLEAVING_FACTOR: usize = 4;
const ERA_REPETITION: usize = 6;

fn build_message(rng: &mut impl Rng) -> Vec<KoalaBear> {
    (0..MESSAGE_SIZE)
        .map(|_| KoalaBear::new(rng.random()))
        .collect()
}

fn build_era_code(
    rng: &mut impl Rng,
    interleaving_factor: usize,
) -> EraCode<IdentityCode<KoalaBear>, KoalaBear> {
    let base_code: IdentityCode<KoalaBear> =
        IdentityCode::new(MESSAGE_SIZE >> interleaving_factor);
    let block_length_segment = (MESSAGE_SIZE >> interleaving_factor) * ERA_REPETITION;

    let p1 = random_permutation(rng, block_length_segment);
    let p2 = random_permutation(rng, block_length_segment);
    let m1: Vec<KoalaBear> = (0..block_length_segment)
        .map(|_| KoalaBear::new(rng.random()))
        .collect();
    let m2: Vec<KoalaBear> = (0..block_length_segment)
        .map(|_| KoalaBear::new(rng.random()))
        .collect();

    EraCode::new(base_code, ERA_REPETITION, p1, p2, m1, m2)
}

fn build_optimized_era_code(
    rng: &mut impl Rng,
    interleaving_factor: usize,
) -> OptimizedEraCode<IdentityCode<KoalaBear>, KoalaBear> {
    let base_code: IdentityCode<KoalaBear> =
        IdentityCode::new(MESSAGE_SIZE >> interleaving_factor);
    let block_length_segment = (MESSAGE_SIZE >> interleaving_factor) * ERA_REPETITION;

    let p1 = random_permutation(rng, block_length_segment);
    let p2 = random_permutation(rng, block_length_segment);
    let m1: Vec<KoalaBear> = (0..block_length_segment)
        .map(|_| KoalaBear::new(rng.random()))
        .collect();
    let m2: Vec<KoalaBear> = (0..block_length_segment)
        .map(|_| KoalaBear::new(rng.random()))
        .collect();

    OptimizedEraCode::new(base_code, ERA_REPETITION, interleaving_factor, p1, p2, m1, m2)
}

fn bench_compare_interleaved(c: &mut Criterion) {
    let mut rng = SmallRng::seed_from_u64(2025);
    let msg = build_message(&mut rng);

    let rs_code: ReedSolomonCode<KoalaBear, _> =
        ReedSolomonCode::new(MESSAGE_SIZE >> INTERLEAVING_FACTOR, (MESSAGE_SIZE >> INTERLEAVING_FACTOR) << RS_INV_RATE);
    let mut optimized_era_code = build_optimized_era_code(&mut rng, INTERLEAVING_FACTOR);
    let mut naive_buffers = EncodeNaiveBuffers::<KoalaBear>::default();

    c.bench_function("reed_solomon_interleaved_rate_half", |b| {
        b.iter_batched(
            || msg.clone(),
            |input| encode_interleaved(&input, &rs_code, INTERLEAVING_FACTOR),
            BatchSize::LargeInput,
        );
    });

    c.bench_function("era_interleaved_repetition_6", |b| {
        b.iter_batched_ref(
            || msg.clone(),
            |input| optimized_era_code.encode_naive_with_buffer(input, &mut naive_buffers),
            BatchSize::LargeInput,
        );
    });
}




fn bench_compare(c: &mut Criterion) {
    let mut rng = SmallRng::seed_from_u64(2025);
    let msg = build_message(&mut rng);

    let rs_code: ReedSolomonCode<KoalaBear, _> =
        ReedSolomonCode::new(MESSAGE_SIZE, MESSAGE_SIZE << RS_INV_RATE);
    let era_code = build_era_code(&mut rng, 0);
    let mut optimized_era_code = build_optimized_era_code(&mut rng, 0);
    let mut naive_buffers = EncodeNaiveBuffers::<KoalaBear>::default();
    let mut radix_buffers = RadixSortBuffers::with_capacity(MESSAGE_SIZE * ERA_REPETITION);

    c.bench_function("reed_solomon_rate_half", |b| {
        b.iter_batched(
            || msg.clone(),
            |input| rs_code.encode(&input),
            BatchSize::LargeInput,
        );
    });

    // c.bench_function("era_repetition_6", |b| {
    //     b.iter_batched(
    //         || msg.clone(),
    //         |input| era_code.encode(&input),
    //         BatchSize::LargeInput,
    //     );
    // });

    c.bench_function("optimized_era_repetition_6", |b| {
        b.iter_batched(
            || msg.clone(),
            |input| optimized_era_code.encode(&input),
            BatchSize::LargeInput,
        );
    });

    // c.bench_function("optimized_era_blocked_repetition_6", |b| {
    //     b.iter_batched(
    //         || msg.clone(),
    //         |input| {
    //             let output = optimized_era_code.encode_blocked(&input);
    //             black_box(output);
    //         },
    //         BatchSize::LargeInput,
    //     );
    // });

    // c.bench_function("optimized_era_naive_buffered", |b| {
    //     b.iter_batched_ref(
    //         || msg.clone(),
    //         |input| optimized_era_code.encode_naive_with_buffer(input, &mut naive_buffers),
    //         BatchSize::LargeInput,
    //     );
    // });

    // c.bench_function("optimized_era_sort_perm", |b| {
    //     b.iter_batched(
    //         || msg.clone(),
    //         |input| optimized_era_code.encode_sort_perm(&input),
    //         BatchSize::LargeInput,
    //     );
    // });

    c.bench_function("optimized_era_radix_sort_perm", |b| {
        b.iter_batched_ref(
            || msg.clone(),
            |input| {
                black_box(
                    optimized_era_code
                        .encode_radix_sort_perm_with_buffer(input, &mut radix_buffers),
                );
            },
            BatchSize::LargeInput,
        );
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_compare_interleaved
}
criterion_main!(benches);
