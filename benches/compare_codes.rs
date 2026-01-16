use agnostir::{EraCode, ErrorCorrectingCode, IdentityCode, ReedSolomonCode};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;

const MESSAGE_SIZE: usize = 1 << 23;
const RS_BLOCK_LENGTH: usize = 1 << 24;
const ERA_REPETITION: usize = 6;

fn build_message() -> Vec<KoalaBear> {
    (0..MESSAGE_SIZE as u32).map(KoalaBear::new).collect()
}

fn build_era_code() -> EraCode<IdentityCode<KoalaBear>, KoalaBear> {
    let base_code: IdentityCode<KoalaBear> = IdentityCode::new(MESSAGE_SIZE);
    let block_length = MESSAGE_SIZE * ERA_REPETITION;

    let p1: Vec<usize> = (0..block_length).collect();
    let p2: Vec<usize> = (0..block_length).collect();
    let m1: Vec<KoalaBear> = vec![KoalaBear::ONE; block_length];
    let m2: Vec<KoalaBear> = vec![KoalaBear::ONE; block_length];

    EraCode::new(base_code, ERA_REPETITION, p1, p2, m1, m2)
}

fn bench_compare(c: &mut Criterion) {
    let msg = build_message();

    let rs_code: ReedSolomonCode<KoalaBear, _> =
        ReedSolomonCode::new(MESSAGE_SIZE, RS_BLOCK_LENGTH);
    let era_code = build_era_code();

    c.bench_function("reed_solomon_rate_half", |b| {
        b.iter_batched(
            || msg.clone(),
            |input| rs_code.encode(input),
            BatchSize::LargeInput,
        );
    });

    c.bench_function("era_repetition_6", |b| {
        b.iter_batched(
            || msg.clone(),
            |input| era_code.encode(input),
            BatchSize::LargeInput,
        );
    });
}

criterion_group!(benches, bench_compare);
criterion_main!(benches);
