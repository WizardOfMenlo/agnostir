use std::hint::black_box;

use agnostir::{
    BrakedownCode, BrakedownParams, EraBuffers, EraCode, ErrorCorrectingCode, FieldElement,
    TensorCode, random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use p3_koala_bear::KoalaBear;
use rand::{Rng, SeedableRng, rngs::SmallRng};

fn main() {
    let message_size = 1 << 20;
    let repetition = 6;

    let mut rng = SmallRng::seed_from_u64(2025);

    // Build ERA code with message_size = 2^20 (no interleaving split)
    let k = (message_size as f64).sqrt() as usize;
    assert_eq!(k * k, message_size);

    let inner_brakedown = BrakedownCode::<SecpScalar>::new(
        k,
        BrakedownParams {
            alpha: 0.045,
            inverse_rate: 1.1,
            cn: 7,
            dn: 11,
        },
        &mut rng,
    );
    let base_code: TensorCode<BrakedownCode<SecpScalar>> = TensorCode::new(inner_brakedown);
    let block_length_segment = base_code.block_length() * repetition;

    let p1 = random_permutation(&mut rng, block_length_segment);
    let p2 = random_permutation(&mut rng, block_length_segment);
    let m1: Vec<SecpScalar> = (0..block_length_segment)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();
    let m2: Vec<SecpScalar> = (0..block_length_segment)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();

    let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);
    let mut buf = EraBuffers::new(era_code.block_length());

    let msg: Vec<SecpScalar> = (0..message_size)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();

    eprintln!("ERA encode profile (msg_size={message_size}, block_length={block_length_segment}, repetition={repetition})");
    eprintln!("Warm-up...");
    black_box(era_code.encode(&msg, &mut buf));

    eprintln!("Profiling...");
    black_box(era_code.encode_profiled(&msg, &mut buf));
}
