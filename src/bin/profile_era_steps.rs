use std::hint::black_box;

use agnostir::{
    BrakedownCode, BrakedownParams, EraCode, ErrorCorrectingCode, FieldElement, random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use rand::{SeedableRng, rngs::SmallRng};

fn era_inner_params_normal(k_log: u32) -> (f64, f64, usize, usize) {
    match k_log {
        14 => (0.12, 1.2, 6, 19),
        15 => (0.12, 1.2, 6, 19),
        _ if k_log >= 16 => (0.12, 1.2, 5, 18),
        other => panic!("no tuned ERA params for segment message size 2^{other}"),
    }
}

fn main() {
    let message_size = 1usize << 14;
    let repetition = 4usize;

    let (alpha, inverse_rate, cn, dn) = era_inner_params_normal(message_size.ilog2());

    let mut rng = SmallRng::seed_from_u64(2026);
    let base_code = BrakedownCode::<SecpScalar>::new(
        message_size,
        BrakedownParams {
            alpha,
            inverse_rate,
            cn,
            dn,
        },
        &mut rng,
    );

    let block_length = base_code.block_length() * repetition;
    let p1 = random_permutation(&mut rng, block_length);
    let p2 = random_permutation(&mut rng, block_length);
    let m1: Vec<SecpScalar> = (0..block_length)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();
    let m2: Vec<SecpScalar> = (0..block_length)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();
    let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);

    let msg: Vec<SecpScalar> = (0..message_size)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();

    eprintln!("=== ERA Step Profile (message_size=2^14) ===");
    eprintln!("message_size={message_size}, repetition={repetition}, block_length={block_length}");
    eprintln!("params: alpha={alpha}, inverse_rate={inverse_rate}, cn={cn}, dn={dn}");

    // Warm-up both paths once.
    black_box(era_code.encode_era(&msg));
    black_box(era_code.encode_conjectured_era(&msg));

    eprintln!();
    eprintln!("--- Current ERA (with multiplication in prefix rounds) ---");
    black_box(era_code.encode_profiled(&msg));

    eprintln!();
    eprintln!("--- Conjectured ERA (no multiplication in prefix rounds) ---");
    black_box(era_code.encode_conjectured_profiled(&msg));
}
