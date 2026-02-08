use std::hint::black_box;

use agnostir::{
    BasefoldCode, BasefoldParams,
    BrakedownCode, BrakedownParams, EraCode, ErrorCorrectingCode, FieldElement,
    TensorCode, random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use rand::{SeedableRng, rngs::SmallRng};

fn main() {
    let message_size = 1 << 20;
    let repetition = 6;
    let eta = 4; // 2^4 = 16 interleaved messages, total = 2^20 * 2^4 = 2^24

    let mut rng = SmallRng::seed_from_u64(2025);

    // Build ERA code with message_size = 2^20
    let k = (message_size as f64).sqrt() as usize;
    assert_eq!(k * k, message_size);

    // ── Brakedown profiling at k = 2^20 ──
    let big_k = 1usize << 20;
    let brakedown_big = BrakedownCode::<SecpScalar>::new(
        big_k,
        BrakedownParams {
            alpha: 0.238,
            inverse_rate: 1.72,
            cn: 9,
            dn: 12,
        },
        &mut rng,
    );
    let brakedown_msg: Vec<SecpScalar> = (0..big_k).map(|_| SecpScalar::random(&mut rng)).collect();
    eprintln!("=== Brakedown base-code profile (k={big_k}) ===");
    black_box(brakedown_big.encode_profiled(&brakedown_msg));
    eprintln!();
    drop(brakedown_big);

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

    let rows = 1usize << eta;
    let total_msg_len = message_size * rows;
    let msg: Vec<SecpScalar> = (0..total_msg_len)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();

    // ── Single-message profiling ──
    eprintln!("=== Single-message ERA profile (gather permutation) ===");
    eprintln!(
        "msg_size={message_size}, block_length={block_length_segment}, repetition={repetition}"
    );
    eprintln!("Warm-up...");
    black_box(era_code.encode_era(&msg[..message_size]));
    eprintln!("Profiling...");
    black_box(era_code.encode_profiled(&msg[..message_size]));

    // ── RipShuffle profiling ──
    eprintln!();
    eprintln!("=== Single-message ERA profile (rip_shuffle permutation) ===");
    eprintln!(
        "msg_size={message_size}, block_length={block_length_segment}, repetition={repetition}"
    );
    eprintln!("Warm-up...");
    black_box(era_code.encode_rip(&msg[..message_size], 42));
    eprintln!("Profiling...");
    black_box(era_code.encode_rip_profiled(&msg[..message_size], 42));

    // ── Interleaved profiling ──
    eprintln!();
    eprintln!("=== Interleaved ERA profile (eta={eta}, rows={rows}) ===");
    eprintln!("total input = {total_msg_len} elements");
    eprintln!("Warm-up...");
    black_box(era_code.encode_interleaved(&msg, eta));
    eprintln!("Profiling...");
    black_box(era_code.encode_interleaved_profiled(&msg, eta));

    // ── Basefold profiling ──
    let basefold_msg_size = 1usize << 20;
    let basefold_code = BasefoldCode::<SecpScalar>::new(
        basefold_msg_size,
        BasefoldParams { log_rate: 2 },
        &mut rng,
    );
    let basefold_msg: Vec<SecpScalar> = (0..basefold_msg_size)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();
    eprintln!();
    eprintln!("=== Basefold profile (msg_size={basefold_msg_size}, log_rate=2) ===");
    eprintln!("Warm-up...");
    black_box(basefold_code.encode(&basefold_msg));
    eprintln!("Profiling...");
    black_box(basefold_code.encode_profiled(&basefold_msg));
}
