use std::hint::black_box;
use std::time::Instant;

use agnostir::{
    BasefoldCode, BasefoldParams,
    BrakedownCode, BrakedownParams, EraCode, ErrorCorrectingCode, FieldElement,
    TensorCode, random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use rand::{SeedableRng, rngs::SmallRng};
use rayon::prelude::*;

fn main() {
    let message_size = 1 << 22;
    let repetition = 6;
    let eta = 4; // 2^4 = 16 interleaved messages, total = 2^20 * 2^4 = 2^24

    let mut rng = SmallRng::seed_from_u64(2025);

    // Build ERA code with segment_msg_size = message_size >> eta
    let segment_msg_size = message_size >> eta;
    let k = (segment_msg_size as f64).sqrt() as usize;
    assert_eq!(k * k, segment_msg_size);

    let (alpha, inverse_rate, cn, dn) = match k.ilog2() {
        6 => (0.03, 1.06, 1, 1),
        7 => (0.035, 1.06, 1, 1),
        8 => (0.04, 1.06, 3, 1),
        9 => (0.04, 1.07, 7, 12),
        10 => (0.04, 1.07, 9, 20),
        11 => (0.045, 1.08, 8, 26),
        12 => (0.05, 1.08, 7, 41),
        13 => (0.05, 1.08, 6, 47),
        other => panic!("no tuned params for k=2^{other}"),
    };
    eprintln!("segment_msg_size={segment_msg_size}, k={k}, alpha={alpha}, inverse_rate={inverse_rate}, cn={cn}, dn={dn}");

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
            alpha,
            inverse_rate,
            cn,
            dn,
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
    let total_msg_len = rows * segment_msg_size;
    let msg: Vec<SecpScalar> = (0..total_msg_len)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();

    // ── Single-message profiling ──
    eprintln!("=== Single-message ERA profile (gather permutation) ===");
    eprintln!(
        "msg_size={segment_msg_size}, block_length={block_length_segment}, repetition={repetition}"
    );
    eprintln!("Warm-up...");
    black_box(era_code.encode_era(&msg[..segment_msg_size]));
    eprintln!("Profiling...");
    black_box(era_code.encode_profiled(&msg[..segment_msg_size]));

    // ── RipShuffle profiling ──
    eprintln!();
    eprintln!("=== Single-message ERA profile (rip_shuffle permutation) ===");
    eprintln!(
        "msg_size={segment_msg_size}, block_length={block_length_segment}, repetition={repetition}"
    );
    eprintln!("Warm-up...");
    black_box(era_code.encode_rip(&msg[..segment_msg_size], 42));
    eprintln!("Profiling...");
    black_box(era_code.encode_rip_profiled(&msg[..segment_msg_size], 42));

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

    // ── Prefix-sum profiling ──
    let prefix_len = 1usize << 22;
    eprintln!();
    eprintln!("=== prefix_sum_in_place step-by-step profile (len=2^22 = {prefix_len}, chunk_len=8192) ===");
    let mut values: Vec<SecpScalar> = (0..prefix_len)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();
    let weights: Vec<SecpScalar> = (0..prefix_len)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();

    let chunk_len = 8192usize;
    let num_chunks = (prefix_len + chunk_len - 1) / chunk_len;

    // Warm up
    {
        let mut tmp = values.clone();
        prefix_sum_in_place::<SecpScalar>(&mut tmp, &weights, chunk_len);
        black_box(tmp);
    }

    // Reset
    for v in values.iter_mut() {
        *v = SecpScalar::random(&mut rng);
    }

    // Step 1: parallel local prefix sums (mul+add)
    let t0 = Instant::now();
    let mut totals: Vec<SecpScalar> = values
        .par_chunks_mut(chunk_len)
        .zip(weights.par_chunks(chunk_len))
        .map(|(chunk, w)| {
            let mut acc = SecpScalar::ZERO;
            for (value, weight) in chunk.iter_mut().zip(w.iter()) {
                acc += *value * *weight;
                *value = acc;
            }
            acc
        })
        .collect();
    let t_local_muladd = t0.elapsed();

    // Step 2: sequential prefix sum of chunk totals
    let t0 = Instant::now();
    let mut running = SecpScalar::ZERO;
    for total in totals.iter_mut() {
        let tmp = *total;
        *total = running;
        running += tmp;
    }
    let t_scan = t0.elapsed();

    // Step 3: parallel offset correction
    let t0 = Instant::now();
    values
        .par_chunks_mut(chunk_len)
        .zip(totals.into_par_iter())
        .for_each(|(chunk, offset)| {
            if !offset.is_zero() {
                chunk.par_iter_mut().for_each(|value| *value += offset);
            }
        });
    let t_correct = t0.elapsed();

    let total_muladd = t_local_muladd + t_scan + t_correct;
    eprintln!("  chunks={num_chunks}");
    eprintln!("  === With mul + add ===");
    eprintln!("  1. Local prefix sums (par):  {:>8.3} ms  ({:>5.1}%)", t_local_muladd.as_secs_f64() * 1e3, t_local_muladd.as_secs_f64() / total_muladd.as_secs_f64() * 100.0);
    eprintln!("  2. Scan chunk totals (seq):  {:>8.3} ms  ({:>5.1}%)", t_scan.as_secs_f64() * 1e3, t_scan.as_secs_f64() / total_muladd.as_secs_f64() * 100.0);
    eprintln!("  3. Offset correction (par):  {:>8.3} ms  ({:>5.1}%)", t_correct.as_secs_f64() * 1e3, t_correct.as_secs_f64() / total_muladd.as_secs_f64() * 100.0);
    eprintln!("  Total:                       {:>8.3} ms", total_muladd.as_secs_f64() * 1e3);

    // Now repeat without multiplication (pure add prefix sum)
    // Reset
    for v in values.iter_mut() {
        *v = SecpScalar::random(&mut rng);
    }
    // Warm up
    {
        let mut tmp = values.clone();
        let _: Vec<SecpScalar> = tmp
            .par_chunks_mut(chunk_len)
            .map(|chunk| {
                let mut acc = SecpScalar::ZERO;
                for value in chunk.iter_mut() {
                    acc += *value;
                    *value = acc;
                }
                acc
            })
            .collect();
        black_box(tmp);
    }
    for v in values.iter_mut() {
        *v = SecpScalar::random(&mut rng);
    }

    // Step 1: parallel local prefix sums (add only)
    let t0 = Instant::now();
    let mut totals: Vec<SecpScalar> = values
        .par_chunks_mut(chunk_len)
        .map(|chunk| {
            let mut acc = SecpScalar::ZERO;
            for value in chunk.iter_mut() {
                acc += *value;
                *value = acc;
            }
            acc
        })
        .collect();
    let t_local_add = t0.elapsed();

    // Step 2: sequential prefix sum of chunk totals
    let t0 = Instant::now();
    let mut running = SecpScalar::ZERO;
    for total in totals.iter_mut() {
        let tmp = *total;
        *total = running;
        running += tmp;
    }
    let t_scan2 = t0.elapsed();

    // Step 3: parallel offset correction
    let t0 = Instant::now();
    values
        .par_chunks_mut(chunk_len)
        .zip(totals.into_par_iter())
        .for_each(|(chunk, offset)| {
            if !offset.is_zero() {
                chunk.par_iter_mut().for_each(|value| *value += offset);
            }
        });
    let t_correct2 = t0.elapsed();

    let total_add = t_local_add + t_scan2 + t_correct2;
    eprintln!();
    eprintln!("  === Without mul (add only) ===");
    eprintln!("  1. Local prefix sums (par):  {:>8.3} ms  ({:>5.1}%)", t_local_add.as_secs_f64() * 1e3, t_local_add.as_secs_f64() / total_add.as_secs_f64() * 100.0);
    eprintln!("  2. Scan chunk totals (seq):  {:>8.3} ms  ({:>5.1}%)", t_scan2.as_secs_f64() * 1e3, t_scan2.as_secs_f64() / total_add.as_secs_f64() * 100.0);
    eprintln!("  3. Offset correction (par):  {:>8.3} ms  ({:>5.1}%)", t_correct2.as_secs_f64() * 1e3, t_correct2.as_secs_f64() / total_add.as_secs_f64() * 100.0);
    eprintln!("  Total:                       {:>8.3} ms", total_add.as_secs_f64() * 1e3);
    eprintln!();
    eprintln!("  Mul cost = {:.3} ms ({:.1}% of muladd local)",
        (t_local_muladd - t_local_add).as_secs_f64() * 1e3,
        (t_local_muladd - t_local_add).as_secs_f64() / t_local_muladd.as_secs_f64() * 100.0,
    );
}

fn add_const_in_place<F: FieldElement>(slice: &mut [F], offset: F) {
    slice.par_iter_mut().for_each(|value| *value += offset);
}

fn prefix_sum_in_place<F: FieldElement>(values: &mut [F], weights: &[F], chunk_len: usize) {
    if values.is_empty() {
        return;
    }

    let mut totals: Vec<F> = values
        .par_chunks_mut(chunk_len)
        .zip(weights.par_chunks(chunk_len))
        .map(|(chunk, w)| {
            let mut acc = F::ZERO;
            for (value, weight) in chunk.iter_mut().zip(w.iter()) {
                acc += *value * *weight;
                *value = acc;
            }
            acc
        })
        .collect();

    let mut running = F::ZERO;
    for total in totals.iter_mut() {
        let tmp = *total;
        *total = running;
        running += tmp;
    }

    values
        .par_chunks_mut(chunk_len)
        .zip(totals.into_par_iter())
        .for_each(|(chunk, offset)| {
            if !offset.is_zero() {
                add_const_in_place(chunk, offset);
            }
        });
}
