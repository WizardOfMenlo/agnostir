use std::hint::black_box;
use std::time::Instant;

use agnostir::{
    BrakedownCode, BrakedownParams, EraCode, ErrorCorrectingCode, FieldElement,
    blake3_merkle_commit_interleaved, random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use rand::{SeedableRng, rngs::SmallRng};
use rayon::prelude::*;

fn era_inner_params_normal(k_log: u32) -> (f64, f64, usize, usize) {
    match k_log {
        14 => (0.12, 1.2, 6, 19),
        15 => (0.12, 1.2, 6, 19),
        _ if k_log >= 16 => (0.12, 1.2, 5, 18),
        other => panic!("no tuned ERA params for segment message size 2^{other}"),
    }
}

fn mean_ms(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}

fn median_ms(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    let n = values.len();
    if n.is_multiple_of(2) {
        (values[n / 2 - 1] + values[n / 2]) * 0.5
    } else {
        values[n / 2]
    }
}

fn main() {
    let k_log = 18usize;
    let eta = 4usize;
    let message_size = 1usize << k_log;
    let seg_count = 1usize << eta;
    let seg_msg_size = 1usize << (k_log - eta);
    let runs = 10usize;
    let warmups = 2usize;
    let single_runs = 30usize;

    let (alpha, inverse_rate, cn, dn) = era_inner_params_normal(seg_msg_size.ilog2());

    let mut rng = SmallRng::seed_from_u64(2025);
    let msg: Vec<SecpScalar> = (0..message_size)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();

    let base_code = BrakedownCode::<SecpScalar>::new(
        seg_msg_size,
        BrakedownParams {
            alpha,
            inverse_rate,
            cn,
            dn,
        },
        &mut rng,
    );
    let repetition = 4usize;
    let bl_seg = base_code.block_length() * repetition;
    let p1 = random_permutation(&mut rng, bl_seg);
    let p2 = random_permutation(&mut rng, bl_seg);
    let m1: Vec<SecpScalar> = (0..bl_seg).map(|_| SecpScalar::random(&mut rng)).collect();
    let m2: Vec<SecpScalar> = (0..bl_seg).map(|_| SecpScalar::random(&mut rng)).collect();
    let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);
    let segment_msg = era_code.message_size();

    eprintln!("=== ERA commit split profile ===");
    eprintln!(
        "k=2^{k_log}, eta={eta}, message_size={message_size}, seg_count={seg_count}, seg_msg=2^{}",
        seg_msg_size.ilog2()
    );
    eprintln!(
        "ERA params: alpha={alpha}, inverse_rate={inverse_rate}, cn={cn}, dn={dn}, repetition={repetition}"
    );
    eprintln!("Runs: {runs} (warmups: {warmups})");

    for _ in 0..warmups {
        let segments: Vec<Vec<_>> = (0..seg_count)
            .into_par_iter()
            .map(|seg| {
                let start = seg * segment_msg;
                era_code.encode_era(&msg[start..start + segment_msg])
            })
            .collect();
        black_box(blake3_merkle_commit_interleaved(&segments));
    }

    // Single encode latency (no profiling instrumentation inside encode_era).
    let one_msg = &msg[..segment_msg];
    let mut single_times_ms = Vec::with_capacity(single_runs);
    for _ in 0..single_runs {
        let t0 = Instant::now();
        black_box(era_code.encode_era(one_msg));
        single_times_ms.push(t0.elapsed().as_secs_f64() * 1e3);
    }

    // 16 encodes done sequentially.
    let mut seq16_times_ms = Vec::with_capacity(runs);
    for _ in 0..runs {
        let t0 = Instant::now();
        let mut out = Vec::with_capacity(seg_count);
        for seg in 0..seg_count {
            let start = seg * segment_msg;
            out.push(era_code.encode_era(&msg[start..start + segment_msg]));
        }
        black_box(out);
        seq16_times_ms.push(t0.elapsed().as_secs_f64() * 1e3);
    }

    let mut encode_times_ms = Vec::with_capacity(runs);
    let mut merkle_times_ms = Vec::with_capacity(runs);
    let mut total_times_ms = Vec::with_capacity(runs);

    for _ in 0..runs {
        let t0 = Instant::now();
        let segments: Vec<Vec<_>> = (0..seg_count)
            .into_par_iter()
            .map(|seg| {
                let start = seg * segment_msg;
                era_code.encode_era(&msg[start..start + segment_msg])
            })
            .collect();
        let t_encode = t0.elapsed();

        let t1 = Instant::now();
        let root = blake3_merkle_commit_interleaved(&segments);
        black_box(root);
        let t_merkle = t1.elapsed();

        let t_total = t_encode + t_merkle;
        encode_times_ms.push(t_encode.as_secs_f64() * 1e3);
        merkle_times_ms.push(t_merkle.as_secs_f64() * 1e3);
        total_times_ms.push(t_total.as_secs_f64() * 1e3);
    }

    let mut encode_for_median = encode_times_ms.clone();
    let mut merkle_for_median = merkle_times_ms.clone();
    let mut total_for_median = total_times_ms.clone();
    let mut single_for_median = single_times_ms.clone();
    let mut seq16_for_median = seq16_times_ms.clone();

    let encode_mean = mean_ms(&encode_times_ms);
    let merkle_mean = mean_ms(&merkle_times_ms);
    let total_mean = mean_ms(&total_times_ms);
    let single_mean = mean_ms(&single_times_ms);
    let seq16_mean = mean_ms(&seq16_times_ms);
    let encode_median = median_ms(&mut encode_for_median);
    let merkle_median = median_ms(&mut merkle_for_median);
    let total_median = median_ms(&mut total_for_median);
    let single_median = median_ms(&mut single_for_median);
    let seq16_median = median_ms(&mut seq16_for_median);

    let parallel_encode_per_msg_mean = encode_mean / seg_count as f64;
    let parallel_encode_per_msg_median = encode_median / seg_count as f64;
    let seq_speedup_mean = seq16_mean / encode_mean;
    let seq_speedup_median = seq16_median / encode_median;

    eprintln!();
    eprintln!("Encoding-only context:");
    eprintln!(
        "  single encode (avg/median): {:8.3} / {:8.3} ms",
        single_mean, single_median
    );
    eprintln!(
        "  16 encodes sequential total (avg/median): {:8.3} / {:8.3} ms",
        seq16_mean, seq16_median
    );
    eprintln!(
        "  16 encodes parallel total (avg/median):   {:8.3} / {:8.3} ms",
        encode_mean, encode_median
    );
    eprintln!(
        "  per-message in parallel (avg/median):     {:8.3} / {:8.3} ms",
        parallel_encode_per_msg_mean, parallel_encode_per_msg_median
    );
    eprintln!(
        "  speedup vs sequential 16 (avg/median):    {:8.2}x / {:8.2}x",
        seq_speedup_mean, seq_speedup_median
    );

    eprintln!();
    eprintln!("Average times over {runs} runs:");
    eprintln!(
        "  encode segments: {:8.3} ms ({:5.1}%)",
        encode_mean,
        encode_mean / total_mean * 100.0
    );
    eprintln!(
        "  merkle commit:   {:8.3} ms ({:5.1}%)",
        merkle_mean,
        merkle_mean / total_mean * 100.0
    );
    eprintln!("  total:           {:8.3} ms", total_mean);

    eprintln!();
    eprintln!("Median times over {runs} runs:");
    eprintln!(
        "  encode segments: {:8.3} ms ({:5.1}%)",
        encode_median,
        encode_median / total_median * 100.0
    );
    eprintln!(
        "  merkle commit:   {:8.3} ms ({:5.1}%)",
        merkle_median,
        merkle_median / total_median * 100.0
    );
    eprintln!("  total:           {:8.3} ms", total_median);
}
