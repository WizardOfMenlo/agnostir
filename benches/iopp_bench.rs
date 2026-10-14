use agnostir::{
    ErrorCorrectingCode,
    interleaved_iopp::fs::{Parameters, prove, verify},
    iopp_experiment::{
        CodeKind, DEFAULT_ETA, DEFAULT_MESSAGE_LOG, DEFAULT_SEED, ExperimentConfig,
        num_queries_from_delta,
    },
    proof::merkle::Commitment,
};
use criterion::{Criterion, criterion_group, criterion_main};
use rayon::{current_num_threads, prelude::*};
use std::{env, hint::black_box};

fn env_number<T: std::str::FromStr>(name: &str, default: T) -> T {
    env::var(name).map_or(default, |raw| {
        raw.parse()
            .unwrap_or_else(|_| panic!("invalid {name}='{raw}'"))
    })
}

fn env_bool(name: &str) -> bool {
    env::var(name).is_ok_and(|raw| match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => true,
        "0" | "false" | "no" | "n" | "off" => false,
        _ => panic!("invalid boolean {name}='{raw}'"),
    })
}

fn bench_iopp(c: &mut Criterion) {
    let config = ExperimentConfig {
        message_log: env_number("IOPP_MESSAGE_LOG", DEFAULT_MESSAGE_LOG),
        eta: env_number("IOPP_ETA", DEFAULT_ETA),
        seed: env_number("IOPP_SEED", DEFAULT_SEED),
    };
    let only_conjectured = env_bool("IOPP_ONLY_CONJECTURED_ERA");
    let mut kinds = if only_conjectured {
        Vec::new()
    } else {
        CodeKind::STANDARD.to_vec()
    };
    if env_bool("IOPP_SKIP_EA") {
        kinds.retain(|kind| *kind != CodeKind::Ea);
    }
    if only_conjectured || env_bool("IOPP_INCLUDE_CONJECTURED_ERA") {
        kinds.push(CodeKind::ConjecturedEra);
    }
    for &kind in &kinds {
        config
            .validate(kind)
            .expect("invalid experiment configuration");
    }

    eprintln!(
        "config: message_log={} eta={} rows={} seed={} threads={} chunk_len={}",
        config.message_log,
        config.eta,
        config.rows(),
        config.seed,
        current_num_threads(),
        env::var("AGNOSTIR_CHUNK_LEN").unwrap_or_else(|_| "8192 (default)".into())
    );
    let (message, point) = config.message_and_point();
    let sequential_era = current_num_threads() <= config.rows();

    for kind in kinds {
        let code = config
            .build_code(kind)
            .expect("validated code configuration");
        let delta = kind.assumed_distance(config.message_log - config.eta);
        let queries = num_queries_from_delta(delta);
        if kind == CodeKind::BoltMax {
            eprintln!(
                "bolt-max adaptation assumes prime-field kernel distance 0.013; setup failure is not certified"
            );
        }
        let encode_segments = |input: &[ark_secp256k1::Fr]| -> Vec<_> {
            input
                .par_chunks(code.message_size())
                .map(|row| code.encode_row(row, sequential_era))
                .collect()
        };

        let parameters = Parameters {
            message_log: config.message_log,
            eta: config.eta,
            block_len: code.block_length(),
            queries,
            code_id: config.code_id(kind),
        };
        c.bench_function(&format!("{}_commit_fs", kind.name()), |b| {
            b.iter(|| black_box(Commitment::new(encode_segments(black_box(&message)))));
        });
        let tree = Commitment::new(encode_segments(&message));
        c.bench_function(&format!("{}_eval_prover_fs", kind.name()), |b| {
            b.iter(|| black_box(prove(parameters, &tree, black_box(&message), &point).unwrap()));
        });
        let (value, proof) = prove(parameters, &tree, &message, &point).unwrap();
        eprintln!(
            "{} assumed_delta={delta:.6} queries={queries} block_length={} serialized_proof_bytes={} commitment_bytes=32",
            kind.name(),
            code.block_length(),
            proof.len()
        );
        c.bench_function(&format!("{}_verify_fs", kind.name()), |b| {
            b.iter(|| {
                verify(
                    parameters,
                    tree.root(),
                    &point,
                    value,
                    black_box(&proof),
                    |m| code.encode(m),
                )
                .unwrap()
            });
        });
    }
}

criterion_group! {
    name = iopp;
    config = Criterion::default().sample_size(10).without_plots();
    targets = bench_iopp
}
criterion_main!(iopp);
