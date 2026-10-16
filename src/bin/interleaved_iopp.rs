use clap::Parser;
use era_codes::{
    ErrorCorrectingCode,
    interleaved_iopp::fs::{Parameters, prove, verify},
    iopp_experiment::{
        CodeKind, DEFAULT_ETA, DEFAULT_MESSAGE_LOG, DEFAULT_SEED, ExperimentConfig,
        num_queries_from_delta,
    },
    proof::merkle::Commitment,
};
use rayon::{current_num_threads, prelude::*};
use std::{fs::OpenOptions, io::Write, path::PathBuf, time::Instant};

/// Canonical Fiat–Shamir interleaved IOPP benchmark. Times include proof transport.
#[derive(Debug, Parser)]
struct Args {
    #[arg(long, value_enum, default_value_t = CodeKind::Era)]
    code: CodeKind,
    #[arg(long, default_value_t = DEFAULT_MESSAGE_LOG)]
    message_log: usize,
    #[arg(long, default_value_t = DEFAULT_ETA)]
    eta: usize,
    #[arg(long, default_value_t = DEFAULT_SEED)]
    seed: u64,
    /// Override the conditional query model; this is not security calibration.
    #[arg(long)]
    queries: Option<usize>,
    /// Externally computed row-code distance; required outside the 2^16-row preset.
    /// This records a numerical assumption, not a soundness certification.
    #[arg(long)]
    distance: Option<f64>,
    /// Explicit Rayon worker count; otherwise use RAYON_NUM_THREADS.
    #[arg(long)]
    threads: Option<usize>,
    /// Number of independent measured commit/prove/verify runs.
    #[arg(long, default_value_t = 3)]
    samples: usize,
    /// Untimed warmup runs before collecting samples.
    #[arg(long, default_value_t = 1)]
    warmups: usize,
    /// Write the last serialized proof to a new file (never overwrite).
    #[arg(long)]
    proof_out: Option<PathBuf>,
    /// Print machine-readable CSV on stdout, diagnostics on stderr.
    #[arg(long)]
    csv: bool,
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    if args.samples == 0 || args.threads == Some(0) {
        return Err("samples and threads must be positive".into());
    }
    if let Some(threads) = args.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| e.to_string())?;
    }
    let config = ExperimentConfig {
        message_log: args.message_log,
        eta: args.eta,
        seed: args.seed,
    };
    config.validate_dimensions()?;
    let delta = if let Some(distance) = args.distance {
        if !distance.is_finite() || !(0.0..1.0).contains(&distance) || distance == 0.0 {
            return Err("distance must be finite and strictly between zero and one".into());
        }
        distance
    } else {
        config.validate(args.code)?;
        args.code.assumed_distance(config.message_log - config.eta)
    };
    let queries = args
        .queries
        .unwrap_or_else(|| num_queries_from_delta(delta));
    if queries == 0 || queries > 1 << 20 {
        return Err("queries must be in 1..=1048576".into());
    }
    let start = Instant::now();
    let code = if args.distance.is_some() {
        config.build_code_with_external_distance(args.code)?
    } else {
        config.build_code(args.code)?
    };
    let setup_ms = start.elapsed().as_secs_f64() * 1000.0;
    let (message, point) = config.message_and_point();
    let parameters = Parameters {
        message_log: config.message_log,
        eta: config.eta,
        block_len: code.block_length(),
        queries,
        code_id: config.code_id(args.code),
    };
    eprintln!(
        "protocol=interleaved-fs-v1 hash=BLAKE3-256 field=secp256k1_scalar threads={} setup_ms={setup_ms:.3} assumed_delta={delta} query_model={} (distance/setup bounds require separate certification)",
        current_num_threads(),
        if args.queries.is_some() {
            "override"
        } else if args.distance.is_some() {
            "external-distance-conditional-100-bit"
        } else {
            "conditional-100-bit"
        }
    );
    if args.csv {
        println!(
            "protocol,field,code,message_log,eta,seed,threads,sample,queries,block_length,setup_ms,commit_ms,prove_ms,verify_ms,proof_bytes,commitment_bytes,accepted"
        );
    }
    for sample in 0..args.samples + args.warmups {
        let start = Instant::now();
        let tree = Commitment::new(
            message
                .par_chunks(code.message_size())
                .map(|row| code.encode_row(row, config.rows() >= current_num_threads()))
                .collect(),
        );
        let commit_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        let (value, proof) =
            prove(parameters, &tree, &message, &point).map_err(|e| e.to_string())?;
        let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
        let start = Instant::now();
        verify(parameters, tree.root(), &point, value, &proof, |m| {
            code.encode(m)
        })
        .map_err(|e| e.to_string())?;
        let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
        if sample < args.warmups {
            continue;
        }
        let sample = sample - args.warmups;
        if args.csv {
            println!(
                "interleaved-fs-v1,secp256k1-scalar,{},{},{},{},{},{sample},{queries},{},{setup_ms:.6},{commit_ms:.6},{prove_ms:.6},{verify_ms:.6},{},32,true",
                args.code.name(),
                config.message_log,
                config.eta,
                config.seed,
                current_num_threads(),
                code.block_length(),
                proof.len()
            );
        } else {
            println!(
                "sample {sample}: commit={commit_ms:.3} ms prove={prove_ms:.3} ms verify={verify_ms:.3} ms proof={} bytes ({:.3} KiB), public commitment=32 bytes, PASS",
                proof.len(),
                proof.len() as f64 / 1024.0
            );
        }
        if sample + 1 == args.samples {
            if let Some(path) = &args.proof_out {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|e| e.to_string())?;
                file.write_all(&proof).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}
