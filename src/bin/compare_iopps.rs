//! Full proof benchmark, with honest labels for the local recursive baseline.
use agnostir::{
    BasefoldCode, BasefoldParams, ErrorCorrectingCode,
    basefold_iopp::{self, FoldingSetup, InterleavedParameters},
    era_iopp,
    iopp_experiment::ExperimentConfig,
    proof::merkle::Commitment,
};
use clap::Parser;
use rand::{SeedableRng, rngs::SmallRng};
use rayon::prelude::*;
use std::time::Instant;

#[derive(Debug, Parser)]
struct Args {
    #[arg(long, default_value_t = 22)]
    message_log: usize,
    #[arg(long, default_value_t = 8)]
    threads: usize,
    #[arg(long, default_value_t = 3)]
    samples: usize,
    #[arg(long, default_value_t = 1)]
    warmups: usize,
    #[arg(long, default_value_t = 2025)]
    seed: u64,
    /// Run a small functional configuration; it has no security calibration.
    #[arg(long)]
    smoke: bool,
    /// Either era, basefold-local, or both.
    #[arg(long, default_value = "both")]
    protocol: String,
}
fn main() -> Result<(), String> {
    let args = Args::parse();
    if args.threads == 0 || args.samples == 0 {
        return Err("threads and samples must be positive".into());
    }
    if !["era", "basefold-local", "both"].contains(&args.protocol.as_str()) {
        return Err("unknown protocol".into());
    }
    if !args.smoke && args.message_log != 22 {
        return Err("only the 2^22 preset is calibrated; use --smoke for a functional test".into());
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build_global()
        .map_err(|e| e.to_string())?;
    let (log, eta, output_log, terminal_log, qera, qbf, qbase) = if args.smoke {
        (10, 2, 6, 2, 24, 24, 24)
    } else {
        (22, 6, 15, 12, 834, 146, 949)
    };
    let config = ExperimentConfig {
        message_log: log,
        eta,
        seed: args.seed,
    };
    let (message, point) = config.message_and_point();
    println!(
        "protocol,message_log,eta,output_log,output_log_rate,terminal_log,seed,threads,sample,setup_ms,commit_ms,prove_ms,verify_ms,proof_bytes,index_rows,online_rows,accepted"
    );
    if args.protocol != "basefold-local" {
        let start = Instant::now();
        let setup = era_iopp::Setup::new(era_iopp::Parameters {
            message_log: log,
            eta,
            output_log,
            output_log_rate: 3,
            terminal_log,
            era_queries: qera,
            basefold_queries: qbf,
            seed: args.seed,
        })
        .map_err(|e| e.to_string())?;
        let setup_ms = start.elapsed().as_secs_f64() * 1000.0;
        eprintln!(
            "ERA setup complete: {:.3} ms, inner ({},{}), ERA length {}, index rows {}",
            setup_ms,
            setup.era.base_code().inner().block_length(),
            setup.era.base_code().inner().message_size(),
            setup.era.block_length(),
            setup.index.rows.len()
        );
        for sample in 0..args.samples + args.warmups {
            let start = Instant::now();
            let tree = setup.commit(&message).map_err(|e| e.to_string())?;
            let commit_ms = start.elapsed().as_secs_f64() * 1000.0;
            let start = Instant::now();
            let (value, proof) = setup
                .prove(&tree, &message, &point)
                .map_err(|e| e.to_string())?;
            let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
            let start = Instant::now();
            setup
                .verify(tree.root(), &point, value, &proof)
                .map_err(|e| e.to_string())?;
            let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
            let online_rows = (setup.era.message_size() + (1 << output_log) - 1)
                / (1 << output_log)
                + (setup.era.base_code().block_length() + (1 << output_log) - 1)
                    / (1 << output_log)
                + 2 * ((setup.era.block_length() + (1 << output_log) - 1) / (1 << output_log));
            if sample < args.warmups {
                continue;
            }
            let sample = sample - args.warmups;
            println!(
                "era-corrected,{log},{eta},{output_log},3,{terminal_log},{},{},{sample},{setup_ms:.6},{commit_ms:.6},{prove_ms:.6},{verify_ms:.6},{},{},{online_rows},true",
                args.seed,
                args.threads,
                proof.len(),
                setup.index.rows.len()
            );
        }
    }
    if args.protocol != "era" {
        let base_eta = if args.smoke { 2 } else { 5 };
        let row_log = log - base_eta;
        let start = Instant::now();
        let setup = FoldingSetup::new(BasefoldCode::new(
            1 << row_log,
            BasefoldParams { log_rate: 1 },
            &mut SmallRng::seed_from_u64(args.seed),
        ));
        let setup_ms = start.elapsed().as_secs_f64() * 1000.0;
        let mut context = blake3::Hasher::new();
        context.update(b"local-basefold-v1");
        context.update(&args.seed.to_le_bytes());
        let parameters = InterleavedParameters {
            message_log: log,
            eta: base_eta,
            terminal_log,
            queries: qbase,
            code_id: *context.finalize().as_bytes(),
        };
        for sample in 0..args.samples + args.warmups {
            let start = Instant::now();
            let tree = Commitment::new(
                message
                    .par_chunks(1 << row_log)
                    .map(|m| setup.code.encode_sequential(m))
                    .collect(),
            );
            let commit_ms = start.elapsed().as_secs_f64() * 1000.0;
            let start = Instant::now();
            let (value, proof) =
                basefold_iopp::prove_interleaved(&setup, parameters, &tree, &message, &point)
                    .map_err(|e| e.to_string())?;
            let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
            let start = Instant::now();
            basefold_iopp::verify_interleaved(
                &setup,
                parameters,
                tree.root(),
                &point,
                value,
                &proof,
            )
            .map_err(|e| e.to_string())?;
            let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
            if sample < args.warmups {
                continue;
            }
            let sample = sample - args.warmups;
            println!(
                "basefold-local,{log},{base_eta},{row_log},1,{terminal_log},{},{},{sample},{setup_ms:.6},{commit_ms:.6},{prove_ms:.6},{verify_ms:.6},{},0,{},true",
                args.seed,
                args.threads,
                proof.len(),
                1 << base_eta
            );
        }
    }
    Ok(())
}
