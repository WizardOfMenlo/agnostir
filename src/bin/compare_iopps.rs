//! Full proof benchmark, with honest labels for the local recursive baseline.
use clap::Parser;
use era_codes::proof::profile::Profile;
use era_codes::{
    BasefoldCode, BasefoldParams, BrakedownBaseCase, BrakedownParams, ErrorCorrectingCode,
    basefold_iopp::{self, FoldingSetup, InterleavedParameters},
    era_iopp,
    iopp_experiment::ExperimentConfig,
    proof::merkle::Commitment,
};
use rand::{SeedableRng, rngs::SmallRng};
use rayon::prelude::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::Instant,
};

fn save_profile(
    output: &mut Option<BufWriter<File>>,
    protocol: &str,
    sample: usize,
    profile: &Profile,
) -> Result<(), String> {
    if let Some(output) = output {
        for m in &profile.measurements {
            writeln!(
                output,
                "{protocol},{sample},{},{:.6},{:.6},{},{}",
                m.path,
                m.inclusive.as_secs_f64() * 1000.0,
                m.exclusive.as_secs_f64() * 1000.0,
                m.inclusive_bytes,
                m.exclusive_bytes
            )
            .map_err(|e| e.to_string())?;
        }
        output.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn save_proof(directory: Option<&Path>, protocol: &str, proof: &[u8]) -> Result<(), String> {
    if let Some(directory) = directory {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join(format!("{protocol}.proof")))
            .map_err(|e| e.to_string())?;
        file.write_all(proof).map_err(|e| e.to_string())?;
    }
    Ok(())
}

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
    /// Write nested wall-clock timings and exact serialized byte counts as CSV.
    #[arg(long)]
    profile_out: Option<PathBuf>,
    /// Separate ERA verifier stage timings and consumed proof byte counts.
    #[arg(long)]
    verify_profile_out: Option<PathBuf>,
    /// Save the first measured, independently verified proof of each protocol.
    #[arg(long)]
    proof_dir: Option<PathBuf>,
    /// Release the original ERA commitment after its last opening.
    #[arg(long)]
    consume_era_commitment: bool,
    /// Optional GKR checkpoint depths from the root, e.g. 3,7,11,15 (full preset).
    #[arg(long, value_delimiter = ',')]
    gkr_checkpoints: Vec<usize>,
    /// Use explicit externally calculated parameters, without a calibration claim.
    #[arg(long, conflicts_with = "smoke")]
    custom_parameters: bool,
    #[arg(long, requires = "custom_parameters")]
    eta: Option<usize>,
    #[arg(long, requires = "custom_parameters")]
    basefold_eta: Option<usize>,
    #[arg(long, requires = "custom_parameters")]
    output_log: Option<usize>,
    /// Base-two logarithm of the codeswitch output inverse rate (default: 3).
    #[arg(long, requires = "custom_parameters")]
    output_log_rate: Option<usize>,
    #[arg(long, requires = "custom_parameters")]
    terminal_log: Option<usize>,
    #[arg(long, requires = "custom_parameters")]
    era_queries: Option<usize>,
    #[arg(long, requires = "custom_parameters")]
    terminal_queries: Option<usize>,
    #[arg(long, requires = "custom_parameters")]
    basefold_queries: Option<usize>,
    #[arg(long, requires = "custom_parameters")]
    era_base_alpha: Option<f64>,
    #[arg(long, requires = "custom_parameters")]
    era_base_inverse_rate: Option<f64>,
    #[arg(long, requires = "custom_parameters")]
    era_base_cn: Option<usize>,
    #[arg(long, requires = "custom_parameters")]
    era_base_dn: Option<usize>,
    /// Terminal code; zero-pad has absolute distance one and needs recalibration.
    #[arg(long, default_value = "rs", value_parser = ["rs", "zero-pad"], requires = "custom_parameters")]
    era_base_case: String,
}
fn main() -> Result<(), String> {
    let args = Args::parse();
    if args.threads == 0 || args.samples == 0 {
        return Err("threads and samples must be positive".into());
    }
    if !["era", "basefold-local", "both"].contains(&args.protocol.as_str()) {
        return Err("unknown protocol".into());
    }
    let custom_base = args.era_base_alpha.is_some()
        || args.era_base_inverse_rate.is_some()
        || args.era_base_cn.is_some()
        || args.era_base_dn.is_some()
        || args.era_base_case != "rs";
    let base_parameters = if custom_base {
        let (Some(alpha), Some(inverse_rate), Some(cn), Some(dn)) = (
            args.era_base_alpha,
            args.era_base_inverse_rate,
            args.era_base_cn,
            args.era_base_dn,
        ) else {
            return Err(
                "custom base requires all four --era-base-{alpha,inverse-rate,cn,dn} options"
                    .into(),
            );
        };
        if args.protocol == "basefold-local"
            || !alpha.is_finite()
            || !inverse_rate.is_finite()
            || !(0.0 < alpha && alpha < 1.0)
            || inverse_rate <= 1.0
            || cn == 0
            || dn == 0
        {
            return Err("invalid custom ERA base parameters".into());
        }
        BrakedownParams {
            alpha,
            inverse_rate,
            cn,
            dn,
        }
    } else {
        BrakedownParams {
            alpha: 0.05,
            inverse_rate: 1.1,
            cn: 6,
            dn: 40,
        }
    };
    let base_case = if args.era_base_case == "zero-pad" {
        BrakedownBaseCase::ZeroPadding
    } else {
        BrakedownBaseCase::ReedSolomon
    };
    if !args.smoke && !args.custom_parameters && args.message_log != 22 {
        return Err(
            "nondefault sizes require --custom-parameters and explicit query counts".into(),
        );
    }
    if args.custom_parameters {
        if args.protocol != "basefold-local"
            && (args.era_queries.is_none() || args.terminal_queries.is_none())
        {
            return Err(
                "custom ERA parameters require --era-queries and --terminal-queries".into(),
            );
        }
        if args.protocol != "era" && args.basefold_queries.is_none() {
            return Err("custom BaseFold parameters require --basefold-queries".into());
        }
        eprintln!(
            "Custom numerical parameters: distance and composed soundness require separate review."
        );
    }
    let mut profiles = args
        .profile_out
        .as_ref()
        .map(|path| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map(BufWriter::new)
        })
        .transpose()
        .map_err(|e| e.to_string())?;
    if let Some(output) = &mut profiles {
        writeln!(
            output,
            "protocol,sample,path,inclusive_ms,exclusive_ms,inclusive_bytes,exclusive_bytes"
        )
        .map_err(|e| e.to_string())?;
    }
    let mut verifier_profiles = args
        .verify_profile_out
        .as_ref()
        .map(|path| {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map(BufWriter::new)
        })
        .transpose()
        .map_err(|e| e.to_string())?;
    if let Some(output) = &mut verifier_profiles {
        writeln!(
            output,
            "protocol,sample,path,inclusive_ms,exclusive_ms,inclusive_bytes,exclusive_bytes"
        )
        .map_err(|e| e.to_string())?;
    }
    if let Some(directory) = &args.proof_dir {
        fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.threads)
        .build_global()
        .map_err(|e| e.to_string())?;
    let (log, eta, output_log, terminal_log, qera, qbf, qbase) = if args.smoke {
        (10, 2, 6, 2, 24, 24, 24)
    } else if args.custom_parameters {
        (
            args.message_log,
            args.eta.unwrap_or(6),
            args.output_log.unwrap_or(15),
            args.terminal_log.unwrap_or(12),
            args.era_queries.unwrap_or(834),
            args.terminal_queries.unwrap_or(146),
            args.basefold_queries.unwrap_or(949),
        )
    } else {
        (22, 6, 15, 12, 834, 146, 949)
    };
    let base_eta = args.basefold_eta.unwrap_or(if args.smoke { 2 } else { 5 });
    let output_log_rate = args.output_log_rate.unwrap_or(3);
    if output_log_rate > 5 {
        return Err("output-log-rate must be in 0..=5".into());
    }
    if log >= 32 || eta >= log || base_eta >= log || terminal_log >= log {
        return Err(
            "invalid dimensions: require eta/basefold-eta/terminal-log < message-log < 32".into(),
        );
    }
    if args.protocol != "era" && terminal_log >= log - base_eta {
        return Err("BaseFold terminal-log must be below its row message log".into());
    }
    if args.protocol != "basefold-local"
        && (!(log - eta).is_multiple_of(2) || output_log >= log - eta || terminal_log >= output_log)
    {
        return Err(
            "ERA requires an even row message log and terminal-log < output-log < row-log".into(),
        );
    }
    if [qera, qbf, qbase].iter().any(|&q| q == 0 || q > 1 << 20) {
        return Err("queries must be in 1..=1048576".into());
    }
    let config = ExperimentConfig {
        message_log: log,
        eta,
        seed: args.seed,
    };
    let (message, point) = config.message_and_point();
    println!(
        "protocol,message_log,eta,output_log,output_log_rate,terminal_log,seed,threads,sample,setup_ms,commit_ms,prove_ms,verify_ms,proof_bytes,index_rows,online_rows,accepted,proof_blake3,gkr_checkpoints,checkpoint_rows"
    );
    if args.protocol != "basefold-local" {
        let start = Instant::now();
        let label = if args.gkr_checkpoints.is_empty() {
            "era-corrected".to_owned()
        } else {
            format!(
                "era-checkpoint-{}",
                args.gkr_checkpoints
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join("-")
            )
        };
        eprintln!("ERA base parameters: {base_parameters:?}; terminal code: {base_case:?}");
        let setup = era_iopp::Setup::new_with_base_code(
            era_iopp::Parameters {
                message_log: log,
                eta,
                output_log,
                output_log_rate,
                terminal_log,
                era_queries: qera,
                basefold_queries: qbf,
                seed: args.seed,
            },
            args.gkr_checkpoints.clone(),
            base_parameters,
            base_case,
        )
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
            let root = tree.root();
            let mut tree = Some(tree);
            let start = Instant::now();
            let (value, proof, profile) = if args.consume_era_commitment {
                setup.prove_consuming_with_profile(
                    tree.take().unwrap(),
                    &message,
                    &point,
                    profiles.is_some(),
                )
            } else {
                setup.prove_with_profile(
                    tree.as_ref().unwrap(),
                    &message,
                    &point,
                    profiles.is_some(),
                )
            }
            .map_err(|e| e.to_string())?;
            let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
            let start = Instant::now();
            let verifier_profile = setup
                .verify_with_profile(root, &point, value, &proof, verifier_profiles.is_some())
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
                "{label},{log},{eta},{output_log},{output_log_rate},{terminal_log},{},{},{sample},{setup_ms:.6},{commit_ms:.6},{prove_ms:.6},{verify_ms:.6},{},{},{online_rows},true,{},{},{}",
                args.seed,
                args.threads,
                proof.len(),
                setup.index.rows.len(),
                blake3::hash(&proof).to_hex(),
                args.gkr_checkpoints
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join("-"),
                setup.checkpoint_rows()
            );
            save_profile(&mut profiles, &label, sample, &profile)?;
            save_profile(&mut verifier_profiles, &label, sample, &verifier_profile)?;
            if sample == 0 {
                save_proof(args.proof_dir.as_deref(), &label, &proof)?;
            }
        }
    }
    if args.protocol != "era" {
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
            let (value, proof, profile) = basefold_iopp::prove_interleaved_with_profile(
                &setup,
                parameters,
                &tree,
                &message,
                &point,
                profiles.is_some(),
            )
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
                "basefold-local,{log},{base_eta},{row_log},1,{terminal_log},{},{},{sample},{setup_ms:.6},{commit_ms:.6},{prove_ms:.6},{verify_ms:.6},{},0,{},true,{},,0",
                args.seed,
                args.threads,
                proof.len(),
                1 << base_eta,
                blake3::hash(&proof).to_hex()
            );
            save_profile(&mut profiles, "basefold-local", sample, &profile)?;
            if sample == 0 {
                save_proof(args.proof_dir.as_deref(), "basefold-local", &proof)?;
            }
        }
    }
    Ok(())
}
