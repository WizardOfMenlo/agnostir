//! Commitment-only adapter for the upstream `bolt32` (degree 16) benchmark.
//! This does not implement Bolt's evaluation argument or estimate its proof size.
use bolt_rs::{
    binary_fields::{BinaryElem, BinaryElem32},
    expander::ExpanderMatrix,
    matrix::ColMajorMatrix,
    merkle_tree::{Blake3Hasher, MerkleHasher, MerkleTree, Sha256Hasher},
    reed_solomon::ReedSolomonEncoding,
    sketch_code::{encode_poly_matrix_merkle_with_hasher, encode_poly_matrix_rs_with_params},
};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::{hint::black_box, time::Instant};

const REVISION: &str = "3832e47b24e7b3e10525c9c5bcfc1cfe66d525f2";
const DEGREE: usize = 16;
const COMPRESSION: usize = 8;

struct Config {
    message_log: usize,
    eta: usize,
    threads: usize,
    samples: usize,
    warmups: usize,
    seed: u64,
    hash: String,
}

impl Config {
    fn parse() -> Result<Self, String> {
        let mut c = Self {
            message_log: 22,
            eta: 6,
            threads: 8,
            samples: 3,
            warmups: 1,
            seed: 2025,
            hash: "sha256".into(),
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            if arg == "--help" {
                println!(
                    "Bolt-min upstream commitment only: --message-log 22 --eta 6 --threads 8 --samples 3 --warmups 1 --seed 2025 --hash sha256|blake3"
                );
                std::process::exit(0);
            }
            let value = args
                .next()
                .ok_or_else(|| format!("missing value for {arg}"))?;
            match arg.as_str() {
                "--hash" => c.hash = value,
                "--seed" => c.seed = value.parse().map_err(|_| "invalid seed")?,
                _ => {
                    let n = value
                        .parse()
                        .map_err(|_| format!("invalid value for {arg}"))?;
                    match arg.as_str() {
                        "--message-log" => c.message_log = n,
                        "--eta" => c.eta = n,
                        "--threads" => c.threads = n,
                        "--samples" => c.samples = n,
                        "--warmups" => c.warmups = n,
                        _ => return Err(format!("unknown option {arg}")),
                    }
                }
            }
        }
        if !(6..=30).contains(&c.message_log)
            || !(1..=7).contains(&c.eta)
            || c.message_log < c.eta + 5
            || c.threads == 0
            || c.samples == 0
            || c.samples.checked_add(c.warmups).is_none()
            || !matches!(c.hash.as_str(), "sha256" | "blake3")
        {
            return Err("invalid dimensions/counts/hash; require 6<=message-log<=30, 1<=eta<=7, message-log>=eta+5, positive threads and samples".into());
        }
        if !cfg!(target_endian = "little") {
            return Err("upstream Merkle byte representation requires a little-endian host".into());
        }
        Ok(c)
    }
}

/// Independent scalar sparse multiply followed by the single-vector RS path.
fn reference_row(
    input: &[BinaryElem32],
    width: usize,
    row: usize,
    expander: &ExpanderMatrix<BinaryElem32>,
    rs: &ReedSolomonEncoding<BinaryElem32>,
) -> Vec<BinaryElem32> {
    let mut parity = vec![BinaryElem32::zero(); rs.block_length()];
    for (out, edges) in parity.iter_mut().zip(&expander.constraints) {
        for &(index, coefficient) in edges {
            *out += coefficient * input[index * width + row];
        }
    }
    rs.encode_non_systematic(&mut parity);
    parity
}

fn check_commitment<H: MerkleHasher>(
    tree: &MerkleTree<H>,
    mat: &ColMajorMatrix<BinaryElem32>,
    message_rows: usize,
) {
    // Upstream's Merkle API uses one-based leaf indices.
    let indices = [1, message_rows, message_rows + 1, mat.num_cols()];
    let leaves: Vec<Vec<u8>> = indices
        .iter()
        .map(|&i| {
            mat.column(i - 1)
                .iter()
                .flat_map(|x| (x.to_u128() as u32).to_le_bytes())
                .collect()
        })
        .collect();
    let proof = tree.prove(&indices);
    assert!(MerkleTree::<H>::verify(
        &tree.root().unwrap(),
        &proof,
        tree.depth(),
        &leaves,
        &indices
    ));
    let mut damaged = leaves;
    damaged[0][0] ^= 1;
    assert!(!MerkleTree::<H>::verify(
        &tree.root().unwrap(),
        &proof,
        tree.depth(),
        &damaged,
        &indices
    ));
}

fn run<H: MerkleHasher>(c: &Config) {
    let width = 1 << c.eta;
    let message_rows = 1 << (c.message_log - c.eta);
    let setup_start = Instant::now();
    let expander = ExpanderMatrix::<BinaryElem32>::new_with_seed(
        message_rows,
        DEGREE,
        DEGREE * COMPRESSION,
        c.seed,
    );
    let constraints = expander.num_constraints();
    let rs = ReedSolomonEncoding::<BinaryElem32>::new(constraints, constraints * 2);
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;
    let total_rows = message_rows + rs.block_length();
    let mut rng = StdRng::seed_from_u64(c.seed ^ 0x626f_6c74_696e_7075);
    let input: Vec<BinaryElem32> = (0..(1 << c.message_log)).map(|_| rng.random()).collect();
    // Validate complete parity vectors for the first and last interleaves.
    // Reference work is outside timing; this is an encoder check, not an IOPP.
    let reference: Vec<_> = [0, width - 1]
        .into_iter()
        .map(|row| (row, reference_row(&input, width, row, &expander, &rs)))
        .collect();
    eprintln!(
        "scope=commitment-only upstream={REVISION} field=GF(2^32) degree={DEGREE} compression={COMPRESSION} rs_inverse_rate=2 retained_merkle=true native_gpu=false; no Bolt evaluation proof is implemented or measured"
    );
    println!(
        "code,scope,field,hash,message_log,eta,seed,threads,sample,degree,compression,block_length,setup_ms,buffer_ms,expander_ms,rs_ms,merkle_ms,commit_ms,commitment_bytes,root_hex,encoder_checked,merkle_checked"
    );
    for sample in 0..c.samples + c.warmups {
        let start = Instant::now();
        let mut mat = ColMajorMatrix::zeros(width, total_rows);
        mat.as_mut_slice()[..input.len()].copy_from_slice(&input);
        let buffered = start.elapsed();
        expander.encode_matrix_inner_product_deferred_32(&mut mat);
        let expanded = start.elapsed();
        encode_poly_matrix_rs_with_params(&mut mat, message_rows, constraints, &rs);
        let encoded = start.elapsed();
        let tree = encode_poly_matrix_merkle_with_hasher::<_, H>(&mat);
        black_box(&tree);
        let committed = start.elapsed();
        assert_eq!(&mat.as_slice()[..input.len()], input.as_slice());
        for (row, expected) in &reference {
            for (col, &value) in expected.iter().enumerate() {
                assert_eq!(mat.get(*row, message_rows + col), value);
            }
        }
        check_commitment(&tree, &mat, message_rows);
        let root_hex = tree
            .root()
            .unwrap()
            .root
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect::<String>();
        if sample >= c.warmups {
            println!(
                "bolt-min,commitment-only,GF(2^32),{},{},{},{},{},{},{DEGREE},{COMPRESSION},{total_rows},{setup_ms:.6},{:.6},{:.6},{:.6},{:.6},{:.6},32,{root_hex},true,true",
                c.hash,
                c.message_log,
                c.eta,
                c.seed,
                rayon::current_num_threads(),
                sample - c.warmups,
                buffered.as_secs_f64() * 1000.0,
                (expanded - buffered).as_secs_f64() * 1000.0,
                (encoded - expanded).as_secs_f64() * 1000.0,
                (committed - encoded).as_secs_f64() * 1000.0,
                committed.as_secs_f64() * 1000.0,
            );
        }
    }
}

fn main() -> Result<(), String> {
    let c = Config::parse()?;
    rayon::ThreadPoolBuilder::new()
        .num_threads(c.threads)
        .build_global()
        .map_err(|e| e.to_string())?;
    match c.hash.as_str() {
        "sha256" => run::<Sha256Hasher>(&c),
        "blake3" => run::<Blake3Hasher>(&c),
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimized_encoder_matches_scalar_reference_and_authenticates() {
        for width in [2, 16, 64] {
            for threads in [1, 4] {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap()
                    .install(|| {
                        let m = 128;
                        let exp = ExpanderMatrix::<BinaryElem32>::new_with_seed(
                            m,
                            DEGREE,
                            DEGREE * COMPRESSION,
                            2025,
                        );
                        let rs = ReedSolomonEncoding::new(m / COMPRESSION, m / COMPRESSION * 2);
                        let mut rng = StdRng::seed_from_u64(17);
                        let input: Vec<BinaryElem32> =
                            (0..m * width).map(|_| rng.random()).collect();
                        let mut mat = ColMajorMatrix::zeros(width, m + rs.block_length());
                        mat.as_mut_slice()[..input.len()].copy_from_slice(&input);
                        exp.encode_matrix_inner_product_deferred_32(&mut mat);
                        encode_poly_matrix_rs_with_params(&mut mat, m, exp.num_constraints(), &rs);
                        assert_eq!(&mat.as_slice()[..input.len()], &input);
                        for row in 0..width {
                            let expected = reference_row(&input, width, row, &exp, &rs);
                            for (col, value) in expected.into_iter().enumerate() {
                                assert_eq!(mat.get(row, m + col), value);
                            }
                        }
                        check_commitment(
                            &encode_poly_matrix_merkle_with_hasher::<_, Sha256Hasher>(&mat),
                            &mat,
                            m,
                        );
                        check_commitment(
                            &encode_poly_matrix_merkle_with_hasher::<_, Blake3Hasher>(&mat),
                            &mat,
                            m,
                        );
                    });
            }
        }
    }
}
