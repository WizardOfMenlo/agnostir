use std::time::Instant;

use agnostir::{
    BrakedownCode, BrakedownParams, EraCode, ErrorCorrectingCode, FieldElement,
    blake3_merkle_interleaved_leaves, blake3_merkle_precompute_levels,
    blake3_merkle_root_from_levels,
    interleaved_iopp::{prover_first_round, prover_second_round, verifier_challenge, verify},
    random_permutation,
};
use ark_secp256k1::Fr as SecpScalar;
use rand::{Rng, SeedableRng, rngs::SmallRng};

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// Public parameters produced by setup.
struct IoppParams {
    era_code: EraCode<BrakedownCode<SecpScalar>, SecpScalar>,
    k: usize,           // log2 of total message length (2^k field elements)
    eta: usize,         // interleaving factor (rows = 2^eta)
    num_queries: usize, // number of random column queries for proximity test
}

/// Commitment output from the prover.
struct IoppCommitment {
    root: [u8; 32],
    segments: Vec<Vec<SecpScalar>>,
    merkle_leaves: Vec<[u8; 32]>,
    merkle_levels: Vec<Vec<[u8; 32]>>,
}

/// Build ERA code with tuned Brakedown parameters (from compare_codes bench).
///
/// `k` is log2 of the total message length.  The message has `2^k` field
/// elements, split into `2^eta` rows of `2^{k-eta}` each.
fn setup(
    k: usize,
    repetition: usize,
    eta: usize,
    num_queries: usize,
    rng: &mut impl Rng,
) -> IoppParams {
    assert!(k > eta, "k must be greater than eta");

    let segment_msg_size = 1usize << (k - eta);

    // Brakedown parameters tuned per segment message size.
    let (alpha, inverse_rate, cn, dn) = match (k - eta) as u32 {
        12 => (0.03, 1.08, 1, 1),
        14 => (0.03, 1.08, 1, 1),
        16 => (0.03, 1.08, 3, 6),
        18 => (0.04, 1.08, 7, 12),
        20 => (0.04, 1.08, 9, 16),
        22 => (0.045, 1.08, 8, 26),
        24 => (0.05, 1.08, 7, 41),
        26 => (0.05, 1.08, 6, 47),
        other => panic!("no tuned params for segment_msg_size=2^{other}"),
    };

    let base_code = BrakedownCode::<SecpScalar>::new(
        segment_msg_size,
        BrakedownParams {
            alpha,
            inverse_rate,
            cn,
            dn,
        },
        rng,
    );

    let block_length_segment = base_code.block_length() * repetition;

    let p1 = random_permutation(rng, block_length_segment);
    let p2 = random_permutation(rng, block_length_segment);
    let m1: Vec<SecpScalar> = (0..block_length_segment)
        .map(|_| SecpScalar::random(rng))
        .collect();
    let m2: Vec<SecpScalar> = (0..block_length_segment)
        .map(|_| SecpScalar::random(rng))
        .collect();

    let era_code = EraCode::new(base_code, repetition, p1, p2, m1, m2);

    IoppParams {
        era_code,
        k,
        eta,
        num_queries,
    }
}

/// Encode and Merkle-commit an interleaved message.
fn commit(params: &IoppParams, message: &[SecpScalar]) -> IoppCommitment {
    let rows = 1usize << params.eta;
    let block_length = params.era_code.block_length();

    let encoded = params.era_code.encode_interleaved(message, params.eta);

    let segments: Vec<Vec<SecpScalar>> = (0..rows)
        .map(|r| encoded[r * block_length..(r + 1) * block_length].to_vec())
        .collect();

    let merkle_leaves = blake3_merkle_interleaved_leaves(&segments);
    let merkle_levels = blake3_merkle_precompute_levels(&merkle_leaves);
    let root = blake3_merkle_root_from_levels(&merkle_levels);

    IoppCommitment {
        root,
        segments,
        merkle_leaves,
        merkle_levels,
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let k = 22; // total message = 2^22 field elements
    let eta = 4; // 2^4 = 16 interleaved rows
    let repetition = 6;
    let num_queries = 40;

    let mut rng = SmallRng::seed_from_u64(42);

    // ── Setup ──
    let t0 = Instant::now();
    let params = setup(k, repetition, eta, num_queries, &mut rng);
    let setup_time = t0.elapsed();
    println!(
        "setup:  {:.3} ms  (k={k}, rep={repetition}, eta={eta}, queries={num_queries})",
        setup_time.as_secs_f64() * 1e3
    );

    // ── Generate random message ──
    let total_msg_len = 1usize << k;
    let rows = 1usize << eta;
    let segment_msg_size = params.era_code.message_size();
    let block_length = params.era_code.block_length();
    let msg: Vec<SecpScalar> = (0..total_msg_len)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();
    println!(
        "message: {total_msg_len} elements ({rows} rows x {segment_msg_size} msg + {block_length} cw each)"
    );

    // ── Commit ──
    let t_commit = Instant::now();
    let commitment = commit(&params, &msg);
    let commit_time = t_commit.elapsed();
    println!(
        "commit: {:.3} ms  (root = {:?})",
        commit_time.as_secs_f64() * 1e3,
        &commitment.root[..8]
    );

    // ── Generate evaluation point z ∈ F^k ──
    let z: Vec<SecpScalar> = (0..k).map(|_| SecpScalar::random(&mut rng)).collect();

    // ── Eval prover time (first round + second round) ──
    let t_eval = Instant::now();
    let first_msg = prover_first_round(&msg, &z, params.eta, params.k);
    let challenge =
        verifier_challenge(params.era_code.block_length(), params.num_queries, &mut rng);
    let second_msg = prover_second_round(
        &commitment.segments,
        &commitment.merkle_leaves,
        &commitment.merkle_levels,
        &challenge,
        params.eta,
    );
    let eval_prover_time = t_eval.elapsed();
    println!(
        "eval prover: {:.3} ms  (folded_msg len={}, {} columns opened)",
        eval_prover_time.as_secs_f64() * 1e3,
        first_msg.folded_msg.len(),
        second_msg.columns.len(),
    );

    // ── Verifier time (challenge + verify) ──
    let t_verify = Instant::now();
    let _challenge_v =
        verifier_challenge(params.era_code.block_length(), params.num_queries, &mut rng);
    let ok = verify(
        &z,
        params.eta,
        params.k,
        &commitment.root,
        &first_msg,
        &challenge,
        &second_msg,
        |m| params.era_code.encode(m),
    );
    let verify_time = t_verify.elapsed();
    println!(
        "verify: {:.3} ms  => {}",
        verify_time.as_secs_f64() * 1e3,
        if ok { "PASS" } else { "FAIL" }
    );

    assert!(ok, "IOPP verification failed!");

    // ── Proof size estimate ──
    // The proof consists of:
    //   1. y (evaluation): 256 bits (one field element)
    //   2. folded_msg: 2^{k-eta} field elements = 256 * 2^{k-eta} bits
    //   3. opened columns: num_queries columns, each with 2^eta field elements
    //      = 256 * num_queries * 2^eta bits
    //   4. Merkle paths: num_queries paths, each with log2(padded_block_length)
    //      sibling hashes of 256 bits
    let seg_msg_size = 1usize << (k - eta);
    let padded_block_len = block_length.next_power_of_two().max(2);
    let merkle_path_len = padded_block_len.ilog2() as u64;
    let proof_bits_y = 256u64;
    let proof_bits_folded_msg = 256 * seg_msg_size as u64;
    let proof_bits_columns = 256 * num_queries as u64 * rows as u64;
    let proof_bits_merkle = 256 * num_queries as u64 * merkle_path_len;
    let total_proof_bits =
        proof_bits_y + proof_bits_folded_msg + proof_bits_columns + proof_bits_merkle;
    let total_proof_kib = total_proof_bits as f64 / 8.0 / 1024.0;
    println!(
        "proof size: {:.2} KiB  (y: {} bits, folded_msg: {} bits, columns: {} bits, merkle: {} bits)",
        total_proof_kib, proof_bits_y, proof_bits_folded_msg, proof_bits_columns, proof_bits_merkle,
    );
}
