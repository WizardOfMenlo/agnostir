use std::time::Instant;

use agnostir::{
    BrakedownCode, BrakedownParams, EraCode, ErrorCorrectingCode, FieldElement,
    blake3_merkle_commit_interleaved,
    poly_utils::multilinear::MultilinearPoint,
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
    k: usize,             // log2 of total message length (2^k field elements)
    eta: usize,           // interleaving factor (rows = 2^eta)
    num_queries: usize,   // number of random column queries for proximity test
}

/// Commitment output from the prover.
struct IoppCommitment {
    root: [u8; 32],
    segments: Vec<Vec<SecpScalar>>,
}

/// Prover's first-round message: folded message, folded codeword, and claimed
/// evaluation y = m(z).
struct ProverFirstMessage {
    /// Folded message: Σ_r eq(z_1, r) · msg_row[r].  Length = 2^{k-eta}.
    folded_msg: Vec<SecpScalar>,
    /// Folded codeword: Σ_r eq(z_1, r) · segments[r].  Length = block_length.
    folded_cw: Vec<SecpScalar>,
    /// Claimed evaluation y = m(z).
    y: SecpScalar,
}

/// Verifier's challenge: q uniformly random column indices drawn from
/// [0, 2^{k-eta} + block_length).  Indices < 2^{k-eta} query the message
/// part; the rest query the codeword part.
struct VerifierChallenge {
    query_indices: Vec<usize>,
}

/// Prover's second-round message: for each queried column, the full column
/// of 2^eta row values.
struct ProverSecondMessage {
    /// columns[i] has 2^eta elements – the values from every row at the
    /// queried column index.
    columns: Vec<Vec<SecpScalar>>,
}

// ---------------------------------------------------------------------------
// IOPP methods
// ---------------------------------------------------------------------------

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

    let root = blake3_merkle_commit_interleaved(&segments);

    IoppCommitment { root, segments }
}

/// Prover's first round: fold the interleaved message and codeword rows,
/// compute y = m(z).
///
/// Given evaluation point `z ∈ F^k`, split as `z = (z_1, z_2)` where
/// `z_1 ∈ F^eta` and `z_2 ∈ F^{k-eta}`.
///
/// Sends to verifier:
///   - folded_msg  (length 2^{k-eta}): Σ_r eq(z_1, r) · msg_row[r]
///   - folded_cw   (length block_length): Σ_r eq(z_1, r) · segments[r]
///   - y = m(z)
fn prover_first_round(
    params: &IoppParams,
    commitment: &IoppCommitment,
    message: &[SecpScalar],
    z: &[SecpScalar],
) -> ProverFirstMessage {
    let eta = params.eta;
    let k = params.k;
    assert_eq!(z.len(), k, "evaluation point must have k={k} coordinates");

    let rows = 1usize << eta;
    let seg_msg_size = 1usize << (k - eta);
    let block_length = params.era_code.block_length();

    // Split z = (z_1, z_2).
    let z_1 = &z[..eta];

    // Compute eq weights for z_1: w[r] = eq(z_1, r) for r in {0,1}^eta.
    let z1_point = MultilinearPoint(z_1.to_vec());
    let eq_weights = z1_point.eq_weights();
    assert_eq!(eq_weights.len(), rows);

    // Fold the message rows.
    let mut folded_msg = vec![SecpScalar::ZERO; seg_msg_size];
    for (r, &w) in eq_weights.iter().enumerate() {
        let row_start = r * seg_msg_size;
        for i in 0..seg_msg_size {
            folded_msg[i] += w * message[row_start + i];
        }
    }

    // Fold the codeword rows.
    let mut folded_cw = vec![SecpScalar::ZERO; block_length];
    for (r, &w) in eq_weights.iter().enumerate() {
        let seg = &commitment.segments[r];
        for j in 0..block_length {
            folded_cw[j] += w * seg[j];
        }
    }

    // Compute y = m(z).
    // y = Σ_i eq(z_2, i) · folded_msg[i]  (equivalent to full eq(z, ·) dot msg).
    let z_2 = &z[eta..];
    let z2_point = MultilinearPoint(z_2.to_vec());
    let eq2_weights = z2_point.eq_weights();
    assert_eq!(eq2_weights.len(), seg_msg_size);
    let y = folded_msg
        .iter()
        .zip(eq2_weights.iter())
        .fold(SecpScalar::ZERO, |acc, (&fm, &e)| acc + fm * e);

    ProverFirstMessage {
        folded_msg,
        folded_cw,
        y,
    }
}

/// Verifier picks q random column indices from [0, 2^{k-eta} + block_length).
fn verifier_challenge(params: &IoppParams, rng: &mut impl Rng) -> VerifierChallenge {
    let seg_msg_size = 1usize << (params.k - params.eta);
    let block_length = params.era_code.block_length();
    let total_cols = seg_msg_size + block_length;

    let query_indices: Vec<usize> = (0..params.num_queries)
        .map(|_| rng.random_range(0..total_cols))
        .collect();

    VerifierChallenge { query_indices }
}

/// Prover's second round: open the queried columns (all 2^eta row values).
///
/// For index j < 2^{k-eta}: column is message column j from each row.
/// For index j >= 2^{k-eta}: column is codeword column (j - 2^{k-eta}) from
/// each committed segment.
fn prover_second_round(
    params: &IoppParams,
    commitment: &IoppCommitment,
    message: &[SecpScalar],
    challenge: &VerifierChallenge,
) -> ProverSecondMessage {
    let eta = params.eta;
    let rows = 1usize << eta;
    let seg_msg_size = 1usize << (params.k - eta);

    let columns: Vec<Vec<SecpScalar>> = challenge
        .query_indices
        .iter()
        .map(|&idx| {
            if idx < seg_msg_size {
                // Message column.
                (0..rows)
                    .map(|r| message[r * seg_msg_size + idx])
                    .collect()
            } else {
                // Codeword column.
                let cw_idx = idx - seg_msg_size;
                (0..rows)
                    .map(|r| commitment.segments[r][cw_idx])
                    .collect()
            }
        })
        .collect();

    ProverSecondMessage { columns }
}

/// Verifier checks:
/// 1. Each opened column folds (with eq(z_1, ·)) to the matching entry in
///    folded_msg || folded_cw.
/// 2. The folded message evaluated at z_2 equals y.
fn verify(
    params: &IoppParams,
    z: &[SecpScalar],
    first_msg: &ProverFirstMessage,
    challenge: &VerifierChallenge,
    second_msg: &ProverSecondMessage,
) -> bool {
    let eta = params.eta;
    let k = params.k;
    let rows = 1usize << eta;
    let seg_msg_size = 1usize << (k - eta);

    // Recompute the eq weights for z_1.
    let z_1 = &z[..eta];
    let z1_point = MultilinearPoint(z_1.to_vec());
    let eq_weights = z1_point.eq_weights();

    // Check each opened column against the folded vector.
    for (qi, (col, &idx)) in second_msg
        .columns
        .iter()
        .zip(challenge.query_indices.iter())
        .enumerate()
    {
        if col.len() != rows {
            eprintln!("query {qi}: column has wrong length");
            return false;
        }

        // Fold the opened column with eq(z_1, ·).
        let folded_val: SecpScalar = col
            .iter()
            .zip(eq_weights.iter())
            .fold(SecpScalar::ZERO, |acc, (&c, &w)| acc + c * w);

        // Look up the expected value from folded_msg || folded_cw.
        let expected = if idx < seg_msg_size {
            first_msg.folded_msg[idx]
        } else {
            first_msg.folded_cw[idx - seg_msg_size]
        };

        if folded_val != expected {
            eprintln!("query {qi} (col {idx}): folding mismatch");
            return false;
        }
    }

    // Evaluate the folded message as a multilinear polynomial at z_2.
    let z_2 = &z[eta..];
    let z2_point = MultilinearPoint(z_2.to_vec());
    let eq2_weights = z2_point.eq_weights();
    assert_eq!(eq2_weights.len(), seg_msg_size);

    let eval: SecpScalar = first_msg
        .folded_msg
        .iter()
        .zip(eq2_weights.iter())
        .fold(SecpScalar::ZERO, |acc, (&fm, &e)| acc + fm * e);

    if eval != first_msg.y {
        eprintln!("folded message evaluation mismatch: eval != y");
        return false;
    }

    true
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
    let z: Vec<SecpScalar> = (0..k)
        .map(|_| SecpScalar::random(&mut rng))
        .collect();

    // ── Eval prover time (first round + second round) ──
    let t_eval = Instant::now();
    let first_msg = prover_first_round(&params, &commitment, &msg, &z);
    let challenge = verifier_challenge(&params, &mut rng);
    let second_msg = prover_second_round(&params, &commitment, &msg, &challenge);
    let eval_prover_time = t_eval.elapsed();
    println!(
        "eval prover: {:.3} ms  (folded_msg len={}, folded_cw len={}, {} columns opened)",
        eval_prover_time.as_secs_f64() * 1e3,
        first_msg.folded_msg.len(),
        first_msg.folded_cw.len(),
        second_msg.columns.len(),
    );

    // ── Verifier time (challenge + verify) ──
    let t_verify = Instant::now();
    let _challenge_v = verifier_challenge(&params, &mut rng);
    let ok = verify(&params, &z, &first_msg, &challenge, &second_msg);
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
    let seg_msg_size = 1usize << (k - eta);
    let proof_bits_y = 256u64;
    let proof_bits_folded_msg = 256 * seg_msg_size as u64;
    let proof_bits_columns = 256 * num_queries as u64 * rows as u64;
    let total_proof_bits = proof_bits_y + proof_bits_folded_msg + proof_bits_columns;
    let total_proof_kib = total_proof_bits as f64 / 8.0 / 1024.0;
    println!(
        "proof size: {:.2} KiB  (y: {} bits, folded_msg: {} bits, columns: {} bits)",
        total_proof_kib,
        proof_bits_y,
        proof_bits_folded_msg,
        proof_bits_columns,
    );
}
