// Experiment parameters for IOPP benchmarks.

// ═══════════════════════════════════════════════════════════════════════════
// Brakedown
// ═══════════════════════════════════════════════════════════════════════════

pub const BRAKEDOWN_ALPHA: f64 = 0.238;
pub const BRAKEDOWN_INV_RATE: f64 = 1.72;
pub const BRAKEDOWN_CN: usize = 9;
pub const BRAKEDOWN_DN: usize = 12;
pub const BRAKEDOWN_DELTA: f64 = 0.07;

// ═══════════════════════════════════════════════════════════════════════════
// EA
// ═══════════════════════════════════════════════════════════════════════════

pub const EA_INV_RATE: usize = 2;
pub const EA_PROB_MUL: usize = 18;
pub const EA_DELTA: f64 = 0.1;

// ═══════════════════════════════════════════════════════════════════════════
// Basefold
// ═══════════════════════════════════════════════════════════════════════════

pub const BASEFOLD_LOG_RATE: usize = 2;

/// Basefold distance as a function of log2(segment message size).
pub fn basefold_delta(log_seg_msg_size: usize) -> f64 {
    match log_seg_msg_size {
        12 => 0.6,
        14 => 0.593,
        16 => 0.585,
        18 => 0.577,
        20 => 0.569,
        other => panic!("no basefold delta for segment message size 2^{other}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ERA (Tensor-Brakedown base code)
// ═══════════════════════════════════════════════════════════════════════════

pub const ERA_REPETITION: usize = 6;

/// ERA inner-Brakedown parameters indexed by log2(k_inner).
pub fn era_inner_params(k_inner_log: u32) -> (f64, f64, usize, usize) {
    match k_inner_log {
        6 => (0.03, 1.08, 1, 1),
        7 => (0.03, 1.08, 1, 1),
        8 => (0.03, 1.08, 3, 6),
        9 => (0.04, 1.08, 7, 12),
        10 => (0.04, 1.08, 9, 16),
        11 => (0.045, 1.08, 8, 26),
        12 => (0.05, 1.08, 7, 41),
        13 => (0.05, 1.08, 6, 47),
        _ => panic!("no tuned ERA params for k_inner=2^{k_inner_log}"),
    }
}

/// ERA distance as a function of log2(segment message size).
pub fn era_delta(log_seg_msg_size: usize) -> f64 {
    match log_seg_msg_size {
        12 => 0.368,
        14 => 0.389,
        _ if log_seg_msg_size >= 16 => 0.395,
        other => panic!("no ERA delta for segment message size 2^{other}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Proof size estimation
// ═══════════════════════════════════════════════════════════════════════════

pub const SECPARAM: f64 = 100.0;
pub const LOG_FIELD_SIZE: f64 = 256.0; // bits per field element (secp256k1)
pub const LOG_HASH_SIZE: f64 = 256.0;  // bits per hash digest (blake3)

/// Number of queries for `secparam`-bit security given proximity parameter
/// `delta`:  eps = 1 - (1 - delta)^{1/3},  q = ceil(-secparam / log2(1 - eps)).
pub fn num_queries_from_delta(secparam: f64, delta: f64) -> usize {
    let eps = 1.0 - (1.0 - delta).cbrt();
    let denom = (1.0 - eps).log2();
    (-secparam / denom).ceil() as usize
}

/// Merkle-tree proof size in bits.
pub fn merkle_tree_size_bits(queries: usize, log_block_length: f64, interleaving_factor: usize) -> f64 {
    let q = queries as f64;
    let n = log_block_length;

    let top_levels = q.log2();
    let proof_size_top = LOG_HASH_SIZE * (q - 2.0);
    let proof_size_siblings = LOG_HASH_SIZE * (n - top_levels) * q;
    let proof_size_leaves = LOG_FIELD_SIZE * q * interleaving_factor as f64;

    proof_size_top + proof_size_siblings + proof_size_leaves
}

/// Total proof size in KiB, including the folded message (2^{k-eta} field
/// elements) and the evaluation y (1 field element).
pub fn proof_size_kib(block_length: usize, k: usize, eta: usize, delta: f64) -> f64 {
    let q = num_queries_from_delta(SECPARAM, delta);
    let log_bl = (block_length as f64).log2();
    let interleaving = 1usize << eta;
    let merkle_bits = merkle_tree_size_bits(q, log_bl, interleaving);

    let first_msg_bits = LOG_FIELD_SIZE + LOG_FIELD_SIZE * (1u64 << (k - eta)) as f64;

    (merkle_bits + first_msg_bits) / 8.0 / 1024.0
}
