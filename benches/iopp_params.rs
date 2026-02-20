// Experiment parameters for IOPP benchmarks.

// ═══════════════════════════════════════════════════════════════════════════
// Brakedown
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) const BRAKEDOWN_ALPHA: f64 = 0.3;
pub(crate) const BRAKEDOWN_INV_RATE: f64 = 2.0;
pub(crate) const BRAKEDOWN_CN: usize = 10;
pub(crate) const BRAKEDOWN_DN: usize = 20;
pub(crate) const BRAKEDOWN_DELTA: f64 = 0.1;

// ═══════════════════════════════════════════════════════════════════════════
// EA
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) const EA_INV_RATE: usize = 2;
pub(crate) const EA_PROB_MUL: usize = 18;
pub(crate) const EA_DELTA: f64 = 0.1;

// ═══════════════════════════════════════════════════════════════════════════
// Basefold
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) const BASEFOLD_LOG_RATE: usize = 1;

/// Basefold distance (rate 1/2) as a function of log2(segment message size).
pub(crate) fn basefold_2_delta(log_seg_msg_size: usize) -> f64 {
    match log_seg_msg_size {
        10 => 0.246,
        11 => 0.240,
        12 => 0.235,
        13 => 0.230,
        14 => 0.224,
        15 => 0.219,
        16 => 0.213,
        17 => 0.208,
        18 => 0.203,
        19 => 0.197,
        20 => 0.192,
        21 => 0.186,
        22 => 0.181,
        other => panic!("no basefold (rate 1/2) delta for segment message size 2^{other}"),
    }
}

/// Basefold distance (rate 1/4) as a function of log2(segment message size).
pub(crate) fn basefold_4_delta(log_seg_msg_size: usize) -> f64 {
    match log_seg_msg_size {
        10 => 0.608,
        11 => 0.605,
        12 => 0.601,
        13 => 0.597,
        14 => 0.593,
        15 => 0.589,
        16 => 0.585,
        17 => 0.581,
        18 => 0.577,
        19 => 0.573,
        20 => 0.569,
        21 => 0.565,
        22 => 0.561,
        other => panic!("no basefold (rate 1/4) delta for segment message size 2^{other}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// ERA (Tensor-Brakedown base code)
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) const ERA_REPETITION: usize = 4;

/// ERA inner-Brakedown parameters indexed by log2(k)
pub(crate) fn era_inner_params_tensor(k_log: u32) -> (f64, f64, usize, usize) {
    match k_log {
        10 => (0.04, 1.1, 9, 16),
        11 => (0.045, 1.1, 9, 26),
        12 => (0.05, 1.1, 7, 37),
        _ if k_log >= 13 => (0.05, 1.1, 6, 40),
        other => panic!("no tuned ERA params for segment message size 2^{other}"),
    }
}

/// ERA inner-Brakedown parameters indexed by log2(k)
pub(crate) fn era_inner_params_normal(k_log: u32) -> (f64, f64, usize, usize) {
    (0.05, 1.1, 6, 38)
}

/// ERA distance as a function of log2(segment message size).
pub(crate) fn era_delta_r4(log_seg_msg_size: usize) -> f64 {
    match log_seg_msg_size {
        12 => 0.204,
        13 => 0.226,
        14 => 0.227,
        _ if log_seg_msg_size >= 15 => 0.228,
        other => panic!("no ERA delta for segment message size 2^{other}"),
    }
}

/// ERA distance as a function of log2(segment message size).
pub(crate) fn era_delta_r6(log_seg_msg_size: usize) -> f64 {
    match log_seg_msg_size {
        10 => 0.248,
        11 => 0.335,
        12 => 0.368,
        13 => 0.382,
        14 => 0.389,
        15 => 0.393,
        _ if log_seg_msg_size >= 16 => 0.395,
        other => panic!("no ERA delta for segment message size 2^{other}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Proof size estimation
// ═══════════════════════════════════════════════════════════════════════════

pub(crate) const SECPARAM: f64 = 100.0;
pub(crate) const LOG_FIELD_SIZE: f64 = 256.0; // bits per field element (secp256k1)
pub(crate) const LOG_HASH_SIZE: f64 = 256.0; // bits per hash digest (blake3)

/// Number of queries for `secparam`-bit security given proximity parameter
/// `delta`:  eps = 1 - (1 - delta)^{1/3},  q = ceil(-secparam / log2(1 - eps)).
pub(crate) fn num_queries_from_delta(secparam: f64, delta: f64) -> usize {
    let eps = 1.0 - (1.0 - delta).cbrt();
    let denom = (1.0 - eps).log2();
    (-secparam / denom).ceil() as usize
}

/// Merkle-tree proof size in bits.
pub(crate) fn merkle_tree_size_bits(
    queries: usize,
    log_block_length: f64,
    interleaving_factor: usize,
) -> f64 {
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
pub(crate) fn proof_size_kib(block_length: usize, k: usize, eta: usize, delta: f64) -> f64 {
    let q = num_queries_from_delta(SECPARAM, delta);
    let log_bl = (block_length as f64).log2();
    let interleaving = 1usize << eta;
    let merkle_bits = merkle_tree_size_bits(q, log_bl, interleaving);

    let first_msg_bits = LOG_FIELD_SIZE + LOG_FIELD_SIZE * (1u64 << (k - eta)) as f64;

    (merkle_bits + first_msg_bits) / 8.0 / 1024.0
}
