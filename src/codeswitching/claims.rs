use crate::FieldElement;

/// One chunk-level claim produced by `split_claim_ip`.
#[derive(Debug, Clone, PartialEq)]
pub struct SplitIpClaim<F> {
    pub chunk_index: usize,
    pub coeffs: Vec<F>,
    pub target: F,
}

impl<F> SplitIpClaim<F> {
    #[must_use]
    pub fn witness_len(&self) -> usize {
        self.coeffs.len()
    }
}

/// One chunk-level claim produced by `split_claim_tip`.
#[derive(Debug, Clone, PartialEq)]
pub struct SplitTipClaim<F> {
    pub chunk_index: usize,
    pub coeffs: Vec<F>,
    pub target: F,
}

impl<F> SplitTipClaim<F> {
    #[must_use]
    pub fn witness_len(&self) -> usize {
        self.coeffs.len()
    }
}

/// Implement the `SplitClaimIP` shorthand from `codeswitching.tex`.
///
/// Computes one inner-product claim per split chunk and enforces that local
/// targets sum to `sigma`.
#[must_use]
pub fn split_claim_ip<F: FieldElement>(
    msg: &[F],
    v_b: &[F],
    sigma: F,
    k_prime: usize,
) -> Vec<SplitIpClaim<F>> {
    assert!(k_prime > 0, "k_prime must be > 0");
    assert_eq!(
        msg.len(),
        v_b.len(),
        "SplitClaimIP requires msg and v_b to have the same length"
    );
    assert_eq!(
        msg.len() % k_prime,
        0,
        "SplitClaimIP requires message length to be divisible by k_prime"
    );

    let chunk_count = msg.len() / k_prime;
    assert!(chunk_count > 0, "SplitClaimIP requires at least one chunk");

    let mut claims = Vec::with_capacity(chunk_count);
    let mut sigma_sum = F::ZERO;

    for (chunk_index, (msg_chunk, coeff_chunk)) in msg
        .chunks_exact(k_prime)
        .zip(v_b.chunks_exact(k_prime))
        .enumerate()
    {
        let sigma_i = inner_product(msg_chunk, coeff_chunk);
        sigma_sum += sigma_i;

        claims.push(SplitIpClaim {
            chunk_index,
            coeffs: coeff_chunk.to_vec(),
            target: sigma_i,
        });
    }

    assert_eq!(
        sigma_sum, sigma,
        "SplitClaimIP chunk targets do not sum to the claimed sigma"
    );

    claims
}

/// Implement the `SplitClaimTIP` shorthand from `codeswitching.tex`.
///
/// Computes one triple-product claim per split chunk and enforces that local
/// targets sum to `sigma`.
#[must_use]
pub fn split_claim_tip<F: FieldElement>(
    msg: &[F],
    msg_prime: &[F],
    v_b: &[F],
    sigma: F,
    k_prime: usize,
) -> Vec<SplitTipClaim<F>> {
    assert!(k_prime > 0, "k_prime must be > 0");
    assert_eq!(
        msg.len(),
        msg_prime.len(),
        "SplitClaimTIP requires msg and msg_prime to have the same length"
    );
    assert_eq!(
        msg.len(),
        v_b.len(),
        "SplitClaimTIP requires msg and v_b to have the same length"
    );
    assert_eq!(
        msg.len() % k_prime,
        0,
        "SplitClaimTIP requires message length to be divisible by k_prime"
    );

    let chunk_count = msg.len() / k_prime;
    assert!(chunk_count > 0, "SplitClaimTIP requires at least one chunk");

    let mut claims = Vec::with_capacity(chunk_count);
    let mut sigma_sum = F::ZERO;

    for (chunk_index, ((msg_chunk, msg_prime_chunk), coeff_chunk)) in msg
        .chunks_exact(k_prime)
        .zip(msg_prime.chunks_exact(k_prime))
        .zip(v_b.chunks_exact(k_prime))
        .enumerate()
    {
        let sigma_i = triple_product(msg_chunk, msg_prime_chunk, coeff_chunk);
        sigma_sum += sigma_i;

        claims.push(SplitTipClaim {
            chunk_index,
            coeffs: coeff_chunk.to_vec(),
            target: sigma_i,
        });
    }

    assert_eq!(
        sigma_sum, sigma,
        "SplitClaimTIP chunk targets do not sum to the claimed sigma"
    );

    claims
}

fn inner_product<F: FieldElement>(lhs: &[F], rhs: &[F]) -> F {
    assert_eq!(lhs.len(), rhs.len(), "inner-product length mismatch");
    lhs.iter()
        .zip(rhs.iter())
        .fold(F::ZERO, |acc, (&x, &y)| acc + x * y)
}

fn triple_product<F: FieldElement>(lhs: &[F], rhs: &[F], coeffs: &[F]) -> F {
    assert_eq!(
        lhs.len(),
        rhs.len(),
        "triple-product lhs/rhs length mismatch"
    );
    assert_eq!(
        lhs.len(),
        coeffs.len(),
        "triple-product coeff length mismatch"
    );

    lhs.iter()
        .zip(rhs.iter())
        .zip(coeffs.iter())
        .fold(F::ZERO, |acc, ((&x, &y), &c)| acc + x * y * c)
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::FieldElement;

    fn f(x: u32) -> KoalaBear {
        <KoalaBear as FieldElement>::from_u32(x)
    }

    #[test]
    fn test_split_claim_ip_scaffolding() {
        let msg: Vec<KoalaBear> = (1..=8).map(f).collect();
        let v_b: Vec<KoalaBear> = vec![f(2), f(0), f(1), f(1), f(3), f(1), f(0), f(2)];
        let sigma = f(46); // 9 + 37

        let claims = split_claim_ip(&msg, &v_b, sigma, 4);

        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].chunk_index, 0);
        assert_eq!(claims[1].chunk_index, 1);
        assert_eq!(claims[0].target, f(9));
        assert_eq!(claims[1].target, f(37));
        assert_eq!(claims[0].witness_len(), 4);
    }

    #[test]
    fn test_split_claim_tip_scaffolding() {
        let msg: Vec<KoalaBear> = (1..=8).map(f).collect();
        let msg_prime: Vec<KoalaBear> = vec![f(2), f(2), f(2), f(2), f(3), f(3), f(3), f(3)];
        let v_b: Vec<KoalaBear> = vec![f(1); 8];
        let sigma = f(98); // 20 + 78

        let claims = split_claim_tip(&msg, &msg_prime, &v_b, sigma, 4);

        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].chunk_index, 0);
        assert_eq!(claims[1].chunk_index, 1);
        assert_eq!(claims[0].target, f(20));
        assert_eq!(claims[1].target, f(78));
        assert_eq!(claims[0].witness_len(), 4);
    }

    #[test]
    #[should_panic]
    fn test_split_claim_ip_panics_on_sigma_mismatch() {
        let msg: Vec<KoalaBear> = (1..=8).map(f).collect();
        let v_b: Vec<KoalaBear> = vec![f(2), f(0), f(1), f(1), f(3), f(1), f(0), f(2)];

        let _ = split_claim_ip(&msg, &v_b, f(45), 4);
    }

    #[test]
    #[should_panic]
    fn test_split_claim_tip_panics_on_length_mismatch() {
        let msg: Vec<KoalaBear> = (1..=8).map(f).collect();
        let msg_prime: Vec<KoalaBear> = vec![f(2); 7];
        let v_b: Vec<KoalaBear> = vec![f(1); 8];

        let _ = split_claim_tip(&msg, &msg_prime, &v_b, f(98), 4);
    }
}
