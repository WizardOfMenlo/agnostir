use ark_ff::FftField;

pub(crate) fn wavelet_transform<F: crate::FieldElement>(values: &mut [F]) {
    assert!(values.len().is_power_of_two());

    let mut stride = 1;
    while stride < values.len() {
        let block = stride << 1;
        for chunk in values.chunks_exact_mut(block) {
            let (low, high) = chunk.split_at_mut(stride);
            for (l, h) in low.iter().zip(high.iter_mut()) {
                *h += *l;
            }
        }
        stride <<= 1;
    }
}

pub(crate) fn inverse_wavelet_transform<F: crate::FieldElement>(values: &mut [F]) {
    assert!(values.len().is_power_of_two());
    if values.len() <= 1 {
        return;
    }

    let mut stride = values.len() >> 1;
    loop {
        let block = stride << 1;
        for chunk in values.chunks_exact_mut(block) {
            let (low, high) = chunk.split_at_mut(stride);
            for (l, h) in low.iter().zip(high.iter_mut()) {
                *h -= *l;
            }
        }

        if stride == 1 {
            break;
        }
        stride >>= 1;
    }
}

pub(crate) fn transpose<T: Clone>(values: &mut [T], rows: usize, cols: usize) {
    assert_eq!(
        rows.checked_mul(cols).expect("rows * cols overflows usize"),
        values.len()
    );

    if rows <= 1 || cols <= 1 {
        return;
    }

    let original = values.to_vec();
    for r in 0..rows {
        for c in 0..cols {
            values[c * rows + r] = original[r * cols + c].clone();
        }
    }
}

fn inverse_ntt_unscaled<F: FftField>(values: &mut [F], omega_inv: F) {
    assert!(values.len().is_power_of_two());
    if values.len() <= 1 {
        return;
    }

    let n = values.len();
    let log_n = n.trailing_zeros();

    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - log_n);
        if i < j {
            values.swap(i, j);
        }
    }

    for s in 0..log_n {
        let m = 1usize << (s + 1);
        let half = m >> 1;
        let wm = omega_inv.pow([(n / m) as u64]);

        let mut k = 0;
        while k < n {
            let mut w = F::ONE;
            for j in 0..half {
                let t = w * values[k + j + half];
                let u = values[k + j];
                values[k + j] = u + t;
                values[k + j + half] = u - t;
                w *= wm;
            }
            k += m;
        }
    }
}

pub(crate) mod test_utils {
    use ark_ff::FftField;

    use super::{inverse_ntt_unscaled, transpose};

    pub(crate) fn transform_evaluations<F: FftField>(
        evals: &mut [F],
        domain_gen_inv: F,
        folding_factor: usize,
    ) {
        assert!(evals.len().is_power_of_two());

        let folding_factor_exp = 1usize << folding_factor;
        assert!(folding_factor_exp > 0);
        assert_eq!(evals.len() % folding_factor_exp, 0);

        let num_cosets = evals.len() / folding_factor_exp;

        transpose(evals, folding_factor_exp, num_cosets);

        let coset_gen_inv = domain_gen_inv.pow([num_cosets as u64]);
        for row in evals.chunks_exact_mut(folding_factor_exp) {
            inverse_ntt_unscaled(row, coset_gen_inv);
        }

        let size_inv = F::from(folding_factor_exp as u64)
            .inverse()
            .expect("folding_factor_exp is non-zero in a field");

        let mut coset_offset_inv = F::ONE;
        for row in evals.chunks_exact_mut(folding_factor_exp) {
            let mut offset_power = F::ONE;
            for value in row.iter_mut() {
                *value *= size_inv * offset_power;
                offset_power *= coset_offset_inv;
            }
            coset_offset_inv *= domain_gen_inv;
        }
    }
}
