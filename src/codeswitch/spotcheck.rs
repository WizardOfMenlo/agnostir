//! Spot-check sampling utilities.

use rand::Rng;

use crate::FieldElement;

use super::{params::CodeswitchParameters, types::SpotCheck};

/// Sample spot-check indices and query the provided oracle at those indices.
pub(crate) fn sample_spot_checks<F: FieldElement, C>(
    params: &CodeswitchParameters<C, F>,
    oracle_word: &[F],
    rng: &mut impl Rng,
) -> Vec<SpotCheck<F>> {
    let domain_size = params.start_code_blocklength();

    (0..params.num_spot_checks())
        .map(|_| {
            let index = rng.random_range(0..domain_size);
            SpotCheck {
                index,
                value: oracle_word[index],
            }
        })
        .collect()
}
