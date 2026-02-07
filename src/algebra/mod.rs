pub(crate) mod embedding;
pub(crate) mod fields;
pub(crate) mod ntt;

pub(crate) mod poly_utils {
    #[allow(unused_imports)]
    pub(crate) use crate::poly_utils::{coeffs, hypercube, multilinear};
}
