use super::oracles::{CodeswitchOraclesOutput, SplitEncoding};

/// Logical namespaces from which a claim can reference an oracle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OracleNamespace {
    Message,
    Aux,
    IndexGenerator,
    IndexIdentity,
    IndexPermutation1,
    IndexPermutation2,
    IndexMultiplier1,
    IndexMultiplier2,
}

/// A typed reference to an oracle inside a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OracleRef {
    pub namespace: OracleNamespace,
    pub index: usize,
}

impl OracleRef {
    pub const fn new(namespace: OracleNamespace, index: usize) -> Self {
        Self { namespace, index }
    }
}

/// Count of available index-oracle chunks per family.
#[derive(Debug, Clone, Copy)]
pub struct IndexOracleCounts {
    pub generator: usize,
    pub identity: usize,
    pub permutation_1: usize,
    pub permutation_2: usize,
    pub multiplier_1: usize,
    pub multiplier_2: usize,
}

impl IndexOracleCounts {
    pub fn from_codeswitch_oracles<F>(oracles: &CodeswitchOraclesOutput<F>) -> Self {
        Self {
            generator: oracles.generator.chunk_count(),
            identity: oracles.identity.chunk_count(),
            permutation_1: oracles.permutation_1.chunk_count(),
            permutation_2: oracles.permutation_2.chunk_count(),
            multiplier_1: oracles.multiplier_1.chunk_count(),
            multiplier_2: oracles.multiplier_2.chunk_count(),
        }
    }

    fn count_for(self, namespace: OracleNamespace) -> Option<usize> {
        match namespace {
            OracleNamespace::IndexGenerator => Some(self.generator),
            OracleNamespace::IndexIdentity => Some(self.identity),
            OracleNamespace::IndexPermutation1 => Some(self.permutation_1),
            OracleNamespace::IndexPermutation2 => Some(self.permutation_2),
            OracleNamespace::IndexMultiplier1 => Some(self.multiplier_1),
            OracleNamespace::IndexMultiplier2 => Some(self.multiplier_2),
            OracleNamespace::Message | OracleNamespace::Aux => None,
        }
    }

    fn validate(self) {
        assert!(
            self.generator > 0,
            "index generator oracle count must be > 0"
        );
        assert!(self.identity > 0, "index identity oracle count must be > 0");
        assert!(
            self.permutation_1 > 0,
            "index permutation_1 oracle count must be > 0"
        );
        assert!(
            self.permutation_2 > 0,
            "index permutation_2 oracle count must be > 0"
        );
        assert!(
            self.multiplier_1 > 0,
            "index multiplier_1 oracle count must be > 0"
        );
        assert!(
            self.multiplier_2 > 0,
            "index multiplier_2 oracle count must be > 0"
        );
    }
}

/// Fixed context required to validate oracle references while building claims.
#[derive(Debug, Clone, Copy)]
pub struct CodeswitchClaimContext {
    pub message_oracle_count: usize,
    pub index_oracles: IndexOracleCounts,
}

impl CodeswitchClaimContext {
    pub fn from_codeswitch_oracles<F>(
        message_oracle_count: usize,
        index_oracles: &CodeswitchOraclesOutput<F>,
    ) -> Self {
        let context = Self {
            message_oracle_count,
            index_oracles: IndexOracleCounts::from_codeswitch_oracles(index_oracles),
        };
        context.validate();
        context
    }

    pub fn validate(self) {
        assert!(
            self.message_oracle_count > 0,
            "message oracle count must be > 0"
        );
        self.index_oracles.validate();
    }
}

/// Linear forms used by split claims.
///
/// This is descriptor-only scaffolding, not a full polynomial engine.
#[derive(Debug, Clone)]
pub enum LinearForm<F> {
    Dense(Vec<F>),
    EqPoint(Vec<F>),
    GeometricPowers {
        base: F,
        len: usize,
    },
    Sparse {
        len: usize,
        entries: Vec<(usize, F)>,
    },
}

impl<F> LinearForm<F> {
    pub fn assert_len(&self, expected_len: usize) {
        match self {
            Self::Dense(values) => {
                assert_eq!(
                    values.len(),
                    expected_len,
                    "dense linear form length does not match k_prime"
                );
            }
            Self::EqPoint(point) => {
                assert_eq!(
                    point.len(),
                    expected_len,
                    "eq-point linear form length does not match k_prime"
                );
            }
            Self::GeometricPowers { len, .. } => {
                assert_eq!(*len, expected_len, "geometric form length mismatch");
            }
            Self::Sparse { len, entries } => {
                assert_eq!(*len, expected_len, "sparse form declared length mismatch");
                for (index, _) in entries {
                    assert!(
                        *index < *len,
                        "sparse form index {index} is out of range for len {len}"
                    );
                }
            }
        }
    }
}

/// A split inner-product claim descriptor.
#[derive(Debug, Clone)]
pub struct IpClaim<F> {
    pub label: String,
    pub oracle: OracleRef,
    pub linear_form: LinearForm<F>,
    pub target: F,
    pub witness_len: usize,
}

/// A split triple-product claim descriptor.
#[derive(Debug, Clone)]
pub struct TipClaim<F> {
    pub label: String,
    pub lhs_oracle: OracleRef,
    pub rhs_oracle: OracleRef,
    pub linear_form: LinearForm<F>,
    pub target: F,
    pub witness_len: usize,
}

/// Auxiliary oracle registered during `CodeswitchClaims` construction.
#[derive(Debug, Clone)]
pub struct AuxOracle<F> {
    pub label: String,
    pub oracle: OracleRef,
    pub split_encoding: SplitEncoding<F>,
}

/// Final claim scaffold output.
#[derive(Debug, Clone)]
pub struct CodeswitchClaimsPlan<F> {
    pub aux_oracles: Vec<AuxOracle<F>>,
    pub ip_claims: Vec<IpClaim<F>>,
    pub tip_claims: Vec<TipClaim<F>>,
}

impl<F> CodeswitchClaimsPlan<F> {
    pub fn num_ip(&self) -> usize {
        self.ip_claims.len()
    }

    pub fn num_tip(&self) -> usize {
        self.tip_claims.len()
    }
}

/// Builder for the `CodeswitchClaims` scaffolding.
///
/// This builder validates all references and shape constraints eagerly and
/// panics on mismatch.
#[derive(Debug, Clone)]
pub struct CodeswitchClaimsBuilder<F> {
    k_prime: usize,
    context: CodeswitchClaimContext,
    aux_oracles: Vec<AuxOracle<F>>,
    ip_claims: Vec<IpClaim<F>>,
    tip_claims: Vec<TipClaim<F>>,
}

impl<F> CodeswitchClaimsBuilder<F> {
    pub fn new(k_prime: usize, context: CodeswitchClaimContext) -> Self {
        assert!(k_prime > 0, "k_prime must be > 0");
        context.validate();

        Self {
            k_prime,
            context,
            aux_oracles: Vec::new(),
            ip_claims: Vec::new(),
            tip_claims: Vec::new(),
        }
    }

    pub fn register_aux_oracle(
        &mut self,
        label: impl Into<String>,
        split_encoding: SplitEncoding<F>,
    ) -> OracleRef {
        assert!(
            !split_encoding.chunks.is_empty(),
            "aux split encoding must contain at least one chunk"
        );
        assert_eq!(
            split_encoding.chunks.len(),
            split_encoding.codewords.len(),
            "aux split encoding has mismatched chunk/codeword counts"
        );

        for chunk in &split_encoding.chunks {
            assert_eq!(
                chunk.len(),
                self.k_prime,
                "aux split chunk length must equal k_prime"
            );
        }

        let first_codeword_len = split_encoding.codewords[0].len();
        assert!(
            first_codeword_len > 0,
            "aux split codeword length must be > 0"
        );
        for codeword in &split_encoding.codewords {
            assert_eq!(
                codeword.len(),
                first_codeword_len,
                "aux split codewords must all have same length"
            );
        }

        let oracle = OracleRef::new(OracleNamespace::Aux, self.aux_oracles.len());
        self.aux_oracles.push(AuxOracle {
            label: label.into(),
            oracle,
            split_encoding,
        });
        oracle
    }

    pub fn add_ip_claim(
        &mut self,
        label: impl Into<String>,
        oracle: OracleRef,
        linear_form: LinearForm<F>,
        target: F,
    ) {
        self.assert_oracle_exists(oracle);
        linear_form.assert_len(self.k_prime);

        self.ip_claims.push(IpClaim {
            label: label.into(),
            oracle,
            linear_form,
            target,
            witness_len: self.k_prime,
        });
    }

    pub fn add_tip_claim(
        &mut self,
        label: impl Into<String>,
        lhs_oracle: OracleRef,
        rhs_oracle: OracleRef,
        linear_form: LinearForm<F>,
        target: F,
    ) {
        self.assert_oracle_exists(lhs_oracle);
        self.assert_oracle_exists(rhs_oracle);
        linear_form.assert_len(self.k_prime);

        self.tip_claims.push(TipClaim {
            label: label.into(),
            lhs_oracle,
            rhs_oracle,
            linear_form,
            target,
            witness_len: self.k_prime,
        });
    }

    pub fn finish(self) -> CodeswitchClaimsPlan<F> {
        CodeswitchClaimsPlan {
            aux_oracles: self.aux_oracles,
            ip_claims: self.ip_claims,
            tip_claims: self.tip_claims,
        }
    }

    fn assert_oracle_exists(&self, oracle: OracleRef) {
        match oracle.namespace {
            OracleNamespace::Message => {
                assert!(
                    oracle.index < self.context.message_oracle_count,
                    "message oracle index {} out of range [0, {})",
                    oracle.index,
                    self.context.message_oracle_count
                );
            }
            OracleNamespace::Aux => {
                assert!(
                    oracle.index < self.aux_oracles.len(),
                    "aux oracle index {} out of range [0, {})",
                    oracle.index,
                    self.aux_oracles.len()
                );
            }
            namespace => {
                let count = self
                    .context
                    .index_oracles
                    .count_for(namespace)
                    .expect("index namespace must map to a known index oracle family");
                assert!(
                    oracle.index < count,
                    "index oracle {:?}[{}] out of range [0, {})",
                    namespace,
                    oracle.index,
                    count
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::codeswitching::oracles::{
        CodeswitchOraclesInput, build_codeswitch_oracles, split_and_encode,
    };
    use crate::{FieldElement, IdentityCode};

    fn f(x: u32) -> KoalaBear {
        <KoalaBear as FieldElement>::from_u32(x)
    }

    fn sample_context() -> (CodeswitchClaimContext, IdentityCode<KoalaBear>) {
        let output_code = IdentityCode::<KoalaBear>::new(4);

        let index_input = CodeswitchOraclesInput {
            n_era: 8,
            generator_vector: (0..12).map(f).collect(),
            permutation_1: vec![3, 2, 1, 0, 7, 6, 5, 4],
            permutation_2: vec![0, 2, 4, 6, 1, 3, 5, 7],
            multiplier_1: (100..108).map(f).collect(),
            multiplier_2: (200..208).map(f).collect(),
        };

        let index_oracles = build_codeswitch_oracles(&index_input, &output_code);
        let context = CodeswitchClaimContext::from_codeswitch_oracles(2, &index_oracles);
        (context, output_code)
    }

    #[test]
    fn test_codeswitch_claims_builder_happy_path() {
        let (context, output_code) = sample_context();
        let mut builder = CodeswitchClaimsBuilder::new(4, context);

        let aux_msg: Vec<KoalaBear> = (50..58).map(f).collect();
        let aux_split = split_and_encode(&aux_msg, &output_code);
        let aux_ref = builder.register_aux_oracle("aux_round_1", aux_split);

        builder.add_ip_claim(
            "message_eval",
            OracleRef::new(OracleNamespace::Message, 0),
            LinearForm::Dense(vec![f(1), f(2), f(3), f(4)]),
            f(9),
        );

        builder.add_ip_claim(
            "index_perm_eval",
            OracleRef::new(OracleNamespace::IndexPermutation1, 0),
            LinearForm::EqPoint(vec![f(5), f(6), f(7), f(8)]),
            f(10),
        );

        builder.add_tip_claim(
            "mult_check",
            aux_ref,
            OracleRef::new(OracleNamespace::IndexMultiplier1, 0),
            LinearForm::GeometricPowers { base: f(3), len: 4 },
            f(11),
        );

        let plan = builder.finish();

        assert_eq!(plan.aux_oracles.len(), 1);
        assert_eq!(plan.num_ip(), 2);
        assert_eq!(plan.num_tip(), 1);
    }

    #[test]
    #[should_panic]
    fn test_codeswitch_claims_builder_panics_on_bad_message_ref() {
        let (context, _output_code) = sample_context();
        let mut builder = CodeswitchClaimsBuilder::new(4, context);

        builder.add_ip_claim(
            "bad_message_ref",
            OracleRef::new(OracleNamespace::Message, 7),
            LinearForm::Dense(vec![f(1), f(2), f(3), f(4)]),
            f(9),
        );
    }

    #[test]
    #[should_panic]
    fn test_codeswitch_claims_builder_panics_on_bad_linear_form_len() {
        let (context, _output_code) = sample_context();
        let mut builder = CodeswitchClaimsBuilder::new(4, context);

        builder.add_ip_claim(
            "bad_form_len",
            OracleRef::new(OracleNamespace::Message, 0),
            LinearForm::Dense(vec![f(1), f(2)]),
            f(9),
        );
    }
}
