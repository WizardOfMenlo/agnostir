use crate::{
    ErrorCorrectingCode, FieldElement, OptimizedEraCode,
    poly_utils::{evals::EvaluationsList, multilinear::MultilinearPoint},
};

#[derive(Debug, Clone)]
pub struct CodeswitchParameters<C, F> {
    message_interleaving: usize,   // \ell_m in the paper
    base_code_interleaving: usize, // \ell_{n_B} in paper
    era_interleaving: usize,       // \ell_{n_{ERA}} in paper

    log_original_code_message: usize,
    log_new_code_message: usize,

    era_code: OptimizedEraCode<C, F>,
}

#[derive(Debug, Clone)]
pub struct CodeswitchInput<F: FieldElement> {
    message: Vec<F>,
    point: Vec<F>,
}

pub fn codeswitch<C: ErrorCorrectingCode, F: FieldElement>(
    params: &CodeswitchParameters<C, F>,
    input: CodeswitchInput<F>,
    point: MultilinearPoint<F>,
) {
    assert_eq!(
        input.message.len(),
        params.message_interleaving * (1 << params.log_new_code_message)
    );
    assert_eq!(params.log_original_code_message, point.0.len());

    let new_code_message_len = 1 << params.log_new_code_message;

    let _z_1 = MultilinearPoint(
        point.0[..(params.log_original_code_message - params.log_new_code_message)].to_vec(),
    );
    let z_2 = MultilinearPoint(
        point.0[(params.log_original_code_message - params.log_new_code_message)..].to_vec(),
    );

    // Assume that message is of size params.message_interleaving * (1 << params.log_new_code_message)

    for i in 0..params.message_interleaving {
        // First, compute the encoding
        let block = EvaluationsList::new(
            input.message[i * new_code_message_len..(i + 1) * new_code_message_len].to_vec(),
        );

        // Placeholder for ongoing implementation.
        let _y_eval_i = block.evaluate(&z_2);

        let ood_point = MultilinearPoint(vec![F::ZERO]); // TODO: Sample 
        let ood_evaluation = block.evaluate(&ood_point);
    }

    let _ = (
        &params.base_code_interleaving,
        &params.era_interleaving,
        &params.era_code,
    );
    let _ = &input.point;
}
