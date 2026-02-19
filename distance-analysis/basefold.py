import argparse
import math

def compute_formula(q, c, d, lam):
    """
    Computes the formula given:
    q: value of log(|F|)
    c: constant multiplier for n sequence
    d: upper bound of summation
    lam: lambda value
    """
    
    # Define the common denominator term: log(|F|) - 1.001
    # Since q is passed as log(|F|), we use q directly.
    denom_log_F = q - 1.001
    
    if denom_log_F == 0:
        raise ValueError("q (log|F|) cannot be 1.001 to avoid division by zero.")

    # Let R be the ratio: log(|F|) / (log(|F|) - 1.001)
    R = q / denom_log_F

    # --- Term 1 ---
    # (1/c) * R^d
    term1 = (1.0 / c) * (R ** d)

    # --- Term 2 (Summation) ---
    sum_val = 0.0
    
    # Initialize n sequence. 
    # The loop runs for i = 1 to d.
    # It requires n_{i-1} and n_i.
    n_prev = c  # This corresponds to n_{0}
    
    for i in range(1, d + 1):
        # Calculate n_i based on n_{i+1} = 2 * n_i (so n_current = 2 * n_prev)
        n_curr = 2 * n_prev
        
        # Calculate log(n_{i-1}). We use log2 assuming standard information theoretic context.
        # If n_prev = 1, log2(n_prev) = 0.
        log_n_prev = math.log2(n_prev)
        
        # Calculate the two parts inside the large brackets
        
        # Part A: 0.6 / (log|F| - 1.001)
        part_a = 0.6 / denom_log_F
        
        # Part B: (2 * log(n_{i-1}) + lambda) / (n_i * (log|F| - 1.001))
        numerator_b = (2 * log_n_prev) + lam
        denominator_b = n_curr * denom_log_F
        part_b = numerator_b / denominator_b
        
        # Sum parts A and B
        brackets = part_a + part_b
        
        # Multiply by R^{d-i}
        outer_factor = R ** (d - i)
        
        # Add to total sum
        sum_val += outer_factor * brackets
        
        # Update n_prev for the next iteration
        n_prev = n_curr

    return 1 - (term1 + sum_val)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute the mathematical formula from the image.")
    
    parser.add_argument("q", type=float, help="The value of log(|F|)")
    parser.add_argument("c", type=float, help="The constant c")
    parser.add_argument("d", type=int, help="The integer d (summation limit)")
    
    # Lambda is required by the formula but wasn't strictly in the 'given' list of the prompt.
    # We add it as an optional argument with a default, or you can supply it explicitly.
    parser.add_argument("--lam", type=float, default=100.0, help="The value of lambda (default: 100.0)")

    args = parser.parse_args()
    
    try:
        result = compute_formula(args.q, args.c, args.d, args.lam)
        print(f"Result: {result}")
    except Exception as e:
        print(f"Error: {e}")