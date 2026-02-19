import math
import argparse

# ==========================================
# Constants and Basic Functions
# ==========================================

M31 = 2**31 - 1
F256 = 2**256 - 1

def log2(x):
    """Base-2 logarithm."""
    if x <= 0:
        return -float('inf')
    return math.log(x, 2)

def h(x):
    """Binary entropy function: -x log2(x) - (1-x) log2(1-x)."""
    if x <= 0 or x >= 1:
        return 0.0
    return -x * log2(x) - (1 - x) * log2(1 - x)

def h_prime(x):
    """Derivative of binary entropy: log2((1-x)/x)."""
    if x <= 0 or x >= 1:
        return 0.0 # technically infinity
    return log2((1 - x) / x)

def h_double_prime(x):
    """Second derivative of binary entropy: -1 / (ln(2) * x * (1-x))."""
    if x <= 0 or x >= 1:
        return -float('inf')
    return -1.0 / (math.log(2) * x * (1 - x))

def log2_binomial(n, k):
    """Calculates log2(Binomial(n, k)) using lgamma."""
    if k < 0 or k > n:
        return -float('inf')
    if k == 0 or k == n:
        return 0.0
    ln_n = math.lgamma(n + 1)
    ln_k = math.lgamma(k + 1)
    ln_nk = math.lgamma(n - k + 1)
    return (ln_n - ln_k - ln_nk) / math.log(2)

def binomial_coeff(n, k):
    """Standard binomial coefficient."""
    if k < 0 or k > n:
        return 0
    return math.comb(n, k)

# ==========================================
# Parameter Definitions
# ==========================================

# Raw parameters: {alpha, beta, r, cn, dn}
PARS = [
    [0.085, 0.02 * 1.154, 1.154, 9, 32],
    [0.045, 0.02 * 1.1, 1.1, 7, 36],
    [0.1195, 0.0284, 1.42, 6, 33],
    [0.138, 0.0444, 1.47, 7, 26],
    [0.178, 0.061, 1.521, 7, 22],
    [0.2, 0.082, 1.64, 8, 19],
    [0.211, 0.097, 1.616, 9, 21],
    [0.238, 0.1205, 1.72, 9, 12],
    [0.68, 0.59, 6, 16, 16],
    [0.3, 0.2, 2, 10, 20],
    [0.05, 0.01 * 1.1, 1.1, 6, 40]
]

def convert_params(alpha, beta, r):
    """Converts {alpha, beta, r} to {alpha, rho, delta}."""
    return [alpha, 1.0 / r, beta / r]

# Converted parameters: {alpha, rho, delta}
PARAMS = [convert_params(p[0], p[1], p[2]) for p in PARS]

def print_parameters():
    print(f"{'alpha':<10} {'beta':<10} {'r':<10} {'cn':<5} {'dn':<5}")
    for p in PARS:
        print(f"{p[0]:<10} {p[1]:<10} {p[2]:<10} {p[3]:<5} {p[4]:<5}")
    print("\n" + "="*40 + "\n")
    print(f"{'alpha':<10} {'rho':<20} {'delta':<20}")
    for p in PARAMS:
        print(f"{p[0]:<10} {p[1]:<20} {p[2]:<20}")

# ==========================================
# Alpha Range Calculations
# ==========================================

def alpha_range_trivial(rho, delta):
    """Returns trivial alpha range [delta/rho, 1 - rho/(1-delta)]."""
    return [delta / rho, 1 - rho / (1 - delta)]

def alpha_range(rho, delta, n, security_lambda=110, modulus=M31, secant=False):
    """
    Computes the alpha range based on tight parameter bounds.
    """
    log2_p = log2(modulus)
    
    # Calculate min
    val_min = (delta / rho) + (1.0 / log2_p) * (
        (security_lambda / n) + h(delta / rho)
    )
    
    # Calculate max based on secant or tangent approximation
    if secant:
        numerator = (
            (1 - 1/log2_p) * (1 - rho) - 
            2 * delta - 
            (1/log2_p) * h(delta)
        )
        denominator = (
            1 - (1/log2_p) * (1 - security_lambda/n) - delta
        )
        val_max = numerator / denominator
    else:
        # Tangent approximation
        numerator = (
            (1 - 1/log2_p) * (1 - rho) - 
            2 * delta - 
            (1/log2_p) * delta * h_prime(delta)
        )
        denominator = (
            1 - 
            (1/log2_p) * (1 - security_lambda/n) - 
            delta + 
            (1/log2_p) * (h(delta) - delta * h_prime(delta))
        )
        val_max = numerator / denominator
        
    return [val_min, val_max]

# ==========================================
# Union Bound
# ==========================================

def union_bound(n, m, d, b, k):
    """
    Brakedown double-union bound (logarithmic).
    Estimates prob that a random d-left-regular graph has a set of size k
    mapped to a set of size at most b.
    """
    b_floor = math.floor(b)
    
    # Impossible events check
    if d > m or d > b:
        # In the Mathematica script, if d > b, it prints "prob zero" (effectively -inf log prob)
        return -float('inf')

    # Binomial formula in log domain
    term1 = log2_binomial(n, k)
    term2 = log2_binomial(m, b_floor)
    
    # Inner term: k * (log2(Binomial(floor(b), d)) - log2(Binomial(m, d)))
    inner_diff = log2_binomial(b_floor, d) - log2_binomial(m, d)
    term3 = k * inner_diff
    
    result = term1 + term2 + term3
    
    # Capped by probability 1 (log 0)
    return min(result, 0.0)

# ==========================================
# Convexity Argument (Large Cases)
# ==========================================

def large_cases(dims, k_range, b_coeffs, security_lambda, verbose=False):
    """
    Convexity argument for large ranges.
    dims: {n, m}
    k_range: {k0, k1}
    b_coeffs: {b0, b1} for b(k) = b0 + b1*k
    """
    n, m = dims
    k0, k1 = k_range
    b0, b1 = b_coeffs
    
    def b_func(k):
        return b0 + b1 * k

    # Sanity checks
    if b0 < 0 or b1 < 0 or b_func(k1) > m:
        print("Non-admissible coefficients for convexity argument.")
        if b_func(k1) > m:
            print(f"b[k1] exceeds m, b[k1]/m = {b_func(k1)/m}")
        return None

    # Define f1(k) = n*h(k/n) + m*h(b(k)/m)
    def f1(k):
        return n * h(k / n) + m * h(b_func(k) / m)

    # Define f2(k) = -k * log2(b(k)/m)
    def f2(k):
        ratio = b_func(k) / m
        if ratio <= 0: return float('inf') # Should not happen if b0,b1 > 0
        return -k * log2(ratio)

    # Define f(k, deg) = f1(k) - deg * f2(k)
    def f(k, deg):
        return f1(k) - deg * f2(k)

    # Define d(k) required for specific lambda
    def d_required(k):
        val_f2 = f2(k)
        if val_f2 == 0: return float('inf')
        return (security_lambda + f1(k)) / val_f2

    # Second derivative calculations for convexity
    # Analytical derivatives derived from h''(x)
    def g1(k):
        # -k * f1''(k)
        # f1''(k) = (1/n)*h''(k/n) + (b1^2/m)*h''(b(k)/m)
        val = (1.0/n) * h_double_prime(k/n) + (b1**2 / m) * h_double_prime(b_func(k)/m)
        return -k * val

    def g2(k):
        # -k * f2''(k)
        # f2(k) = -k * log2(b(k)) + k * log2(m)
        # f2'(k) = -log2(b(k)) - k * b1/(b(k)*ln(2)) + log2(m)
        # f2''(k) = -b1/(b(k)*ln(2)) - [ (b1 * b(k) - k*b1^2) / (b(k)^2 * ln(2)) ] ... simplified derivation needed
        # Analytic form: f2''(k) = (1/ln2) * ( -2*b1/b(k) + k*b1^2/b(k)^2 )
        bk = b_func(k)
        val = (1.0 / math.log(2)) * ( (-2 * b1 / bk) + (k * (b1**2) / (bk**2)) )
        return -k * val

    # Calculate degree bounds
    d_k0 = d_required(k0)
    d_k1 = d_required(k1)
    
    # Convexity constraint: g1(k1) / g2(k0)
    # Ensure denominators are not zero/invalid
    try:
        conv_constraint = g1(k1) / g2(k0)
    except:
        conv_constraint = 0 # Fallback

    deg_bounds = [d_k0, d_k1, conv_constraint]
    
    if min(deg_bounds) < 0:
        print("Unexpected: one of the quotients is negative")
        return None

    deg = math.ceil(max(deg_bounds))

    if deg > m:
        print("Too large vertex degree for matrix dimension.")
        return None

    prob = max(f(k0, deg), f(k1, deg))

    if verbose:
        print(f"Convexity argument over [k0, k1] = [{k0}, {k1}]")
        print(f"Degree bound and prob.: d={deg}, log2(P) = {prob}")

    return deg, prob

# ==========================================
# Exhaustive Search (Small Cases)
# ==========================================

def small_cases(dims, b_list, k1, security_lambda, dmax):
    """
    Exhaustive search for small ranges.
    dims: {n, m}
    b_list: list of bounds for k starting at k1
    dmax: maximum degree to check
    """
    n, m = dims
    
    # We want to find smallest d in [1, dmax] such that for all k, prob <= -lambda
    # Since d is monotonic (higher d -> lower prob), we can search linearly or simpler.
    
    valid_degrees = []
    
    # In the Mathematica script, it computes a table of booleans for all d and checks validity.
    # Here we just iterate d from 1 to dmax.
    
    final_d = float('inf')
    found = False

    for d in range(1, dmax + 1):
        is_valid_d = True
        
        for i, b_val in enumerate(b_list):
            k = k1 + i
            if k <= 1 and d == 1: continue # Trivial case handling if necessary
            
            prob = union_bound(n, m, d, b_val, k)
            if prob > -security_lambda:
                is_valid_d = False
                break
        
        if is_valid_d:
            final_d = d
            found = True
            break # Smallest d found
            
    if not found:
        print("small cases: too high bound for given dmax. Try to increase it.")
        return None
        
    if final_d > m:
        print("small cases: degree bound exceeds m")
        return None
        
    return final_d

# ==========================================
# Matrix A Weight Calculation
# ==========================================

def row_weight_a(n_input, params, modulus=2**127, security=100, threshold=500, 
                 secant=False, tangent_point=0, max_degree=50, verbose=False):
    """
    Determines vertex degree for compression matrix A.
    params: {alpha, rho, delta}
    """
    alpha, rho, delta = params
    
    wordsize = math.floor((1.0 / rho) * n_input)
    n = n_input
    m = math.ceil(alpha * n)
    k1 = math.floor(delta * wordsize)
    
    recursive_steps = log2(n) / log2(1.0 / alpha)
    
    # Adjust lambda based on union bound over recursion steps and range
    lambda_adj = security + log2(k1) + log2(recursive_steps)
    
    log2_p = log2(modulus)

    # Function f(k)
    def f_func(k):
        return k + (lambda_adj + n * h(k/n)) / log2_p

    if verbose:
        print(f"Matrix dimensions {{n,m}} = {{{n},{m}}}")
        print(f"Expansion interval {{k1,k2}} = {{1, {k1}}}")

    # --- Large Cases ---
    deg_large = 0
    prob_large = -float('inf')
    
    k0 = threshold
    
    if k1 >= k0:
        if verbose: print("--------------- large cases ---------------")
        
        # Calculate linear bound b(k) = b0 + b1*k
        if secant:
            b1 = f_func(k0) / k0
            b0 = 0.0
            if verbose: print(f"Secant at k0 = {k0}")
        else:
            # Tangent at specific point in [k0, k1]
            p_val = k0 + tangent_point * (k1 - k0)
            # Derivative of f(x)
            # f'(x) = 1 + (n * h'(x/n) * (1/n)) / log2_p = 1 + h'(x/n) / log2_p
            f_prime = 1 + h_prime(p_val / n) / log2_p
            b1 = f_prime
            b0 = f_func(p_val) - b1 * p_val
            if verbose: print(f"Tangent at {p_val}")

        result = large_cases([n, m], [k0, k1], [b0, b1], lambda_adj, verbose)
        if result:
            deg_large, prob_large = result
    
    # --- Small Cases ---
    if verbose: print("--------------- small cases ---------------")
    upper_small = min(k0 - 1, k1)
    if verbose: print(f"over interval [1, {upper_small}]")
    
    # integerLessThan logic: if int, minus 1, else floor.
    def integer_less_than(val):
        if val.is_integer():
            return int(val) - 1
        return math.floor(val)

    b_list = []
    range_small = range(1, upper_small + 1)
    
    if secant:
        # Constant array logic from script
        val = f_func(upper_small)
        b_val = integer_less_than(val)
        b_list = [b_val] * len(range_small)
    else:
        # Table logic
        for k in range_small:
            # term = k + (lambda + log2(binom(n,k))) / log2(p)
            term = k + (lambda_adj + log2_binomial(n, k)) / log2_p
            b_list.append(integer_less_than(term))

    deg_small = small_cases([n, m], b_list, 1, lambda_adj, max_degree)

    print("Matrix A Weight Calculation Results:")
    print("Small cases degree:", deg_small)
    print("Large cases degree:", deg_large)
    
    d_final = max(deg_small if deg_small else 0, deg_large)
    
    # Recalculate max prob for verification (omitted plotting logic)
    
    return d_final, prob_large # Returning prob_large as heuristic, script calculates actual max prob

# ==========================================
# Matrix B Weight Calculation
# ==========================================

def row_weight_b(n_input, params, modulus=2**127, security=100, threshold=500, 
                 secant=False, tangent_point=1, max_degree=50, exhaustive_bound=False, verbose=False):
    """
    Determines vertex degree for stretching matrix B.
    params: {alpha, rho, delta}
    """
    alpha, rho, delta = params
    
    wordsize = math.floor(n_input / rho)
    n = math.floor(math.ceil(alpha * n_input) / rho)
    m = wordsize - n - n_input
    
    k1 = math.ceil(delta * n)
    k2 = math.floor(delta * wordsize)
    
    recursive_steps = log2(n) / log2(1.0 / alpha)
    
    lambda_adj = security
    if k2 > k1:
        lambda_adj += log2(k2 - k1)
    lambda_adj += log2(recursive_steps)
    
    log2_p = log2(modulus)
    
    if verbose:
        print(f"Matrix dimensions {{n,m}} = {{{n},{m}}}")
        print(f"Expansion interval {{k1,k2}} = {{{k1}, {k2}}}")

    # Function f(k) for B
    def f_func_b(k):
        term1 = (wordsize - n) * delta
        term2 = k
        term3 = (m + lambda_adj + n * h(k/n)) / log2_p
        return term1 + term2 + term3

    deg_large = 0
    prob_large = -float('inf')
    k0_val = max(k1, threshold)
    
    # --- Large Cases ---
    if k2 >= threshold:
        if verbose: print("--------------- large cases ---------------")
        
        if secant:
            b1 = f_func_b(k0_val) / k0_val
            b0 = 0.0
        else:
            p_val = k0_val + tangent_point * (k2 - k0_val) # Note k2 here
            # Derivative D[f]
            # f(k) = C + k + (C2 + n*h(k/n))/logp
            # f'(k) = 1 + (n * h'(k/n) * 1/n)/logp = 1 + h'(k/n)/logp
            f_prime = 1 + h_prime(p_val / n) / log2_p
            b1 = f_prime
            b0 = f_func_b(p_val) - b1 * p_val
            
        result = large_cases([n, m], [k0_val, k2], [b0, b1], lambda_adj, verbose)
        if result:
            deg_large, prob_large = result
    
    # --- Small Cases ---
    deg_small = 0
    if k1 < threshold:
        if verbose: print("--------------- small cases ---------------")
        upper = min(threshold - 1, k2)
        if verbose: print(f"over interval [{k1}, {upper}]")
        
        def integer_less_than(val):
            if val.is_integer():
                return int(val) - 1
            return math.floor(val)
            
        b_list = []
        # Range from k1 to upper
        range_small = range(k1, upper + 1)
        
        # Simplified logic from script (exhaustiveBound=False branch usually taken)
        for k in range_small:
            term = k + (wordsize - n)*delta + (m + lambda_adj + log2_binomial(n, k)) / log2_p
            b_list.append(integer_less_than(term))
            
        deg_small = small_cases([n, m], b_list, k1, lambda_adj, max_degree)

    print("Matrix B Weight Calculation Results:")
    print("Small cases degree:", deg_small)
    print("Large cases degree:", deg_large)
        
    d_final = max(deg_small if deg_small else 0, deg_large)
    
    return d_final, prob_large

# ==========================================
# Main Execution Example
# ==========================================

def main(alpha, beta, r, n, security):
    """Run the full analysis for given alpha, beta, r, n, security."""
    params = convert_params(alpha, beta, r)
    n_in = 2**n

    rho = params[1]
    delta = params[2]

    print(f"Parameters: alpha={alpha}, beta={beta}, r={r}, n=2^{n}={n_in}, security={security}")
    print(f"Converted:  alpha={params[0]}, rho={rho}, delta={delta}")
    print()

    print("Trivial Alpha Range:", alpha_range_trivial(rho, delta))

    range_secant = alpha_range(rho, delta, n_in, security, F256, secant=True)
    print("Alpha Range (Secant):", range_secant)

    range_tangent = alpha_range(rho, delta, n_in, security, F256, secant=False)
    print("Alpha Range (Tangent):", range_tangent)

    print(f"\nCalculating RowWeightA for n={n_in} with params {params}")
    d_a, prob_a = row_weight_a(n_in, params, security=security, verbose=True)
    print(f"Result Matrix A: d = {d_a}")

    print(f"\nCalculating RowWeightB for n={n_in} with params {params}")
    d_b, prob_b = row_weight_b(n_in, params, security=security, verbose=True)
    print(f"Result Matrix B: d = {d_b}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brakedown parameter analysis")
    parser.add_argument("alpha", type=float, help="Alpha parameter")
    parser.add_argument("beta", type=float, help="Beta parameter")
    parser.add_argument("r", type=float, help="Rate parameter r")
    parser.add_argument("-n", type=int, default=15, help="Log2 of input size (default: 15, i.e. n=2^15)")
    parser.add_argument("-s", "--security", type=int, default=100, help="Security parameter lambda (default: 100)")
    args = parser.parse_args()

    main(args.alpha, args.beta, args.r, args.n, args.security)