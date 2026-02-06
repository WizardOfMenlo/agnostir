'''
This script follows Figure 1: CalcDist in the ERA analysis section, please refer to the paper for more details.
'''

import numpy as np
from scipy.optimize import root
import argparse
import sys

def solve_system(c, r, gamma, db):
    """
    Solves for relative distance of ERA code given c, r, gamma and db.
    """

    # Pre-compute common constants dependent on c and r
    A = 1 - c/r
    B = c/r
    h_arg_const = B / A
    h_arg_const = np.clip(h_arg_const, 1e-16, 1.0 - 1e-16)

    # delta initial guess based on setting derivative wrt to d1 = 0 and exponent = -gamma
    current_delta_guess = 0.0

    # Binary entropy function (using base-2 log)
    def H(x):
        x = np.clip(x, 1e-16, 1.0 - 1e-16)
        return -x * np.log2(x) - (1 - x) * np.log2(1 - x)

    # Derivative of binary entropy function
    def Hprime(x):
        x = np.clip(x, 1e-16, 1.0 - 1e-16)
        return np.log2((1 - x) / x)

    # Second derivative of binary entropy function
    def Hprimeprime(x):
        x = np.clip(x, 1e-16, 1.0 - 1e-16)
        return -1.0 / (x * (1 - x) * np.log(2))

    # Compute exponent 
    def exponent_term(d0, d1, delta):

        # E1: (1/r) * H(d0)
        E1 = (1.0 / r) * H(d0)
        
        # E2: d0 * (1-c/r) * H(c/(r-c))
        E2 = d0 * A * H(h_arg_const)
        
        # E3: d1 * H( d0(1-c/r)/d1 )
        arg_E3 = (d0 * A) / d1
        E3 = d1 * H(arg_E3)
        
        # E4: (1-d1) * H( d0*c / (r*(1-d1)) )
        arg_E4 = (d0 * B) / (1 - d1)
        E4 = (1 - d1) * H(arg_E4)
        
        # E5: -H(d0)
        E5 = -H(d0)
        
        # E6: d1 * (1-c/r) * H(c/(r-c))
        E6 = d1 * A * H(h_arg_const)
        
        # E7: delta * H( d1(1-c/r)/delta )
        arg_E7 = (d1 * A) / delta
        E7 = delta * H(arg_E7)
        
        # E8: (1-delta) * H( d1*c/r / (1-delta) )
        arg_E8 = (d1 * B) / (1 - delta)
        E8 = (1 - delta) * H(arg_E8)
        
        # E9: -H(d1)
        E9 = -H(d1)
        
        total_exponent = E1 + E2 + E3 + E4 + E5 + E6 + E7 + E8 + E9

        return total_exponent
    
    # compute derivative of exponent wrt d1
    def d1_prime(d0, d1, delta):

        # 1. Derivative of d1 * H( (d0*(1-c/r))/d1 )
        # Result: -log2( 1 - d0 * A / d1 )
        arg_log1 = 1 - (d0 * A / d1)
        arg_log1 = np.maximum(arg_log1, 1e-16)
        term_d1_1 = -np.log2(arg_log1)
        
        # 2. Derivative of (1-d1) * H( (d0*c) / (r*(1-d1)) )
        # Result: log2( 1 - d0 * B / (1-d1) )
        arg_log2 = 1 - (d0 * B / (1 - d1))
        arg_log2 = np.maximum(arg_log2, 1e-16)
        term_d1_2 = np.log2(arg_log2)

        # 3. Derivative of d1 * (1-c/r) * H(c/(r-c))
        # Result: (1-c/r) * H(c/(r-c))
        term_d1_3 = A * H(h_arg_const)
        
        # 4. Derivative of delta * H( d1(1-c/r)/delta )
        # Result: (1-c/r) * log2( delta / (d1(1-c/r)) - 1 )
        term_d1_4 = A * Hprime(d1 * A / delta)
        
        # 5. Derivative of (1-delta) * H( d1*c/r / (1-delta) )
        # Result: (c/r) * log2( r(1-delta)/(d1*c) - 1 )
        term_d1_5 = B * Hprime(d1 * B / (1 - delta))
        
        # 6. Derivative of -H(d1)
        # Result: log2( d1 / (1-d1) )
        term_d1_6 = -Hprime(d1)
        
        total_derivative = term_d1_1 + term_d1_2 + term_d1_3 + term_d1_4 + term_d1_5 + term_d1_6

        return total_derivative
    
    # compute derivative of exponent wrt d1
    def d0_prime(d0, d1, delta):

        # 1. Derivative of ((1/r) - 1) * H(d0)
        # Result: (1/r - 1) * log2( (1-d0)/d0 )
        term_d0_1 = (1.0 / r - 1.0) * Hprime(d0)

        # 2. Derivative of d0 * (1-c/r) * H(c/(r-c))
        # Result: (1-c/r) * H(c/(r-c))
        term_d0_2 = A * H(h_arg_const)

        # 3. Derivative of d1 * H( d0(1-c/r)/d1 )
        # Result: A * log2( (d1 / (d0*A)) - 1 )
        term_d0_3 = A * Hprime(d0 * A / d1)

        # 4. Derivative of (1-d1) * H( d0*c / (r*(1-d1)) )
        # Result: B * log2( (r*(1-d1) / (d0*c)) - 1 )
        term_d0_4 = B * Hprime((d0 * B) / (1 - d1))

        total_derivative = term_d0_1 + term_d0_2 + term_d0_3 + term_d0_4

        return total_derivative

    # compute second derivative of exponent wrt d0
    def d0_prime_prime(d0, d1, delta):

        X = d0 * A / d1
        Y = (d0 * B) / (1.0 - d1)

        term_00_1 = (1.0 / r - 1.0) * Hprimeprime(d0)
        term_00_2 = (A ** 2) / d1 * Hprimeprime(X)
        term_00_3 = (B ** 2) / (1.0 - d1) * Hprimeprime(Y)

        return term_00_1 + term_00_2 + term_00_3
    
    # compute second derivative of exponent wrt d1
    def d1_prime_prime(d0, d1, delta):

        X = d0 * A / d1
        Y = (d0 * B) / (1.0 - d1)

        term_11_1 = X**2 * Hprimeprime(X) / d1
        term_11_2 = Y**2 * Hprimeprime(Y) / (1.0 - d1)
        term_11_3 = A**2 * Hprimeprime(d1 * A / delta) / delta
        term_11_4 = B**2 * Hprimeprime(d1 * B / (1.0 - delta)) / (1.0 - delta)
        term_11_5 = - Hprimeprime(d1)

        return term_11_1 + term_11_2 + term_11_3 + term_11_4 + term_11_5
        
    # compute mixed derivative of exponent wrt d1 and d0
    def d0_d1_mixed_prime(d0, d1, delta):

        X = d0 * A / d1
        Y = (d0 * B) / (1.0 - d1)

        # Compute Mixed Partial Derivative E_01 (d^2E / dd0 dd1)
        # Formula: (-X^2 * H''(X) + Y^2 * H''(Y)) / d0
        return (-X**2 * Hprimeprime(X) + Y**2 * Hprimeprime(Y)) / d0

    def solve_for_delta(vars):
        d1, delta = vars
        d1 = np.clip(d1, 1e-16, 1.0 - 1e-16)
        delta = np.clip(delta, 1e-16, 1.0 - 1e-16)

        eq1 = d1_prime(db, d1, delta)
        eq2 = gamma + exponent_term(db, d1, delta)
        return [eq1, eq2]

    def verify(vars):
        d0, d1, delta = vars
        d0 = np.clip(d0, 1e-16, 1.0 - 1e-16)
        d1 = np.clip(d1, 1e-16, 1.0 - 1e-16)
        delta = np.clip(delta, 1e-16, 1.0 - 1e-16)

        eq1 = d0_prime(d0, d1, delta)
        eq2 = d1_prime(d0, d1, delta)
        eq3 = d0_prime_prime(d0, d1, delta) * d1_prime_prime(d0, d1, delta) - (d0_d1_mixed_prime(d0, d1, delta))**2

        return [eq1, eq2, eq3]


    # Compute delta_1^* as defined in Figure 1
    guesses_first_system = [
        [1e-8, 0.1], [1e-6, 0.1], [1e-4, 0.1], [1e-3, 0.1],
        [0.1, 0.3], [0.15, 0.4], [0.2, 0.5], [0.3, 0.7],
        [0.05, 0.3], [0.2, 0.4], [0.5, 0.8],
    ]
    sol = None
    for x0 in guesses_first_system:
        temp_sol = root(solve_for_delta, x0, method='lm')

        if temp_sol.success and np.max(np.abs(temp_sol.fun)) < 1e-12 \
            and np.all((temp_sol.x > 1e-16)) \
            and temp_sol.x[0] > db * (1 - c/r) \
            and temp_sol.x[1] > temp_sol.x[0] * (1 - c/r) \
            and temp_sol.x[1] < (1.0 - c / r) ** 2:

            current_delta_guess = temp_sol.x[1]
            print(f"Guess for delta: {current_delta_guess}")
            sol = current_delta_guess
            break

    if sol is None:
        print("Failed to compute delta_1^*: likely that the value of n is too small.")
        return None

    # Compute delta_2^* as defined in Figure 1
    guesses_second_system = [
        [x/8, x/2, x] for x in np.arange(0, 1, 0.001) 
    ]
    best_verify_sol = None
    for x0 in guesses_second_system:
        verify_sol = root(verify, x0, method='lm')
        new_delta_guess = verify_sol.x[2]
    
        if verify_sol.success and np.max(np.abs(verify_sol.fun)) < 1e-12 \
            and np.all((verify_sol.x > 1e-16)) \
            and verify_sol.x[1] > verify_sol.x[0] * (1 - c/r) \
            and new_delta_guess > verify_sol.x[1] * (1 - c/r) \
            and new_delta_guess < (1.0 - c / r) ** 2:

            # Pick the solution with the smallest verify_sol.x[2]
            if best_verify_sol is None or new_delta_guess < best_verify_sol:
                print(f"Found new solution for 3 equations: (d0, d1, delta_2^*) = ({verify_sol.x})")
                best_verify_sol = new_delta_guess
            

    if sol > best_verify_sol:
        print(f"Guess for delta: {current_delta_guess} is invalid: exponent not minimized at d0 = {db}. Maximum possible delta: {best_verify_sol}")
        sol = best_verify_sol
    else:
        print(f"Guess for delta: {current_delta_guess} is valid.")

    return sol


def compute_c_from_q_bound(r, secparam, db, n_lower_bound, q_lower_bound):
    """
    Calculates the lower bound for q based on step 1 of Figure 1.
    """
    def rhs_log2(c_val):
        alpha = 1 - (c_val / (np.e * r)) ** (c_val / r)
        term1 = -np.log2(db) 
        term2 = (r - r * alpha + 1 + c_val * alpha) * np.log2(np.e) 
        term3 = c_val * alpha * np.log2(r / c_val)
        term4 = - (r - r * alpha) * np.log2(1 - alpha)
        term5 = (r * (2 * secparam + 4 + 4 * n_lower_bound)) / (db * (2 ** n_lower_bound))
        return (term1 + term2 + term3 + term4 + term5) / (c_val - 1)
    
    # Find c such that rhs_log2(c) = q_lower_bound
    def equation_to_solve(c_val):
        return rhs_log2(c_val) - q_lower_bound

    # Initial guesses for c    
    c_guesses = [1.1, 1.5, 2.0, 3.0, 5.0, 10.0]

    c_value = None
    for x0 in c_guesses:
        temp_sol = root(equation_to_solve, x0, method='lm')
        if temp_sol.success and temp_sol.x > 1:
            c_value = temp_sol.x[0]
            break

    return c_value


def compute_gamma_from_n_bound(r, c, secparam, n_lower_bound):
    """
    Calculates the value of gamma based on step 2 of Figure 1.
    """
    term_inside_log = (c**2 * (r-c)**3) / (r**5)
    n = 2**n_lower_bound
    return (secparam + 1 + np.log2(term_inside_log) + 7 * np.log2(n + 1)) / n


def run_simulation():
    r_values = [4, 6, 8, 10, 16, 25, 50, 100]
    db_values = [0.001, 0.003, 0.01, 0.03]
    n_val = 20.0
    q_val = 256.0
    secparam = 100

    lines = []
    header = f"| delta_B \\ r | " + " | ".join([f"{r}" for r in r_values]) + " |"
    separator = "| :--- | " + " | ".join([":---:" for _ in r_values]) + " |"
    lines.extend([header, separator])

    for db in db_values:
        row_str = f"| **{db}** |"
        for r in r_values:

            c = compute_c_from_q_bound(r, secparam, db, n_val, q_val)
            c_upper_bound = (r / 2) * (1 - 1 / np.sqrt(5))

            gamma = compute_gamma_from_n_bound(r, c, secparam, n_val)
            
            val_str = "-"
            if c is not None and (1 < c < c_upper_bound):
                # 3. Solve System
                delta = solve_system(c, r, gamma, db)
                if delta is not None:
                    val_str = f"{delta:.4f}"
                else:
                    val_str = "No Sol"
            else:
                val_str = "Inv c"
            
            row_str += f" {val_str} |"
        lines.append(row_str)

    with open("table.txt", "w", encoding="ascii") as outfile:
        outfile.write("\n".join(lines) + "\n")


if __name__ == "__main__":

    # run_simulation()

    parser = argparse.ArgumentParser(description="Given lower bounds on block length (n) and field size (q), compute the relative distance of ERA code given repetition parameter r and base code distance db.")
    
    parser.add_argument("-n", type=float, default=20.0, help="Lower bound for block length (n) in log2")
    parser.add_argument("-q", type=float, default=192.0, help="Lower bound for field size (q) in log2")
    parser.add_argument("-secparam", type=int, default=100, help="Soundness parameter")
    parser.add_argument("-r", type=int, required=True, help="Repetition parameter")
    parser.add_argument("-db", type=float, required=True, help="Relative distance of base code")

    args = parser.parse_args()

    c = compute_c_from_q_bound(args.r, args.secparam, args.db, args.n, args.q)
    c_upper_bound = (args.r / 2) * (1 - 1 / np.sqrt(5))
    if c is None \
        or not (1 < c < c_upper_bound):
        print(f"Error: Could not compute a valid c value. For r={args.r}, need 1 < c < {c_upper_bound}. Got {c}. Likely that the value of q/n/db is too small.")
        sys.exit(1)
    print(f"Computed c: {c}")

    gamma = compute_gamma_from_n_bound(args.r, c, args.secparam, args.n)
    print(f"Computed gamma: {gamma}")

    result = solve_system(c, args.r, gamma, args.db)
    if result is not None:
        print(f"ERA code has relative distance: {result}")
    else:
        print("Error: Could not compute relative distance.")
        sys.exit(1)