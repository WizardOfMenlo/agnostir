import math

# --- 1. DEFINED VARIABLES ---

# General parameters
LOG_HASH_SIZE = 256
LOG_FIELD_SIZE = 256
lam = 100

# IOPP parameters
eta = 2**4
k = 2**26
k_prime = 2**26 # 2**24
n_last = 2**12
log_n_last = math.ceil(math.log2(n_last))
log_k_prime = math.ceil(math.log2(k_prime))

# Initial ERA code parameters
r = 4
b = 1.21
delta_era = 0.221
n_b = b * k
n_era = r * b * k
eps_era = 1 - (1 - delta_era)**(1/3)
indices_era = math.ceil(-lam / math.log2(1 - eps_era))

# Basefold parameters
delta_bf = 0.158 # 0.842
inv_rate_bf = 2 # 16
eps_bf = 1 - (1 - delta_bf)**(1/3)
indices_bf = math.ceil(-lam / math.log2(1 - eps_bf))

# --- 2. ORACLE PARAMETERS (CEILED INDEPENDENTLY) ---
ell_m = math.ceil(k / k_prime)
ell_b = math.ceil(b * k / k_prime)
ell_g = math.ceil(math.sqrt(b) * k / k_prime)
ell_era = math.ceil(r * b * k / k_prime)

# --- 3. FIELD ELEMENTS: STARTING IOR ---
# starting_elements = indices_era * eta + 3 * math.ceil(math.log2(k * eta))
starting_elements = indices_bf * eta

# --- 4. FIELD ELEMENTS: BASE PROOF ---
log_n_era_ceil = math.ceil(math.log2(n_era))

term_1 = (2 * log_n_era_ceil + 1) * log_n_era_ceil
term_2_5 = 5 * ell_m + 4 * ell_g + 4 * ell_b + 20 * ell_era
term_6_8 = 8 + 3 * math.log2(k) + 4 * math.log2(k_prime)

codeswitch_elements = term_1 + term_2_5 + term_6_8

# --- 5. FIELD ELEMENTS: ORACLES ---
indexer_oracles = ell_g + 3 * ell_era
indexer_elements = indexer_oracles * indices_bf

online_oracles = ell_m + ell_b + 2 * ell_era
online_elements = online_oracles * indices_bf

# --- 6. BASEFOLD IOPP FIELD ELEMENTS ---
rounds = log_k_prime - log_n_last
sumcheck_elements = rounds * 3
queried_elements = rounds * 3 * indices_bf
base_case_elements = n_last
total_basefold_elements = sumcheck_elements + queried_elements + base_case_elements

# --- 7. HASH SIZES (MERKLE TREES) ---
def merkle_tree_hashes(queries, n_depth):
    top_levels = math.log2(queries)
    hashes_top = queries - 2
    hashes_sib = math.ceil((n_depth - top_levels) * queries)
    return hashes_top, hashes_sib

# Tree A (Starting IOR)
top_A, sib_A = merkle_tree_hashes(indices_era, math.ceil(math.log2(n_era)))
total_hashes_A = top_A + sib_A

# Trees B (Codeswitch IOR)
top_B, sib_B = merkle_tree_hashes(indices_bf, math.ceil(math.log2(k_prime * inv_rate_bf)))
total_hashes_B = 2 * (top_B + sib_B)

# Trees C (Basefold IOPP)
top_C_total = 0
sib_C_total = 0
for n in range(log_n_last+1, log_k_prime+1):
    top_C, sib_C = merkle_tree_hashes(indices_bf, n + math.ceil(math.log2(inv_rate_bf)) - 1) # The -1 is coz the oracles are are folded in half and then stacked
    top_C_total += top_C
    sib_C_total += sib_C
total_hashes_C = 2 * (top_C_total + sib_C_total)

# --- 8. GRAND TOTALS ---
# total_field_elements = starting_elements + codeswitch_elements + indexer_elements + online_elements + total_basefold_elements
total_field_elements = starting_elements + total_basefold_elements
field_kb = (total_field_elements * LOG_FIELD_SIZE) / 8 / 1000

# total_hashes = total_hashes_A + total_hashes_B + total_hashes_C
total_hashes = total_hashes_C
hash_kb = (total_hashes * LOG_HASH_SIZE) / 8 / 1000

grand_total_kb = field_kb + hash_kb
grand_total_mb = grand_total_kb / 1000

print("--- ORACLE PARAMETERS ---")
print(f"ell_m: {ell_m}, ell_b: {ell_b}, ell_g: {ell_g}, ell_era: {ell_era}")

print("\n--- FIELD ELEMENTS ---")
print(f"Starting IOR Elements: {starting_elements}")
print(f"Codeswitch Elements: {codeswitch_elements}")
print(f"Indexer Elements: {indexer_elements} ({indexer_oracles} oracles * {indices_bf} indices)")
print(f"Online Elements: {online_elements} ({online_oracles} oracles * {indices_bf} indices)")
print(f"Basefold Elements: {total_basefold_elements}")
print(f"Total Field Elements: {total_field_elements} ({field_kb:.3f} KB)")

print("\n--- HASH COMPONENTS (CEILED) ---")
print(f"Tree A Hashes: {total_hashes_A} (Starting IOR)")
print(f"Trees B Hashes: {total_hashes_B} (Codeswitch IOR)")
print(f"Trees C Hashes: {total_hashes_C} (Basefold IOPP)")
print(f"Total Hashes: {total_hashes} ({hash_kb:.3f} KB)")

print("\n--- GRAND TOTAL ---")
print(f"Total Proof Size: {grand_total_kb:.3f} KB")
print(f"Total Proof Size: {grand_total_mb:.3f} MB")