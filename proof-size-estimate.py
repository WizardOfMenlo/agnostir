import numpy as np

LOG_FIELD_SIZE = 256
LOG_HASH_SIZE = 256

def merkle_tree_size(queries, n, interleaving_factor):
    
    # for the first log queries levels of the Merkle tree, just return all the nodes 
    # (-2 because the root is already in the commitment)
    top_levels = np.log2(queries)
    proof_size_top_levels = LOG_HASH_SIZE * (queries - 2)

    # siblings for remaining levels of the Merkle tree
    proof_size_siblings = LOG_HASH_SIZE * (n - top_levels) * queries

    # leaves
    proof_size_leaves = LOG_FIELD_SIZE * (queries * interleaving_factor)

    return proof_size_top_levels + proof_size_siblings + proof_size_leaves

def num_queries(secparam, eps):

    denom = np.log2(1 - eps)
    return -secparam / denom

def total_proof_size(secparam, delta, n, interleaving_factor, ud=False):

    if ud:
        eps = delta / 3
    else:
        eps = 1 - (1 - delta) ** (1/3)

    q = num_queries(secparam, eps)
    return merkle_tree_size(q, n, interleaving_factor)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Estimate proof size for Merkle-based commitment")
    parser.add_argument("-n", type=int, required=True, help="log2 of the codeword length")
    parser.add_argument("-eta", "--interleaving-factor", type=int, required=True, help="Interleaving factor (number of rows)")
    parser.add_argument("-delta", type=float, required=True, help="Distance of the code")
    parser.add_argument("--secparam", type=int, default=100, help="Security parameter (default: 100)")
    parser.add_argument("--ud", action="store_true", help="Use UD distance instead of standard distance")
    args = parser.parse_args()

    bits = total_proof_size(args.secparam, args.delta, args.n, args.interleaving_factor, ud=args.ud)
    print(f"proof size = {bits / 8 / 1024:.2f} KiB")