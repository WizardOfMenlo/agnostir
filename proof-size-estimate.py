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


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Estimate proof size for Merkle-based commitment")
    parser.add_argument("-q", "--queries", type=int, required=True, help="Number of queries")
    parser.add_argument("-n", type=int, required=True, help="log2 of the codeword length")
    parser.add_argument("-eta", "--interleaving-factor", type=int, required=True, help="Interleaving factor (number of rows)")
    args = parser.parse_args()

    bits = merkle_tree_size(args.queries, args.n, args.interleaving_factor)
    print(f"queries = {args.queries}, n = {args.n}, interleaving_factor = {args.interleaving_factor}")
    print(f"proof size = {bits / 8 / 1024:.2f} KiB")