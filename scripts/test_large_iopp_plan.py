"""Small exhaustive checks of the expected serialized multiproof model."""
import itertools
import unittest

from plan_large_iopp import authentication_hashes, distinct, power_ceiling


def actual_hash_count(n, queries):
    frontier = set(queries)
    result = 0
    for _ in range((power_ceiling(max(2, n))).bit_length()-1):
        result += sum((i ^ 1) not in frontier for i in frontier)
        frontier = {i//2 for i in frontier}
    return result


class MultiproofExpectation(unittest.TestCase):
    def test_uniform_queries_with_replacement_and_padded_tails(self):
        for n in range(1, 9):
            for q in range(1, 4):
                draws = list(itertools.product(range(n), repeat=q))
                self.assertAlmostEqual(distinct(n, q),
                                       sum(len(set(x)) for x in draws)/len(draws), places=10)
                self.assertAlmostEqual(authentication_hashes(n, q),
                                       sum(actual_hash_count(n, x) for x in draws)/len(draws), places=10)

    def test_opened_pairs_have_no_authentication_at_bottom_level(self):
        for n in [2, 4, 8]:
            for q in [1, 2, 3]:
                draws = list(itertools.product(range(n), repeat=q))
                mean = sum(actual_hash_count(2*n, [j for i in x for j in [2*i, 2*i+1]])
                           for x in draws)/len(draws)
                self.assertAlmostEqual(authentication_hashes(n, q), mean, places=10)


if __name__ == '__main__':
    unittest.main()
