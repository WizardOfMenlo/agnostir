"""Paper-based regression tests: python3 -m unittest discover -s distance-analysis -v."""

import contextlib
from decimal import Decimal, localcontext
from fractions import Fraction
import io
import itertools
import math
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import numpy as np
from scipy.optimize import differential_evolution

import basefold
import brakedown
import era


class ZeroPaddingBaseTests(unittest.TestCase):
    def test_recursive_bound_uses_distance_one_at_terminal_code(self):
        report = brakedown.check_recursive(512, .026, 1.075, .01477, 9, 16,
                                          security=102, base_case='zero-pad')
        self.assertTrue(report['bound_passes'])
        self.assertEqual(report['events'], 4)
        self.assertEqual(report['base_dimensions'], [14, 15])
        self.assertEqual(report['base_absolute_distance'], 1)
        self.assertIsNone(report['base_rs_passes'])

    def test_padding_cannot_inherit_rs_distance(self):
        args = (16, .05, 1.5, .045, 6, 40)
        self.assertTrue(brakedown.check_recursive(*args)['bound_passes'])
        self.assertFalse(brakedown.check_recursive(*args, base_case='zero-pad')['bound_passes'])


class BasefoldTests(unittest.TestCase):
    def test_published_closed_form_independent_high_precision(self):
        # §1.3 closed form evaluated at 70 digits, independent of the iterative
        # floating-point implementation. k0=1, inverse rate 8, 15 doublings.
        with localcontext() as ctx:
            ctx.prec = 70
            q, c, lam, d = Decimal(256), Decimal(8), Decimal(100), 15
            ratio = q/(q-Decimal('1.001'))
            bound = 1-ratio**d/c
            for i in range(1, d+1):
                ni = c*2**i
                bound -= ratio**(d-i)/(q-Decimal('1.001'))*(Decimal('.6')+(2*Decimal(i+2)+lam)/ni)
            self.assertAlmostEqual(basefold.compute_formula(256, 8, d, 100), float(bound), places=14)

    def test_setup_union_bound(self):
        expected = basefold.compute_formula(255.999, 2, 16, 104)
        self.assertEqual(basefold.distance_for_setup_bits(255.999, 2, 16, 100), expected)
        self.assertLess(expected, basefold.compute_formula(255.999, 2, 16, 100))
        self.assertAlmostEqual(expected, .20520464567045915)

    def test_domain_and_vacuous_bound(self):
        for args in [(9, 2, 16, 100), (256, .5, 16, 100), (256, 2, -1, 100), (math.nan, 2, 16, 100)]:
            with self.assertRaises(ValueError):
                basefold.compute_formula(*args)
        self.assertEqual(basefold.compute_formula(10, 2, 16, 100), 0)
        self.assertEqual(basefold.compute_formula(256, 2, 0, 100), .5)


class BrakedownTests(unittest.TestCase):
    def test_union_bound_against_enumerated_graphs(self):
        # Two input vertices, each choosing a distinct uniform 2-subset of 4
        # outputs. Failure to expand their union beyond 2 iff subsets match.
        choices = list(itertools.combinations(range(4), 2))
        bad = sum(len(set(a)|set(b)) <= 2 for a, b in itertools.product(choices, repeat=2))
        exact = Fraction(bad, len(choices)**2)
        formula = Fraction(math.comb(4, 2)*math.comb(2, 2)**2, math.comb(4, 2)**2)
        self.assertEqual(exact, formula)
        self.assertAlmostEqual(2**brakedown.union_bound(2, 4, 2, 2, 2), float(exact), places=14)

    def test_singleton_is_not_skipped(self):
        self.assertEqual(brakedown.small_cases([10, 10], [1], 1, 100, 10), 2)

    def test_impossible_graph_and_failed_search_raise(self):
        with self.assertRaises(ValueError):
            brakedown.union_bound(10, 2, 3, 1, 1)
        with contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError):
                brakedown.small_cases([10, 10], [9], 1, 100, 2)
            # Previously returned degree 1 after the large-k branch failed.
            with self.assertRaises(ValueError):
                brakedown.row_weight_b(65536, [.04, 1/1.05, .03])

    def test_convexity_bound_dominates_entire_interval(self):
        degree, endpoint_bound = brakedown.large_cases([1000, 600], [20, 100], [2, 1.2], 100)
        for k in range(20, 101):
            self.assertLessEqual(brakedown.union_bound(1000, 600, degree, 2+1.2*k, k), endpoint_bound+1e-9)
        self.assertLessEqual(endpoint_bound, -100)

    def test_recursive_budget_and_small_levels(self):
        result = brakedown.check_recursive(65536, .3, 2, .1, 10, 20)
        self.assertEqual(result['events'], 24)
        self.assertEqual(result['per_event_bits'], 105)
        self.assertEqual(result['base_rs_dimensions'], [48, 96])
        self.assertTrue(result['levels'][0]['A']['passes'])
        self.assertTrue(result['levels'][0]['B']['passes'])
        self.assertFalse(result['bound_passes'])
        self.assertFalse(result['levels'][-1]['B']['passes'])
        self.assertTrue(brakedown.check_recursive(65536, .3, 2, .1, 14, 28)['bound_passes'])

    def test_era_base_preset_at_explicit_distance(self):
        result = brakedown.check_recursive(65536, .04, 1.05, .0009, 5, 42, security=102)
        self.assertTrue(result['bound_passes'])
        self.assertEqual(result['base_rs_dimensions'], [2622, 2753])


class EraTests(unittest.TestCase):
    def test_gradient_and_hessian_against_finite_differences(self):
        model = era.Exponent(1.08, 4)
        for point in [(0.01, .05, .2), (.08, .15, .25), (.2, .3, .35)]:
            d0, d1, delta = point
            grad, hess = model.derivatives(*point)
            h = 1e-6
            def fun(z): return model.value(z[0], z[1], delta)
            p = np.array([d0, d1])
            for i in range(2):
                v = np.eye(2)[i]*h
                numeric = (fun(p-2*v)-8*fun(p-v)+8*fun(p+v)-fun(p+2*v))/(12*h)
                self.assertAlmostEqual(grad[i], numeric, delta=2e-8)
                hp = model.derivatives(*(p+v), delta)[0]
                hm = model.derivatives(*(p-v), delta)[0]
                np.testing.assert_allclose(hess[:, i], (hp-hm)/(2*h), rtol=2e-7, atol=1e-7)

    def test_no_clipping_invalid_weights(self):
        with self.assertRaises(ValueError): era.entropy(1.01)
        with self.assertRaises(ValueError): era.Exponent(1.08, 4).value(.2, .01, .3)
        with self.assertRaises(ValueError): era.solve_system(1.08, 4, .002, .001)

    def test_field_equation_and_infeasible_inputs(self):
        c = era.compute_c_from_q_bound(4, 100, .001, 20, 255.999)
        target = 255.999 + math.log1p(-2**-255.999)/math.log(2)
        value = era.field_bound_log2(c, 4, 100, .001, 20)
        self.assertLessEqual(value, target)
        self.assertAlmostEqual(value, target, places=8)
        self.assertIsNone(era.compute_c_from_q_bound(4, 100, .0001, 16, 192))

    def test_known_valid_roots_agree_with_original_script(self):
        c = era.compute_c_from_q_bound(4, 100, .001, 20, 255.999)
        gamma = era.compute_gamma_from_n_bound(4, c, 100, 20)
        result = era.solve_details(c, 4, gamma, .001)
        self.assertAlmostEqual(result['delta1'], .2594459524362902, places=10)
        self.assertAlmostEqual(result['delta2'], .22434671959587246, places=10)
        model = era.Exponent(c, 4)
        grad, hessian = model.derivatives(*result['critical_point'])
        self.assertLess(np.max(np.abs(grad)), 1e-8)
        self.assertLess(abs(np.linalg.det(hessian)), 1e-6)

    def test_missing_second_root_fails_closed(self):
        with patch.object(era, 'critical_delta', return_value=None):
            self.assertIsNone(era.solve_system(1.08, 4, .0002, .001))

    def test_numerical_independent_domain_search(self):
        # Additional falsification check, NOT a global or interval certificate.
        c = era.compute_c_from_q_bound(4, 102, .0009, math.log2(275248), 255.999)
        gamma = era.compute_gamma_from_n_bound(4, c, 102, math.log2(275248))
        delta = era.solve_system(c, 4, gamma, .0009)
        model = era.Exponent(c, 4)
        def value(z):
            d0 = .0009+(delta/model.A**2-.0009)*z[0]
            d1 = d0*model.A+(delta/model.A-d0*model.A)*z[1]
            return model.value(d0, d1, delta)
        result = differential_evolution(lambda z: -value(z), [(1e-9, 1-1e-9)]*2,
                                        seed=2025, tol=1e-8, popsize=15)
        self.assertLess(-result.fun, -gamma)


class CliTests(unittest.TestCase):
    def test_invalid_input_exits_nonzero(self):
        directory = Path(__file__).parent
        commands = [('basefold.py', '1', '2', '16'), ('era.py', '-r', '3', '-db', '.01'),
                    ('brakedown.py', '.9', '.2', '2')]
        for command in commands:
            result = subprocess.run([sys.executable, str(directory/command[0]), *command[1:]],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
