import unittest

from benchmarks.rate_intervals import wilson_95


class WilsonIntervalTests(unittest.TestCase):
    def test_zero_and_full_observed_rates_have_nontrivial_bounds(self):
        self.assertEqual(wilson_95(0, 0), None)
        self.assertAlmostEqual(wilson_95(0, 25)[0], 0.0)
        self.assertGreater(wilson_95(0, 25)[1], 0.1)
        self.assertLess(wilson_95(25, 25)[0], 0.9)
        self.assertAlmostEqual(wilson_95(25, 25)[1], 1.0)

    def test_invalid_counts_fail(self):
        for counts in ((-1, 25), (26, 25), (0, -1)):
            with self.subTest(counts=counts), self.assertRaises(ValueError):
                wilson_95(*counts)


if __name__ == "__main__":
    unittest.main()
