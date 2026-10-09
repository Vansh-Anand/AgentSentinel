import unittest

from benchmarks.gateway_eval import evaluate


class EvaluationTests(unittest.TestCase):
    def test_fixture_policy_cases(self):
        result = evaluate()
        self.assertTrue(result["all_expectations_met"])
        self.assertEqual(result["attack_cases_denied"], result["attack_cases_total"])
        self.assertEqual(result["benign_cases_executed"], result["benign_cases_total"])


if __name__ == "__main__":
    unittest.main()
