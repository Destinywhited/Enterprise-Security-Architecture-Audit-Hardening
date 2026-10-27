import unittest

from src.api_security import APISecurityAuditor


class TestAPISecurityAdditional(unittest.TestCase):
    def test_expected_denial_observed_denial_passes(self):
        observation = {
            "endpoint": "/synthetic/private",
            "test_case": "invalid_credentials",
            "expected": "DENY",
            "observed": "DENY",
        }
        result = APISecurityAuditor().analyze([observation])
        self.assertEqual(result[0].status, "PASS")


if __name__ == "__main__":
    unittest.main()
