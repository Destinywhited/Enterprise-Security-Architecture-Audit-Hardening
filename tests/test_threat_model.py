import unittest

from src.threat_model import ThreatModeler


class TestThreatModelAdditional(unittest.TestCase):
    def test_unknown_exposure_requires_review(self):
        asset = {
            "asset_id": "A2", "name": "Unknown Service", "type": "service",
            "exposure": "unknown", "authentication": "enabled",
            "authorization": "enabled", "sensitive_data": False,
        }
        results = ThreatModeler().analyze([asset])
        self.assertTrue(any(
            result.category == "Architecture visibility"
            and result.status == "REVIEW"
            for result in results
        ))


if __name__ == "__main__":
    unittest.main()
