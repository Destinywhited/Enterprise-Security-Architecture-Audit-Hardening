import unittest

from src.dependency_audit import DependencyAuditor


class TestDependencyAuditAdditional(unittest.TestCase):
    def test_duplicate_dependency_is_flagged(self):
        dependency = {
            "name": "example-package", "version": "1.2.3", "direct": True,
        }
        results = DependencyAuditor().analyze([dependency, dependency])
        self.assertTrue(any("Duplicate" in item.description for item in results))


if __name__ == "__main__":
    unittest.main()
