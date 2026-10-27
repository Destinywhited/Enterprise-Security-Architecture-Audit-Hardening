import unittest

from src.audit_engine import AuditEngine, Finding, Severity, Status
from src.threat_model import ThreatModeler
from src.dependency_audit import DependencyAuditor
from src.api_security import APISecurityAuditor
from src.remediation import RemediationTracker


class TestAuditEngine(unittest.TestCase):
    def test_add_and_summarize_finding(self):
        engine = AuditEngine()
        engine.add_finding(Finding(
            "F-001", "Example finding", "Architecture",
            Severity.MEDIUM, Status.REVIEW,
            "Needs review", "Synthetic test evidence", "Review configuration"
        ))
        summary = engine.summary()
        self.assertEqual(summary["total_findings"], 1)
        self.assertEqual(summary["status_counts"]["REVIEW"], 1)

    def test_duplicate_finding_rejected(self):
        engine = AuditEngine()
        finding = Finding(
            "F-001", "Example", "Architecture", Severity.LOW, Status.PASS,
            "Test", "Synthetic evidence", "No action"
        )
        engine.add_finding(finding)
        with self.assertRaises(ValueError):
            engine.add_finding(finding)


class TestThreatModel(unittest.TestCase):
    def test_public_asset_without_authentication(self):
        asset = {
            "asset_id": "A1", "name": "Synthetic API", "type": "api",
            "exposure": "public", "authentication": "none",
            "authorization": "enabled", "sensitive_data": False,
        }
        results = ThreatModeler().analyze([asset])
        self.assertTrue(any(
            result.category == "Authentication"
            and result.status == "FAIL"
            for result in results
        ))

    def test_missing_required_field_rejected(self):
        with self.assertRaises(ValueError):
            ThreatModeler().analyze([{"asset_id": "A1"}])


class TestDependencyAudit(unittest.TestCase):
    def test_unpinned_dependency_flagged(self):
        dependency = {
            "name": "example-package", "version": "latest", "direct": True,
        }
        results = DependencyAuditor().analyze([dependency])
        self.assertTrue(any(result.status == "REVIEW" for result in results))

    def test_malformed_dependency_rejected(self):
        with self.assertRaises(ValueError):
            DependencyAuditor().analyze([{"name": "example-package"}])


class TestAPISecurity(unittest.TestCase):
    def test_missing_credentials_accepted_by_server_is_failure(self):
        observation = {
            "endpoint": "/synthetic/resource",
            "test_case": "missing_credentials",
            "expected": "DENY",
            "observed": "ALLOW",
        }
        results = APISecurityAuditor().analyze([observation])
        self.assertEqual(results[0].status, "FAIL")
        self.assertEqual(results[0].severity, "HIGH")

    def test_untested_endpoint_requires_review(self):
        observation = {
            "endpoint": "/synthetic/resource",
            "test_case": "expired_credentials",
            "expected": "DENY",
            "observed": "NOT_TESTED",
        }
        results = APISecurityAuditor().analyze([observation])
        self.assertEqual(results[0].status, "REVIEW")


class TestRemediation(unittest.TestCase):
    def test_closure_requires_verification_evidence(self):
        tracker = RemediationTracker()
        tracker.create("F-001", "Synthetic issue", "Apply a fix")
        tracker.update_status("F-001", "READY_FOR_VERIFICATION")

        with self.assertRaises(ValueError):
            tracker.update_status("F-001", "VERIFIED")

        record = tracker.update_status(
            "F-001", "VERIFIED", "Synthetic regression test passed"
        )
        self.assertEqual(record.status, "VERIFIED")

    def test_unknown_finding_rejected(self):
        tracker = RemediationTracker()
        with self.assertRaises(KeyError):
            tracker.update_status("UNKNOWN", "IN_PROGRESS")


if __name__ == "__main__":
    unittest.main()
