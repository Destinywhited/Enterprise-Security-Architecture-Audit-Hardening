"""Evidence-based API authentication and authorization assessment."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class APIFinding:
    finding_id: str
    endpoint: str
    test_case: str
    severity: str
    status: str
    description: str
    evidence: str
    remediation: str


class APISecurityAuditor:
    """Evaluate recorded API test observations, not live endpoints."""

    REQUIRED_FIELDS = {
        "endpoint",
        "test_case",
        "expected",
        "observed",
    }

    VALID_CASES = {
        "missing_credentials",
        "invalid_credentials",
        "expired_credentials",
        "insufficient_privileges",
        "valid_credentials",
    }

    def analyze(
        self, observations: list[dict[str, Any]]
    ) -> list[APIFinding]:
        if not isinstance(observations, list):
            raise ValueError("Observations must be supplied as a list")

        findings: list[APIFinding] = []
        seen: set[tuple[str, str]] = set()

        for index, item in enumerate(observations):
            if not isinstance(item, dict):
                raise ValueError(
                    f"Observation at index {index} must be an object"
                )

            missing = self.REQUIRED_FIELDS - item.keys()
            if missing:
                raise ValueError(
                    f"Observation at index {index} is missing fields: "
                    f"{sorted(missing)}"
                )

            endpoint = item["endpoint"]
            test_case = item["test_case"]
            expected = item["expected"]
            observed = item["observed"]

            if not isinstance(endpoint, str) or not endpoint.strip():
                raise ValueError(
                    f"Observation at index {index} has an invalid endpoint"
                )

            if test_case not in self.VALID_CASES:
                raise ValueError(
                    f"Observation at index {index} has an unsupported test case"
                )

            if expected not in {"ALLOW", "DENY"}:
                raise ValueError(
                    f"Observation at index {index}: expected must be ALLOW or DENY"
                )

            if observed not in {"ALLOW", "DENY", "ERROR", "NOT_TESTED"}:
                raise ValueError(
                    f"Observation at index {index}: invalid observed outcome"
                )

            endpoint = endpoint.strip()
            key = (endpoint, test_case)

            if key in seen:
                raise ValueError(
                    f"Duplicate API test observation: {endpoint}, {test_case}"
                )
            seen.add(key)

            if observed in {"ERROR", "NOT_TESTED"}:
                findings.append(APIFinding(
                    finding_id=f"API-{index + 1:04d}",
                    endpoint=endpoint,
                    test_case=test_case,
                    severity="MEDIUM",
                    status="REVIEW",
                    description="API security behavior could not be verified.",
                    evidence=f"Observed outcome: {observed}.",
                    remediation="Investigate the test error or execute the missing test and record the actual response.",
                ))
                continue

            if observed != expected:
                security_impact = (
                    test_case in {
                        "missing_credentials",
                        "invalid_credentials",
                        "expired_credentials",
                        "insufficient_privileges",
                    }
                    and expected == "DENY"
                    and observed == "ALLOW"
                )

                findings.append(APIFinding(
                    finding_id=f"API-{index + 1:04d}",
                    endpoint=endpoint,
                    test_case=test_case,
                    severity="HIGH" if security_impact else "MEDIUM",
                    status="FAIL",
                    description="Observed API access behavior differs from the expected policy.",
                    evidence=f"Test case={test_case}; expected={expected}; observed={observed}.",
                    remediation="Verify the endpoint's authentication and authorization policy, correct enforcement, and add a regression test.",
                ))
            else:
                findings.append(APIFinding(
                    finding_id=f"API-{index + 1:04d}",
                    endpoint=endpoint,
                    test_case=test_case,
                    severity="INFO",
                    status="PASS",
                    description="Recorded API outcome matches the declared expectation.",
                    evidence=f"Test case={test_case}; expected={expected}; observed={observed}.",
                    remediation="Retain the test as a regression check and validate coverage across protected endpoints.",
                ))

        return findings
