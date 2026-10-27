"""Dependency inventory validation and evidence-based risk checks."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DependencyFinding:
    finding_id: str
    package: str
    severity: str
    status: str
    description: str
    evidence: str
    remediation: str


class DependencyAuditor:
    """Review dependency records without assuming unverified vulnerabilities."""

    REQUIRED_FIELDS = {"name", "version", "direct"}

    def analyze(
        self, dependencies: list[dict[str, Any]]
    ) -> list[DependencyFinding]:
        if not isinstance(dependencies, list):
            raise ValueError("Dependencies must be supplied as a list")

        findings: list[DependencyFinding] = []
        seen: set[tuple[str, str]] = set()

        for index, dependency in enumerate(dependencies):
            if not isinstance(dependency, dict):
                raise ValueError(
                    f"Dependency at index {index} must be an object"
                )

            missing = self.REQUIRED_FIELDS - dependency.keys()
            if missing:
                raise ValueError(
                    f"Dependency at index {index} is missing fields: "
                    f"{sorted(missing)}"
                )

            name = dependency["name"]
            version = dependency["version"]
            direct = dependency["direct"]

            if not isinstance(name, str) or not name.strip():
                raise ValueError(
                    f"Dependency at index {index} has an invalid name"
                )

            if not isinstance(version, str):
                raise ValueError(
                    f"Dependency {name}: version must be a string"
                )

            if not isinstance(direct, bool):
                raise ValueError(
                    f"Dependency {name}: direct must be a boolean"
                )

            name = name.strip()
            version = version.strip()
            key = (name.lower(), version)

            if key in seen:
                findings.append(DependencyFinding(
                    finding_id=f"DEP-{index + 1:04d}",
                    package=name,
                    severity="LOW",
                    status="REVIEW",
                    description="Duplicate package/version entry in the supplied inventory.",
                    evidence=f"Repeated inventory entry: {name} {version or '(version missing)'}.",
                    remediation="Deduplicate the inventory or confirm why the entry appears more than once.",
                ))
                continue

            seen.add(key)

            if not version or version.lower() in {
                "latest", "*", "any", "unknown", "unspecified"
            }:
                findings.append(DependencyFinding(
                    finding_id=f"DEP-{index + 1:04d}",
                    package=name,
                    severity="MEDIUM",
                    status="REVIEW",
                    description="Dependency version is missing or not pinned.",
                    evidence=f"Supplied version value: {version or '(empty)'}.",
                    remediation="Resolve and pin an approved version; verify the lockfile and transitive dependency tree.",
                ))

            if dependency.get("known_vulnerable") is True:
                advisory = dependency.get("advisory_id")
                if not isinstance(advisory, str) or not advisory.strip():
                    findings.append(DependencyFinding(
                        finding_id=f"DEP-{index + 1:04d}-ADV",
                        package=name,
                        severity="MEDIUM",
                        status="REVIEW",
                        description="Vulnerability is asserted but no advisory identifier was supplied.",
                        evidence="known_vulnerable is true; supporting advisory is absent.",
                        remediation="Verify the assertion against a trusted advisory source and record the advisory ID and affected version range.",
                    ))
                else:
                    findings.append(DependencyFinding(
                        finding_id=f"DEP-{index + 1:04d}-ADV",
                        package=name,
                        severity="HIGH",
                        status="FAIL",
                        description="Dependency is marked vulnerable in the supplied evidence.",
                        evidence=f"Supplied advisory reference: {advisory.strip()}.",
                        remediation="Verify the advisory, affected version range, exploitability, and patched release; then update and retest.",
                    ))

        return findings
