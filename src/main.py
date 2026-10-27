"""Run the security audit framework on synthetic demonstration inputs."""

import csv
import json
from pathlib import Path
from dataclasses import asdict

from src.audit_engine import AuditEngine, Finding, Severity, Status
from src.threat_model import ThreatModeler
from src.dependency_audit import DependencyAuditor
from src.api_security import APISecurityAuditor


ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUTPUT = ROOT / "output"


def load_json(filename):
    path = DATA / filename
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)
    engine = AuditEngine()

    assets = load_json("assets.json")
    dependencies = load_json("dependencies.json")
    api_cases = load_json("api_test_cases.json")

    threat_results = ThreatModeler().analyze(assets)
    dependency_results = DependencyAuditor().analyze(dependencies)
    api_results = APISecurityAuditor().analyze(api_cases)

    for result in threat_results:
        engine.add_finding(Finding(
            result.threat_id, result.description, result.category,
            Severity(result.severity), Status(result.status),
            result.description, result.evidence, result.remediation
        ))

    for result in dependency_results:
        engine.add_finding(Finding(
            result.finding_id, result.description, "Dependency",
            Severity(result.severity), Status(result.status),
            result.description, result.evidence, result.remediation
        ))

    for result in api_results:
        engine.add_finding(Finding(
            result.finding_id, result.description, "API Security",
            Severity(result.severity), Status(result.status),
            result.description, result.evidence, result.remediation
        ))

    engine.export_json(OUTPUT / "audit_results.json")

    summary = engine.summary()
    with (OUTPUT / "audit_summary.json").open("w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2)

    with (OUTPUT / "audit_findings.csv").open(
        "w", newline="", encoding="utf-8"
    ) as file:
        fields = [
            "finding_id", "title", "category", "severity", "status",
            "description", "evidence", "remediation"
        ]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for finding in engine.findings:
            writer.writerow(engine._serialize(finding))

    print("Audit run completed.")
    print("Input type: SYNTHETIC DEMONSTRATION DATA")
    print(f"Total findings: {summary['total_findings']}")
    print(f"Status counts: {summary['status_counts']}")
    print(f"Severity counts: {summary['severity_counts']}")
    print(f"JSON: {OUTPUT / 'audit_results.json'}")
    print(f"CSV:  {OUTPUT / 'audit_findings.csv'}")


if __name__ == "__main__":
    main()
