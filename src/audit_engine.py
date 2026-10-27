"""Core security audit engine with structured findings and safe error handling."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable
import json
from pathlib import Path


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"


@dataclass
class Finding:
    finding_id: str
    title: str
    category: str
    severity: Severity
    status: Status
    description: str
    evidence: str
    remediation: str


class AuditEngine:
    """Collect, validate, summarize, and export security assessment results."""

    REQUIRED_FIELDS = (
        "finding_id",
        "title",
        "category",
        "severity",
        "status",
        "description",
        "evidence",
        "remediation",
    )

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add_finding(self, finding: Finding) -> None:
        if not finding.finding_id.strip():
            raise ValueError("finding_id must not be empty")
        if any(
            existing.finding_id == finding.finding_id
            for existing in self.findings
        ):
            raise ValueError(f"Duplicate finding ID: {finding.finding_id}")
        self.findings.append(finding)

    def load_records(self, records: Iterable[dict[str, Any]]) -> int:
        """Load records, rejecting malformed entries instead of guessing."""
        added = 0
        for index, record in enumerate(records):
            if not isinstance(record, dict):
                raise ValueError(f"Record {index} must be an object")

            missing = set(self.REQUIRED_FIELDS) - set(record)
            if missing:
                raise ValueError(
                    f"Record {index} is missing fields: {sorted(missing)}"
                )

            try:
                finding = Finding(
                    finding_id=str(record["finding_id"]),
                    title=str(record["title"]),
                    category=str(record["category"]),
                    severity=Severity(record["severity"]),
                    status=Status(record["status"]),
                    description=str(record["description"]),
                    evidence=str(record["evidence"]),
                    remediation=str(record["remediation"]),
                )
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid record {index}: {exc}") from exc

            self.add_finding(finding)
            added += 1

        return added

    def summary(self) -> dict[str, Any]:
        severity_counts = {severity.value: 0 for severity in Severity}
        status_counts = {status.value: 0 for status in Status}

        for finding in self.findings:
            severity_counts[finding.severity.value] += 1
            status_counts[finding.status.value] += 1

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(self.findings),
            "severity_counts": severity_counts,
            "status_counts": status_counts,
            "results": [self._serialize(f) for f in self.findings],
        }

    @staticmethod
    def _serialize(finding: Finding) -> dict[str, str]:
        record = asdict(finding)
        record["severity"] = finding.severity.value
        record["status"] = finding.status.value
        return record

    def export_json(self, destination: str | Path) -> Path:
        path = Path(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(self.summary(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return path
