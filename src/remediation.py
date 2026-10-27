"""Track security remediation and evidence-based closure."""

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class RemediationRecord:
    finding_id: str
    description: str
    status: str
    remediation_action: str
    verification_evidence: str = ""
    updated_at: str = ""


class RemediationTracker:
    VALID_STATUSES = {
        "OPEN",
        "IN_PROGRESS",
        "READY_FOR_VERIFICATION",
        "VERIFIED",
        "REOPENED",
    }

    def __init__(self) -> None:
        self.records: dict[str, RemediationRecord] = {}

    def create(
        self, finding_id: str, description: str, remediation_action: str
    ) -> RemediationRecord:
        if not finding_id.strip():
            raise ValueError("finding_id must not be empty")
        if finding_id in self.records:
            raise ValueError(f"Remediation record already exists: {finding_id}")
        if not description.strip() or not remediation_action.strip():
            raise ValueError("Description and remediation action are required")

        record = RemediationRecord(
            finding_id=finding_id,
            description=description,
            status="OPEN",
            remediation_action=remediation_action,
            updated_at=self._now(),
        )
        self.records[finding_id] = record
        return record

    def update_status(
        self,
        finding_id: str,
        status: str,
        verification_evidence: str = "",
    ) -> RemediationRecord:
        if finding_id not in self.records:
            raise KeyError(f"Unknown finding ID: {finding_id}")
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Unsupported remediation status: {status}")

        record = self.records[finding_id]

        if status == "VERIFIED" and not verification_evidence.strip():
            raise ValueError(
                "Verification evidence is required before closure"
            )

        if status == "VERIFIED":
            if record.status not in {"READY_FOR_VERIFICATION", "REOPENED"}:
                raise ValueError(
                    "Finding must be ready for verification before closure"
                )

        record.status = status
        if verification_evidence.strip():
            record.verification_evidence = verification_evidence.strip()
        record.updated_at = self._now()
        return record

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def summary(self) -> dict[str, int]:
        counts = {status: 0 for status in self.VALID_STATUSES}
        for record in self.records.values():
            counts[record.status] += 1
        counts["TOTAL"] = len(self.records)
        return counts
