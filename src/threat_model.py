"""Rule-based threat-model review for enterprise microservices."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Threat:
    threat_id: str
    asset: str
    category: str
    severity: str
    status: str
    description: str
    evidence: str
    remediation: str


class ThreatModeler:
    """Identify reviewable architectural risks from supplied configuration."""

    REQUIRED_ASSET_FIELDS = {
        "asset_id",
        "name",
        "type",
        "exposure",
        "authentication",
        "authorization",
        "sensitive_data",
    }

    def analyze(self, assets: list[dict[str, Any]]) -> list[Threat]:
        if not isinstance(assets, list):
            raise ValueError("Assets must be supplied as a list")

        threats: list[Threat] = []
        seen_ids: set[str] = set()

        for index, asset in enumerate(assets):
            if not isinstance(asset, dict):
                raise ValueError(f"Asset at index {index} must be an object")

            missing = self.REQUIRED_ASSET_FIELDS - asset.keys()
            if missing:
                raise ValueError(
                    f"Asset at index {index} is missing fields: "
                    f"{sorted(missing)}"
                )

            asset_id = str(asset["asset_id"]).strip()
            if not asset_id:
                raise ValueError(f"Asset at index {index} has an empty asset_id")
            if asset_id in seen_ids:
                raise ValueError(f"Duplicate asset_id: {asset_id}")
            seen_ids.add(asset_id)

            name = str(asset["name"])
            exposure = str(asset["exposure"]).lower()
            authentication = str(asset["authentication"]).lower()
            authorization = str(asset["authorization"]).lower()
            sensitive = asset["sensitive_data"]

            if not isinstance(sensitive, bool):
                raise ValueError(
                    f"Asset {asset_id}: sensitive_data must be true or false"
                )

            if exposure not in {"public", "internal", "restricted", "unknown"}:
                raise ValueError(
                    f"Asset {asset_id}: unsupported exposure value"
                )

            if exposure == "unknown":
                threats.append(Threat(
                    threat_id=f"TM-{asset_id}-01",
                    asset=name,
                    category="Architecture visibility",
                    severity="MEDIUM",
                    status="REVIEW",
                    description="Asset exposure is not established.",
                    evidence="Input configuration sets exposure to unknown.",
                    remediation="Confirm network reachability and document trust boundaries.",
                ))

            if exposure == "public" and authentication in {"none", "disabled"}:
                threats.append(Threat(
                    threat_id=f"TM-{asset_id}-02",
                    asset=name,
                    category="Authentication",
                    severity="HIGH",
                    status="FAIL",
                    description="Publicly exposed asset is configured without authentication.",
                    evidence="Supplied configuration identifies public exposure and no authentication.",
                    remediation="Require appropriate authentication or document an approved, constrained public-access design.",
                ))

            if authorization in {"none", "disabled"} and (
                exposure == "public" or sensitive
            ):
                threats.append(Threat(
                    threat_id=f"TM-{asset_id}-03",
                    asset=name,
                    category="Authorization",
                    severity="HIGH",
                    status="FAIL",
                    description="Authorization is configured as absent for an exposed or sensitive asset.",
                    evidence="Supplied configuration indicates no authorization.",
                    remediation="Enforce least-privilege authorization and test access to protected operations.",
                ))

            if sensitive and authentication in {"unknown", "unspecified"}:
                threats.append(Threat(
                    threat_id=f"TM-{asset_id}-04",
                    asset=name,
                    category="Authentication",
                    severity="HIGH",
                    status="REVIEW",
                    description="Authentication for a sensitive-data asset is unverified.",
                    evidence="Input configuration does not establish the authentication mechanism.",
                    remediation="Verify identity enforcement, credential validation, and service-to-service authentication.",
                ))

        return threats
