from __future__ import annotations

import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from backend.config import settings
from backend.database import transaction, utcnow
from backend.repository import identifier, json_value


class ThreatIntelError(RuntimeError):
    """A bounded, analyst-safe external-enrichment error."""


class VirusTotalClient:
    """Explicit hash-only lookup client.

    This adapter never uploads an APK and never bulk-submits extracted indicators.
    The caller must deliberately invoke the investigation endpoint for one sample
    hash, keeping the external boundary visible in the UI and audit trail.
    """

    def lookup_file(self, sha256: str) -> dict[str, Any]:
        if not settings.virustotal_api_key:
            raise ThreatIntelError("VirusTotal is not configured")
        request = Request(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": settings.virustotal_api_key, "Accept": "application/json"},
            method="GET",
        )
        try:
            with urlopen(request, timeout=settings.virustotal_timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if error.code == 404:
                return {"status": "not_found", "summary": {"provider_message": "No file record was returned for this hash."}}
            raise ThreatIntelError(f"VirusTotal lookup returned HTTP {error.code}") from error
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            raise ThreatIntelError("VirusTotal lookup could not be completed") from error

        attributes = payload.get("data", {}).get("attributes", {}) if isinstance(payload, dict) else {}
        statistics = attributes.get("last_analysis_stats", {}) if isinstance(attributes, dict) else {}
        normalized_statistics = {
            key: int(value)
            for key, value in statistics.items()
            if key in {"harmless", "malicious", "suspicious", "undetected", "timeout", "failure", "type-unsupported"}
            and isinstance(value, int)
            and value >= 0
        }
        summary: dict[str, Any] = {"last_analysis_stats": normalized_statistics}
        for key in ("reputation", "meaningful_name", "last_analysis_date", "times_submitted"):
            value = attributes.get(key) if isinstance(attributes, dict) else None
            if isinstance(value, (str, int)):
                summary[key] = value if not isinstance(value, str) else value[:240]
        return {"status": "found", "summary": summary}


def record_observation(
    case_id: str,
    provider: str,
    subject_type: str,
    subject_value: str,
    status: str,
    summary: dict[str, Any],
) -> dict[str, Any]:
    observed_at = utcnow()
    record_id = identifier("intel")
    with transaction() as connection:
        connection.execute(
            """INSERT INTO threat_intel_observations
               (id, case_id, provider, subject_type, subject_value, status, summary_json, observed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (record_id, case_id, provider, subject_type, subject_value, status, json.dumps(summary, ensure_ascii=False, sort_keys=True), observed_at),
        )
    return {
        "id": record_id,
        "provider": provider,
        "subject_type": subject_type,
        "subject_value": subject_value,
        "status": status,
        "summary": summary,
        "observed_at": observed_at,
    }


def _hydrate_observations(rows: list[Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["summary"] = json_value(item.pop("summary_json", None), {})
        observations.append(item)
    return observations


def observations_for_case(case_id: str) -> list[dict[str, Any]]:
    with transaction() as connection:
        rows = connection.execute(
            """SELECT id, provider, subject_type, subject_value, status, summary_json, observed_at
               FROM threat_intel_observations WHERE case_id = ? ORDER BY observed_at DESC, id DESC LIMIT 30""",
            (case_id,),
        ).fetchall()
    return _hydrate_observations(rows)


def all_observations(limit: int = 100) -> list[dict[str, Any]]:
    with transaction() as connection:
        rows = connection.execute(
            """SELECT threat_intel_observations.id, threat_intel_observations.case_id,
                      cases.title AS case_title, threat_intel_observations.provider,
                      threat_intel_observations.subject_type, threat_intel_observations.subject_value,
                      threat_intel_observations.status, threat_intel_observations.summary_json,
                      threat_intel_observations.observed_at
               FROM threat_intel_observations JOIN cases ON cases.id = threat_intel_observations.case_id
               ORDER BY threat_intel_observations.observed_at DESC, threat_intel_observations.id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return _hydrate_observations(rows)
