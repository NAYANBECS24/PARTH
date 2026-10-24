from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from typing import Any

from backend.database import transaction, utcnow
from backend.intake import StoredUpload


STAGES = (
    "intake",
    "inventory",
    "manifest",
    "dex_api",
    "indicators",
    "blindspot_ledger",
    "guarded_path_evaluation",
    "findings",
    "capsule_report",
)


def identifier(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def json_value(value: str | None, default: Any) -> Any:
    return json.loads(value) if value else default


def create_case_and_job(
    upload: StoredUpload,
    title: str,
    analyst_note: str,
    profile: str,
    nvidia_requested: bool,
    dynamic_lab_requested: bool,
) -> tuple[str, str, bool]:
    case_id = identifier("case")
    job_id = identifier("job")
    created_at = utcnow()
    with transaction() as connection:
        sample_exists = connection.execute("SELECT 1 FROM samples WHERE sha256 = ?", (upload.sha256,)).fetchone()
        if not sample_exists:
            connection.execute(
                """INSERT INTO samples (sha256, original_filename, byte_size, storage_path, archive_entry_count, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (upload.sha256, upload.original_filename, upload.byte_size, str(upload.storage_path), upload.archive_entry_count, created_at),
            )
        connection.execute(
            """INSERT INTO cases (id, title, analyst_note, profile, nvidia_requested, dynamic_lab_requested, sample_sha256, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (case_id, title.strip(), analyst_note.strip(), profile, int(nvidia_requested), int(dynamic_lab_requested), upload.sha256, created_at, created_at),
        )
        connection.execute(
            """INSERT INTO jobs (id, case_id, sample_sha256, status, created_at, updated_at)
               VALUES (?, ?, ?, 'queued', ?, ?)""",
            (job_id, case_id, upload.sha256, created_at, created_at),
        )
        connection.executemany(
            "INSERT INTO job_stages (job_id, stage_key, position, status) VALUES (?, ?, ?, 'pending')",
            ((job_id, stage, position) for position, stage in enumerate(STAGES, 1)),
        )
    return case_id, job_id, bool(sample_exists)


def create_retry_job(case_id: str) -> str:
    job_id = identifier("job")
    created_at = utcnow()
    with transaction() as connection:
        case = connection.execute("SELECT sample_sha256 FROM cases WHERE id = ?", (case_id,)).fetchone()
        if not case:
            raise ValueError("Case not found")
        connection.execute(
            "INSERT INTO jobs (id, case_id, sample_sha256, status, created_at, updated_at) VALUES (?, ?, ?, 'queued', ?, ?)",
            (job_id, case_id, case["sample_sha256"], created_at, created_at),
        )
        connection.executemany(
            "INSERT INTO job_stages (job_id, stage_key, position, status) VALUES (?, ?, ?, 'pending')",
            ((job_id, stage, position) for position, stage in enumerate(STAGES, 1)),
        )
        connection.execute("UPDATE cases SET status = 'queued', updated_at = ? WHERE id = ?", (created_at, case_id))
    return job_id


def log_event(job_id: str, level: str, message: str, payload: dict[str, Any] | None = None) -> None:
    with transaction() as connection:
        connection.execute(
            "INSERT INTO job_events (job_id, level, message, payload_json, created_at) VALUES (?, ?, ?, ?, ?)",
            (job_id, level, message, _json(payload or {}), utcnow()),
        )


def set_stage(job_id: str, stage_key: str, status: str, detail: dict[str, Any] | None = None) -> None:
    now = utcnow()
    with transaction() as connection:
        if status == "running":
            connection.execute(
                """UPDATE job_stages SET status = ?, started_at = COALESCE(started_at, ?), detail_json = ?
                   WHERE job_id = ? AND stage_key = ?""",
                (status, now, _json(detail or {}), job_id, stage_key),
            )
            connection.execute("UPDATE jobs SET status = 'running', current_stage = ?, started_at = COALESCE(started_at, ?), updated_at = ? WHERE id = ?", (stage_key, now, now, job_id))
            connection.execute("UPDATE cases SET status = 'running', updated_at = ? WHERE id = (SELECT case_id FROM jobs WHERE id = ?)", (now, job_id))
        else:
            connection.execute(
                """UPDATE job_stages SET status = ?, finished_at = ?, detail_json = ?
                   WHERE job_id = ? AND stage_key = ?""",
                (status, now, _json(detail or {}), job_id, stage_key),
            )


def request_cancel(job_id: str) -> bool:
    with transaction() as connection:
        result = connection.execute("UPDATE jobs SET cancellation_requested = 1, updated_at = ? WHERE id = ? AND status IN ('queued', 'running')", (utcnow(), job_id))
        return result.rowcount == 1


def cancellation_requested(job_id: str) -> bool:
    with transaction() as connection:
        row = connection.execute("SELECT cancellation_requested FROM jobs WHERE id = ?", (job_id,)).fetchone()
        return bool(row and row[0])


def finish_job(job_id: str, status: str, error_code: str | None = None, error_detail: str | None = None) -> None:
    if status not in {"completed", "partial", "failed", "cancelled"}:
        raise ValueError(f"Invalid terminal job status: {status}")
    now = utcnow()
    with transaction() as connection:
        connection.execute(
            """UPDATE jobs SET status = ?, error_code = ?, error_detail = ?, finished_at = ?, updated_at = ? WHERE id = ?""",
            (status, error_code, error_detail, now, now, job_id),
        )
        connection.execute("UPDATE cases SET status = ?, updated_at = ? WHERE id = (SELECT case_id FROM jobs WHERE id = ?)", (status, now, job_id))


def add_artifact(
    case_id: str,
    job_id: str,
    artifact_type: str,
    subject: str,
    source_locator: str,
    data: dict[str, Any],
    sha256: str | None = None,
) -> str:
    artifact_id = identifier("art")
    with transaction() as connection:
        connection.execute(
            """INSERT INTO artifacts (id, case_id, job_id, artifact_type, subject, source_locator, sha256, data_json, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (artifact_id, case_id, job_id, artifact_type, subject, source_locator, sha256, _json(data), utcnow()),
        )
    return artifact_id


def add_finding(
    case_id: str,
    job_id: str,
    rule_id: str,
    title: str,
    category: str,
    severity: str,
    description: str,
    artifact_ids: Iterable[str],
    limitations: list[str] | None = None,
    evidence_status: str = "observed",
    location: dict[str, Any] | None = None,
) -> str:
    finding_id = identifier("finding")
    with transaction() as connection:
        connection.execute(
            """INSERT INTO findings (id, case_id, job_id, rule_id, rule_version, title, category, severity, evidence_status,
                description, limitations_json, artifact_ids_json, location_json, created_at)
                VALUES (?, ?, ?, ?, '1.0.0', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (finding_id, case_id, job_id, rule_id, title, category, severity, evidence_status, description, _json(limitations or []), _json(list(artifact_ids)), _json(location or {}), utcnow()),
        )
    return finding_id


def add_blindspot(
    case_id: str,
    job_id: str,
    scope_type: str,
    scope_id: str,
    reason_code: str,
    limitation: str,
    suggested_next_step: str | None = None,
    artifact_ids: Iterable[str] | None = None,
) -> str:
    blindspot_id = identifier("blindspot")
    with transaction() as connection:
        connection.execute(
            """INSERT INTO blindspots (id, case_id, job_id, scope_type, scope_id, reason_code, limitation,
                suggested_next_step, artifact_ids_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (blindspot_id, case_id, job_id, scope_type, scope_id, reason_code, limitation, suggested_next_step, _json(list(artifact_ids or [])), utcnow()),
        )
    return blindspot_id


def add_indicator(case_id: str, job_id: str, indicator_type: str, value: str, artifact_id: str) -> None:
    with transaction() as connection:
        connection.execute(
            """INSERT OR IGNORE INTO indicators (id, case_id, job_id, indicator_type, value, observable_level, artifact_id, created_at)
               VALUES (?, ?, ?, ?, ?, 'static_string', ?, ?)""",
            (identifier("ioc"), case_id, job_id, indicator_type, value, artifact_id, utcnow()),
        )


def update_case_summary(case_id: str, risk_score: int | None, risk_tier: str, completeness: int) -> None:
    with transaction() as connection:
        connection.execute("UPDATE cases SET risk_score = ?, risk_tier = ?, completeness = ?, updated_at = ? WHERE id = ?", (risk_score, risk_tier, completeness, utcnow(), case_id))


def create_report(case_id: str, job_id: str, report_json_path: str, report_pdf_path: str, capsule_path: str, capsule_sha256: str) -> str:
    report_id = identifier("report")
    with transaction() as connection:
        connection.execute(
            """INSERT INTO reports (id, case_id, job_id, report_json_path, report_pdf_path, capsule_path, capsule_sha256, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (report_id, case_id, job_id, report_json_path, report_pdf_path, capsule_path, capsule_sha256, utcnow()),
        )
    return report_id
