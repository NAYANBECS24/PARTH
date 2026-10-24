from __future__ import annotations

import asyncio
import json
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field

from backend.config import settings
from backend.database import get_connection, initialise_database, transaction, utcnow
from backend.intake import store_upload
from backend.reports import verify_capsule
from backend.repository import create_case_and_job, identifier, json_value, request_cancel


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row else None


def _json_fields(item: dict[str, Any], *names: str) -> dict[str, Any]:
    for name in names:
        if name in item:
            item[name.removesuffix("_json")] = json_value(item.pop(name), []) if name.endswith(("ids_json", "limitations_json")) else json_value(item.pop(name), {})
    return item


def _case_or_404(case_id: str) -> dict[str, Any]:
    with transaction() as connection:
        row = connection.execute(
            """SELECT cases.*, samples.original_filename, samples.byte_size, samples.archive_entry_count, samples.synthetic_fixture
               FROM cases JOIN samples ON samples.sha256 = cases.sample_sha256 WHERE cases.id = ?""",
            (case_id,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "Case not found")
    return dict(row)


def _job_or_404(job_id: str) -> dict[str, Any]:
    with transaction() as connection:
        row = connection.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Job not found")
    return dict(row)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    initialise_database()
    yield


app = FastAPI(title="SHADOWPATH Ω — NEXUS API", version="0.1.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)


class FindingReview(BaseModel):
    decision: Literal["reviewed", "needs_further_testing", "false_positive"]
    note: str = Field(default="", max_length=4000)
    analyst: str = Field(default="local-analyst", max_length=120)


@app.get("/health")
def health() -> dict[str, Any]:
    initialise_database()
    with transaction() as connection:
        queued = connection.execute("SELECT count(*) FROM jobs WHERE status = 'queued'").fetchone()[0]
        active = connection.execute("SELECT count(*) FROM jobs WHERE status = 'running'").fetchone()[0]
        cases = connection.execute("SELECT count(*) FROM cases").fetchone()[0]
    try:
        import androguard  # type: ignore[import-not-found]

        androguard_status = {"status": "available", "version": getattr(androguard, "__version__", "installed")}
    except ImportError:
        androguard_status = {"status": "unavailable", "reason": "Python dependency not installed"}
    return {
        "status": "ok",
        "mode": "local_static_only",
        "database": "available",
        "worker": {"queued_jobs": queued, "running_jobs": active},
        "cases": cases,
        "adapters": {
            "zip_inventory": "available",
            "androguard": androguard_status,
            "nvidia": "configured" if settings.enable_nvidia else "not_configured",
            "dynamic_lab": "not_configured",
        },
    }


@app.post("/api/cases/intake", status_code=201)
async def intake_case(
    file: UploadFile = File(...),
    case_name: str = Form(..., min_length=1, max_length=160),
    analyst_note: str = Form(default="", max_length=4000),
    profile: Literal["lite", "standard", "advanced"] = Form(default="standard"),
    nvidia_reasoning: bool = Form(default=False),
    isolated_dynamic_lab: bool = Form(default=False),
) -> dict[str, Any]:
    if nvidia_reasoning and not settings.enable_nvidia:
        raise HTTPException(409, {"code": "nvidia_not_configured", "message": "NVIDIA reasoning is not configured; keep it disabled or configure a reviewed provider."})
    if isolated_dynamic_lab:
        raise HTTPException(409, {"code": "dynamic_lab_not_configured", "message": "No isolated dynamic lab is configured. Uploaded APKs are never executed on this host."})
    upload = await store_upload(file)
    case_id, job_id, sample_already_known = create_case_and_job(upload, case_name, analyst_note, profile, nvidia_reasoning, isolated_dynamic_lab)
    return {
        "case_id": case_id,
        "job_id": job_id,
        "sample": {"sha256": upload.sha256, "byte_size": upload.byte_size, "original_filename": upload.original_filename, "deduplicated_content": sample_already_known},
        "status": "queued",
        "dynamic_lab": "not_configured",
    }


@app.get("/api/overview")
def overview() -> dict[str, Any]:
    with transaction() as connection:
        counts = dict(connection.execute("SELECT count(*) AS case_count, sum(CASE WHEN status IN ('queued','running') THEN 1 ELSE 0 END) AS active_count FROM cases").fetchone())
        recent_cases = [dict(row) for row in connection.execute(
            "SELECT cases.id, cases.title, cases.status, cases.risk_score, cases.risk_tier, cases.completeness, cases.created_at, "
            "samples.original_filename, substr(cases.sample_sha256, 1, 12) AS sha_prefix "
            "FROM cases JOIN samples ON samples.sha256 = cases.sample_sha256 ORDER BY cases.created_at DESC LIMIT 10"
        ).fetchall()]
        jobs = [dict(row) for row in connection.execute(
            "SELECT id, case_id, status, current_stage, created_at, updated_at FROM jobs WHERE status IN ('queued','running') ORDER BY created_at DESC LIMIT 10"
        ).fetchall()]
        high_findings = connection.execute("SELECT count(*) FROM findings WHERE severity IN ('high','critical') AND reviewer_status = 'unreviewed'").fetchone()[0]
        blindspots = connection.execute("SELECT count(*) FROM blindspots").fetchone()[0]
    return {"counts": {"cases": counts["case_count"], "active_jobs": counts["active_count"] or 0, "unreviewed_high_priority_findings": high_findings, "open_blindspots": blindspots}, "recent_cases": recent_cases, "jobs": jobs}


@app.get("/api/cases")
def list_cases(
    search: str = Query(default="", max_length=160),
    status: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> dict[str, Any]:
    conditions = ["1=1"]
    parameters: list[Any] = []
    if search:
        conditions.append("(cases.title LIKE ? OR samples.original_filename LIKE ? OR cases.sample_sha256 LIKE ?)")
        parameters.extend([f"%{search}%", f"%{search}%", f"%{search}%"])
    if status:
        conditions.append("cases.status = ?")
        parameters.append(status)
    where = " AND ".join(conditions)
    with transaction() as connection:
        total = connection.execute(
            f"SELECT count(*) FROM cases JOIN samples ON samples.sha256 = cases.sample_sha256 WHERE {where}", parameters
        ).fetchone()[0]
        records = [dict(row) for row in connection.execute(
            f"SELECT cases.*, samples.original_filename, samples.byte_size, samples.synthetic_fixture "
            f"FROM cases JOIN samples ON samples.sha256 = cases.sample_sha256 "
            f"WHERE {where} ORDER BY cases.created_at DESC LIMIT ? OFFSET ?",
            [*parameters, page_size, (page - 1) * page_size],
        ).fetchall()]
    return {"items": records, "page": page, "page_size": page_size, "total": total}


@app.get("/api/cases/{case_id}")
def get_case(case_id: str) -> dict[str, Any]:
    case = _case_or_404(case_id)
    with transaction() as connection:
        job = connection.execute("SELECT * FROM jobs WHERE case_id = ? ORDER BY created_at DESC LIMIT 1", (case_id,)).fetchone()
        artifacts = [
            _json_fields(dict(row), "data_json")
            for row in connection.execute("SELECT * FROM artifacts WHERE case_id = ? ORDER BY created_at", (case_id,)).fetchall()
        ]
        findings = [
            _json_fields(dict(row), "limitations_json", "artifact_ids_json", "location_json")
            for row in connection.execute("SELECT * FROM findings WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
        ]
        blindspots = [
            _json_fields(dict(row), "artifact_ids_json")
            for row in connection.execute("SELECT * FROM blindspots WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()
        ]
        indicators = [dict(row) for row in connection.execute("SELECT * FROM indicators WHERE case_id = ? ORDER BY indicator_type, value", (case_id,)).fetchall()]
        reports = [dict(row) for row in connection.execute("SELECT id, job_id, capsule_sha256, verification_status, created_at FROM reports WHERE case_id = ? ORDER BY created_at DESC", (case_id,)).fetchall()]
    return {"case": case, "latest_job": dict(job) if job else None, "artifacts": artifacts, "findings": findings, "blindspots": blindspots, "indicators": indicators, "reports": reports}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict[str, Any]:
    job = _job_or_404(job_id)
    with transaction() as connection:
        stages = [_json_fields(dict(row), "detail_json") for row in connection.execute("SELECT * FROM job_stages WHERE job_id = ? ORDER BY position", (job_id,)).fetchall()]
        events = [_json_fields(dict(row), "payload_json") for row in connection.execute("SELECT * FROM job_events WHERE job_id = ? ORDER BY id DESC LIMIT 100", (job_id,)).fetchall()]
    return {"job": job, "stages": stages, "events": list(reversed(events))}


@app.get("/api/jobs/{job_id}/events")
async def job_events(job_id: str) -> StreamingResponse:
    _job_or_404(job_id)

    async def events() -> AsyncIterator[str]:
        last_event = 0
        while True:
            payload = get_job(job_id)
            current_events = payload["events"]
            newest = max((event["id"] for event in current_events), default=last_event)
            if newest > last_event or payload["job"]["status"] in {"completed", "partial", "failed", "cancelled"}:
                last_event = newest
                yield f"event: job\ndata: {json.dumps(payload, default=str)}\n\n"
            if payload["job"]["status"] in {"completed", "partial", "failed", "cancelled"}:
                return
            await asyncio.sleep(1)

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/jobs/{job_id}/cancel")
def cancel_job(job_id: str) -> dict[str, Any]:
    _job_or_404(job_id)
    if not request_cancel(job_id):
        raise HTTPException(409, "Only queued or running jobs can be cancelled")
    return {"job_id": job_id, "status": "cancellation_requested"}


@app.get("/api/findings")
def list_findings(
    severity: str | None = None,
    evidence_status: str | None = None,
    case_id: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=100),
) -> dict[str, Any]:
    conditions = ["1=1"]
    parameters: list[Any] = []
    for column, value in (("severity", severity), ("evidence_status", evidence_status), ("case_id", case_id)):
        if value:
            conditions.append(f"findings.{column} = ?")
            parameters.append(value)
    where = " AND ".join(conditions)
    with transaction() as connection:
        total = connection.execute(f"SELECT count(*) FROM findings WHERE {where}", parameters).fetchone()[0]
        records = [
            _json_fields(dict(row), "limitations_json", "artifact_ids_json", "location_json")
            for row in connection.execute(f"SELECT * FROM findings WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?", [*parameters, page_size, (page - 1) * page_size]).fetchall()
        ]
    return {"items": records, "total": total, "page": page, "page_size": page_size}


@app.post("/api/findings/{finding_id}/review")
def review_finding(finding_id: str, review: FindingReview) -> dict[str, Any]:
    with transaction() as connection:
        finding = connection.execute("SELECT id FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if not finding:
            raise HTTPException(404, "Finding not found")
        annotation_id = identifier("annotation")
        connection.execute("UPDATE findings SET reviewer_status = ? WHERE id = ?", (review.decision, finding_id))
        connection.execute(
            "INSERT INTO annotations (id, finding_id, decision, note, analyst, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (annotation_id, finding_id, review.decision, review.note, review.analyst, utcnow()),
        )
    return {"annotation_id": annotation_id, "finding_id": finding_id, "reviewer_status": review.decision}


@app.get("/api/cases/{case_id}/graph")
def case_graph(case_id: str, limit: int = Query(default=150, ge=1, le=500)) -> dict[str, Any]:
    _case_or_404(case_id)
    with transaction() as connection:
        artifacts = [dict(row) for row in connection.execute("SELECT id, artifact_type, subject FROM artifacts WHERE case_id = ? ORDER BY created_at LIMIT ?", (case_id, limit)).fetchall()]
        findings = [_json_fields(dict(row), "artifact_ids_json") for row in connection.execute("SELECT id, title, severity, evidence_status, artifact_ids_json FROM findings WHERE case_id = ?", (case_id,)).fetchall()]
    nodes = [{"id": f"artifact:{item['id']}", "type": "artifact", "label": item["subject"], "data": item} for item in artifacts]
    nodes.extend({"id": f"finding:{item['id']}", "type": "finding", "label": item["title"], "data": item} for item in findings)
    known_artifacts = {item["id"] for item in artifacts}
    edges = [
        {"id": f"e:{finding['id']}:{artifact_id}", "source": f"finding:{finding['id']}", "target": f"artifact:{artifact_id}", "type": "supported_by"}
        for finding in findings
        for artifact_id in finding["artifact_ids"]
        if artifact_id in known_artifacts
    ]
    return {"nodes": nodes, "edges": edges, "limited": len(artifacts) >= limit}


@app.get("/api/compare")
def compare_cases(left: str = Query(...), right: str = Query(...)) -> dict[str, Any]:
    left_case = _case_or_404(left)
    right_case = _case_or_404(right)
    with transaction() as connection:
        def values(case_id: str, kind: str) -> set[str]:
            return {row[0] for row in connection.execute("SELECT value FROM indicators WHERE case_id = ? AND indicator_type = ?", (case_id, kind)).fetchall()}

        left_iocs = {kind: values(left, kind) for kind in ("url", "domain", "ip")}
        right_iocs = {kind: values(right, kind) for kind in ("url", "domain", "ip")}
        left_findings = {row[0] for row in connection.execute("SELECT rule_id FROM findings WHERE case_id = ?", (left,)).fetchall()}
        right_findings = {row[0] for row in connection.execute("SELECT rule_id FROM findings WHERE case_id = ?", (right,)).fetchall()}
    return {
        "left": left_case,
        "right": right_case,
        "indicator_diff": {kind: {"shared": sorted(left_iocs[kind] & right_iocs[kind]), "left_only": sorted(left_iocs[kind] - right_iocs[kind]), "right_only": sorted(right_iocs[kind] - left_iocs[kind])} for kind in left_iocs},
        "finding_rules": {"shared": sorted(left_findings & right_findings), "left_only": sorted(left_findings - right_findings), "right_only": sorted(right_findings - left_findings)},
        "limitation": "Shared static artifacts are evidence-backed relationships, not attribution to an actor or malware family.",
    }


@app.get("/api/reports")
def list_reports() -> dict[str, Any]:
    with transaction() as connection:
        reports = [dict(row) for row in connection.execute("SELECT reports.id, reports.case_id, reports.job_id, reports.capsule_sha256, reports.verification_status, reports.created_at, cases.title FROM reports JOIN cases ON cases.id = reports.case_id ORDER BY reports.created_at DESC").fetchall()]
    return {"items": reports}


@app.get("/api/reports/{report_id}/download/{kind}")
def download_report(report_id: str, kind: Literal["json", "pdf", "capsule"]) -> FileResponse:
    column = {"json": "report_json_path", "pdf": "report_pdf_path", "capsule": "capsule_path"}[kind]
    with transaction() as connection:
        row = connection.execute(f"SELECT {column} FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not row or not Path(row[column]).is_file():
        raise HTTPException(404, "Report file not found")
    media_type = {"json": "application/json", "pdf": "application/pdf", "capsule": "application/zip"}[kind]
    return FileResponse(row[column], media_type=media_type, filename=f"shadowpath-{report_id}.{ 'zip' if kind == 'capsule' else kind}")


@app.post("/api/reports/{report_id}/verify")
def verify_report(report_id: str) -> dict[str, Any]:
    with transaction() as connection:
        row = connection.execute("SELECT capsule_path FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Report not found")
    result = verify_capsule(row["capsule_path"])
    with transaction() as connection:
        connection.execute("UPDATE reports SET verification_status = ? WHERE id = ?", ("verified" if result["valid"] else "failed", report_id))
    return result
