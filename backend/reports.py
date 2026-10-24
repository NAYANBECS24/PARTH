from __future__ import annotations

import hashlib
import json
import textwrap
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from backend.config import settings
from backend.database import transaction
from backend.repository import create_report, json_value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hydrate_rows(rows: list, json_columns: tuple[str, ...]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in rows:
        value = dict(row)
        for column in json_columns:
            value[column.removesuffix("_json")] = json_value(value.pop(column, None), [] if column.endswith("ids_json") or column.endswith("limitations_json") else {})
        items.append(value)
    return items


def build_report_payload(
    case_id: str,
    job_id: str,
    stage_overrides: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    with transaction() as connection:
        case = connection.execute(
            """SELECT cases.*, samples.original_filename, samples.byte_size, samples.archive_entry_count, samples.created_at AS sample_received_at
               FROM cases JOIN samples ON samples.sha256 = cases.sample_sha256 WHERE cases.id = ?""",
            (case_id,),
        ).fetchone()
        if not case:
            raise ValueError(f"Unknown case: {case_id}")
        job = connection.execute("SELECT * FROM jobs WHERE id = ? AND case_id = ?", (job_id, case_id)).fetchone()
        if not job:
            raise ValueError(f"Unknown job: {job_id}")
        stages = _hydrate_rows(connection.execute("SELECT stage_key, position, status, started_at, finished_at, detail_json FROM job_stages WHERE job_id = ? ORDER BY position", (job_id,)).fetchall(), ("detail_json",))
        artifacts = _hydrate_rows(connection.execute("SELECT id, artifact_type, subject, source_locator, sha256, data_json, created_at FROM artifacts WHERE job_id = ? ORDER BY created_at", (job_id,)).fetchall(), ("data_json",))
        findings = _hydrate_rows(connection.execute("SELECT id, rule_id, rule_version, title, category, severity, evidence_status, description, limitations_json, artifact_ids_json, location_json, reviewer_status, created_at FROM findings WHERE job_id = ? ORDER BY created_at", (job_id,)).fetchall(), ("limitations_json", "artifact_ids_json", "location_json"))
        blindspots = _hydrate_rows(connection.execute("SELECT id, scope_type, scope_id, reason_code, limitation, suggested_next_step, artifact_ids_json, created_at FROM blindspots WHERE job_id = ? ORDER BY created_at", (job_id,)).fetchall(), ("artifact_ids_json",))
        indicators = [dict(row) for row in connection.execute("SELECT id, indicator_type, value, observable_level, artifact_id, created_at FROM indicators WHERE job_id = ? ORDER BY indicator_type, value", (job_id,)).fetchall()]
    for stage in stages:
        override = (stage_overrides or {}).get(stage["stage_key"])
        if override:
            stage.update(override)
    return {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "product": {"name": "SHADOWPATH Ω — NEXUS", "analysis_mode": "local_static_only"},
        "case": dict(case),
        "job": dict(job),
        "stages": stages,
        "artifacts": artifacts,
        "findings": findings,
        "blindspots": blindspots,
        "indicators": indicators,
        "integrity_note": "This capsule proves consistency of included files, not legal admissibility or safety of the application.",
    }


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _minimal_pdf(lines: list[str]) -> bytes:
    """A small dependency-free PDF writer for a readable local forensic summary."""
    printable_lines: list[str] = []
    for line in lines:
        printable_lines.extend(textwrap.wrap(line, width=104, replace_whitespace=False) or [""])
    body = ["BT", "/F1 10 Tf", "50 790 Td", "14 TL"]
    for index, line in enumerate(printable_lines[:48]):
        if index:
            body.append("T*")
        body.append(f"({_pdf_escape(line)}) Tj")
    body.append("ET")
    stream = "\n".join(body).encode("latin-1", errors="replace")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, payload in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode())
        output.extend(payload)
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(output)


def generate_report(case_id: str, job_id: str, stage_overrides: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    payload = build_report_payload(case_id, job_id, stage_overrides=stage_overrides)
    report_stem = f"{case_id}-{job_id}"
    report_json_path = settings.report_dir / f"{report_stem}.json"
    report_pdf_path = settings.report_dir / f"{report_stem}.pdf"
    capsule_path = settings.capsule_dir / f"{report_stem}.zip"
    report_json = _canonical_json(payload)
    report_json_path.write_bytes(report_json)
    summary_lines = [
        "SHADOWPATH Ω — NEXUS Evidence Report",
        f"Case: {payload['case']['title']} ({case_id})",
        f"APK: {payload['case']['original_filename']}",
        f"SHA-256: {payload['case']['sample_sha256']}",
        f"Job: {job_id} — {payload['job']['status']}",
        f"Risk: {payload['case']['risk_tier']} / {payload['case']['risk_score']}",
        f"Static-analysis completeness: {payload['case']['completeness']}%",
        "",
        f"Evidence-backed findings: {len(payload['findings'])}",
    ]
    summary_lines.extend(f"- [{finding['severity']}/{finding['evidence_status']}] {finding['title']}" for finding in payload["findings"])
    summary_lines.extend(["", f"Blindspots / unknowns: {len(payload['blindspots'])}"])
    summary_lines.extend(f"- {item['reason_code']}: {item['limitation']}" for item in payload["blindspots"])
    summary_lines.extend(["", payload["integrity_note"]])
    report_pdf_path.write_bytes(_minimal_pdf(summary_lines))
    capsule_manifest = {
        "schema_version": "1.0.0",
        "case_id": case_id,
        "job_id": job_id,
        "files": [
            {"path": "report.json", "sha256": hashlib.sha256(report_json).hexdigest()},
            {"path": "report.pdf", "sha256": hashlib.sha256(report_pdf_path.read_bytes()).hexdigest()},
        ],
    }
    with zipfile.ZipFile(capsule_path, "w", compression=zipfile.ZIP_DEFLATED) as capsule:
        capsule.writestr("report.json", report_json)
        capsule.write(report_pdf_path, "report.pdf")
        capsule.writestr("manifest.json", _canonical_json(capsule_manifest))
    capsule_sha256 = hashlib.sha256(capsule_path.read_bytes()).hexdigest()
    report_id = create_report(case_id, job_id, str(report_json_path), str(report_pdf_path), str(capsule_path), capsule_sha256)
    return {"id": report_id, "json_path": str(report_json_path), "pdf_path": str(report_pdf_path), "capsule_path": str(capsule_path), "capsule_sha256": capsule_sha256}


def verify_capsule(capsule_path: str | Path) -> dict[str, Any]:
    path = Path(capsule_path)
    failures: list[dict[str, str]] = []
    try:
        with zipfile.ZipFile(path) as capsule:
            manifest = json.loads(capsule.read("manifest.json"))
            for entry in manifest.get("files", []):
                member_path = entry["path"]
                actual = hashlib.sha256(capsule.read(member_path)).hexdigest()
                if actual != entry.get("sha256"):
                    failures.append({"path": member_path, "expected": entry.get("sha256", ""), "actual": actual})
    except (OSError, zipfile.BadZipFile, KeyError, json.JSONDecodeError) as error:
        failures.append({"path": "capsule", "expected": "valid evidence capsule", "actual": f"{type(error).__name__}: {error}"})
    return {"valid": not failures, "failures": failures, "capsule_sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None}
