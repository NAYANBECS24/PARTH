from __future__ import annotations

import hashlib
import json
import textwrap
import zipfile
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any

from backend.config import settings
from backend.database import transaction
from backend.repository import create_report, json_value

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hydrate_rows(rows: list, json_columns: tuple[str, ...]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in rows:
        value = dict(row)
        for column in json_columns:
            value[column.removesuffix("_json")] = json_value(
                value.pop(column, None),
                [] if column.endswith(("ids_json", "limitations_json", "errors_json")) else {},
            )
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
        stages = _hydrate_rows(
            connection.execute("SELECT stage_key, position, status, started_at, finished_at, detail_json FROM job_stages WHERE job_id = ? ORDER BY position", (job_id,)).fetchall(),
            ("detail_json",),
        )
        artifacts = _hydrate_rows(
            connection.execute("SELECT id, artifact_type, subject, source_locator, sha256, data_json, created_at FROM artifacts WHERE job_id = ? ORDER BY created_at", (job_id,)).fetchall(),
            ("data_json",),
        )
        findings = _hydrate_rows(
            connection.execute("SELECT id, rule_id, rule_version, title, category, severity, evidence_status, description, limitations_json, artifact_ids_json, location_json, reviewer_status, created_at FROM findings WHERE job_id = ? ORDER BY created_at", (job_id,)).fetchall(),
            ("limitations_json", "artifact_ids_json", "location_json"),
        )
        blindspots = _hydrate_rows(
            connection.execute("SELECT id, scope_type, scope_id, reason_code, limitation, suggested_next_step, artifact_ids_json, created_at FROM blindspots WHERE job_id = ? ORDER BY created_at", (job_id,)).fetchall(),
            ("artifact_ids_json",),
        )
        guard_paths = _hydrate_rows(
            connection.execute("SELECT id, target_method_id, guard_ast_json, solver_status, supported_subset, witness_json, limitations_json, created_at FROM guard_paths WHERE job_id = ? ORDER BY created_at", (job_id,)).fetchall(),
            ("guard_ast_json", "witness_json", "limitations_json"),
        )
        indicators = [dict(row) for row in connection.execute("SELECT id, indicator_type, value, observable_level, artifact_id, created_at FROM indicators WHERE job_id = ? ORDER BY indicator_type, value", (job_id,)).fetchall()]
        ai_proposals = _hydrate_rows(
            connection.execute(
                """SELECT id, provider, model, status, proposal_json, validation_errors_json,
                          evidence_ids_json, created_at FROM ai_proposals WHERE job_id = ? ORDER BY created_at""",
                (job_id,),
            ).fetchall(),
            ("proposal_json", "validation_errors_json", "evidence_ids_json"),
        )
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
        "guard_paths": guard_paths,
        "indicators": indicators,
        "ai_proposals": ai_proposals,
        "integrity_note": "This capsule proves consistency of included files, not legal admissibility or safety of the application.",
    }


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _minimal_pdf(lines: list[str]) -> bytes:
    """A small dependency-free fallback PDF writer."""
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
        f"<< /Length {len(stream)} >>\nstream\n".encode("latin-1") + stream + b"\nendstream",
    ]
    offsets = [0]
    out = bytearray(b"%PDF-1.4\n")
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{index} 0 obj\n".encode("latin-1"))
        out.extend(obj)
        out.extend(b"\nendobj\n")
    xref = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("latin-1"))
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))
    out.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("latin-1"))
    return bytes(out)


def _generate_reportlab_pdf(payload: dict[str, Any]) -> bytes:
    """Generates a professional forensic PDF report using ReportLab."""
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Heading1"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0B1119"),
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#4A5568"),
    )
    section_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1A202C"),
        spaceBefore=12,
        spaceAfter=6,
    )
    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
    )
    cell_bold = ParagraphStyle(
        "TableCellBold",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        fontName="Helvetica-Bold",
    )

    story: list[Any] = []

    # Title & Header
    story.append(Paragraph("SHADOWPATH Ω — NEXUS", title_style))
    story.append(Paragraph("Evidence-Driven Android Malware Blindspot Discovery & Adaptive Forensic Verification Report", subtitle_style))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2BD4C5"), spaceAfter=12))

    # Case Summary Meta Table
    case = payload.get("case", {})
    summary_data = [
        [Paragraph("Case Title:", cell_bold), Paragraph(str(case.get("title", "")), cell_style),
         Paragraph("Analysis Status:", cell_bold), Paragraph(str(payload.get("job", {}).get("status", "")).upper(), cell_style)],
        [Paragraph("APK Filename:", cell_bold), Paragraph(str(case.get("original_filename", "")), cell_style),
         Paragraph("Risk Tier / Score:", cell_bold), Paragraph(f"{case.get('risk_tier', '').upper()} ({case.get('risk_score', 0)}/100)", cell_style)],
        [Paragraph("SHA-256 Hash:", cell_bold), Paragraph(str(case.get("sample_sha256", "")), cell_style),
         Paragraph("Completeness:", cell_bold), Paragraph(f"{case.get('completeness', 0)}%", cell_style)],
        [Paragraph("Generated At:", cell_bold), Paragraph(payload.get("generated_at", ""), cell_style),
         Paragraph("Engine Mode:", cell_bold), Paragraph("Local Static + Z3 SMT", cell_style)],
    ]
    meta_table = Table(summary_data, colWidths=[90, 200, 95, 155])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7FAFC")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # Findings Section
    story.append(Paragraph(f"Evidence-Backed Findings ({len(payload.get('findings', []))})", section_style))
    findings = payload.get("findings", [])
    if findings:
        findings_data = [
            [Paragraph("Rule ID", cell_bold), Paragraph("Severity", cell_bold), Paragraph("Status", cell_bold), Paragraph("Title & Description", cell_bold)]
        ]
        for f in findings[:25]:
            sev = f.get("severity", "info").upper()
            st = f.get("evidence_status", "observed").replace("_", " ").upper()
            findings_data.append([
                Paragraph(f.get("rule_id", ""), cell_style),
                Paragraph(sev, cell_bold),
                Paragraph(st, cell_style),
                Paragraph(f"<b>{f.get('title', '')}</b><br/>{f.get('description', '')}", cell_style),
            ])
        f_table = Table(findings_data, colWidths=[70, 60, 90, 320])
        f_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(f_table)
    else:
        story.append(Paragraph("No evidence-backed risk findings observed in inspected regions.", subtitle_style))

    story.append(Spacer(1, 12))

    # Guarded Paths / Z3 Section
    guard_paths = payload.get("guard_paths", [])
    story.append(Paragraph(f"Guarded Paths & Z3 Solver Analysis ({len(guard_paths)})", section_style))
    if guard_paths:
        gp_data = [
            [Paragraph("Target Method", cell_bold), Paragraph("Solver Status", cell_bold), Paragraph("Synthesized Trigger Witness", cell_bold)]
        ]
        for gp in guard_paths[:10]:
            gp_data.append([
                Paragraph(str(gp.get("target_method_id", "")), cell_style),
                Paragraph(str(gp.get("solver_status", "")).upper(), cell_bold),
                Paragraph(json.dumps(gp.get("witness", {}), ensure_ascii=False), cell_style),
            ])
        gp_table = Table(gp_data, colWidths=[180, 80, 280])
        gp_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(gp_table)
    else:
        story.append(Paragraph("No bounded guard predicates satisfied in inspected subset.", subtitle_style))

    story.append(Spacer(1, 12))

    # Blindspots Section
    blindspots = payload.get("blindspots", [])
    story.append(Paragraph(f"Blindspot Ledger & Declared Limitations ({len(blindspots)})", section_style))
    if blindspots:
        bs_data = [
            [Paragraph("Scope", cell_bold), Paragraph("Reason Code", cell_bold), Paragraph("Limitation & Remediation", cell_bold)]
        ]
        for b in blindspots[:15]:
            bs_data.append([
                Paragraph(f"{b.get('scope_type', '')}/{b.get('scope_id', '')}", cell_style),
                Paragraph(b.get("reason_code", ""), cell_bold),
                Paragraph(f"{b.get('limitation', '')}<br/><i>Next step: {b.get('suggested_next_step', '')}</i>", cell_style),
            ])
        bs_table = Table(bs_data, colWidths=[110, 150, 280])
        bs_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EDF2F7")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(bs_table)

    story.append(Spacer(1, 16))
    story.append(Paragraph(f"<b>Integrity Guarantee:</b> {payload.get('integrity_note', '')}", subtitle_style))

    doc.build(story)
    return buffer.getvalue()


def generate_report(case_id: str, job_id: str, stage_overrides: dict[str, dict[str, Any]] | None = None) -> dict[str, str]:
    payload = build_report_payload(case_id, job_id, stage_overrides=stage_overrides)
    report_stem = f"{case_id}-{job_id}"
    report_json_path = settings.report_dir / f"{report_stem}.json"
    report_pdf_path = settings.report_dir / f"{report_stem}.pdf"
    capsule_path = settings.capsule_dir / f"{report_stem}.zip"

    report_json = _canonical_json(payload)
    report_json_path.write_bytes(report_json)

    # Produce PDF via ReportLab or fallback
    if REPORTLAB_AVAILABLE:
        try:
            pdf_bytes = _generate_reportlab_pdf(payload)
        except Exception:
            pdf_bytes = _minimal_pdf([
                "SHADOWPATH Ω — NEXUS Evidence Report",
                f"Case: {payload['case']['title']} ({case_id})",
                f"APK: {payload['case']['original_filename']}",
                f"SHA-256: {payload['case']['sample_sha256']}",
                f"Risk: {payload['case']['risk_tier']} / {payload['case']['risk_score']}",
            ])
    else:
        pdf_bytes = _minimal_pdf([
            "SHADOWPATH Ω — NEXUS Evidence Report",
            f"Case: {payload['case']['title']} ({case_id})",
            f"APK: {payload['case']['original_filename']}",
            f"SHA-256: {payload['case']['sample_sha256']}",
            f"Risk: {payload['case']['risk_tier']} / {payload['case']['risk_score']}",
        ])
    report_pdf_path.write_bytes(pdf_bytes)

    # Structured capsule entries
    findings_json = _canonical_json(payload.get("findings", []))
    blindspots_json = _canonical_json(payload.get("blindspots", []))
    guard_paths_json = _canonical_json(payload.get("guard_paths", []))
    ai_proposals_json = _canonical_json(payload.get("ai_proposals", []))

    capsule_manifest = {
        "schema_version": "1.0.0",
        "case_id": case_id,
        "job_id": job_id,
        "files": [
            {"path": "report.json", "sha256": hashlib.sha256(report_json).hexdigest()},
            {"path": "report.pdf", "sha256": hashlib.sha256(pdf_bytes).hexdigest()},
            {"path": "claims/findings.json", "sha256": hashlib.sha256(findings_json).hexdigest()},
            {"path": "claims/blindspots.json", "sha256": hashlib.sha256(blindspots_json).hexdigest()},
            {"path": "claims/guarded_paths.json", "sha256": hashlib.sha256(guard_paths_json).hexdigest()},
            {"path": "claims/ai_proposals.json", "sha256": hashlib.sha256(ai_proposals_json).hexdigest()},
        ],
    }

    with zipfile.ZipFile(capsule_path, "w", compression=zipfile.ZIP_DEFLATED) as capsule:
        capsule.writestr("report.json", report_json)
        capsule.writestr("report.pdf", pdf_bytes)
        capsule.writestr("claims/findings.json", findings_json)
        capsule.writestr("claims/blindspots.json", blindspots_json)
        capsule.writestr("claims/guarded_paths.json", guard_paths_json)
        capsule.writestr("claims/ai_proposals.json", ai_proposals_json)
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
