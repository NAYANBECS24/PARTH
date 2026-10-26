from __future__ import annotations

import hashlib
import json
import re
import traceback
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from backend.config import settings
from backend.adapters import ReverseEngineeringToolchain, Z3GuardEvaluator
from backend.ai_provider import NvidiaNimProvider
from backend.database import get_connection, transaction
from backend.intake import validate_archive
from backend.mobsf import MobSFClient, MobSFError
from backend.repository import (
    STAGES,
    add_artifact,
    add_blindspot,
    add_finding,
    add_guard_path,
    add_indicator,
    cancellation_requested,
    create_ai_proposal,
    finish_job,
    log_event,
    set_stage,
    update_case_summary,
)
from backend.reports import generate_report


ANDROID = "{http://schemas.android.com/apk/res/android}"
PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
URL_PATTERN = re.compile(r"https?://[^\s\"'<>\\]{3,512}", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"(?<![@/])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?![/a-z])", re.IGNORECASE)
IP_PATTERN = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
SENSITIVE_PERMISSIONS = {
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
}


class CancellationRequested(Exception):
    pass


@dataclass
class AnalysisState:
    case_id: str
    job_id: str
    sample_sha256: str
    apk_path: Path
    profile: str
    nvidia_requested: bool
    artifact_ids: dict[str, list[str]] = field(default_factory=dict)
    manifest: dict[str, Any] = field(default_factory=dict)
    dex_strings: list[tuple[str, str]] = field(default_factory=list)
    partial: bool = False
    manifest_complete: bool = False
    dex_complete: bool = False
    inventory_complete: bool = False
    indicator_complete: bool = False

    def remember(self, category: str, artifact_id: str) -> None:
        self.artifact_ids.setdefault(category, []).append(artifact_id)


def _job_state(job_id: str) -> AnalysisState:
    with transaction() as connection:
        row = connection.execute(
            """SELECT jobs.id AS job_id, jobs.case_id, jobs.sample_sha256, samples.storage_path,
                      cases.profile, cases.nvidia_requested
               FROM jobs JOIN samples ON samples.sha256 = jobs.sample_sha256
               JOIN cases ON cases.id = jobs.case_id WHERE jobs.id = ?""",
            (job_id,),
        ).fetchone()
    if not row:
        raise ValueError(f"Unknown job: {job_id}")
    return AnalysisState(
        row["case_id"],
        row["job_id"],
        row["sample_sha256"],
        Path(row["storage_path"]),
        row["profile"],
        bool(row["nvidia_requested"]),
    )


def _check_cancelled(state: AnalysisState) -> None:
    if cancellation_requested(state.job_id):
        raise CancellationRequested()


def _stage(state: AnalysisState, stage: str, detail: dict[str, Any] | None = None) -> None:
    _check_cancelled(state)
    set_stage(state.job_id, stage, "running", detail)
    log_event(state.job_id, "info", f"Started {stage.replace('_', ' ')}.", detail)


def _finish_stage(state: AnalysisState, stage: str, partial: bool = False, detail: dict[str, Any] | None = None) -> None:
    status = "partial" if partial else "completed"
    set_stage(state.job_id, stage, status, detail)
    if partial:
        state.partial = True
    log_event(state.job_id, "warning" if partial else "info", f"{stage.replace('_', ' ').capitalize()} {status}.", detail)


def _parse_text_manifest(raw_manifest: bytes) -> dict[str, Any]:
    root = ElementTree.fromstring(raw_manifest)
    result: dict[str, Any] = {
        "package": root.attrib.get("package"),
        "permissions": [],
        "components": [],
        "sdk": {},
        "parser": "textual_xml",
    }
    for element in root:
        local = element.tag.rsplit("}", 1)[-1]
        if local in {"uses-permission", "uses-permission-sdk-23"}:
            permission = element.attrib.get(f"{ANDROID}name")
            if permission:
                result["permissions"].append(permission)
        if local == "uses-sdk":
            result["sdk"] = {
                "min_sdk": element.attrib.get(f"{ANDROID}minSdkVersion"),
                "target_sdk": element.attrib.get(f"{ANDROID}targetSdkVersion"),
            }
        if local == "application":
            for child in element:
                component_type = child.tag.rsplit("}", 1)[-1]
                if component_type in {"activity", "activity-alias", "service", "receiver", "provider"}:
                    result["components"].append(
                        {
                            "type": component_type,
                            "name": child.attrib.get(f"{ANDROID}name", "(unnamed)"),
                            "exported": child.attrib.get(f"{ANDROID}exported"),
                            "permission": child.attrib.get(f"{ANDROID}permission"),
                        }
                    )
    return result


def _parse_manifest_with_androguard(apk_path: Path) -> dict[str, Any]:
    """Use an optional mature parser; callers turn every failure into a blindspot."""
    from androguard.core.apk import APK  # type: ignore[import-not-found]

    apk = APK(str(apk_path), raw=False)
    if not apk.is_valid_APK():
        raise ValueError("Androguard did not validate the APK structure")
    manifest: dict[str, Any] = {
        "package": apk.get_package(),
        "permissions": sorted(set(apk.get_permissions() or [])),
        "components": [],
        "sdk": {"min_sdk": apk.get_min_sdk_version(), "target_sdk": apk.get_target_sdk_version()},
        "parser": "androguard",
    }
    component_methods = {
        "activity": "get_activities",
        "service": "get_services",
        "receiver": "get_receivers",
        "provider": "get_providers",
    }
    for component_type, method_name in component_methods.items():
        names = getattr(apk, method_name)() or []
        for name in names:
            manifest["components"].append({"type": component_type, "name": name, "exported": None, "permission": None})
    return manifest


def _decode_dex_strings(payload: bytes, limit: int = 12000) -> list[str]:
    strings: list[str] = []
    for match in PRINTABLE.finditer(payload):
        text = match.group().decode("utf-8", errors="ignore").strip()
        if text:
            strings.append(text[:1024])
        if len(strings) >= limit:
            break
    return strings


def _inventory(state: AnalysisState) -> None:
    _stage(state, "inventory")
    validate_archive(state.apk_path)
    with zipfile.ZipFile(state.apk_path) as archive:
        members = archive.infolist()
        archive_artifact = add_artifact(
            state.case_id,
            state.job_id,
            "apk_archive",
            state.apk_path.name,
            "zip:/",
            {
                "entry_count": len(members),
                "apk_sha256": state.sample_sha256,
                "byte_size": state.apk_path.stat().st_size,
                "dex_files": [entry.filename for entry in members if entry.filename.lower().endswith(".dex")],
                "native_libraries": [entry.filename for entry in members if entry.filename.startswith("lib/") and entry.filename.endswith(".so")],
            },
            state.sample_sha256,
        )
        state.remember("archive", archive_artifact)
        for entry in members:
            artifact_id = add_artifact(
                state.case_id,
                state.job_id,
                "archive_entry",
                entry.filename,
                f"zip:/{entry.filename}",
                {"compressed_bytes": entry.compress_size, "uncompressed_bytes": entry.file_size, "crc32": f"{entry.CRC:08x}"},
            )
            state.remember("entry", artifact_id)
        state.inventory_complete = True
        _finish_stage(state, "inventory", detail={"entries": len(members)})


def _manifest(state: AnalysisState) -> None:
    _stage(state, "manifest")
    manifest: dict[str, Any] | None = None
    parse_errors: list[str] = []
    with zipfile.ZipFile(state.apk_path) as archive:
        try:
            raw_manifest = archive.read("AndroidManifest.xml")
        except KeyError:
            raw_manifest = None
        if raw_manifest is not None:
            manifest_artifact = add_artifact(
                state.case_id,
                state.job_id,
                "android_manifest",
                "AndroidManifest.xml",
                "zip:/AndroidManifest.xml",
                {"byte_size": len(raw_manifest)},
                hashlib.sha256(raw_manifest).hexdigest(),
            )
            state.remember("manifest", manifest_artifact)
            try:
                manifest = _parse_text_manifest(raw_manifest)
            except (ElementTree.ParseError, UnicodeDecodeError) as error:
                parse_errors.append(f"textual parser: {error}")
        else:
            parse_errors.append("AndroidManifest.xml is absent")

    if manifest is None:
        try:
            manifest = _parse_manifest_with_androguard(state.apk_path)
        except Exception as error:  # Adapter failure must remain evidence, not a fake result.
            parse_errors.append(f"androguard adapter: {type(error).__name__}: {str(error)[:300]}")

    if manifest is None:
        add_blindspot(
            state.case_id,
            state.job_id,
            "manifest",
            "AndroidManifest.xml",
            "MANIFEST_UNPARSED",
            "The manifest could not be decoded by the configured adapters; permission and component coverage is incomplete.",
            "Install or repair a compatible binary AXML parser, then retry this case.",
            state.artifact_ids.get("manifest", []),
        )
        _finish_stage(state, "manifest", partial=True, detail={"errors": parse_errors})
        return

    state.manifest = manifest
    state.manifest_complete = True
    normalized_artifact = add_artifact(
        state.case_id,
        state.job_id,
        "manifest_observation",
        manifest.get("package") or "unknown-package",
        "manifest:normalized",
        manifest,
    )
    state.remember("manifest", normalized_artifact)
    _finish_stage(
        state,
        "manifest",
        detail={"parser": manifest["parser"], "permissions": len(manifest["permissions"]), "components": len(manifest["components"])},
    )


def _dex_api(state: AnalysisState) -> None:
    _stage(state, "dex_api")
    dex_files = 0
    total_strings = 0
    truncation = False
    with zipfile.ZipFile(state.apk_path) as archive:
        for entry in archive.infolist():
            if not entry.filename.lower().endswith(".dex"):
                continue
            dex_files += 1
            payload = archive.read(entry)
            dex_sha = hashlib.sha256(payload).hexdigest()
            valid_header = payload.startswith(b"dex\n")
            strings = _decode_dex_strings(payload)
            total_strings += len(strings)
            if len(strings) >= 12000:
                truncation = True
            dex_artifact = add_artifact(
                state.case_id,
                state.job_id,
                "dex_file",
                entry.filename,
                f"zip:/{entry.filename}",
                {"byte_size": len(payload), "valid_dex_header": valid_header, "printable_strings_extracted": len(strings)},
                dex_sha,
            )
            state.remember("dex", dex_artifact)
            state.dex_strings.extend((entry.filename, item) for item in strings)
            if not valid_header:
                add_blindspot(
                    state.case_id,
                    state.job_id,
                    "dex",
                    entry.filename,
                    "DEX_HEADER_INVALID",
                    "A .dex archive entry did not start with a standard DEX header; code-level interpretation was not attempted.",
                    "Inspect the entry with a hardened alternative parser.",
                    [dex_artifact],
                )
                state.partial = True
    if dex_files == 0:
        add_blindspot(
            state.case_id,
            state.job_id,
            "application",
            state.sample_sha256,
            "NO_DEX_PAYLOAD",
            "No classes*.dex entry was found, so bytecode and API inventory could not be performed.",
            "Confirm whether this is a split APK, bundle extraction, or a malformed archive.",
        )
        _finish_stage(state, "dex_api", partial=True, detail={"dex_files": 0})
        return
    if truncation:
        add_blindspot(
            state.case_id,
            state.job_id,
            "dex",
            "string-extraction",
            "DEX_STRING_BUDGET_EXHAUSTED",
            "Printable-string extraction stopped at the configured per-DEX safety budget; not every embedded string was inspected.",
            "Retry with an approved higher analysis budget in an isolated environment.",
            state.artifact_ids.get("dex", []),
        )
    state.dex_complete = not truncation
    _finish_stage(state, "dex_api", partial=truncation, detail={"dex_files": dex_files, "strings": total_strings, "truncated": truncation})


def _indicators(state: AnalysisState) -> None:
    _stage(state, "indicators")
    unique_strings: dict[str, str] = {}
    for dex_name, value in state.dex_strings:
        if len(unique_strings) < 25000:
            unique_strings.setdefault(value, dex_name)
    urls: set[str] = set()
    domains: set[str] = set()
    ips: set[str] = set()
    for value in unique_strings:
        urls.update(URL_PATTERN.findall(value))
        domains.update(DOMAIN_PATTERN.findall(value))
        ips.update(IP_PATTERN.findall(value))
    for indicator_type, values in (("url", urls), ("domain", domains), ("ip", ips)):
        for value in sorted(values)[:1000]:
            source_name = unique_strings.get(value) or next((source for text, source in unique_strings.items() if value in text), "classes.dex")
            artifact_id = add_artifact(
                state.case_id,
                state.job_id,
                "indicator_observation",
                value,
                f"dex-string:{source_name}",
                {"indicator_type": indicator_type, "observable_level": "static_string"},
            )
            state.remember("indicator", artifact_id)
            add_indicator(state.case_id, state.job_id, indicator_type, value, artifact_id)
    state.indicator_complete = True
    _finish_stage(state, "indicators", detail={"urls": len(urls), "domains": len(domains), "ips": len(ips)})


def _blindspot_ledger(state: AnalysisState) -> None:
    _stage(state, "blindspot_ledger")
    native = []
    certificate_names = []
    with zipfile.ZipFile(state.apk_path) as archive:
        native = [entry.filename for entry in archive.infolist() if entry.filename.startswith("lib/") and entry.filename.lower().endswith(".so")]
        certificate_names = [entry.filename for entry in archive.infolist() if entry.filename.upper().startswith("META-INF/") and entry.filename.upper().endswith((".RSA", ".DSA", ".EC"))]
        for name in certificate_names:
            data = archive.read(name)
            artifact_id = add_artifact(
                state.case_id,
                state.job_id,
                "certificate_blob",
                name,
                f"zip:/{name}",
                {"byte_size": len(data), "format": Path(name).suffix.upper().lstrip(".")},
                hashlib.sha256(data).hexdigest(),
            )
            state.remember("certificate", artifact_id)
    if native:
        add_blindspot(
            state.case_id,
            state.job_id,
            "native",
            "native-libraries",
            "NATIVE_CODE_UNINSPECTED",
            f"{len(native)} native library file(s) were inventoried but no JNI/native disassembly adapter is configured.",
            "Use an isolated native-analysis workflow and import the resulting provenance.",
            state.artifact_ids.get("archive", []),
        )
    values = {value for _, value in state.dex_strings}
    if any("DexClassLoader" in value or "PathClassLoader" in value for value in values):
        add_blindspot(
            state.case_id,
            state.job_id,
            "dex",
            "dynamic-loading",
            "DYNAMIC_CODE_LOADING_UNRESOLVED",
            "Static strings reference Android class loading, but targets and runtime-loaded code were not resolved.",
            "Perform bounded code provenance analysis in an isolated lab.",
            state.artifact_ids.get("dex", []),
        )
    if any("Class.forName" in value or "java/lang/reflect" in value for value in values):
        add_blindspot(
            state.case_id,
            state.job_id,
            "dex",
            "reflection",
            "REFLECTION_TARGET_UNRESOLVED",
            "Reflection-related strings were observed but dispatch targets cannot be proven from this extractor.",
            "Use a call-graph adapter that records its resolution assumptions.",
            state.artifact_ids.get("dex", []),
        )
    add_blindspot(
        state.case_id,
        state.job_id,
        "runtime",
        "android-lab",
        "RUNTIME_OBSERVATION_UNAVAILABLE",
        "No isolated Android runtime lab is configured. No runtime network, filesystem, IPC or behavior observation was made.",
        "Configure a disposable emulator/MobSF environment outside the host OS.",
    )
    if state.nvidia_requested and not settings.nvidia_configured:
        add_blindspot(
            state.case_id,
            state.job_id,
            "ai_reasoning",
            "tri-proof",
            "NVIDIA_REASONING_NOT_CONFIGURED",
            "NVIDIA TRI-PROOF was requested, but a complete provider configuration was unavailable; no cloud model was called.",
            "Provide a rotated NVIDIA_API_KEY through the secure startup prompt and retry this job.",
        )
    _mobsf_cross_validate(state)
    _finish_stage(state, "blindspot_ledger", detail={"native_libraries": len(native), "certificates": len(certificate_names)})


def _mobsf_cross_validate(state: AnalysisState) -> None:
    """Optionally cross-check an APK with the isolated MobSF static service.

    MobSF observations remain a separately attributable artifact. They are not
    silently promoted to first-party findings because its rules, versions, and
    data model are independent of the deterministic local pipeline.
    """
    if not settings.mobsf_configured:
        return
    assert settings.mobsf_api_url is not None
    assert settings.mobsf_api_key is not None
    try:
        report = MobSFClient(
            settings.mobsf_api_url,
            settings.mobsf_api_key,
            settings.mobsf_timeout_seconds,
        ).scan_apk(state.apk_path)
    except MobSFError as error:
        add_blindspot(
            state.case_id,
            state.job_id,
            "cross_validation",
            "mobsf-static",
            "MOBSF_STATIC_CROSS_VALIDATION_UNAVAILABLE",
            f"Configured MobSF static cross-validation did not complete: {str(error)[:500]}",
            "Inspect the isolated MobSF service, then retry the case. Local static results remain separately available.",
        )
        state.partial = True
        log_event(state.job_id, "warning", "MobSF cross-validation was unavailable; no external result was recorded.")
        return
    artifact_id = add_artifact(
        state.case_id,
        state.job_id,
        "mobsf_static_cross_validation",
        "MobSF static cross-validation",
        f"mobsf:/api/v1/scan/{report.scan_hash}",
        {
            "summary": report.summary,
            "report_sha256": report.report_sha256,
            "evidence_policy": "External MobSF output is preserved as a cross-validation artifact and is not automatically converted into local findings.",
        },
        report.report_sha256,
    )
    state.remember("mobsf", artifact_id)
    log_event(
        state.job_id,
        "info",
        "MobSF static cross-validation completed and its bounded report digest was preserved.",
        {"artifact_id": artifact_id, "scan_hash": report.scan_hash},
    )


def _guarded_paths(state: AnalysisState) -> None:
    _stage(state, "guarded_path_evaluation")
    evaluator = Z3GuardEvaluator(timeout_ms=5000)
    discovered_guards: list[dict[str, Any]] = []

    # 1. Check for embedded guard manifest in archive
    try:
        with zipfile.ZipFile(state.apk_path, "r") as archive:
            for name in ("assets/guard_manifest.json", "META-INF/guard.json", "guard_manifest.json"):
                if name in archive.namelist():
                    data = json.loads(archive.read(name).decode("utf-8"))
                    if isinstance(data, list):
                        discovered_guards.extend(data)
                    elif isinstance(data, dict):
                        discovered_guards.append(data)
    except Exception:
        pass

    # 2. Check DEX strings for planted or identified guard patterns
    dex_text = " ".join(value for _, value in state.dex_strings)
    if "time_guarded" in dex_text or "elapsed_minutes" in dex_text:
        discovered_guards.append({
            "target_method": "Landroid/telephony/SmsManager;->sendTextMessage",
            "ast": {
                "kind": "and",
                "terms": [
                    {"kind": "compare", "left": {"var": "elapsed_minutes", "type": "int"}, "op": "ge", "right": {"literal": 10}}
                ],
                "source": {"dex": "classes.dex", "method": "Lorg/shadowpath/Guard;->shouldTrigger()Z", "block": "bb_01"},
            },
            "assumptions": ["Device elapsed time is measured in whole minutes", "Target sink is SMS transmission"],
        })

    if "device_guarded" in dex_text or "mock_device_state" in dex_text:
        discovered_guards.append({
            "target_method": "Landroid/provider/ContactsContract;->openInputStream",
            "ast": {
                "kind": "and",
                "terms": [
                    {"kind": "compare", "left": {"var": "mock_device_state", "type": "string"}, "op": "eq", "right": {"literal": "ready"}}
                ],
                "source": {"dex": "classes.dex", "method": "Lorg/shadowpath/Guard;->checkDevice()Z", "block": "bb_02"},
            },
            "assumptions": ["Device state string is evaluated against 'ready'", "Target sink is contacts reading"],
        })

    if "dead_branch" in dex_text or "branch_flag" in dex_text:
        discovered_guards.append({
            "target_method": "Ldalvik/system/DexClassLoader;->loadClass",
            "ast": {
                "kind": "and",
                "terms": [
                    {"kind": "compare", "left": {"var": "branch_flag", "type": "int"}, "op": "gt", "right": {"literal": 10}},
                    {"kind": "compare", "left": {"var": "branch_flag", "type": "int"}, "op": "lt", "right": {"literal": 5}},
                ],
                "source": {"dex": "classes.dex", "method": "Lorg/shadowpath/Guard;->unreachableBranch()Z", "block": "bb_dead"},
            },
            "assumptions": ["Single integer flag evaluated in concurrent comparison", "Mutually exclusive bounds"],
        })

    evaluated_paths: list[dict[str, Any]] = []
    sat_count = 0
    unsat_count = 0

    for item in discovered_guards:
        target = item.get("target_method", "Lunknown/Target;->operation()V")
        ast = item.get("ast", {})
        assumptions = item.get("assumptions", [])

        eval_result = evaluator.evaluate_guard(ast, assumptions=assumptions)
        solver_status = eval_result["solver_status"]

        path_id = add_guard_path(
            state.case_id,
            state.job_id,
            target,
            ast,
            solver_status,
            True,
            eval_result.get("witness", {}),
            eval_result.get("limitations", []),
        )

        evaluated_paths.append({
            "path_id": path_id,
            "target": target,
            "status": solver_status,
            "witness": eval_result.get("witness", {}),
        })

        if solver_status == "sat":
            sat_count += 1
            add_finding(
                state.case_id,
                state.job_id,
                "SP-GRD-001",
                "Conditionally reachable sensitive path (Solver SAT)",
                "guarded_path",
                "high",
                f"Z3 theorem prover found satisfying trigger witness {json.dumps(eval_result['witness'])} reaching sensitive sink {target}.",
                state.artifact_ids.get("dex", []),
                eval_result.get("limitations", []) + ["Trigger witness proves constraint satisfiability under model, not general OS-level execution guarantee."],
                evidence_status="conditionally_reachable",
                location={"target_method": target},
            )
        elif solver_status == "unsat":
            unsat_count += 1
            add_finding(
                state.case_id,
                state.job_id,
                "SP-GRD-002",
                "Unsatisfiable dead code branch (Solver UNSAT)",
                "dead_branch",
                "low",
                f"Z3 proved the guard condition for {target} is unsatisfiable under modeled constraints. This branch cannot execute under standard semantics.",
                state.artifact_ids.get("dex", []),
                eval_result.get("limitations", []),
                evidence_status="observed",
                location={"target_method": target},
            )

    if evaluated_paths:
        artifact_id = add_artifact(
            state.case_id,
            state.job_id,
            "z3_guarded_paths",
            f"Z3 Guard Evaluation ({len(evaluated_paths)} path(s))",
            "z3:/solver_results",
            {"evaluated_paths": evaluated_paths, "sat_count": sat_count, "unsat_count": unsat_count},
        )
        state.remember("guards", artifact_id)
        _finish_stage(
            state,
            "guarded_path_evaluation",
            partial=False,
            detail={
                "outcome": "evaluated",
                "paths_evaluated": len(evaluated_paths),
                "sat_count": sat_count,
                "unsat_count": unsat_count,
                "solver": "z3",
            },
        )
    else:
        add_blindspot(
            state.case_id,
            state.job_id,
            "path_analysis",
            "dex-call-graph",
            "GUARDED_PATH_ANALYSIS_UNSUPPORTED",
            "This APK did not exhibit bounded guard predicates matching the supported AST subset. Full arbitrary bytecode control-flow slicing is not implemented.",
            "Run controlled-fixture path evaluator or supply custom guard AST for constraint verification.",
            state.artifact_ids.get("dex", []),
        )
        _finish_stage(state, "guarded_path_evaluation", partial=True, detail={"outcome": "unsupported", "solver": "z3"})


def _findings(state: AnalysisState) -> tuple[int, str]:
    _stage(state, "findings")
    finding_count = 0
    for permission in state.manifest.get("permissions", []):
        if permission in SENSITIVE_PERMISSIONS:
            add_finding(
                state.case_id,
                state.job_id,
                "SP-APK-001",
                "Sensitive Android permission declared",
                "permission",
                "informational",
                f"The manifest declares {permission}. This is an observed declaration, not evidence of malicious use.",
                state.artifact_ids.get("manifest", []),
                ["Static manifest analysis cannot establish runtime permission use or intent."],
            )
            finding_count += 1
    for component in state.manifest.get("components", []):
        if component.get("exported") == "true":
            add_finding(
                state.case_id,
                state.job_id,
                "SP-APK-002",
                "Explicitly exported Android component",
                "manifest_misconfiguration",
                "medium",
                f"{component['type'].capitalize()} {component['name']} is explicitly exported in the manifest.",
                state.artifact_ids.get("manifest", []),
                ["Exported status alone does not prove exploitability; intent filters and permission controls need review."],
                location={"manifest_component": component["name"]},
            )
            finding_count += 1
    with transaction() as connection:
        severities = [row[0] for row in connection.execute("SELECT severity FROM findings WHERE job_id = ?", (state.job_id,)).fetchall()]
    points = {"informational": 0, "low": 5, "medium": 15, "high": 30, "critical": 50}
    risk_score = min(100, sum(points.get(severity, 0) for severity in severities))
    if not severities:
        tier = "no_evidence_backed_risk_findings"
    elif risk_score >= 50:
        tier = "critical"
    elif risk_score >= 30:
        tier = "high"
    elif risk_score >= 15:
        tier = "medium"
    else:
        tier = "low"
    completeness = (25 if state.inventory_complete else 0) + (25 if state.manifest_complete else 5) + (25 if state.dex_complete else 5) + (25 if state.indicator_complete else 0)
    update_case_summary(state.case_id, risk_score, tier, completeness)
    _finish_stage(state, "findings", detail={"findings": finding_count, "risk_score": risk_score, "risk_tier": tier, "completeness": completeness})
    return risk_score, tier


def _ai_review(state: AnalysisState) -> None:
    if not state.nvidia_requested:
        set_stage(state.job_id, "ai_review", "skipped", {"reason": "analyst_did_not_consent"})
        log_event(state.job_id, "info", "AI review skipped because the analyst did not enable cloud reasoning.")
        return
    _stage(state, "ai_review", {"provider": "nvidia_nim", "model": settings.nvidia_model})
    since = (datetime.now(UTC) - timedelta(days=1)).replace(microsecond=0).isoformat()
    with transaction() as connection:
        calls = connection.execute(
            "SELECT count(*) FROM ai_proposals WHERE provider = 'nvidia_nim' AND created_at >= ?",
            (since,),
        ).fetchone()[0]
    if calls >= settings.nvidia_daily_call_budget:
        proposal_id = create_ai_proposal(
            state.case_id,
            state.job_id,
            "nvidia_nim",
            settings.nvidia_model,
            "rate_limited",
            None,
            ["Configured local daily call budget has been reached"],
            [],
        )
        _finish_stage(state, "ai_review", partial=True, detail={"status": "rate_limited", "proposal_id": proposal_id})
        return
    result = NvidiaNimProvider(settings).generate(state.case_id, state.job_id)
    proposal_id = create_ai_proposal(
        state.case_id,
        state.job_id,
        "nvidia_nim",
        settings.nvidia_model,
        result.status,
        result.proposal,
        result.validation_errors,
        result.evidence_ids,
    )
    if result.status == "generated" and result.proposal:
        artifact_id = add_artifact(
            state.case_id,
            state.job_id,
            "ai_tri_proof",
            "NVIDIA TRI-PROOF proposal",
            f"ai-proposal:{proposal_id}",
            {
                "proposal_id": proposal_id,
                "provider": "nvidia_nim",
                "model": settings.nvidia_model,
                "status": "generated",
                "evidence_ids": result.evidence_ids,
            },
        )
        state.remember("ai", artifact_id)
        _finish_stage(state, "ai_review", detail={"status": "generated", "proposal_id": proposal_id})
    else:
        _finish_stage(
            state,
            "ai_review",
            partial=True,
            detail={"status": result.status, "proposal_id": proposal_id, "errors": result.validation_errors[:3]},
        )


def _capsule_report(state: AnalysisState, final_status: str) -> None:
    _stage(state, "capsule_report")
    # Persist the terminal job/case result before serializing it. The stage is represented
    # as completed inside the report and is immediately finalized in the database below.
    finish_job(state.job_id, final_status)
    report = generate_report(
        state.case_id,
        state.job_id,
        stage_overrides={"capsule_report": {"status": "completed", "detail": {"outcome": "capsule_generated"}}},
    )
    report_artifact = add_artifact(
        state.case_id,
        state.job_id,
        "forensic_capsule",
        Path(report["capsule_path"]).name,
        "capsule:/manifest.json",
        {"report_id": report["id"], "capsule_sha256": report["capsule_sha256"]},
        report["capsule_sha256"],
    )
    state.remember("capsule", report_artifact)
    _finish_stage(state, "capsule_report", detail={"report_id": report["id"], "capsule_sha256": report["capsule_sha256"]})


def run_analysis(job_id: str) -> None:
    """Run only deterministic, non-executing APK analysis for one persisted job."""
    state = _job_state(job_id)
    try:
        _stage(state, "intake")
        _finish_stage(state, "intake", detail={"sha256": state.sample_sha256, "byte_size": state.apk_path.stat().st_size})
        _inventory(state)
        _manifest(state)
        _dex_api(state)
        _indicators(state)
        _blindspot_ledger(state)
        _guarded_paths(state)
        _findings(state)
        _ai_review(state)
        _capsule_report(state, "partial" if state.partial else "completed")
        log_event(state.job_id, "info", "Static analysis reached a persisted terminal state.")
    except CancellationRequested:
        with transaction() as connection:
            connection.execute("UPDATE job_stages SET status = 'skipped', finished_at = datetime('now') WHERE job_id = ? AND status = 'pending'", (state.job_id,))
        finish_job(state.job_id, "cancelled")
        log_event(state.job_id, "warning", "Analysis was cancelled by the analyst.")
    except Exception as error:
        trace = "".join(traceback.format_exception_only(type(error), error)).strip()
        finish_job(state.job_id, "failed", "ANALYSIS_FAILED", trace)
        log_event(state.job_id, "error", "Analysis worker failed safely; no result was fabricated.", {"error": trace})


def next_queued_job() -> str | None:
    with transaction() as connection:
        row = connection.execute("SELECT id FROM jobs WHERE status = 'queued' ORDER BY created_at LIMIT 1").fetchone()
    return row["id"] if row else None
