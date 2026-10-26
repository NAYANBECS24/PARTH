from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_isolated(script: str, tmp_path: Path) -> dict:
    environment = os.environ.copy()
    environment["SHADOWPATH_DATA_DIR"] = str(tmp_path / "data")
    environment["SHADOWPATH_DATABASE_URL"] = str(tmp_path / "data" / "shadowpath.db")
    environment["SHADOWPATH_AUTH_DISABLED"] = "false"
    environment["SHADOWPATH_ENABLE_NVIDIA"] = "false"
    environment["SHADOWPATH_DISABLE_MOBSF"] = "true"
    environment["VIRUSTOTAL_API_KEY"] = ""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(completed.stdout.splitlines()[-1])


def test_text_manifest_apk_yields_evidence_and_verifiable_capsule(tmp_path: Path) -> None:
    result = run_isolated(
        """
import hashlib, json, zipfile
from pathlib import Path
from backend.config import settings
from backend.database import initialise_database, transaction
from backend.intake import StoredUpload
from backend.repository import create_case_and_job
from backend.analyzer import run_analysis
from backend.reports import verify_capsule

initialise_database()
apk = settings.upload_dir / 'fixture.apk'
manifest = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="test.fixture"><uses-permission android:name="android.permission.SEND_SMS"/><application><activity android:name=".OpenActivity" android:exported="true"/></application></manifest>'''
dex = b'dex\\n035\\x00' + b'https://lab.example.test/path DexClassLoader Class.forName '
with zipfile.ZipFile(apk, 'w') as archive:
    archive.writestr('AndroidManifest.xml', manifest)
    archive.writestr('classes.dex', dex)
    archive.writestr('META-INF/CERT.RSA', b'controlled-certificate')
sha = hashlib.sha256(apk.read_bytes()).hexdigest()
target = settings.upload_dir / f'{sha}.apk'
apk.rename(target)
upload = StoredUpload(sha, target.stat().st_size, 'fixture.apk', target, 3)
case_id, job_id, _ = create_case_and_job(upload, 'Controlled manifest fixture', '', 'standard', False, False)
run_analysis(job_id)
with transaction() as connection:
    job = dict(connection.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone())
    findings = connection.execute('SELECT count(*) FROM findings WHERE job_id = ?', (job_id,)).fetchone()[0]
    blindspots = connection.execute('SELECT count(*) FROM blindspots WHERE job_id = ?', (job_id,)).fetchone()[0]
    report = dict(connection.execute('SELECT capsule_path FROM reports WHERE job_id = ?', (job_id,)).fetchone())
print(json.dumps({'job': job['status'], 'findings': findings, 'blindspots': blindspots, 'verification': verify_capsule(report['capsule_path'])['valid']}))
""",
        tmp_path,
    )
    assert result["job"] == "partial"
    assert result["findings"] >= 2
    assert result["blindspots"] >= 3
    assert result["verification"] is True


def test_static_behavior_rules_preserve_technique_and_signal_evidence(tmp_path: Path) -> None:
    result = run_isolated(
        """
import hashlib, json, zipfile
from pathlib import Path
from backend.config import settings
from backend.database import initialise_database, transaction
from backend.intake import StoredUpload
from backend.repository import create_case_and_job
from backend.analyzer import run_analysis

initialise_database()
apk = settings.upload_dir / 'behavior-fixture.apk'
manifest = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="behavior.fixture"><uses-permission android:name="android.permission.SEND_SMS"/><uses-permission android:name="android.permission.SYSTEM_ALERT_WINDOW"/><application/></manifest>'''
dex = b'dex\\n035\\x00 SmsManager sendTextMessage DexClassLoader PathClassLoader AccessibilityService onAccessibilityEvent TYPE_VIEW_TEXT_CHANGED MediaProjection createVirtualDisplay TYPE_APPLICATION_OVERLAY frida '
with zipfile.ZipFile(apk, 'w') as archive:
    archive.writestr('AndroidManifest.xml', manifest)
    archive.writestr('classes.dex', dex)
sha = hashlib.sha256(apk.read_bytes()).hexdigest()
target = settings.upload_dir / f'{sha}.apk'
apk.rename(target)
upload = StoredUpload(sha, target.stat().st_size, 'behavior-fixture.apk', target, 2)
case_id, job_id, _ = create_case_and_job(upload, 'Static behavior fixture', '', 'standard', False, False)
run_analysis(job_id)
with transaction() as connection:
    rows = connection.execute("SELECT rule_id, evidence_status, location_json FROM findings WHERE job_id = ? AND rule_id >= 'SP-APK-101' ORDER BY rule_id", (job_id,)).fetchall()
records = {row['rule_id']: {'status': row['evidence_status'], 'location': json.loads(row['location_json'])} for row in rows}
print(json.dumps(records))
""",
        tmp_path,
    )
    assert set(result) == {
        "SP-APK-101",
        "SP-APK-102",
        "SP-APK-103",
        "SP-APK-104",
        "SP-APK-105",
        "SP-APK-106",
        "SP-APK-107",
    }
    assert result["SP-APK-101"]["status"] == "observed"
    assert result["SP-APK-101"]["location"]["technique"]["id"] == "T1407"
    assert result["SP-APK-103"]["location"]["technique"]["id"] == "T1417.001"
    assert result["SP-APK-104"]["location"]["matched_permissions"] == ["android.permission.SEND_SMS"]
    assert result["SP-APK-107"]["location"]["confidence"] == "low"


def test_source_workspace_and_cross_case_intelligence_are_bounded(tmp_path: Path) -> None:
    result = run_isolated(
        """
import hashlib, json
from pathlib import Path
from backend.config import settings
from backend.database import initialise_database
from backend.intake import StoredUpload
from backend.repository import add_artifact, add_finding, add_indicator, create_case_and_job
from backend.api import intelligence_correlations
from backend.source_workspace import JadxSourceWorkspace, SourceWorkspaceError
from backend.threat_intel import ThreatIntelError, VirusTotalClient

initialise_database()
def case(name):
    content = name.encode()
    sha = hashlib.sha256(content).hexdigest()
    path = settings.upload_dir / f'{sha}.apk'
    path.write_bytes(content)
    upload = StoredUpload(sha, len(content), f'{name}.apk', path, 1)
    return create_case_and_job(upload, name, '', 'standard', False, False)[:2], sha

(left, left_sha) = case('left')
(right, right_sha) = case('right')
left_case, left_job = left
right_case, right_job = right
for case_id, job_id in ((left_case, left_job), (right_case, right_job)):
    artifact = add_artifact(case_id, job_id, 'indicator_observation', 'shared.example.test', 'dex-string:classes.dex', {'indicator_type': 'domain'})
    add_indicator(case_id, job_id, 'domain', 'shared.example.test', artifact)
    add_finding(case_id, job_id, 'SP-APK-101', 'Dynamic code-loading API referenced', 'dynamic_code_loading', 'medium', 'fixture', [artifact])

root = settings.source_workspace_dir / left_sha / 'sources' / 'fixture'
root.mkdir(parents=True, exist_ok=True)
(root / 'Recovered.java').write_text('class Recovered { void inspect() {} }', encoding='utf-8')
status = JadxSourceWorkspace.status(left_sha)
content = JadxSourceWorkspace.read(left_sha, 'fixture/Recovered.java')
blocked = False
try:
    JadxSourceWorkspace.read(left_sha, '../outside.java')
except SourceWorkspaceError:
    blocked = True
vt_blocked = False
try:
    VirusTotalClient().lookup_file(left_sha)
except ThreatIntelError:
    vt_blocked = True
relationships = intelligence_correlations(limit=60)
print(json.dumps({
    'generated': status['generated'],
    'file_count': len(status['files']),
    'content': content['content'],
    'traversal_blocked': blocked,
    'vt_blocked_without_key': vt_blocked,
    'relationship_kinds': sorted({item['kind'] for item in relationships['items']}),
}))
""",
        tmp_path,
    )
    assert result["generated"] is True
    assert result["file_count"] == 1
    assert "class Recovered" in result["content"]
    assert result["traversal_blocked"] is True
    assert result["vt_blocked_without_key"] is True
    assert result["relationship_kinds"] == ["indicator", "rule"]


def test_invalid_archive_is_rejected(tmp_path: Path) -> None:
    result = run_isolated(
        """
import json
from pathlib import Path
from fastapi import HTTPException
from backend.config import settings
from backend.intake import validate_archive

bad = settings.upload_dir / 'not-an-apk.apk'
bad.write_bytes(b'PK\\x03\\x04not-a-real-zip')
try:
    validate_archive(bad)
except HTTPException as error:
    print(json.dumps({'status': error.status_code, 'code': error.detail['code']}))
""",
        tmp_path,
    )
    assert result == {"status": 422, "code": "invalid_apk"}


def test_api_import_initialises_database_before_the_first_request(tmp_path: Path) -> None:
    result = run_isolated(
        """
import json
from backend.api import app
from backend.auth import bootstrap_required

print(json.dumps({'title': app.title, 'bootstrap_required': bootstrap_required()}))
""",
        tmp_path,
    )
    assert result == {"title": "SHADOWPATH Ω — NEXUS API", "bootstrap_required": True}


def test_vercel_entrypoint_uses_serverless_storage(tmp_path: Path) -> None:
    result = run_isolated(
        """
import json
import os

os.environ['VERCEL'] = '1'
os.environ['SHADOWPATH_AUTH_DISABLED'] = 'true'
from api.index import app
from backend.config import settings
from backend.database import transaction

with transaction() as connection:
    users_table = connection.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'").fetchone() is not None

print(json.dumps({
    'title': app.title,
    'serverless_data_dir': settings.data_dir.name == 'shadowpath_data' and settings.database_path.parent == settings.data_dir,
    'users_table': users_table,
}))
""",
        tmp_path,
    )
    assert result == {
        "title": "SHADOWPATH Ω — NEXUS API",
        "serverless_data_dir": True,
        "users_table": True,
    }


def test_capsule_verifier_rejects_tampered_content(tmp_path: Path) -> None:
    result = run_isolated(
        """
import json, zipfile
from backend.config import settings
from backend.reports import verify_capsule

capsule = settings.capsule_dir / 'tampered.zip'
with zipfile.ZipFile(capsule, 'w') as archive:
    archive.writestr('report.json', b'tampered')
    archive.writestr('manifest.json', json.dumps({'files': [{'path': 'report.json', 'sha256': '0' * 64}]}))
result = verify_capsule(capsule)
print(json.dumps({'valid': result['valid'], 'failure_path': result['failures'][0]['path']}))
""",
        tmp_path,
    )
    assert result == {"valid": False, "failure_path": "report.json"}


def test_ai_payload_redacts_observables_and_rejects_fabricated_evidence(tmp_path: Path) -> None:
    result = run_isolated(
        """
import hashlib, json, zipfile
from backend.ai_provider import build_sanitized_evidence, validate_proposal
from backend.config import settings
from backend.database import initialise_database
from backend.intake import StoredUpload
from backend.repository import add_artifact, add_finding, add_indicator, create_case_and_job

initialise_database()
apk = settings.upload_dir / 'ai-fixture.apk'
with zipfile.ZipFile(apk, 'w') as archive:
    archive.writestr('AndroidManifest.xml', b'<manifest package="fixture"><application/></manifest>')
sha = hashlib.sha256(apk.read_bytes()).hexdigest()
target = settings.upload_dir / f'{sha}.apk'
apk.rename(target)
case_id, job_id, _ = create_case_and_job(StoredUpload(sha, target.stat().st_size, 'ai-fixture.apk', target, 1), 'AI fixture', 'private note', 'standard', False, False)
artifact_id = add_artifact(case_id, job_id, 'dex_strings', 'classes.dex', 'zip:classes.dex', {'raw': 'DO NOT SEND'})
finding_id = add_finding(case_id, job_id, 'RULE.TEST', 'Test', 'test', 'low', 'Observed test', [artifact_id])
secret = 'https://private.example/path?token=top-secret'
add_indicator(case_id, job_id, 'url', secret, artifact_id)
payload, allowed = build_sanitized_evidence(case_id, job_id)
raw = json.dumps(payload)
proposal = json.dumps({'schema_version':'1.0','malicious_hypothesis':{'statement':'Candidate misuse','supporting_evidence_ids':['invented-id'],'contradicting_evidence_ids':[]},'benign_explanation':{'statement':'Possible benign use','supporting_evidence_ids':[finding_id],'contradicting_evidence_ids':[]},'discriminating_test':'Review evidence','proposed_experiment':{'operation_id':'review_manifest_evidence','rationale':'Resolve intent','requires_analyst_approval':True},'notes':'Hypothesis only'})
validated = validate_proposal(proposal, allowed)
valid_proposal = proposal.replace('invented-id', finding_id)
accepted = validate_proposal(valid_proposal, allowed)
print(json.dumps({'raw_secret_absent': secret not in raw, 'raw_artifact_absent': 'DO NOT SEND' not in raw, 'hash_present': hashlib.sha256(secret.encode()).hexdigest()[:16] in raw, 'status': validated.status, 'accepted': accepted.status}))
""",
        tmp_path,
    )
    assert result == {"raw_secret_absent": True, "raw_artifact_absent": True, "hash_present": True, "status": "validation_failed", "accepted": "generated"}


def test_api_intake_worker_and_report_verification(tmp_path: Path) -> None:
    result = run_isolated(
        """
import io, json, zipfile
from fastapi.testclient import TestClient
from backend.api import app
from backend.analyzer import run_analysis

archive = io.BytesIO()
with zipfile.ZipFile(archive, 'w') as apk:
    apk.writestr('AndroidManifest.xml', b'<manifest package="fixture"><application/></manifest>')
    apk.writestr('classes.dex', b'dex\\n035\\x00https://api.fixture.test')

with TestClient(app) as client:
    unauthenticated_status = client.get('/api/cases').status_code
    bootstrap = client.post('/api/auth/bootstrap', json={'username': 'analyst', 'password': 'controlled-passphrase'}).json()
    headers = {'Authorization': f"Bearer {bootstrap['token']}"}
    nvidia_unavailable_status = client.post('/api/cases/intake', headers=headers, files={'file': ('api-fixture.apk', archive.getvalue(), 'application/vnd.android.package-archive')}, data={'case_name': 'AI request', 'profile': 'standard', 'nvidia_reasoning': 'true', 'isolated_dynamic_lab': 'false'}).status_code
    response = client.post('/api/cases/intake', headers=headers, files={'file': ('api-fixture.apk', archive.getvalue(), 'application/vnd.android.package-archive')}, data={'case_name': 'API fixture', 'profile': 'standard', 'nvidia_reasoning': 'false', 'isolated_dynamic_lab': 'false'})
    response.raise_for_status()
    created = response.json()
    run_analysis(created['job_id'])
    job = client.get(f"/api/jobs/{created['job_id']}", headers=headers).json()
    case = client.get(f"/api/cases/{created['case_id']}", headers=headers).json()
    report_id = case['reports'][0]['id']
    verification = client.post(f'/api/reports/{report_id}/verify', headers=headers).json()
    samples = client.get('/api/samples', headers=headers).json()
    indicators = client.get('/api/indicators', headers=headers).json()
    setting = client.patch('/api/settings', headers=headers, json={'default_profile': 'advanced'}).json()
    retry = client.post(f"/api/jobs/{created['job_id']}/retry", headers=headers).json()
    print(json.dumps({'unauthenticated': unauthenticated_status, 'nvidia_unavailable': nvidia_unavailable_status, 'job': job['job']['status'], 'report_count': len(case['reports']), 'verified': verification['valid'], 'stage_count': len(job['stages']), 'samples': samples['total'], 'indicators': indicators['total'], 'default_profile': setting['values']['default_profile'], 'retry_status': retry['status']}))
""",
        tmp_path,
    )
    assert result == {"unauthenticated": 401, "nvidia_unavailable": 409, "job": "partial", "report_count": 1, "verified": True, "stage_count": 10, "samples": 1, "indicators": 2, "default_profile": "advanced", "retry_status": "queued"}


def test_z3_guard_evaluator_sat_unsat_and_capabilities(tmp_path: Path) -> None:
    result = run_isolated(
        """
import json
from backend.adapters import ReverseEngineeringToolchain, Z3GuardEvaluator

evaluator = Z3GuardEvaluator(timeout_ms=3000)

# 1. SAT guard
sat_ast = {
    "kind": "and",
    "terms": [
        {"kind": "compare", "left": {"var": "elapsed_minutes", "type": "int"}, "op": "ge", "right": {"literal": 10}}
    ]
}
sat_res = evaluator.evaluate_guard(sat_ast)

# 2. UNSAT guard
unsat_ast = {
    "kind": "and",
    "terms": [
        {"kind": "compare", "left": {"var": "branch_flag", "type": "int"}, "op": "gt", "right": {"literal": 10}},
        {"kind": "compare", "left": {"var": "branch_flag", "type": "int"}, "op": "lt", "right": {"literal": 5}}
    ]
}
unsat_res = evaluator.evaluate_guard(unsat_ast)

# 3. Toolchain map
caps = ReverseEngineeringToolchain.capabilities_map()

print(json.dumps({
    'sat_status': sat_res['solver_status'],
    'sat_witness_has_elapsed': 'elapsed_minutes' in sat_res['witness'],
    'unsat_status': unsat_res['solver_status'],
    'has_z3_tool': 'z3_solver' in caps['tools'],
    'has_jadx_tool': 'jadx' in caps['tools'],
    'has_dynamic_lab': 'dynamic_lab' in caps['tools'],
}))
""",
        tmp_path,
    )
    assert result["sat_status"] == "sat"
    assert result["sat_witness_has_elapsed"] is True
    assert result["unsat_status"] == "unsat"
    assert result["has_z3_tool"] is True
    assert result["has_jadx_tool"] is True
    assert result["has_dynamic_lab"] is True


def test_guarded_path_analysis_on_fixture_apk(tmp_path: Path) -> None:
    result = run_isolated(
        """
import hashlib, json, shutil
from pathlib import Path
from backend.config import settings
from backend.database import initialise_database, transaction
from backend.intake import StoredUpload
from backend.repository import create_case_and_job
from backend.analyzer import run_analysis
from backend.reports import verify_capsule

initialise_database()
src_fixture = Path('fixtures/safe-android-apps/time_guarded_sink.apk')
if not src_fixture.exists():
    from scripts.create_safe_fixture import generate_all_fixtures
    generate_all_fixtures()

sha = hashlib.sha256(src_fixture.read_bytes()).hexdigest()
target = settings.upload_dir / f'{sha}.apk'
shutil.copy(src_fixture, target)

upload = StoredUpload(sha, target.stat().st_size, 'time_guarded_sink.apk', target, 4)
case_id, job_id, _ = create_case_and_job(upload, 'Guarded Path Test Case', '', 'standard', False, False)
run_analysis(job_id)

with transaction() as connection:
    job = dict(connection.execute('SELECT status FROM jobs WHERE id = ?', (job_id,)).fetchone())
    guard_paths = connection.execute('SELECT count(*), solver_status FROM guard_paths WHERE job_id = ? GROUP BY solver_status', (job_id,)).fetchall()
    cond_reach = connection.execute("SELECT count(*) FROM findings WHERE job_id = ? AND evidence_status = 'conditionally_reachable'", (job_id,)).fetchone()[0]
    report = dict(connection.execute('SELECT capsule_path, report_pdf_path FROM reports WHERE job_id = ?', (job_id,)).fetchone())

print(json.dumps({
    'job_status': job['status'],
    'guard_path_count': len(guard_paths),
    'cond_reach_count': cond_reach,
    'pdf_exists': Path(report['report_pdf_path']).stat().st_size > 500,
    'capsule_valid': verify_capsule(report['capsule_path'])['valid'],
}))
""",
        tmp_path,
    )
    assert result["guard_path_count"] >= 1
    assert result["cond_reach_count"] >= 1
    assert result["pdf_exists"] is True
    assert result["capsule_valid"] is True


def test_assistant_uses_allowlisted_real_backend_tools_and_persists_chat(tmp_path: Path) -> None:
    result = run_isolated(
        """
import io, json, zipfile
from fastapi.testclient import TestClient
from backend.api import app
from backend.analyzer import run_analysis
from backend.assistant import execute_tool

archive = io.BytesIO()
with zipfile.ZipFile(archive, 'w') as apk:
    apk.writestr('AndroidManifest.xml', b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="assistant.fixture"><uses-permission android:name="android.permission.SEND_SMS"/><application><activity android:name=".Open" android:exported="true"/></application></manifest>')
    apk.writestr('classes.dex', b'dex\\n035\\x00https://assistant.fixture.test/path Class.forName')

with TestClient(app) as client:
    bootstrap = client.post('/api/auth/bootstrap', json={'username': 'assistant-analyst', 'password': 'controlled-passphrase'}).json()
    headers = {'Authorization': f"Bearer {bootstrap['token']}"}
    intake = client.post('/api/cases/intake', headers=headers, files={'file': ('assistant.apk', archive.getvalue(), 'application/vnd.android.package-archive')}, data={'case_name': 'Assistant evidence case', 'profile': 'standard', 'nvidia_reasoning': 'false', 'isolated_dynamic_lab': 'false'}).json()
    run_analysis(intake['job_id'])
    catalog = client.get('/api/assistant/tools', headers=headers).json()
    created = client.post('/api/assistant/threads', headers=headers, json={'case_id': intake['case_id'], 'title': 'Evidence review'}).json()['thread']
    summary = client.post(f"/api/assistant/threads/{created['id']}/messages", headers=headers, json={'content': 'Summarize this case and explain findings and blindspots.', 'use_cloud': False})
    cloud_rejected = client.post(f"/api/assistant/threads/{created['id']}/messages", headers=headers, json={'content': 'Use cloud AI.', 'use_cloud': True}).status_code
    conversation = client.get(f"/api/assistant/threads/{created['id']}", headers=headers).json()

    local_iocs = execute_tool('list_indicators', {'case_id': intake['case_id']}, cloud_safe=False).data
    cloud_iocs = execute_tool('list_indicators', {'case_id': intake['case_id']}, cloud_safe=True).data
    forbidden = False
    try:
        execute_tool('shell', {'command': 'whoami'})
    except ValueError:
        forbidden = True

    body = summary.json()
    tool_names = [item['tool'] for item in body['assistant_message']['tool_runs']]
    print(json.dumps({
        'summary_status': summary.status_code,
        'mode': body['assistant_message']['mode'],
        'tools': tool_names,
        'citation_count': len(body['assistant_message']['citations']),
        'message_count': len(conversation['messages']),
        'catalog_size': len(catalog['items']),
        'policy': catalog['execution_policy'],
        'shell_forbidden': 'shell' in catalog['forbidden'] and forbidden,
        'cloud_rejected': cloud_rejected,
        'raw_local': [item['value'] for item in local_iocs['items']],
        'raw_absent_cloud': 'assistant.fixture.test' not in json.dumps(cloud_iocs),
        'cloud_redacted': cloud_iocs['values_redacted_for_cloud'],
    }))
""",
        tmp_path,
    )
    assert result["summary_status"] == 201
    assert result["mode"] == "local_deterministic"
    assert result["tools"] == ["get_case_summary", "list_findings", "list_blindspots"]
    assert result["citation_count"] >= 1
    assert result["message_count"] == 2
    assert result["catalog_size"] >= 13
    assert result["policy"] == "read_only_allowlist"
    assert result["shell_forbidden"] is True
    assert result["cloud_rejected"] == 409
    assert any("assistant.fixture.test" in value for value in result["raw_local"])
    assert result["raw_absent_cloud"] is True
    assert result["cloud_redacted"] is True
