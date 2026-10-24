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
    response = client.post('/api/cases/intake', files={'file': ('api-fixture.apk', archive.getvalue(), 'application/vnd.android.package-archive')}, data={'case_name': 'API fixture', 'profile': 'standard', 'nvidia_reasoning': 'false', 'isolated_dynamic_lab': 'false'})
    response.raise_for_status()
    created = response.json()
    run_analysis(created['job_id'])
    job = client.get(f"/api/jobs/{created['job_id']}").json()
    case = client.get(f"/api/cases/{created['case_id']}").json()
    report_id = case['reports'][0]['id']
    verification = client.post(f'/api/reports/{report_id}/verify').json()
    print(json.dumps({'job': job['job']['status'], 'report_count': len(case['reports']), 'verified': verification['valid'], 'stage_count': len(job['stages'])}))
""",
        tmp_path,
    )
    assert result == {"job": "partial", "report_count": 1, "verified": True, "stage_count": 9}
