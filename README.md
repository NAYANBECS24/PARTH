# SHADOWPATH Ω — NEXUS

An evidence-driven, local-first Android APK forensic triage MVP. It hashes and safely
stores submitted APK archives, runs **static-only** analysis in a separate worker, and
keeps observations, limitations, job stages, findings, blindspots and exports in SQLite.

> Defensive research only. Never use it to execute unknown APKs on your workstation.

## What is implemented

- Safe `.apk` intake: filename validation, streaming size limit, SHA-256 identity,
  ZIP traversal/count/ratio/uncompressed-size checks and hash-addressed storage.
- Persisted cases and worker jobs with stage records, events, cancellation requests and
  restart-safe interrupted-job handling.
- Deterministic static archive, DEX-shaped payload, textual/binary-manifest adapter,
  certificate-blob and string/IoC inventory. Unsupported parser outcomes are recorded.
- Evidence-backed rules for explicitly exported manifest components and selected
  sensitive permission declarations. A declaration is not treated as proof of intent.
- Blindspot ledger for unparsed manifests, native code, dynamic loading/reflection,
  missing DEX, extraction budgets, disabled AI, unavailable guarded-path analysis and
  unavailable dynamic runtime observation.
- React analyst workspace: intake wizard, persisted progress timeline, case tabs,
  evidence triage, indicators, bounded graph fallback, reports and health.
- JSON report, simple readable PDF, ZIP evidence capsule and independent hash verifier.

## Deliberately unavailable in this MVP

- APK execution, emulator/MobSF/Frida lab, general DEX control-flow/taint analysis,
  SMT witness proof, authenticated multi-user access, live threat intelligence and
  NVIDIA TRI-PROOF requests. The UI/API marks these as `unknown`, `unsupported`, or
  `not configured`; it does not manufacture a result.

## Quickstart (Windows)

Prerequisites: Node 24+, npm, and Python 3.12+. The default PowerShell script expects
the Python path used on this machine; override it when yours differs.

```powershell
./scripts/dev.ps1
# or: ./scripts/dev.ps1 -Python "C:\Path\To\python.exe"
```

Open `http://127.0.0.1:5173`. The API is at `http://127.0.0.1:8000`, with its health
check at `http://127.0.0.1:8000/health`.

For separate terminals:

```powershell
C:\Users\nayan\AppData\Local\Programs\Python\Python312\python.exe -m pip install -r backend/requirements.txt
C:\Users\nayan\AppData\Local\Programs\Python\Python312\python.exe -m uvicorn backend.api:app --host 127.0.0.1 --port 8000
C:\Users\nayan\AppData\Local\Programs\Python\Python312\python.exe -m backend.worker
cd frontend; npm install; npm run dev
```

## Controlled demo fixture

The following builds a **non-installable controlled static fixture**, useful only to
exercise the intake and evidence UI. It includes a textual manifest, a DEX-shaped
payload and fixed strings; it is never real-world malware.

```powershell
C:\Users\nayan\AppData\Local\Programs\Python\Python312\python.exe scripts/create_safe_fixture.py
```

Upload `fixtures/controlled_static_fixture.apk`, wait for the worker, then inspect the
exported-component observation, static string IoC, native/runtime/path blindspots, and
download / verify the capsule.

## Tests and checks

```powershell
C:\Users\nayan\AppData\Local\Programs\Python\Python312\python.exe -m pytest -q
cd frontend
npm run lint
npm run typecheck
npm run test
npm run build
```

## Evidence model and limitations

`observed` means a deterministic extractor or rule captured a stored artifact. It does
not establish malicious intent, runtime use or reachability. Risk score and static
analysis completeness are separate fields. A capsule hash chain proves the integrity of
included export files, not court admissibility.

The engineering sources supplied with this repository require a much broader research
platform. The exact current implementation boundary is tracked in
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md); design decisions are
in [`docs/architecture-decisions.md`](docs/architecture-decisions.md).
