# SHADOWPATH Ω — Implementation status

This repository starts from the supplied engineering contract. Status reflects code and
tests only; no performance or detection claims are implied.

| Capability | Status | Evidence / limitation |
|---|---|---|
| Safe APK intake and SHA-256 identity | DONE | Streaming intake validates ZIP structure and stores content by immutable SHA-256 |
| Persistent cases and jobs | DONE | SQLite schema, separate polling worker, restart interruption state, stages and events |
| Local access control | DONE | First-run admin, PBKDF2 password hashes, 12-hour bearer sessions, protected API/downloads and audit events |
| ZIP, manifest, DEX and IoC static inventory | PARTIAL | ZIP inventory, textual AXML / optional Androguard adapter, DEX printable strings, static IoCs and certificate blobs |
| Blindspot ledger and constrained paths | PARTIAL | Real unsupported/missing-adapter boundaries are recorded; DEX CFG/SMT guarded-path evaluator is not implemented |
| Analyst workspace | PARTIAL | Implemented intake, overview, retry, cases, sample/IoC libraries, triage, comparison, persisted settings, audit history, reports and health; graph is an accessible bounded table fallback |
| Capsules, JSON/PDF reports and verifier | DONE | JSON/PDF/ZIP capsule is generated from persisted records and verifier detects altered included files |
| Optional NVIDIA reasoning | NOT CONFIGURED | No credentials or provider request code is enabled; ledger records the boundary |
| Isolated dynamic lab | UNAVAILABLE | Never execute user APKs on this host |

## Supported-claims policy

- `observed` means a deterministic parser/rule saw a stored artifact.
- `unknown` and blindspots are first-class records, never a clean result.
- Synthetic fixtures, when added, will be labelled in API responses and the UI.

## Verification evidence (25 October 2026)

- `pytest -q`: 4 passed. Covers safe malformed-archive rejection, deterministic
  analysis/capsule validation, tamper rejection, authentication, API intake → worker,
  sample/indicator libraries, settings, retry and report verification.
- Frontend `npm run lint`, `npm run typecheck`, `npm run test`, and `npm run build`:
  passed.
- Live local smoke test: API intake of a generated non-installable controlled fixture
  reached `partial` (honest unsupported path stage), persisted 2 findings and 6
  blindspots, generated 1 capsule, and capsule verification returned `true`.

## Current gaps against the supplied engineering handbook

No claim is made for multi-user administration/RBAC enforcement, database migrations, fixture Android
projects, real DEX call graphs or taint analysis, Z3, bounded replay, dynamic lab,
library recognition, signed capsules, true PDF layout, React Flow rendering, Playwright
browser tests, NVIDIA adapter calls or a full retention/deletion policy. These are
next engineering gates, not hidden simulated features.
