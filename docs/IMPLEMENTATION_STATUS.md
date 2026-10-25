# SHADOWPATH Ω — Implementation status

This repository starts from the supplied engineering contract. Status reflects code and
tests only; no performance or detection claims are implied.

| Capability | Status | Evidence / limitation |
|---|---|---|
| Safe APK intake and SHA-256 identity | DONE | Streaming intake validates ZIP structure and stores content by immutable SHA-256 |
| Persistent cases and jobs | DONE | SQLite schema, separate polling worker, restart interruption state, stages and events |
| Local access control | DONE | First-run admin, PBKDF2 password hashes, 12-hour bearer sessions, protected API/downloads and audit events |
| ZIP, manifest, DEX and IoC static inventory | DONE | ZIP container validation, Android binary/textual AXML, Androguard integration, DEX printable strings, static IoC normalization, and certificate blobs |
| Reverse engineering toolchain adapters | DONE | Explicit adapters for JADX, AAPT2, ApkSigner, MobSF, and Dynamic Lab with live health capability reporting |
| Z3 SMT constraint solver & trigger witnesses | DONE | Z3Py integration evaluating typed guard ASTs (numeric, boolean, string equality), generating SAT witnesses, UNSAT dead-branch proofs, and timeouts |
| Blindspot ledger and declared limitations | DONE | Explicit reason codes (NATIVE_CODE_UNINSPECTED, DYNAMIC_CODE_LOADING_UNRESOLVED, REFLECTION_TARGET_UNRESOLVED, RUNTIME_OBSERVATION_UNAVAILABLE) |
| Controlled test fixture matrix | DONE | 6 laboratory fixtures in `fixtures/safe-android-apps/` with expected ground-truth contracts in `fixtures/expected/` |
| Analyst workspace & Command Palette | DONE | Responsive React/Vite console, Ctrl+K command palette, guarded paths inspector, triage, IoC library, comparison, audit history, and live toolchain health |
| Capsules, ReportLab PDF reports and verifier | DONE | ReportLab styled PDF report, JSON export, ZIP capsule with hash chain over claims/guarded_paths.json and verifier |
| Optional NVIDIA reasoning (TRI-PROOF) | CONFIGURATION READY | NIM adapter, opt-in consent, minimized/redacted payload, schema/citation validation, allowlisted proposal and UI are implemented |
| NEXUS conversational analyst assistant | DONE | Persistent threads/messages, 13 read-only evidence tools, case citations, deterministic offline answers, optional redacted NVIDIA function calling, strict no-shell/no-ADB boundary |
| Isolated dynamic lab | ISOLATED / ADAPTER READY | Host execution disabled by design (never execute untrusted APKs on analyst host); external emulator/lab adapter status tracked |

## Supported-claims policy

- `observed` means a deterministic parser/rule saw a stored artifact.
- `conditionally_reachable` means an SMT solver (Z3) satisfied constraints under explicit bounded AST assumptions.
- `unknown` and blindspots are first-class records, never a clean result.
- Synthetic fixtures are explicitly labelled in API responses and the UI.

## Verification evidence (25 October 2026)

- `pytest -q`: 8 passed in 18.86s. Covers:
  1. Safe malformed-archive rejection
  2. Deterministic analysis/capsule validation
  3. Capsule tamper rejection
  4. Authentication & first-run bootstrap
  5. AI payload redaction & fabricated-evidence rejection
  6. Z3 guard evaluator (SAT witness reconstruction, UNSAT dead branch, and capability map)
  7. Guarded path stage execution on `time_guarded_sink.apk` with ReportLab PDF and verified capsule.
  8. Assistant API persistence, real evidence tool execution, cloud-data redaction, missing-provider behavior and non-allowlisted shell rejection.
- Frontend `npm run lint`: passed with 0 errors and 0 warnings (`--max-warnings=0`).
- Frontend `npm run typecheck`: passed with 0 errors (`tsc --noEmit`).
- Frontend `npm run test`: passed 2/2 tests (`vitest run`).
- Frontend `npm run build`: passed (`dist/assets/index-*.js`, 271 kB JS, 42 kB CSS).

## Current boundaries against the supplied engineering handbook

Full general-case arbitrary bytecode control-flow slicing across millions of instructions without denominator is honestly marked unsupported for non-fixture APKs, falling back to static reference findings and blindspots. Host execution is quarantined by design.
