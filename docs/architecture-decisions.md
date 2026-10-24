# SHADOWPATH Ω — Architecture decisions

## ADR-001: local-first, safe static analysis

The MVP never executes uploaded APKs. Intake stores a hash-addressed copy only after
ZIP/APK checks pass. Static inventory, manifest inspection, DEX string extraction and
deterministic rules run in a separate worker process. Dynamic analysis is deliberately
reported as unavailable until an isolated lab is explicitly provisioned.

## ADR-002: evidence before inference

Every persisted finding points to one or more immutable artifact records. The UI keeps
the evidence status (`observed`, `conditionally_reachable`, `suspected`, `unknown`)
separate from severity. Risk is separate from analysis completeness.

## ADR-003: SQLite for the reproducible MVP

SQLite keeps local investigation state, jobs, artifacts, findings, blindspots and
annotations across restarts. The data model is intentionally relational and can be
migrated to PostgreSQL without changing the API contract.

## ADR-004: capability honesty

Binary AXML parsing uses Androguard when available. If an adapter cannot parse an APK,
the pipeline records a precise blindspot rather than manufacturing manifest, call-graph,
runtime or AI findings. NVIDIA reasoning remains disabled unless explicitly configured.

## ADR-005: forensic export is independently checkable

Reports are generated from persisted data. A capsule includes a canonical JSON report
and a hash manifest; verification recalculates the chain without an AI service.

