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

## ADR-006: cloud reasoning is a constrained proposal channel

NVIDIA NIM runs only after explicit case-level consent. The adapter sends bounded
structured metadata and hashed observables rather than APK bytes, notes, code, strings,
or raw indicators. Pydantic validation rejects unknown evidence IDs, non-allowlisted
operations, malformed schemas, and experiments without analyst approval. AI proposals
are stored separately and cannot create findings or change deterministic evidence status.

## ADR-007: conversational assistance is a bounded evidence-tool layer

The NEXUS assistant stores analyst threads and messages in SQLite and answers through a
fixed registry of read-only tools. Those tools cover persisted case summaries, findings,
blindspots, indicators, guarded paths, artifacts, jobs, reports, capsule verification,
case comparison and live capabilities. There is no generic SQL, shell, ADB, arbitrary
network fetch, filesystem write or APK-execution interface.

Offline mode routes common forensic questions to deterministic tools and describes the
returned records without pretending to use a model. Optional NVIDIA mode uses bounded
function calling; the server overrides case-scoped arguments, limits tool rounds, hashes
IoC values, removes artifact payloads and never forwards prior local answers. Tool runs
and citations are persisted with the response so analysts can inspect the basis of an
answer. Assistant output never promotes evidence status or creates a finding.
