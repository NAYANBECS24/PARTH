# SHADOWPATH Ω — NEXUS

**MASTER CODEX BUILD PROMPT AND ENGINEERING CONTRACT**  
**Project:** Evidence-Driven Android Malware Blindspot Discovery & Adaptive Forensic Verification Platform  
**Official challenge:** AI-Assisted Android Application Security and Forensic Analysis Platform — Malware Analysis  
**Team:** PARTH | **Repository name:** `parth` | **Revision:** 1.0 | **Date:** 24 October 2026  
**Deliverable:** A genuine end-to-end working full-stack application with a premium, production-oriented user experience, real APK analysis, auditable results, and reproducible tests.

> **IMPORTANT FOR THE CODING AGENT:** This document is an executable engineering brief. Build functioning software in the repository rather than merely responding with a design. Complete the critical path first. All hard or optional research modules must have honest states; do not simulate or fabricate findings, progress, risk percentages, scan data, dynamic analysis, or benchmark results. You may use **clearly labelled synthetic fixtures only for demo/test mode**. Never execute untrusted APKs directly on the user's host OS.

---

# PART A — THE SINGLE MASTER INSTRUCTION TO GIVE CODEX

## 1. Assignment, objective, and decision authority

Act as a **staff-level full-stack engineer, Android security engineer, application security architect, forensic software designer, and principal product designer**. Implement SHADOWPATH Ω — NEXUS as a cohesive, polished cybersecurity investigation product. You are responsible for the working React frontend, Python backend, persistent jobs, real/static APK extraction, evidence model, explainable scoring, optional NVIDIA reasoning, forensic report generation, automated tests, docs, and reproducible startup. Do not give me only mockups, scaffolding, architecture notes, pseudocode, empty functions, or a final polished README while core features do not work.

**Definition of success:** A user can start the application, log in, upload a real Android APK, receive a persisted scan job, watch true progress, inspect extracted manifest/DEX/certificate/network evidence and explicitly documented analysis blindspots, review evidence-backed findings, explore reachable or unresolved sensitive code paths when supported, compare samples, export a verified JSON/PDF evidence report, and re-open the case after restarting the service. The system must continue to work in offline mode without NVIDIA credentials. On an ordinary machine it must not require a GPU.

**Your authority:** Choose reasonable implementation details without asking repetitive questions. Inspect existing repository files before modifying them; preserve working code unless replacement is justified. When any dependency or analysis approach is unavailable, implement the honest supported subset and show `unsupported`, `not_configured`, `pending`, or `unknown` instead of pretending the feature works. Implement in vertical slices and validate each slice. In scope-changing cases, leave a precise documented limitation rather than inventing output.

**Hard requirements, ranked:**

1. Functioning system, reproducible startup, non-fabricated results.
2. Safe handling of hostile APKs, privacy controls, evidence provenance.
3. Sophisticated visual design and complete real user journeys.
4. Unique core: blindspot ledger + guarded sensitive-path analysis + evidence capsule.
5. Optional NVIDIA cloud reasoning through a secure adapter; strictly validated, non-authoritative.
6. CPU-first performance, robust job handling, deterministic offline operation.
7. Scientifically defensible evaluation and accurate demonstration.

### Delivery discipline

- Implement the application and commit **iteratively**, in reviewable feature increments; do not generate one final repository dump. Use commit messages such as `feat(api): implement safe apk intake`, `feat(core): add manifest and dex inventory`, `feat(ui): build investigation workspace`, `test(evidence): verify capsule hash chain`.
- Code must compile, lint, and pass targeted tests at the end of each increment. Never claim a command ran unless it actually ran; report its exit code or output when relevant.
- Do not hardcode secrets. Do not upload samples to external threat services. Do not embed API keys in JS bundles or Git commits.
- Avoid excessive skeletons and TODOs. A declared MVP feature must execute on real data; hide or mark advanced research features unsupported if they are not implemented.
- Use the repository's exact name `parth` when creating it for the team. If GitHub credentials or repository access are not available, implement everything locally, provide the commands, and do not falsely claim a remote push occurred.

## 2. Official problem fit and proposed product thesis

The challenge requires: (a) static/manifest/resource analysis, (b) dynamic behavioural analysis, (c) permissions/API/evasion checks, (d) network/certificate/library analysis, (e) explainable threat intelligence and risk, and (f) rapid multi-APK investigation and forensic reporting.

SHADOWPATH's distinctive question is **not merely “is the APK malware?”** but **“which security-relevant behaviours were actually inspected, which guarded paths remain unverified, why is the evidence incomplete, and what safe experiment can reduce that uncertainty?”**

The product's three technical pillars are:

**BLINDSPOT LEDGER:** Explicitly records unparsed DEX, native/JNI boundaries, reflection, dynamic loading, unsupported APIs, unresolved dispatch, unvisited paths, unavailable runtime observation, parser disagreements, and resource-exhaustion stop conditions. It never equates a clean scan with a safe app.

**GUARDED PATH INVESTIGATOR:** Finds candidate sensitive sources/sinks and guard conditions. In an explicitly supported subset of code, it constructs backward slices, typed constraints and *candidate* trigger witnesses. It separates syntactic path existence, constrained reachability, bounded verification, and observed runtime behaviour. For real APKs it must be conservative and expose unsupported cases. No general Android behavioural proof is claimed.

**PROVENANCE CAPSULE:** Creates inspectable evidence records with APK hash, tool versions, input parameters, graph or path references, timestamps, analyst actions, replay results when available, unknown conditions and a tamper-evident hash-linked manifest. Supports independent `verify` without an AI service.

NVIDIA reasoning (TRI-PROOF) proposes competing malicious/benign explanations and safe tests, but local code must validate every citation and run only approved operations. The model cannot elevate a finding into an observed fact.

**Intended use:** Defensive research and analysis of APKs the operator is authorised to examine; controlled sample laboratory; reproducible forensic triage. This tool is not a malware authoring system, exfiltration system, credential extractor, surveillance tool, or automatic proof of criminal intent.

## 3. What “working” means at each scope level

| Capability | MVP (must truly work) | Advanced tier (implement if time/resources permit) | Never misrepresent |
|---|---|---|---|
| APK upload | Real file, size checks, hash, ZIP/DEX/manifest inventory | Deduplication and larger scale | Dropped/fake file paths |
| Security checks | Real permissions, exported components, strings, APIs, URLs, certificates when parsable | Multi-parser disagreement, dynamic library mapping | Guessed API findings |
| Detection | Deterministic rules linked to observed artifacts | Taint/CFG guided analysis and measured statistical model | Made-up probabilities |
| Blindspot ledger | Precise successes/failures and unknown reasons | Per-method graph coverage and verification debt | “100% scanned” without denominator |
| Trigger investigation | Supported fixture classes; real guarded paths when actually resolved | Z3 with bounded slicing on real DEX subset | Arbitrary APK path proof |
| Runtime | Explicit unavailable status unless connected to isolated emulator | Opt-in supervised lab via MobSF/ADB/Frida | Executing malware on laptop |
| NVIDIA | Optional real requests or deterministic offline fallback | Cost-aware experiment planner | Model hallucination as evidence |
| Reports | Working JSON and PDF + integrity verifier | Digital signatures and independent replay | Court admissibility claim |
| Multi-sample | Persist cases, search, inspect, compare | Family graph with typed weighted evidence | Attribution by one shared SDK |

---

# PART B — PRODUCT EXPERIENCE AND VISUAL DESIGN

## 4. Non-negotiable interface design direction

Deliver a **high-end SOC/DFIR enterprise product**, the quality level of a serious security platform, not a hackathon template, dashboard clone, animated marketing page, or “vibe-coded” interface. Aim for precise visual rhythm, restrained density, legible forensic information, subtle depth, excellent keyboard navigation, and a consistent design system. The site must remain responsive, accessible, and usable when no scans exist.

**Visual identity:** Product name `SHADOWPATH Ω` with a secondary `NEXUS` technology label. Use a minimal vector mark based on a path split or forensic aperture. Avoid stock hacker imagery, matrix rain, purple neon everywhere, glowing blobs, generic cybersecurity shields, emojis as icons, random gradients, glassmorphism overload, and excessive skeleton animations. Use a mature design language closer to an analyst workstation than a futuristic gaming UI.

**Design system — use CSS variables / tokens, not hardcoded random colors:**

| Token | Dark mode baseline | Purpose |
|---|---|---|
| `--canvas` | `#0B1119` | Workspace background |
| `--sidebar` | `#0D1620` | Navigation surface |
| `--surface` | `#121D28` | Primary panels |
| `--surface-raised` | `#172432` | Elevated panels |
| `--border` | `#253446` | 1px structural dividers |
| `--text` | `#EBF2F8` | Primary text |
| `--text-muted` | `#91A4B8` | Secondary text |
| `--accent` | `#2BD4C5` | Controlled highlights and focus |
| `--info` | `#63AAFA` | Informational states |
| `--warning` | `#F2B35C` | Unverified or caution |
| `--danger` | `#F3777F` | Confirmed high-severity warning |
| `--success` | `#67C69C` | Completed/verified states |

Implement a considered light theme too, using semantic tokens, with system preference support and persistent preference. Contrast should meet WCAG AA for ordinary text whenever practicable. Use `Inter` for UI and `JetBrains Mono` for hashes, method descriptors, evidence IDs, time values, API status codes, and code. Gracefully fall back to system fonts. Avoid externally hosted fonts where offline mode matters; bundle only font licenses permitting redistribution, otherwise use safe local fallbacks.

**Geometry:** Sidebar 248–264 px expanded, 68–76 px collapsed; utility topbar 60–68 px; work area max-width approximately 1600 px; 8 px spacing grid; panel corner radius 10–14 px; line heights generous for findings; dividers subtle; hover and focus indicators deliberate. Desktop-first 1440 x 900 analyst viewport, functional down to 390 px mobile with simplified panels. No horizontal document overflow. Large tables scroll within their own regions.

**Typography:** Page title 26–32 px; section title 18–22 px; table labels 12–13 px; body 14–15 px; numbers and timestamps tabular; no artificially huge numerals. Use text + shape + icon for statuses; color alone must not carry meaning. Animations between 100–220 ms and disabled under reduced-motion preferences.

**UX integrity:** No placeholder values labelled as real metrics. Hide panels when data does not exist or show specific empty states. “Not observed,” “Unverified,” “Not supported,” and “Analyzed” must look distinct. A sample's risk score and its analysis completeness must occupy separate cards and use different colors/labels. Never show `0 threats` to mean `not scanned`.

## 5. Application shell and global interactions

Use React + TypeScript with a fixed but responsive shell: collapsible left navigation, header with breadcrumbs and global search, case/workspace selector, small job activity indicator, model/offline status, theme toggle, analyst menu. Use cmd/ctrl+K command palette to navigate to recent cases, actions, filters, or the new-scan flow. Include purposeful keyboard focus, predictable URLs, recoverable loading/error states, and optimistic UI only for safe reversible actions.

Primary navigation:

1. **Overview** `/app/overview`
2. **New Investigation** `/app/scans/new`
3. **Investigations** `/app/cases`
4. **APK Library** `/app/samples`
5. **Findings** `/app/findings`
6. **Evidence Graph** `/app/graph`
7. **Indicators / IoCs** `/app/indicators`
8. **Comparisons** `/app/compare`
9. **Reports & Capsules** `/app/reports`
10. **System Health** `/app/health`
11. **Settings** `/app/settings`

Do not place every menu item at the same visual weight. Group `Investigations` and `Intelligence`, with `System` near the bottom. In the shell, show a subtle version tag and current data mode (Live analysis / Demo fixture). Only show `Live` when backed by real API data.

## 6. Screen-by-screen production specification

### 6.1 Overview — analyst command center

Above the fold: page title, date, `New Investigation` primary action, truthful active-job count, last completed scan, high-priority findings, unresolved blindspots. Then a risk-by-severity chart using real data, an investigation queue with live status, last 10 samples, and a right-hand **Action Required** stack listing jobs with unresolved evidence or review decisions. Every metric is clickable and deep-links to filtered real records. If there is no data, display a polished getting-started state that explains APK upload and includes clearly labelled fixture exploration.

### 6.2 New Investigation — 3-stage creation flow

Stage A: drag-and-drop `.apk` or browse. Show filename, byte size, mime/extension validation, SHA-256 preview once upload is complete, non-executable static analysis warning. Stage B: case name, analyst note, processing profile (`Lite`, `Standard`, `Advanced`), toggle for NVIDIA reasoning (off by default), toggle for isolated dynamic lab (disabled with explanation when not configured). Stage C: review privacy choices and initiate scan. On submit, persist case and sample then navigate to the live job view. On upload errors show exact validation reason with retry; never say `Scan started` if job persistence failed.

### 6.3 Live investigation — real progress, not timer theater

Route `/app/jobs/:jobId`. Horizontal or vertical evidence stage timeline: intake → inventory → manifest → DEX/API extraction → indicators → blindspot ledger → guarded-path evaluation → findings → AI review (optional) → capsule/report. Each stage receives server events with `pending`, `running`, `completed`, `partial`, `skipped`, or `failed`, plus timestamp and count. Show real structured worker logs, throughput or bytes only where measurable, cancellation, retry, copy-job-ID, and reload/resume support. Allow background navigation; job status must survive refresh and process restart. Use SSE with event IDs and reconnection; never animate fake progress indefinitely.

### 6.4 Investigation detail — multi-tab professional workspace

Route `/app/cases/:caseId` with sticky case header (sample name, case ID, exact SHA-256 copy button, analysis status, last run, analyst). Layout: left high-level navigation, main working panel, optional right evidence inspector. Tabs:

- **Summary**: risk vs completeness, major findings, module availability, source file characteristics, action recommendations.
- **Static Genome**: manifest tree, declared permissions, exported components, SDK/target, certificate fingerprints, resource archive inventory, DEX files, native libraries.
- **Behaviour & Paths**: method/sink references, guard predicates, supported/unsupported path analysis, each source-backed path card; never conflate static and observed behaviour.
- **Blindspot Ledger**: grouped unknowns by reason and severity of investigation gap; searchable, expandable file/method references, parser failure details, action to schedule a safe next test.
- **TRI-PROOF AI**: malicious hypothesis, benign explanation, discriminating test, evidence anchors, refusal/error when model unavailable. Label output `AI PROPOSAL` prominently.
- **Network & IoCs**: static strings vs runtime-observed network destinations, first-seen context, provenance, URL/IP/domain with safe text rendering.
- **Evidence Graph**: typed relationships between sample, method, trigger, source, sink, indicator, library, and finding; inspector highlights grounded edge evidence.
- **Capsules & Reports**: generated JSON and PDF, verification status, provenance chain, export actions, analyst decisions and reports history.

Each tab needs filter/search, pagination or virtualization where appropriate, responsive loading/empty/error states, and cross-links to the exact underlying evidence record.

### 6.5 Investigations library

Server-backed searchable table with case title, sample filename, SHA prefix, created timestamp, latest risk tier, analysis completeness band, open unknowns, job status, analyst, and `Open` actions. Add real filters, sorting, pagination and an accessible row selection pattern. Bulk exports can be a later-phase feature and must not render as functional until implemented.

### 6.6 Findings / evidence triage

Central list with rule ID, category, severity, **evidence status**, source observation, affected method/file, supporting artifact ID, notes and reviewer status. Advanced filter drawer supports severity, evidence status, module, app, date and analyst decision. Right drawer shows all raw evidence and provenance. `Mark reviewed`, `Need further testing`, and `False positive` should persist as analyst annotations without deleting underlying observations. An analyst annotation is not a machine observation.

### 6.7 Evidence graph

Use React Flow (or Cytoscape if graphs are large). Support zoom-to-fit, node/edge selection, filters by type and confidence, graph minimap, stable positions, and a collapsible side inspector. Do not render massive graphs all at once; use bounded neighborhoods, limits and clear `show more` actions. Distinguish `shared artifact` from `same actor` and avoid automatic attribution. Provide table fallback for accessibility.

### 6.8 Compare APKs

Select two real samples. Compare hashes, permissions added/removed, components, certificates, DEX count, native libraries, extracted indicators, guarded operations, rule findings and unknowns. Display comparable results in a structured diff with provenance. If analysis capabilities differ, explain why comparisons may be incomplete.

### 6.9 Reports, health and settings

Reports: list exports with date, generator version, hash chain verification, download JSON/PDF, run local verification. Health: backend, DB, job worker, parser adapters, NVIDIA connectivity (no API key exposure), optional MobSF/ADB lab, storage and job backlog; refresh based on real checks. Settings: theme, concurrency, budget, privacy/redaction policy, model selection, report branding and analyst users. Only expose editable settings that are persisted, validated and enforceable.

## 7. Design components and UI quality checks

Build reusable components: `AppShell`, `PageHeading`, `StatusPill`, `EvidenceStatus`, `SeverityBadge`, `RiskIndicator`, `CoverageMeter`, `StageTimeline`, `ArtifactTree`, `HashField`, `CopyToken`, `ForensicCodeViewer`, `EvidenceDrawer`, `FindingCard`, `UnknownReasonTag`, `CaseTable`, `EventLog`, `RiskVsCompleteness`, `GraphLegend`, `ReportAction`, `EmptyState`, `ErrorPanel`, `PermissionGate`, `OnlineOfflineIndicator`, `Toast`, `Skeleton`, `FilterBar`.

Use shadcn/ui primitives, Radix accessibility patterns, Tailwind for layout, TanStack Query for server state, TanStack Table for grids, Zod + React Hook Form for inputs, Lucide icons, Recharts (or lightweight SVG) for metrics, and React Flow for relationship graphs. Choose only what materially helps; avoid loading three component libraries.

Minimum visual QA: verify 1440x900, 1280x800, 768x1024, 390x844; capture actual app screenshots with Playwright; inspect spacing, overflow, clipped tables, double scrollbars, side panel interactions and keyboard focus. The interface must not look like a generic AI-generated dashboard: prioritize detailed domain-specific workflows and actual sample data relationships. Responsive behaviour must be designed, not patched as an afterthought.

---

# PART C — ENGINEERING STACK, ARCHITECTURE, AND REPOSITORY

## 8. Technology decisions (start with this stack)

| Concern | Default choice | Reason and constraints |
|---|---|---|
| Frontend | React + TypeScript + Vite | Modern SPA, fast dev/build, typed views |
| Design | Tailwind CSS + shadcn/ui + Radix | Consistent and accessible primitives |
| Data fetching | TanStack Query + typed API client | Cache, invalidation, retries |
| Graphs | React Flow | Typed evidence graph interaction |
| Backend | Python 3.12 + FastAPI + Pydantic v2 | Portable parser integration, API schemas |
| Persistence | SQLite + SQLAlchemy 2 + Alembic | CPU-first, zero external DB for MVP |
| Background jobs | Durable SQL-backed queue + standalone worker process | Survives HTTP request and refresh |
| Progress | SSE for one-way job events; polling fallback | Efficient progress with replay |
| APK parser | Python standard ZIP safety + Androguard adapter | Real metadata/DEX inspection |
| Optional analyzers | aapt2, JADX, MobSF via explicit adapters | Enhancements, never hidden dependency |
| Constraints | Z3 solver with strict timeout | Supported trigger/guard witness checks |
| Local graphs | NetworkX for small bounded graphs | Analysis and graph relationship handling |
| Reports | ReportLab or WeasyPrint with safe templates | Real PDF reports |
| AI | NVIDIA hosted NIM via OpenAI-compatible client | Optional, no local GPU |
| Tests | pytest, HTTPX, Playwright, Vitest, Ruff, mypy | Reproducible verification |
| Deployment | Single-node local process; optional Docker Compose | Works on ordinary computers |

Use a dependency lockfile or constraints file and pinned compatible versions after checking install/build compatibility. Never invent SDK methods or hardcode a model name without testing. Expose `NVIDIA_MODEL` configuration and select from supported provider models (document the verified default). Default application launch must not require MobSF, Docker, an emulator, or NVIDIA credentials. Provide optional flags for expensive capabilities.

## 9. Architectural decomposition

```text
                        BROWSER / REACT ANALYST CONSOLE
      Overview | Upload | Live Jobs | Case Detail | Graph | Reports
                                   |
                            Typed REST + SSE
                                   |
                    FASTAPI CONTROL / SECURITY PLANE
       Auth | Cases | Samples | Jobs | Evidence | Reports | Settings
                     |                         |
                 SQLite DB              Content-addressed Vault
                     |                         |
                     +------------+------------+
                                  |
                     DURABLE LOCAL WORKER / ORCHESTRATOR
                                  |
            +---------------------+---------------------+
            |                     |                     |
        Intake + ZIP         Static Engines         Evidence Assembly
       safety + hashing     Manifest/DEX/IoC         Findings + Capsule
            |                     |                     |
            +--------------- Blindspot Ledger ---------+
                                  |
                      Guarded Path / Z3 Planner
                                  |
                  Optional NVIDIA AI Proposal Adapter
                                  |
            Deterministic validation / allowlisted safe tests
                                  |
           Optional isolated Android lab (separate host/process)
```

Trust boundaries: uploaded APK = hostile bytes; extracted strings and code = untrusted data; model outputs = untrusted suggestions; browser = untrusted client; evidence vault = immutable storage; worker is a strictly limited, nonprivileged execution environment. Separate the API from heavy scanning. Do not import/rely on a scanner process in the web request thread.

## 10. Repository structure to actually create

```text
parth/
  README.md
  AGENTS.md
  .gitignore
  .env.example
  .editorconfig
  .github/workflows/ci.yml
  docs/
    architecture.md
    threat-model.md
    evidence-policy.md
    architecture-decisions.md
    api-examples.md
    demo-script.md
    evaluation-plan.md
    IMPLEMENTATION_STATUS.md
  apps/
    web/
      package.json
      vite.config.ts
      src/
        app/                  # router/providers/auth/shell
        pages/                # overview, upload, jobs, case, graph, reports...
        components/           # reusable UI and forensic components
        features/             # samples, jobs, findings, cases, evidence, AI
        hooks/
        lib/api/              # typed client, SSE subscription, query keys
        styles/               # theme, tokens, typography
        test/
      e2e/
    api/
      pyproject.toml
      alembic.ini
      app/
        main.py
        core/                 # config, auth, security, logging, errors
        api/v1/               # routers
        db/                   # models, sessions, migrations
        schemas/              # Pydantic request/response contracts
        services/             # uploads, jobs, findings, reports, capsules
        worker/               # durable executor and recovery
        analysis/
          ingest/
          adapters/           # androguard, optional mobsf/jadx/aapt
          manifest/
          dex/
          ontology/
          graph/
          blindspots/
          guards/
          iocs/
          certificates/
          risk/
          ai/
          evidence/
        tests/
  fixtures/
    README.md
    safe-android-apps/       # source for benign controlled test APKs
    expected/                 # fixture ground-truth JSON
  scripts/
    dev.ps1
    dev.sh
    build-fixtures.sh
    verify-capsule.py
    bootstrap.py
  compose.yaml                # optional, not required for Lite mode
```

Do not add Kubernetes, microservices, Kafka, Neo4j, Redis, MongoDB or GPU servers in MVP. If advanced scale becomes justified, write an ADR and add an adapter instead of rewriting the whole system. The default monorepo must start from documented commands on Windows via PowerShell and on Linux/macOS via shell.


# PART D — REAL BACKEND, DATABASE, AND SERVICE CONTRACTS

## 11. Exact domain entities and persistence rules

Use UUIDv7 or UUID4 identifiers (choose one consistently); store timestamps as UTC ISO-8601; maintain immutable file hashes and provenance references. Create SQLAlchemy models with Alembic migrations, relationships, FK constraints, unique indexes and repositories. At minimum implement:

| Entity | Essential fields and invariant |
|---|---|
| `users` | `id`, `email`, `password_hash`, `role`, `active`, created/updated; never store plaintext passwords |
| `cases` | `id`, `title`, `summary`, `owner_id`, `state`, created/updated; owner/permissions enforced |
| `samples` | `id`, `sha256` unique, `filename_original`, `byte_size`, `stored_path`, `media_type`, `created_at`; bytes immutable |
| `case_samples` | case-sample association, uploader, created timestamp |
| `analysis_jobs` | `id`, `sample_id`, `case_id`, `profile`, `status`, `stage`, `progress_current`, `progress_total`, `started_at`, `finished_at`, `error_code`, `cancel_requested`, `configuration_snapshot` |
| `job_events` | monotonically increasing integer `id`, `job_id`, `seq`, `stage`, `status`, `payload_json`, `created_at`; unique (`job_id`,`seq`) |
| `artifacts` | `id`, `sample_id`, `job_id`, `kind`, `path_or_locator`, `sha256`, `parser`, `parser_version`, `metadata_json`; provenance mandatory |
| `components` | `id`, `job_id`, `type`, `name`, `exported`, `permission`, `source_artifact_id` |
| `permissions` | `id`, `job_id`, `name`, `manifest_declared`, `source_artifact_id` |
| `methods` | `id`, `job_id`, `dex_index`, `descriptor`, `class_name`, `method_name`, `flags`, `references_json`; identity stable within job |
| `edges` | `id`, `job_id`, `source_node`, `target_node`, `edge_type`, `evidence_artifact_id`, `confidence_label` |
| `observations` | `id`, `job_id`, `type`, `location`, `raw_value`, `source_artifact_id`, `certainty`, `created_at`; no observation without source |
| `findings` | `id`, `job_id`, `rule_id`, `title`, `severity`, `evidence_status`, `explanation`, `confidence_class`, `observations_json`, `limitations_json`; immutable machine result version |
| `blindspots` | `id`, `job_id`, `scope`, `reason_code`, `details`, `affected_artifact_id`, `count_known`, `verification_gap`, `remediation_hint` |
| `guard_paths` | `id`, `job_id`, `target_method_id`, `guard_ast_json`, `solver_status`, `supported_subset`, `witness_json`, `limitations_json` |
| `experiments` | `id`, `job_id`, `path_id`, `type`, `status`, `budget_json`, `input_hash`, `output_hash`, `observation_ids`, `requested_by`, `started_at` |
| `indicators` | `id`, `job_id`, `type`, `canonical_value`, `source_kind`, `artifact_id`, `context`, `observable_state` |
| `ai_proposals` | `id`, `job_id`, `provider`, `model`, `prompt_hash`, `response_hash`, `redaction_policy`, `output_json`, `validation_status`, `token_usage`, `created_at` |
| `reports` | `id`, `case_id`, `job_id`, `format`, `sha256`, `storage_path`, `manifest_path`, `generated_at`, `verified_at` |
| `review_events` | `id`, `case_id`, `finding_id`, `actor_id`, `action`, `notes`, `created_at`; append-only audit |
| `system_audit` | `id`, `actor`, `action`, `object_type`, `object_id`, `details_hash`, `timestamp`; append-only |

Use unique constraint `(sample_id, profile, analysis_version, tool_configuration_hash)` only for optional cache reuse, not to suppress legitimately requested rescans. Distinguish immutable observations from analyst annotations. Prevent deletion of sample bytes referenced by retained evidence unless retention policy explicitly invalidates and records the operation. All artifact locators must be relative/opaque IDs, never accept arbitrary client-supplied filesystem paths.

**Persistent job state machine:**

```text
QUEUED -> VALIDATING -> INVENTORY -> STATIC_ANALYSIS ->
BLINDSPOT_BUILD -> PATH_EVALUATION -> FINDINGS ->
OPTIONAL_AI -> CAPSULE -> COMPLETED

At each stage: FAILED | CANCELLED | PARTIAL, with reason.
Timeout = PARTIAL or FAILED depending whether valid results remain;
never falsely set COMPLETED when a mandatory stage failed.
```

Do not use `FastAPI BackgroundTasks` as the sole execution system for long-running analyses. Implement separate worker process polling a durable jobs table with atomic claim, heartbeat/lease, retries with backoff, idempotent stages and recovery after worker restart. For SQLite WAL: single-writer concerns must be managed; cap concurrency to 1 by default; avoid long write transactions. Include clear cancellation between stages and during subprocess timeout handling.

## 12. Typed REST API contracts

Prefix all endpoints `/api/v1`. Use Pydantic response models, consistent pagination (`page`, `page_size`, `total`), request IDs, proper HTTP status codes, HTTP-only session cookies (or secure bearer tokens if justified), and structured validation errors. Minimum endpoint contract:

| Method / endpoint | Effect | Returns |
|---|---|---|
| `POST /auth/login` | Authenticate; rate limited | user/session (no credentials) |
| `POST /auth/logout` | Terminate session | status |
| `GET /auth/me` | Current permissions | user profile |
| `GET /health/live` | Liveness, no secrets | `ok` / failure |
| `GET /health/ready` | DB/worker/storage readiness | categorized states |
| `GET /health/capabilities` | Parser/solver/AI/emulator availability | real availability map |
| `POST /cases` | Create case | case object |
| `GET /cases` | Paginated filtered case list | records + total |
| `GET /cases/{id}` | Full case metadata | case object |
| `PATCH /cases/{id}` | Update permitted annotations | case object |
| `POST /samples/upload` | Stream and validate APK | sample id, sha256, size |
| `GET /samples` | Search samples | sample summary list |
| `GET /samples/{id}` | Sample metadata | immutable hash/attributes |
| `POST /jobs` | Create persisted analysis job | job id, stage/status |
| `GET /jobs/{id}` | Progress and stage result | job object |
| `POST /jobs/{id}/cancel` | Request cooperative cancellation | accepted state |
| `GET /jobs/{id}/events` | SSE replay and tail | event stream |
| `GET /jobs/{id}/logs` | Paginated structured logs | logs |
| `GET /jobs/{id}/manifest` | Actual parsed manifest | metadata + evidence refs |
| `GET /jobs/{id}/dex` | DEX inventory/API references | paged list |
| `GET /jobs/{id}/findings` | Explainable findings | records |
| `GET /jobs/{id}/blindspots` | Exact unknown ledger | records |
| `GET /jobs/{id}/paths` | Supported guarded paths | guarded paths + status |
| `GET /jobs/{id}/indicators` | Extracted IoCs with provenance | records |
| `GET /jobs/{id}/graph` | Typed bounded evidence graph | nodes/edges/page |
| `POST /jobs/{id}/ai/propose` | Explicit optional hypothesis task | queued proposal/task id |
| `GET /jobs/{id}/ai/proposals` | Stored validated proposals | records |
| `POST /cases/{id}/reports` | Export JSON/PDF evidence | report id/state |
| `GET /reports/{id}/download` | Authorized stream by ID | report bytes |
| `POST /reports/{id}/verify` | Hash-chain integrity validation | per-file verification |
| `GET /compare?left=...&right=...` | Typed diff of two real jobs | diff + coverage warnings |
| `GET /settings` / `PATCH /settings` | Persist allowed policy config | validated config |

**Suggested response envelope** for structured application data; use status codes for errors instead of HTTP 200 everywhere:

```json
{
  "data": {
    "job_id": "8e88b1ba-4300-4c7a-ade0-72ab7b0eeb35",
    "status": "STATIC_ANALYSIS",
    "profile": "standard",
    "stage": "dex_inventory",
    "stages_completed": 3,
    "stages_total": 9,
    "capabilities": {"dynamic_analysis": "not_configured", "nvidia": "disabled"}
  },
  "meta": {"request_id": "req-example", "schema_version": "1.0"}
}
```

**Standard error:** `{ "error": { "code": "APK_TOO_LARGE", "message": "Upload exceeds configured 80 MiB limit", "retryable": false }, "request_id": "..." }`. Implement 401/403 auth, 404 unknown IDs, 409 conflicting stage state, 413 upload size, 415 format, 422 invalid data, 429 rate limits, 503 optional dependency unavailable. Never leak stack traces, server paths, secrets, or model prompts in user-facing errors.

## 13. Real-time updates via SSE

SSE is server → browser only and suited for scan logs/progress. Persist every job event before publication. Support reconnect using `Last-Event-ID` or explicit `after` offset, sequence order, keepalive comments, disconnect detection, and a 2–5 second polling fallback if SSE is unavailable. Provide `EventSource`-compatible cookie auth and same-origin or explicitly configured CORS. Avoid flooding: cap logs, coalesce high-frequency progress updates, paginate historical events. Final events must be emitted for completed/partial/failed/cancelled.

```text
id: 1842
event: job.stage
 data: {"job_id":"...","seq":14,"stage":"manifest","status":"completed","observations":12,"at":"2026-10-24T16:30:00Z"}

id: 1843
event: job.stage
 data: {"job_id":"...","seq":15,"stage":"dex_inventory","status":"running","at":"2026-10-24T16:30:01Z"}
```

In actual SSE syntax remove the leading space before `data:`. Events are emitted from real worker transitions, **never** from a browser timer that increments percent independently of the backend. Display phase completion rather than fabricated ETA when estimates are not reliably measured.

## 14. Secure and memory-bounded APK ingestion

Implement safe upload using streaming reads to a temporary quarantine directory, hard byte cap (default 80 MiB, configurable), SHA-256 hashing while streaming, extension + PK ZIP signature checks, content-addressed destination, atomic move, and a transactional sample record. Parse the ZIP central directory without extraction initially. Apply bounded ZIP entry count, maximum total uncompressed size, per-entry uncompressed size, compression ratio and maximum nesting depth; reject path traversal (`..`, absolute paths, Windows drive prefixes, Unicode normalization tricks), duplicated critical entries, symlinks and resource anomalies as appropriate. Do not follow archive paths. Parse malicious byte streams in an isolated low-permission worker, preferably a disposable sandbox; subprocess timeout and memory quotas where OS-supported.

**Default intake caps:** `MAX_UPLOAD_MIB=80`, `MAX_ZIP_ENTRIES=10000`, `MAX_TOTAL_UNCOMPRESSED_MIB=300`, `MAX_COMPRESSION_RATIO=100`, `MAX_ANALYSIS_SECONDS=300` (profile-dependent). Document these as engineering defaults, not empirical safe limits. Reject oversize files early. Record `archive_intake_rejected` as a machine event with file hash only when securely computed.

All paths must be rooted in managed storage, not client-provided. When a parser fails, record `PARSER_EXCEPTION`, tool version and the scope that could not be analysed, without upgrading it to a malicious verdict.

## 15. Genuine Android static-analysis pipeline

**Mandatory parser stages (use actual bytes, no API mock responses):**

1. **APK container:** validate ZIP; enumerate classes*.dex, AndroidManifest.xml, resources.arsc, lib/<ABI>/*.so, assets/, res/, META-INF, signing blocks where supported; report counts, sizes and coverage.
2. **Manifest:** parse Android binary AXML using a real APK parser, not plain UTF-8 regex. Extract package, version, min/target SDK, permissions, uses-feature, exported components and their intent filters; unknown if decoding fails.
3. **DEX inventory:** enumerate each DEX file, method/class counts when parsable, method identifiers, method references, cross-references, strings, suspicious API invocation candidates. Use Androguard and optionally JADX; do not claim complete call graph just from string matches.
4. **Permissions and configuration rules:** explain each rule and cite manifest element/artifact, e.g., debuggable flag, exported component without expected protection, cleartext traffic allowed, dangerous capabilities. Context matters; permission alone is not malware proof.
5. **Certificates / signing:** extract signer info and certificate fingerprints via supported library or `apksigner` adapter if configured; failure must say `not_available`.
6. **Network indicators:** extract potential URL/IP/domain strings (including normalization and dedup) as **static indicators**. Never say connection occurred unless runtime telemetry establishes it. Do not resolve, visit or enrich arbitrary destinations by default.
7. **Native/JNI:** inventory ELF metadata / ABI and JNI load patterns; mark uninspected native behavior as unknown.
8. **Dependency/library inventory:** best-effort from package fingerprints, not imaginary precise CVEs. Explicitly state when library identification is heuristic or version-unknown.
9. **Optional MobSF/JADX/aapt2:** independent adapter. Show tool version, configuration, timeout and their parser disagreement; failures cannot halt core static workflow unless fundamental archive integrity is compromised.

Implement structured rules as versioned records (`rule_id`, category, evidence_type, severity_policy, requirement, description, source_locator, MASVS/MASTG reference if verified). Store raw observations and derive findings, preserving a mapping back to the source artifact. Rule evaluation must be deterministic and unit tested with safe fixture APKs.

**Risk explanation:** support `Informational`, `Low`, `Medium`, `High`, `Critical` tiers based on documented weighted rule logic; do not display a 0–100 number as a probability. If numeric severity index is displayed, label it `triage index (heuristic)` and list contributing evidence. A triage index cannot be confused with detection accuracy, likelihood of guilt, or observed behaviour.

## 16. Blindspot Ledger: the product's first research differentiator

Implement a typed coverage ledger recording both discovered regions and unresolved regions at each analysis stage. Each record must contain: `scope_type` (`apk|manifest|dex|class|method|native|runtime|network`), scope identifier, `reason_code`, observation source, effect on confidence/coverage, suggested next step, and timestamp. Possible reason codes: `PARSE_ERROR`, `NATIVE_CODE_UNINSPECTED`, `REFLECTION_TARGET_UNRESOLVED`, `DYNAMIC_LOAD_TARGET_UNKNOWN`, `GUARD_UNSUPPORTED`, `SMT_TIMEOUT`, `METHOD_TOO_LARGE`, `BUDGET_EXCEEDED`, `ANDROID_API_MODEL_MISSING`, `RUNTIME_NOT_CONFIGURED`, `EMULATOR_ENVIRONMENT_LIMIT`, `NETWORK_DEPENDENCY_UNAVAILABLE`, `TOOL_DISAGREEMENT`, `NO_TRACE`, `UNKNOWN`.

Distinguish denominators. Examples: parsed DEX files / discovered DEX files; analyzed methods / inventoried methods; validated guard candidates / detected guard candidates; runtime scenarios executed / configured scenarios. An “overall 95% complete” metric is **prohibited** unless an explicit, measured, defensible denominator and weighting scheme is documented. Display coverage along dimensions instead.

If all checked stages returned no dangerous operations, but dynamic analysis is absent and JNI exists, the result must show `No relevant behaviour observed in performed checks` **and** `Native/runtime coverage incomplete`. A missing capability must never be silently interpreted as no risk.

## 17. Sensitive-path and trigger analysis: precise scientific contract

**First supported source/sink ontology (versioned):** Android SMS/contacts/location/clipboard/file reads, package/system properties, network I/O and intent/IPC surfaces. Map specific Android API method descriptors and provenance. Differentiate declared permission, API reference, proven invocation, observed invocation and sensitive data flow; they represent different claims.

**Phase-1 guarded paths:** support narrow, testable patterns (simple numeric comparisons, Boolean flags, synthetic fixture environment variables, time-window comparisons) in a bounded control-flow subset. Parse guard expressions to a typed JSON AST or DSL rather than free-text. Backward slice from a sensitive target through supported predecessor basic blocks, with call-depth/time/node budgets; mark all unresolved reflection, polymorphic dispatch, concurrency and native transitions.

**Guard AST example:**

```json
{
  "kind": "and",
  "terms": [
    {"kind": "compare", "left": {"var": "mock_device_state"}, "op": "eq", "right": {"literal": "ready"}},
    {"kind": "compare", "left": {"var": "elapsed_minutes"}, "op": "ge", "right": {"literal": 10}}
  ],
  "source": {"dex": "classes.dex", "method": "Ldemo/Guard;->shouldRun()Z", "block": "bb_12"}
}
```

Only solve actual supported numeric/Boolean constraints using Z3 with a strict solver timeout. Enumerate at most configured `MAX_WITNESSES_PER_PATH` and rank minimal witnesses under an explicitly defined cost. The term `witness` means a model satisfying **the analyzer's assumed constraints**; it is not evidence that an Android device will execute the path. If the target or variable semantics are unsupported, return `UNKNOWN`, `UNSUPPORTED`, or `TIMEOUT` — never convert solver failure into proof that path is impossible.

**Verification tiers:**

- `STATIC_REFERENCE`: code or manifest contains a referenced sensitive operation.
- `CONDITIONALLY_REACHABLE`: a solver-supported path under explicit assumptions; no runtime observation implied.
- `BOUNDED_REPLAY_CONFIRMED`: supported interpreter/test fixture actually traversed expected branch with logged test inputs.
- `RUNTIME_OBSERVED`: controlled Android runtime telemetry recorded the action; include trace artifact and instrumentation metadata.
- `UNRESOLVED`: insufficient coverage or contradictory evidence.

Evidence status fourfold UI remains `Observed`, `Conditionally reachable`, `Suspected`, `Unknown`; verification tier is recorded separately. Never use “proven malicious” automatically. For the MVP, it is acceptable if arbitrary real APKs produce mostly `STATIC_REFERENCE` and `UNRESOLVED` while controlled fixtures demonstrate supported witness reconstruction. That is scientifically honest and useful.

**Implementable bounded-path algorithm:**

```text
for each selected sensitive operation S:
  scope = build_local_cfg_and_call_references(S, limits)
  path_set = backward_slice(scope, stop_at_android_entry_or_budget)
  for candidate in path_set:
      guards, missing = extract_supported_guards(candidate)
      if missing: record_blindspot(candidate, missing)
      if not guards: record_static_reference(candidate)
      else:
          result = solver.check(guards, timeout)
          if result == SAT: store_candidate_witness_with_assumptions()
          elif result == UNSAT: store_unsat_for_this_model_only()
          else: store_unknown_reason()
  emit_versioned_records_with_artifact_locators()
```

Avoid treating all code paths as independently executable: Android event lifecycles, asynchronous callbacks, permissions, dynamic dispatch and app state cause substantial model gaps. Make gaps visible.

## 18. Differential analysis, evidence graph, and IoC provenance

Create typed nodes (`APK`, `DEX`, `Method`, `ManifestComponent`, `Permission`, `Library`, `NativeBinary`, `Indicator`, `Trigger`, `Finding`, `Blindspot`, `Experiment`) and typed edges (`CONTAINS`, `DECLARES`, `CALLS`, `REFERENCES`, `GUARDED_BY`, `OBSERVED_IN`, `EXTRACTED_FROM`, `SHARES_WITH`, `SUPPORTED_BY`). Each edge has `origin`, `artifact_id`, `derivation_rule`, and `confidence_label`. High fan-out nodes must be bounded and paged.

Between APKs, support exact certificate match, exact indicator match, code/strings similarity (clearly labelled heuristic), permission diffs, and differences in unknown coverage. Do not attribute two samples to the same attacker merely due to one shared CDN, generic SDK or signing certificate.

Threat intelligence: disabled by default. Optionally allow user-approved, privacy-aware enrichment of hashes or indicators; never upload full APK or personal information without authorisation. Support IoC import from known offline JSON for hackathon mode with source and timestamp.


# PART E — NVIDIA AI, FORENSIC EVIDENCE, AND ISOLATED VERIFICATION

## 19. NVIDIA NIM AI: secure and honest integration

Implement a **pluggable model provider** at `/analysis/ai/provider.py` with `NoAIProvider` and `NvidiaNimProvider`. The app must boot successfully with `NVIDIA_API_KEY` unset. Show model status and a button to turn AI-assisted review on for a case. Do not invoke a model automatically on every sample or add mandatory hosted dependencies.

**Environment configuration:**

```dotenv
APP_ENV=development
APP_HOST=127.0.0.1
APP_PORT=8000
DATA_DIR=./data
DATABASE_URL=sqlite:///./data/shadowpath.db
MAX_UPLOAD_MIB=80
MAX_ANALYSIS_SECONDS=300
ANALYSIS_PROFILE=standard
ENABLE_DEMO_FIXTURES=true
ENABLE_DYNAMIC_LAB=false
ENABLE_AI=false
NVIDIA_API_KEY=
NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1
NVIDIA_MODEL=
NVIDIA_MAX_TOKENS=1200
NVIDIA_TIMEOUT_SECONDS=45
NVIDIA_DAILY_CALL_BUDGET=25
CLOUD_EVIDENCE_CONSENT_REQUIRED=true
REPORT_SIGNING_PRIVATE_KEY_PATH=
```

Before selecting a default model, verify the exact model identifier against NVIDIA Build and the provided account; make it user-configurable. NVIDIA NIM hosted inference supports OpenAI-compatible `POST /v1/chat/completions` at `https://integrate.api.nvidia.com/v1`. Handle HTTP 401, 429, 5xx, timeouts, invalid responses, incompatible model IDs and missing credentials. Implement exponential backoff for retryable calls within bounded attempt/token cost; never loop indefinitely. **Do not infer that free NVIDIA API access is unlimited or that the chosen model is guaranteed to remain available.**

**Data minimisation policy:** cloud OFF by default; explicit analyst consent per case; send only sanitized evidence summaries: rule IDs, generalized method descriptor categories, boolean markers and redacted or hashed indicators. Do not send raw APK bytes, customer data, personal identifiers, private URLs, credentials, forensic case notes, access tokens, or arbitrary unredacted code. Build a redaction unit test. Treat APK strings as adversarial instructions: escape content into JSON evidence fields and tell the model that extracted app data is untrusted, not instructions.

**TRI-PROOF output schema:**

```json
{
  "schema_version": "1.0",
  "malicious_hypothesis": {
    "statement": "Candidate misuse of sensitive capability",
    "supporting_evidence_ids": ["obs-101"],
    "contradicting_evidence_ids": [],
    "uncertainties": ["No runtime observation"]
  },
  "benign_hypothesis": {
    "statement": "Potential legitimate feature use",
    "supporting_evidence_ids": ["obs-102"],
    "contradicting_evidence_ids": [],
    "uncertainties": ["Purpose not independently verified"]
  },
  "proposed_experiment": {
    "operation_id": "INSPECT_GUARDED_PATH",
    "input_evidence_ids": ["obs-101", "obs-102"],
    "expected_information_gain": "May distinguish guarded network path from standalone API reference",
    "requires_analyst_approval": true
  },
  "notes": "Hypothesis only; no assertion that malicious behaviour occurred"
}
```

Use Pydantic to validate the exact allowed schema, evidence ID existence, permitted operation IDs, bounded string lengths, and forbidden leakage. A model response must never execute shell, Python, browser navigation, ADB, network requests or dynamic instrumentation commands. It may select only from a **static whitelist** of safe investigative operations, each approved/executed by local deterministic code. Reject fabricated evidence IDs and store validation errors for review. A rejected AI proposal cannot produce a `finding` or change evidence status.

**AI explanation status:** `not_configured`, `disabled`, `consent_required`, `queued`, `generated`, `validation_failed`, `rate_limited`, `temporarily_unavailable`, `redacted`. Where offline, generate a concise factual text summary from deterministic records without pretending it came from NVIDIA.

**Adaptive planner (optional advanced):** propose experiments with a transparent score such as `estimated_relevance × coverage_gap_reduction / (predicted_cpu_cost + memory_penalty + execution_risk)`, all components logged. Initially use manually configured estimates; never describe them as measured until benchmarked. Always prioritize bounded, safe tests; no external target probing.

## 20. Forensic capsule and report engine — verifiable evidence

A complete case report must contain: case/sample identities, immutable original file SHA-256, analysis profile, tool/version ledger, UTC times, extracted metadata, permissions/components, code/API references, IoCs, findings and their evidence statuses, precise blindspot ledger, supported guarded paths/witness assumptions, AI hypotheses clearly demoted to proposals, experiments and their observed outcomes, risk methodology, verification limitations, and analyst annotations. Produce exportable PDF and machine-readable JSON.

**Capsule directory (immutable after finalization):**

```text
capsules/<case-id>/<job-id>/
  manifest.json                 # canonical files list and hashes
  sample.json                   # original sample identity only
  config.json                   # sanitized profile and tool settings
  tool_versions.json
  artifacts/
    manifest.json
    dex_inventory.json
    permissions.json
    indicators.json
  claims/
    findings.json
    blindspots.json
    guarded_paths.json
    ai_proposals.json
  experiments/
    experiment_index.json
  analyst/
    review_events.json
  reports/
    report.pdf
  verification.json
```

Canonicalize JSON consistently (document Unicode/number normalization) and hash each stored file before writing a manifest with deterministic ordering. Manifest must not hash itself circularly; calculate final manifest digest separately. Optionally sign digest using an Ed25519 key stored outside repository/APP data (when cryptographic dependency is available). The verifier must independently rehash all listed files, validate manifest ordering/schema, detect extra/missing/changed files, validate signature if provided, and distinguish `INTEGRITY_PASS`, `INTEGRITY_FAIL`, `SIGNATURE_NOT_CONFIGURED`, `SIGNATURE_INVALID`. It should verify integrity, **not** claim that findings are scientifically correct.

Provide both CLI `python scripts/verify-capsule.py <path>` and API action; ensure tests modify one exported artifact and verify the tool flags tampering. Avoid embedding user secrets or file system paths in generated reports. Embed safe descriptions and source locators. Provide a professional PDF with title, executive summary, finding detail table, evidence chain, limitations and review footer.

## 21. Optional dynamic analysis laboratory — never run malware on main host

Dynamic analysis is **not required for core app startup**. Implement an explicit lab adapter architecture with capability detection. If the user has a disposable Android emulator/device in an isolated environment and separately configures MobSF or ADB/Frida, show a guided opt-in workflow; otherwise show `NOT_CONFIGURED` and list missing requirements.

Minimum safe design: separate worker/container/VM network namespace from main host, no access to personal data or credentials, synthetic fixture contacts/messages, network default-deny with a local sink/server for observation, storage snapshot/revert, bounded runtime timeout, complete lab logs. Never automatically bypass production protections or contact suspected command-and-control servers; do not run real malware on the user's personal Android device. All instrumentation actions must be defensive and explicitly approved.

**Runtime event provenance:** `experiment_id`, `sample_sha256`, `runtime_environment_id`, `device_image_version`, `interception_tool`, `event_type`, `event_time`, `trace_artifact_id`, `captured_payload_redaction_status`. A static URL string is not a runtime network connection; display these as separate observable categories.

**Optional MobSF:** official REST API can support upload/scan/report and an optional runtime integration, but it is never the only source of product functionality. Make MobSF an adapter displaying its own version, status and coverage. Map imported findings to canonical observations with source tool metadata and retain original reports without silently overwriting SHADOWPATH conclusions.

---

# PART F — SECURITY, PERFORMANCE, TESTING AND OPERATIONS

## 22. Authentication, authorisation and platform security

Implement single-node local analyst operation with a secure first-run admin setup and roles `admin`, `analyst`, `viewer`. Default deployment must not ship a universal hardcoded password. Use Argon2id password hashing, secure server sessions or appropriately protected HttpOnly cookies, CSRF protection on mutating requests, rate limiting, and role/owner checks on every case/report/resource. Secure cookies in HTTPS production, `SameSite`, structured logout, idle expiry. Avoid localStorage tokens if using session cookies.

Host API on loopback by default. Tight CORS for dev frontend origin; in deployment use same-origin reverse proxy. Validate input and output payloads; escape malicious extracted strings (XSS). Implement proper Content Security Policy, clickjacking defense, file-download `Content-Disposition`, conservative logging and retention controls. No arbitrary path or URL fetch endpoints. No unauthenticated static access to uploaded samples or reports.

**Unsafe upload threat model:** ZIP slip, ZIP bomb, overlapping/malformed ZIP, crafted AXML/DEX/ELF parser exploitation, memory exhaustion, CPU denial, log injection, Unicode path spoofing, formula injection in exported CSV, persisted XSS from APK names/strings, prompt injection in APK literals, leaked keys, report tampering, local path traversal. Write at least one negative test for each relevant class; document any gaps.

Never execute extracted code in the parser worker. If using subprocess-based external parsers, supply argument arrays with `shell=False`, absolute vetted binary paths, timeouts and restricted environment. A malicious APK must not gain network access from the parser stage. For Windows environments where hard process memory limits cannot be enforced safely, note the limitation and recommend running untrusted analyzers through WSL2/container/isolation; do not claim stronger sandboxing than implemented.

## 23. Reliability and operations

Structured JSON logs with request ID, job ID, sample ID (no raw private data), stage, elapsed milliseconds and error code. Health page should show true availability of DB, worker heartbeat, storage free space, parser version, optional model; never assert `healthy` if worker is missing. Write log rotation and retention policies; expose bounded application telemetry without secret values. Job queue persists after restart; stage retries are idempotent and do not duplicate observations. Use transaction boundaries and constraints to handle concurrent requests.

**Performance profiles, targets not guarantees:**

- `Lite`: CPU-first, one job, APK inventory + manifest + basic rules; design target of operation on 4 GB system RAM for small APKs; set memory/time budgets and downgrade gracefully.
- `Standard`: DEX inventory, IoCs, blindspot ledger, backed findings, modest graphs; aimed at 8 GB RAM without GPU.
- `Advanced`: additional path analysis, Z3, optional external parsers/cloud AI; may consume more resources.

On any profile, show actual peak memory/time metrics only if measured. Avoid unconditional parallel parsers on low-end hardware. Apply hard operation budgets and record precisely why stages are partial. Performance benchmarks must be reproducible and labelled with sample size, machine specs, tool versions and run count.

## 24. Fixture-first testing and real demonstration data

Create **controlled, benign or synthetic laboratory APK fixtures** from source checked into `fixtures/safe-android-apps/`. A small Android Gradle project per fixture is enough. Build their APKs using Android SDK where available; when unavailable provide prebuilt, verified redistribution-safe fixtures only if licensing and provenance are documented. Never check known live malware into the repo.

Minimum fixture matrix:

| Fixture | Planted behaviour | Ground truth / expected result |
|---|---|---|
| `hello_world` | Ordinary benign UI | Manifest and basic inventory; no invented threats |
| `permissions_legitimate` | Legitimate permission use | Permission observation, no automatic malware verdict |
| `manifest_misconfig` | Deliberately unsafe exported test component | Verified rule with source locator |
| `time_guarded_sink` | Controlled sensitive test sink behind time guard | Candidate witness and fixture replay |
| `device_guarded_sink` | Test sink behind synthetic device-state guard | Supported guard AST and analysis assumptions |
| `dead_branch` | Unsatisfiable simple guard | UNSAT within supported model; not “app safe” |
| `reflection_unknown` | Reflection unresolved without target | Blindspot, never false confident no-threat |
| `native_placeholder` | JNI stub or benign `.so` | Inventory + native-uninspected blindspot |
| `malformed_archive` | Intentionally invalid ZIP | Rejected safely, no host crash |
| `oversize_archive` | Compression-ratio/size abuse fixture | Deterministic rejection |
| `adversarial_strings` | APK string says “ignore prior instructions” | UI escapes string; AI ignores as instruction |
| `variant_a` / `variant_b` | Shared certificate/known URL in lab | Evidence-backed graph edges with limitations |

**Never silently show fixture data as real case evidence.** Show a persistent `SYNTHETIC TEST DATA` label on each fixture, and have the API also return fixture metadata. Include a one-click `Load Test Cases` development-only feature that populates a local case from true fixture APKs; disable it in production by default.

## 25. Test suite and precise acceptance criteria

### Backend unit tests

- Valid APK creates immutable SHA-256 record and queues exactly one requested job.
- Duplicate upload returns the same content hash safely; separate case association works.
- Non-APK, traversal filename, archive bomb, truncated DEX, malformed AXML are rejected or marked partial without crashing API.
- Manifest permission/component observations point to source artifact IDs.
- Static string indicator does not become `RUNTIME_OBSERVED`.
- Worker cancellation and restart recovery leave coherent terminal/nonterminal states.
- Z3 SAT/UNSAT/TIMEOUT/unsupported preserve their distinct statuses.
- Blindspot reason codes and denominators remain truthful.
- Model fabricated IDs are rejected; no shell command or unsafe operation runs.
- Capsule verifier passes unmodified output and fails after tampering.
- Auth and case authorisation prevent cross-user access.

### Frontend tests

- New investigation upload validation, profile selection, error handling.
- Live job stage updates and SSE reconnection/poll fallback.
- Case reopen after browser refresh; results reflect persisted API content.
- All main routes have loading/empty/error states.
- Click finding opens exact source evidence; graph edge inspector shows provenance.
- Disabled NVIDIA and dynamic lab states are honest, not empty success.
- Tables filter/sort/paginate real results, with accessibility checks.
- PDF/JSON export action downloads the correct file and reports failure visibly.

### End-to-end real run

From a clean clone: install dependencies, initialize DB, create first user, start backend + worker + frontend, build/load a controlled APK, upload it, wait for persisted job result, view manifest, findings, blindspots, guarded path (on supported fixture), export capsule, verify hashes, kill and restart services, and reopen identical evidence. Capture screenshots/logs and a short screen recording (optional) **from the actual app**, not design mocks.

### Quality gate commands

Create scripts to run: `ruff check`, `ruff format --check`, `mypy` (or documented scoped type checking), `pytest -q`, `npm run lint`, `npm run typecheck`, `npm run test`, `npm run build`, `npx playwright test`. Pin/configure tools in repo. If any cannot run due to platform or missing SDK, state explicitly what was not verified and provide reproducible instructions; do not report all green.

### Metrics research plan

On a separately held-out fixture set, measure precision, recall, false-positive rate for guarded-path detection, witness validation accuracy, analysis coverage and unknown rate, CPU seconds per verified lead, peak memory, repeatability across 3 runs, and failure rates under hostile inputs. Label all unmeasured targets as goals, not results. Compare fixed analysis sequence vs resource-adaptive analysis only if both are truly implemented. Report complete sample counts and dataset provenance.

## 26. Developer startup experience and deployability

One fresh-clone path is mandatory. Implement `scripts/dev.ps1` for Windows PowerShell, `scripts/dev.sh` for bash, and an optional Docker Compose path. These scripts must create `.env` from `.env.example` if absent (without overwriting real secrets), prepare directories, install from lockfiles, run migrations, start API and worker in proper processes, and start Vite frontend with discoverable local URLs. Avoid port conflicts; prefer API 8000, web 5173, and detect busy ports with a clear error or configurable values. Do not open network interfaces beyond localhost without explicit config.

Document prerequisites: supported Python/Node versions, Android SDK only for fixture compilation, Docker/MobSF only for optional adapters, NVIDIA API key only for opt-in cloud AI. Provide `README` sections: Quickstart, Features Actually Implemented, Architecture, Screenshots from real app, API, Fixtures, Threat Model, Limitations, Testing, Deployment, Collaborator Setup, Video Demo Script, and Troubleshooting. Build a real `/health` page and show environment capability checks.

**CI workflow:** Python lint/tests and frontend lint/typecheck/build/test; do not fetch untrusted live samples in CI. Generate clean, reproducible artifacts; use GitHub Actions with dependency caching and no exposed secrets. A separate opt-in workflow may compile fixture APKs when Android SDK runner is available. Do not depend on unrestricted hosted scanning to get passing tests.

---

# PART G — CODEX BUILD SEQUENCE AND DEFINITION OF DONE

## 27. Implement in these vertical slices (do not stop at planning)

**Gate 0 — Inspect and design contract.** Examine repository tree, installed dependencies and OS. Create concise `docs/architecture-decisions.md` and `docs/IMPLEMENTATION_STATUS.md` listing supported vs planned modules. Establish monorepo, environment, build scripts and baseline tests. Commit.

**Gate 1 — End-to-end upload works.** Implement backend FastAPI app, DB migrations, secure first-run auth, sample intake, case creation, background worker and job queue, SSE/poll, frontend shell and upload workflow. Upload a controlled APK through browser and persist job record across restart. Write tests and commit.

**Gate 2 — Real scanner pipeline works.** Parse APK container, binary AndroidManifest, permissions/components, DEX method/reference inventory, strings/IoCs, certificate fingerprint if supported. Persist artifact source IDs and rule results. UI shows true extracted observations; failures are explicit. Write tests and commit.

**Gate 3 — Signature feature works.** Implement blindspot reason taxonomy/coverage ledger and page. Add versioned source/sink ontology and at least one limited guarded-path evaluator for controlled fixtures. Use Z3 only for defined typed constraints; show precise assumptions and ambiguous cases. Finish evidence status separation. Write tests and commit.

**Gate 4 — Analyst-grade UI and investigation.** Implement overview, job live progress, detailed multi-tab case, findings explorer, library, comparison, evidence graph with bounded nodes, indicators, review notes and system health; visual tests and responsive screenshots. Every listed interaction needs a real route or is explicitly marked unavailable. Write tests and commit.

**Gate 5 — NVIDIA + reporting + integrity.** Implement optional sanitized provider with explicit consent, TRI-PROOF schema, allowlisted operations, offline fallback. Implement report JSON/PDF and evidence capsule with verifier. Write tests; test key-missing and 429 failures; commit.

**Gate 6 — Harden, benchmark, demonstrate.** Add authorization tests, hostile upload tests, worker recovery, real fixture end-to-end, benchmark tables, captured screenshots, clean README, CI, release notes, limitations and 8–10 minute video outline. Verify honest capability map. Commit.

**Do not** jump to Gate 4 decorative charts before Gates 1–3 genuinely work. If there is insufficient time, stop after a complete, tested vertical slice rather than declaring later gates complete. Maintain a concise implementation status list with `DONE`, `PARTIAL`, `NOT STARTED`, and evidence (test/commit) for each capability.

## 28. Exact definition of done — no exceptions for the MVP

A release labelled `MVP READY` is permitted only when:

- [ ] Clean-clone startup works with zero NVIDIA credentials and without Docker.
- [ ] Browser performs real APK upload; server hashes and safely stores actual bytes.
- [ ] Standalone worker consumes and persists jobs; reload/restart restores real status.
- [ ] Manifest and DEX insights are extracted from real APK bytes and saved with source references.
- [ ] Every finding has supporting artifact(s), a deterministic rule/version and evidence status.
- [ ] Blindspot ledger is populated from real missing capabilities/unsupported parsing—not invented numbers.
- [ ] Supported fixture guarded paths return explicit constraints/witness or `unsupported`, and matching controls prove conservatism.
- [ ] NVIDIA optional integration never changes deterministic observation status; disabled state works.
- [ ] JSON and PDF report downloads work; independent capsule verifier detects tampering.
- [ ] Overview, cases, scan page, job progress, details, findings, graph and reports are connected to live APIs.
- [ ] Empty/error/loading/small-screen states, keyboard focus and accessible labels are handled.
- [ ] User auth and storage access controls work; no secrets appear in client bundle.
- [ ] Unit, integration, security-negative and at least one Playwright end-to-end test pass.
- [ ] Screenshots are captured from the running product, not concept renders.
- [ ] `IMPLEMENTATION_STATUS.md` precisely identifies limitations, optional dependencies, and test outcomes.
- [ ] Git history contains multiple feature commits with actual code progression.

## 29. Required Codex working style and final handoff

**Start coding immediately** after inspecting the environment. Deliver real file changes in small coherent commits. Plan briefly in `docs/IMPLEMENTATION_STATUS.md`, then implement. Do not respond with “Here is how I would build it” as the final artifact. At the end of each gate run actual commands, resolve failures, and include terminal/test output in a concise status summary.

Before claiming completion, execute and document:

```text
[ ] git status --short
[ ] backend dependency install and DB migration
[ ] backend unit tests
[ ] API worker startup and health checks
[ ] frontend install, lint, typecheck, build
[ ] Playwright browser smoke test
[ ] fixture APK intake and completed analysis
[ ] persisted findings/unknowns/guard demo
[ ] report export and hash-chain verification
[ ] service restart and data persistence
[ ] NVIDIA key-missing/offline functionality
[ ] commit history inspection
```

Final response from the coding agent must include: (1) implemented capabilities with source paths, (2) local startup commands, (3) screenshot locations, (4) test commands/results, (5) known gaps and unsupported research features, (6) demo flow, (7) commit references, and (8) any required manual setup. If a requirement could not be implemented, say precisely why; no inaccurate “100% working” promise.

## 30. Nine-minute submission video plan for Team PARTH

The organiser asks for an 8–10 minute explanation and demonstration video. Make the recording 9 minutes, ensure the Google Drive link is actually accessible to the designated reviewer account, and **show a working application rather than PPT only**. This is a production plan, not a claim that the portal already accepted the submission.

| Segment | Duration | Demonstrate |
|---|---:|---|
| Context | 0:00–0:50 | Malicious Android apps and why short scans can miss hidden behaviours |
| Differentiator | 0:50–1:45 | Blindspot ledger, guarded-path investigation, verified forensic capsule |
| Architecture | 1:45–2:30 | One clean system diagram: browser, backend, worker, evidence, optional NVIDIA |
| Real intake | 2:30–3:50 | Upload genuine benign/control APK, show SHA-256, manifest/DEX contents |
| Investigation | 3:50–5:30 | Findings plus blindspot ledger, explain observed vs unknown |
| Hard feature | 5:30–6:45 | Fixture guarded path, solver witness/limits, controlled verification |
| AI and evidence | 6:45–7:50 | Optional TRI-PROOF with citations; JSON/PDF capsule download and verify |
| Closing | 7:50–9:00 | Real test metrics, research novelty, limitations, team Git commits |

Use screen recordings of actual API-backed interactions. If NVIDIA API is down, show offline fallback intentionally. Never replace a failed runtime with an edited/faked terminal transcript. If dynamic emulation was not implemented, explain honestly that it is an optional research extension.

---

# PART H — REFERENCE LINKS AND SCIENTIFIC CAUTIONS

## 31. Authoritative integration references for the coding agent

Use official and actively maintained documentation, validate API signatures and compatible versions at implementation time. Relevant starting points:

- **Official Android assessment:** https://mas.owasp.org/ (MASVS, MASTG, MASWE; use current test IDs only after verifying them).
- **MobSF official repository:** https://github.com/MobSF/Mobile-Security-Framework-MobSF
- **MobSF API documentation:** https://mobsf.live/api_docs
- **Androguard documentation:** https://androguard.readthedocs.io/
- **JADX:** https://github.com/skylot/jadx
- **Z3Py:** https://ericpony.github.io/z3py-tutorial/guide-examples.htm
- **NVIDIA hosted inference:** https://docs.api.nvidia.com/nim/reference/llm-apis
- **NVIDIA model catalogue:** https://build.nvidia.com/
- **FastAPI:** https://fastapi.tiangolo.com/
- **SQLAlchemy 2:** https://docs.sqlalchemy.org/en/20/
- **React:** https://react.dev/
- **TanStack Query:** https://tanstack.com/query/latest
- **React Flow:** https://reactflow.dev/
- **DroidBench:** https://github.com/secure-software-engineering/DroidBench
- **TaintBench:** https://taintbench.github.io/evaluation/

Do not copy proprietary datasets, closed-source APKs or copyrighted assets into the repo without documented permission. Existing research and products cover many related ideas; differentiation and performance must be validated experimentally. Scientific notes: an anti-analysis-looking artifact can arise from ordinary packaging; a trigger is not proof of malicious intent; absence of observed behavior is not evidence of safety; confidence intervals and conformal bounds apply only under their explicit assumptions; tamper-evident hashes prove file integrity, not court admissibility.

## 32. Final command to the Codex agent

**Implement SHADOWPATH Ω — NEXUS now, directly in this repository.** Follow Gates 0 through 6 in sequence, prioritising a functional, secure, verified vertical slice. Produce a visual design indistinguishable in care and consistency from a mature enterprise DFIR product, but never trade evidence accuracy for appearance. Run the application, inspect it through an actual browser, fix broken interactions, validate the APK analysis and forensic exports, and deliver code, tests, screenshots and reproducible startup instructions. Do not stop after generating a specification. Continue implementation until the supported acceptance gates pass or a real external blocker is documented. Use explicit supported/partial/unavailable states for difficult research functionality. **No fabricated findings, simulated progress, or false completion claims.**

---

# APPENDIX I — EXAMPLE FRONTEND COMPONENT DATA CONTRACT

```ts
export type EvidenceStatus =
  | 'observed'
  | 'conditionally_reachable'
  | 'suspected'
  | 'unknown';

export type StageStatus =
  | 'pending' | 'running' | 'completed'
  | 'partial' | 'skipped' | 'failed';

export interface ForensicFinding {
  id: string;
  jobId: string;
  ruleId: string;
  title: string;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  evidenceStatus: EvidenceStatus;
  sourceArtifactIds: string[];
  location?: { dex?: string; descriptor?: string; manifestPath?: string };
  description: string;
  limitations: string[];
}

export interface BlindspotRecord {
  id: string;
  jobId: string;
  scopeType: string;
  scopeId: string;
  reasonCode: string;
  affectedArtifactIds: string[];
  limitation: string;
  suggestedNextStep?: string;
}

export interface AnalysisJob {
  id: string;
  caseId: string;
  sampleId: string;
  status: string;
  stagesCompleted: number;
  stagesTotal: number;
  startedAt?: string;
  finishedAt?: string;
  errorCode?: string;
}
```

# APPENDIX II — SAFE DEMO GROUND-TRUTH CONTRACT

Each controlled APK fixture must have a checked-in expected-results JSON (source, commit, build hash, known intentionally planted behaviours). Example:

```json
{
  "fixture": "time_guarded_sink",
  "synthetic": true,
  "apk_sha256": "POPULATE_FROM_ACTUAL_BUILD",
  "expected": {
    "manifest_parsed": true,
    "dex_inventory_nonempty": true,
    "guard_class": "simple_time_comparison",
    "sensitive_operation_type": "synthetic_test_sink",
    "runtime_maliciousness_claim": false
  },
  "notes": "Controlled non-harmful fixture; never label as real-world malware"
}
```

# APPENDIX III — FINAL ENGINEERING GUARDRAILS

**If Codex faces a choice between a broad, largely decorative system and a narrow functioning one, choose the narrow functioning system.** If it faces a choice between a fabricated impressive result and a truthful `UNKNOWN`, choose `UNKNOWN`. If it faces a choice between running an APK on the host and skipping unsupported dynamic analysis, skip and explain. If it faces a choice between cloud AI convenience and exposing sensitive evidence, keep the data local. If it faces a choice between a single final commit and incremental verified commits, commit incrementally. If it faces a choice between a flashy dashboard and traceable evidence, prioritize traceable evidence and design that makes it understandable.

**END OF CODEX MASTER PROMPT.**
