from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator

from backend.config import settings


SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS samples (
  sha256 TEXT PRIMARY KEY,
  original_filename TEXT NOT NULL,
  byte_size INTEGER NOT NULL,
  storage_path TEXT NOT NULL,
  archive_entry_count INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  synthetic_fixture INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cases (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  analyst_note TEXT NOT NULL DEFAULT '',
  profile TEXT NOT NULL CHECK(profile IN ('lite', 'standard', 'advanced')),
  nvidia_requested INTEGER NOT NULL DEFAULT 0,
  dynamic_lab_requested INTEGER NOT NULL DEFAULT 0,
  sample_sha256 TEXT NOT NULL REFERENCES samples(sha256),
  status TEXT NOT NULL DEFAULT 'queued',
  risk_score INTEGER,
  risk_tier TEXT NOT NULL DEFAULT 'undetermined',
  completeness INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  sample_sha256 TEXT NOT NULL REFERENCES samples(sha256),
  status TEXT NOT NULL CHECK(status IN ('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')),
  current_stage TEXT,
  error_code TEXT,
  error_detail TEXT,
  cancellation_requested INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_stages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  stage_key TEXT NOT NULL,
  position INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'running', 'completed', 'partial', 'skipped', 'failed')),
  started_at TEXT,
  finished_at TEXT,
  detail_json TEXT NOT NULL DEFAULT '{}',
  UNIQUE(job_id, stage_key)
);

CREATE TABLE IF NOT EXISTS job_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  level TEXT NOT NULL CHECK(level IN ('info', 'warning', 'error')),
  message TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  artifact_type TEXT NOT NULL,
  subject TEXT NOT NULL,
  source_locator TEXT NOT NULL,
  sha256 TEXT,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL,
  rule_version TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('informational', 'low', 'medium', 'high', 'critical')),
  evidence_status TEXT NOT NULL CHECK(evidence_status IN ('observed', 'conditionally_reachable', 'suspected', 'unknown')),
  description TEXT NOT NULL,
  limitations_json TEXT NOT NULL,
  artifact_ids_json TEXT NOT NULL,
  location_json TEXT NOT NULL DEFAULT '{}',
  reviewer_status TEXT NOT NULL DEFAULT 'unreviewed',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS blindspots (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  reason_code TEXT NOT NULL,
  limitation TEXT NOT NULL,
  suggested_next_step TEXT,
  artifact_ids_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS indicators (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  indicator_type TEXT NOT NULL,
  value TEXT NOT NULL,
  observable_level TEXT NOT NULL CHECK(observable_level IN ('static_string', 'runtime_observed')),
  artifact_id TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  UNIQUE(case_id, indicator_type, value, artifact_id)
);

CREATE TABLE IF NOT EXISTS annotations (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  decision TEXT NOT NULL CHECK(decision IN ('reviewed', 'needs_further_testing', 'false_positive')),
  note TEXT NOT NULL DEFAULT '',
  analyst TEXT NOT NULL DEFAULT 'local-analyst',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  report_json_path TEXT NOT NULL,
  report_pdf_path TEXT NOT NULL,
  capsule_path TEXT NOT NULL,
  capsule_sha256 TEXT NOT NULL,
  verification_status TEXT NOT NULL DEFAULT 'not_verified',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS guard_paths (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  target_method_id TEXT NOT NULL,
  guard_ast_json TEXT NOT NULL,
  solver_status TEXT NOT NULL CHECK(solver_status IN ('sat', 'unsat', 'unknown', 'unsupported', 'timeout')),
  supported_subset INTEGER NOT NULL,
  witness_json TEXT NOT NULL DEFAULT '{}',
  limitations_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_proposals (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('generated', 'validation_failed', 'rate_limited', 'temporarily_unavailable', 'failed')),
  proposal_json TEXT NOT NULL DEFAULT '{}',
  validation_errors_json TEXT NOT NULL DEFAULT '[]',
  evidence_ids_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel_observations (
  id TEXT PRIMARY KEY,
  case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_value TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('found', 'not_found', 'error')),
  summary_json TEXT NOT NULL DEFAULT '{}',
  observed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin', 'analyst', 'viewer')),
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
  key TEXT PRIMARY KEY,
  value_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_id TEXT,
  detail_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assistant_threads (
  id TEXT PRIMARY KEY,
  case_id TEXT REFERENCES cases(id) ON DELETE SET NULL,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assistant_messages (
  id TEXT PRIMARY KEY,
  thread_id TEXT NOT NULL REFERENCES assistant_threads(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
  content TEXT NOT NULL,
  mode TEXT NOT NULL CHECK(mode IN ('user', 'local_deterministic', 'nvidia_nim', 'local_fallback')),
  citations_json TEXT NOT NULL DEFAULT '[]',
  tool_runs_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, created_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id, artifact_type);
CREATE INDEX IF NOT EXISTS idx_findings_case ON findings(case_id, severity);
CREATE INDEX IF NOT EXISTS idx_blindspots_case ON blindspots(case_id, reason_code);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash, expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ai_proposals_case ON ai_proposals(case_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_guard_paths_case ON guard_paths(case_id, solver_status);
CREATE INDEX IF NOT EXISTS idx_assistant_threads_user ON assistant_threads(user_id, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_assistant_messages_thread ON assistant_messages(thread_id, created_at);
CREATE INDEX IF NOT EXISTS idx_threat_intel_case ON threat_intel_observations(case_id, provider, observed_at DESC);
"""


def utcnow() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def get_connection(path: Path | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(path or settings.database_path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def initialise_database() -> None:
    settings.ensure_directories()
    with get_connection() as connection:
        connection.executescript(SCHEMA)
        connection.execute(
            "INSERT OR IGNORE INTO app_settings (key, value_json, updated_at) VALUES ('default_profile', '\"standard\"', ?)",
            (utcnow(),),
        )


@contextmanager
def transaction() -> Iterator[sqlite3.Connection]:
    connection = get_connection()
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def row_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None
