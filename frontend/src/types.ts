export type StageStatus = 'pending' | 'running' | 'completed' | 'partial' | 'skipped' | 'failed'
export type EvidenceStatus = 'observed' | 'conditionally_reachable' | 'suspected' | 'unknown'

export interface CaseRecord {
  id: string
  title: string
  analyst_note: string
  profile: 'lite' | 'standard' | 'advanced'
  status: string
  sample_sha256: string
  original_filename: string
  byte_size: number
  risk_score: number | null
  risk_tier: string
  completeness: number
  created_at: string
  synthetic_fixture: number
}

export interface JobStage {
  stage_key: string
  position: number
  status: StageStatus
  started_at: string | null
  finished_at: string | null
  detail: Record<string, unknown>
}

export interface Job {
  id: string
  case_id: string
  sample_sha256: string
  status: string
  current_stage: string | null
  error_code: string | null
  error_detail: string | null
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface JobEvent {
  id: number
  level: 'info' | 'warning' | 'error'
  message: string
  payload: Record<string, unknown>
  created_at: string
}

export interface Finding {
  id: string
  rule_id: string
  title: string
  category: string
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical'
  evidence_status: EvidenceStatus
  description: string
  limitations: string[]
  artifact_ids: string[]
  reviewer_status: string
}

export interface Blindspot {
  id: string
  scope_type: string
  scope_id: string
  reason_code: string
  limitation: string
  suggested_next_step: string | null
  artifact_ids: string[]
}

export interface Artifact {
  id: string
  artifact_type: string
  subject: string
  source_locator: string
  sha256: string | null
  data: Record<string, unknown>
}

export interface Indicator {
  id: string
  indicator_type: string
  value: string
  observable_level: string
}

export interface ReportRecord {
  id: string
  case_id: string
  job_id: string
  capsule_sha256: string
  verification_status: string
  created_at: string
  title?: string
}
