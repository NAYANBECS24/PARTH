import type { Artifact, Blindspot, CaseRecord, Finding, Indicator, Job, JobEvent, JobStage, ReportRecord } from './types'

const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://127.0.0.1:8000'

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message)
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, options)
  if (!response.ok) {
    const body = await response.json().catch(() => null) as { detail?: string | { message?: string } } | null
    const detail = typeof body?.detail === 'string' ? body.detail : body?.detail?.message
    throw new ApiError(response.status, detail ?? `Request failed (${response.status})`)
  }
  return response.json() as Promise<T>
}

export interface Health {
  status: string
  mode: string
  worker: { queued_jobs: number; running_jobs: number }
  adapters: Record<string, string | { status: string; version?: string; reason?: string }>
}

export interface Overview {
  counts: { cases: number; active_jobs: number; unreviewed_high_priority_findings: number; open_blindspots: number }
  recent_cases: Array<Pick<CaseRecord, 'id' | 'title' | 'status' | 'risk_score' | 'risk_tier' | 'completeness' | 'created_at' | 'original_filename'> & { sha_prefix: string }>
  jobs: Array<Pick<Job, 'id' | 'case_id' | 'status' | 'current_stage' | 'created_at'>>
}

export interface CaseDetail {
  case: CaseRecord
  latest_job: Job | null
  artifacts: Artifact[]
  findings: Finding[]
  blindspots: Blindspot[]
  indicators: Indicator[]
  reports: ReportRecord[]
}

export interface JobDetail { job: Job; stages: JobStage[]; events: JobEvent[] }

export const api = {
  health: () => request<Health>('/health'),
  overview: () => request<Overview>('/api/overview'),
  cases: (search = '') => request<{ items: CaseRecord[]; total: number }>(`/api/cases?search=${encodeURIComponent(search)}`),
  case: (id: string) => request<CaseDetail>(`/api/cases/${id}`),
  job: (id: string) => request<JobDetail>(`/api/jobs/${id}`),
  findings: () => request<{ items: Finding[] }>('/api/findings'),
  reports: () => request<{ items: ReportRecord[] }>('/api/reports'),
  graph: (caseId: string) => request<{ nodes: Array<{ id: string; type: string; label: string }>; edges: Array<{ id: string; source: string; target: string; type: string }>; limited: boolean }>(`/api/cases/${caseId}/graph`),
  async intake(form: FormData) {
    return request<{ case_id: string; job_id: string; sample: { sha256: string; byte_size: number; original_filename: string; deduplicated_content: boolean } }>('/api/cases/intake', { method: 'POST', body: form })
  },
  async cancel(jobId: string) {
    return request<{ status: string }>(`/api/jobs/${jobId}/cancel`, { method: 'POST' })
  },
  async reviewFinding(findingId: string, decision: 'reviewed' | 'needs_further_testing' | 'false_positive') {
    return request(`/api/findings/${findingId}/review`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision }) })
  },
  verifyReport: (id: string) => request<{ valid: boolean; failures: Array<{ path: string }> }>(`/api/reports/${id}/verify`, { method: 'POST' }),
  downloadUrl: (id: string, kind: 'json' | 'pdf' | 'capsule') => `${API_BASE}/api/reports/${id}/download/${kind}`,
}
