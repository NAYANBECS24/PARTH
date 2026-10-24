import type {
  Artifact,
  Blindspot,
  CaseRecord,
  Finding,
  Indicator,
  Job,
  JobEvent,
  JobStage,
  ReportRecord,
} from "./types";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://127.0.0.1:8000";
const TOKEN_KEY = "shadowpath-session";

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers);
  const token = localStorage.getItem(TOKEN_KEY);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as {
      detail?: string | { message?: string };
    } | null;
    const detail =
      typeof body?.detail === "string" ? body.detail : body?.detail?.message;
    if (response.status === 401 && !path.startsWith("/api/auth/")) {
      localStorage.removeItem(TOKEN_KEY);
      window.dispatchEvent(new Event("shadowpath-auth-expired"));
    }
    throw new ApiError(
      response.status,
      detail ?? `Request failed (${response.status})`,
    );
  }
  return response.json() as Promise<T>;
}

export interface Health {
  status: string;
  mode: string;
  worker: { queued_jobs: number; running_jobs: number };
  adapters: Record<
    string,
    string | { status: string; version?: string; reason?: string }
  >;
}

export interface Overview {
  counts: {
    cases: number;
    active_jobs: number;
    unreviewed_high_priority_findings: number;
    open_blindspots: number;
  };
  recent_cases: Array<
    Pick<
      CaseRecord,
      | "id"
      | "title"
      | "status"
      | "risk_score"
      | "risk_tier"
      | "completeness"
      | "created_at"
      | "original_filename"
    > & { sha_prefix: string }
  >;
  jobs: Array<
    Pick<Job, "id" | "case_id" | "status" | "current_stage" | "created_at">
  >;
}

export interface CaseDetail {
  case: CaseRecord;
  latest_job: Job | null;
  artifacts: Artifact[];
  findings: Finding[];
  blindspots: Blindspot[];
  indicators: Indicator[];
  reports: ReportRecord[];
}

export interface JobDetail {
  job: Job;
  stages: JobStage[];
  events: JobEvent[];
}

export interface AuthUser {
  id: string | null;
  username: string;
  role: "admin" | "analyst" | "viewer";
}
export interface AuthStatus {
  bootstrap_required: boolean;
  authenticated: boolean;
  auth_disabled: boolean;
  user: AuthUser | null;
}
export interface SampleRecord {
  sha256: string;
  original_filename: string;
  byte_size: number;
  archive_entry_count: number;
  created_at: string;
  synthetic_fixture: number;
  case_count: number;
  finding_count: number;
  blindspot_count: number;
  latest_case_id: string;
  latest_case_title: string;
  latest_status: string;
}
export interface LibraryIndicator extends Indicator {
  case_title: string;
  case_id: string;
  sample_sha256: string;
  created_at: string;
}
export interface AppSettings {
  values: { default_profile: "lite" | "standard" | "advanced" };
  capabilities: {
    data_mode: string;
    max_upload_bytes: number;
    nvidia: string;
    dynamic_lab: string;
  };
}
export interface Comparison {
  left: CaseRecord;
  right: CaseRecord;
  indicator_diff: Record<
    string,
    { shared: string[]; left_only: string[]; right_only: string[] }
  >;
  finding_rules: {
    shared: string[];
    left_only: string[];
    right_only: string[];
  };
  limitation: string;
}
export interface AuditEvent {
  id: number;
  username: string | null;
  action: string;
  subject_type: string;
  subject_id: string | null;
  detail: Record<string, unknown>;
  created_at: string;
}

export const api = {
  authStatus: () => request<AuthStatus>("/api/auth/status"),
  async bootstrap(username: string, password: string) {
    const result = await request<{ token: string; user: AuthUser }>(
      "/api/auth/bootstrap",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      },
    );
    localStorage.setItem(TOKEN_KEY, result.token);
    return result;
  },
  async login(username: string, password: string) {
    const result = await request<{ token: string; user: AuthUser }>(
      "/api/auth/login",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      },
    );
    localStorage.setItem(TOKEN_KEY, result.token);
    return result;
  },
  async logout() {
    try {
      await request("/api/auth/logout", { method: "POST" });
    } finally {
      localStorage.removeItem(TOKEN_KEY);
    }
  },
  health: () => request<Health>("/health"),
  overview: () => request<Overview>("/api/overview"),
  cases: (search = "") =>
    request<{ items: CaseRecord[]; total: number }>(
      `/api/cases?search=${encodeURIComponent(search)}`,
    ),
  samples: (search = "") =>
    request<{ items: SampleRecord[]; total: number }>(
      `/api/samples?search=${encodeURIComponent(search)}`,
    ),
  case: (id: string) => request<CaseDetail>(`/api/cases/${id}`),
  job: (id: string) => request<JobDetail>(`/api/jobs/${id}`),
  findings: () => request<{ items: Finding[] }>("/api/findings"),
  indicators: (search = "", type = "") =>
    request<{ items: LibraryIndicator[]; total: number }>(
      `/api/indicators?search=${encodeURIComponent(search)}${type ? `&indicator_type=${encodeURIComponent(type)}` : ""}`,
    ),
  compare: (left: string, right: string) =>
    request<Comparison>(
      `/api/compare?left=${encodeURIComponent(left)}&right=${encodeURIComponent(right)}`,
    ),
  settings: () => request<AppSettings>("/api/settings"),
  saveSettings: (default_profile: "lite" | "standard" | "advanced") =>
    request<AppSettings>("/api/settings", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ default_profile }),
    }),
  audit: () => request<{ items: AuditEvent[] }>("/api/audit"),
  reports: () => request<{ items: ReportRecord[] }>("/api/reports"),
  graph: (caseId: string) =>
    request<{
      nodes: Array<{ id: string; type: string; label: string }>;
      edges: Array<{
        id: string;
        source: string;
        target: string;
        type: string;
      }>;
      limited: boolean;
    }>(`/api/cases/${caseId}/graph`),
  async intake(form: FormData) {
    return request<{
      case_id: string;
      job_id: string;
      sample: {
        sha256: string;
        byte_size: number;
        original_filename: string;
        deduplicated_content: boolean;
      };
    }>("/api/cases/intake", { method: "POST", body: form });
  },
  async cancel(jobId: string) {
    return request<{ status: string }>(`/api/jobs/${jobId}/cancel`, {
      method: "POST",
    });
  },
  retry: (jobId: string) =>
    request<{ job_id: string; case_id: string }>(`/api/jobs/${jobId}/retry`, {
      method: "POST",
    }),
  async reviewFinding(
    findingId: string,
    decision: "reviewed" | "needs_further_testing" | "false_positive",
  ) {
    return request(`/api/findings/${findingId}/review`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ decision }),
    });
  },
  verifyReport: (id: string) =>
    request<{ valid: boolean; failures: Array<{ path: string }> }>(
      `/api/reports/${id}/verify`,
      { method: "POST" },
    ),
  async downloadReport(id: string, kind: "json" | "pdf" | "capsule") {
    const headers = new Headers();
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) headers.set("Authorization", `Bearer ${token}`);
    const response = await fetch(
      `${API_BASE}/api/reports/${id}/download/${kind}`,
      { headers },
    );
    if (!response.ok)
      throw new ApiError(
        response.status,
        `Download failed (${response.status})`,
      );
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `shadowpath-${id}.${kind === "capsule" ? "zip" : kind}`;
    anchor.click();
    URL.revokeObjectURL(url);
  },
};
