export type StageStatus =
  | "pending"
  | "running"
  | "completed"
  | "partial"
  | "skipped"
  | "failed";
export type EvidenceStatus =
  | "observed"
  | "conditionally_reachable"
  | "suspected"
  | "unknown";

export interface CaseRecord {
  id: string;
  title: string;
  analyst_note: string;
  profile: "lite" | "standard" | "advanced";
  status: string;
  sample_sha256: string;
  original_filename: string;
  byte_size: number;
  risk_score: number | null;
  risk_tier: string;
  completeness: number;
  created_at: string;
  synthetic_fixture: number;
}

export interface JobStage {
  stage_key: string;
  position: number;
  status: StageStatus;
  started_at: string | null;
  finished_at: string | null;
  detail: Record<string, unknown>;
}

export interface Job {
  id: string;
  case_id: string;
  sample_sha256: string;
  status: string;
  current_stage: string | null;
  error_code: string | null;
  error_detail: string | null;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export interface JobEvent {
  id: number;
  level: "info" | "warning" | "error";
  message: string;
  payload: Record<string, unknown>;
  created_at: string;
}

export interface FindingLocation {
  evidence_type?: string;
  confidence?: "low" | "medium" | "high";
  matched_terms?: string[];
  matched_permissions?: string[];
  source_files?: string[];
  manifest_component?: string;
  technique?: {
    framework?: string;
    id?: string;
    name?: string;
  };
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  category: string;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  evidence_status: EvidenceStatus;
  description: string;
  limitations: string[];
  artifact_ids: string[];
  location: FindingLocation;
  reviewer_status: string;
}

export interface Blindspot {
  id: string;
  scope_type: string;
  scope_id: string;
  reason_code: string;
  limitation: string;
  suggested_next_step: string | null;
  artifact_ids: string[];
}

export interface Artifact {
  id: string;
  artifact_type: string;
  subject: string;
  source_locator: string;
  sha256: string | null;
  data: Record<string, unknown>;
}

export interface Indicator {
  id: string;
  indicator_type: string;
  value: string;
  observable_level: string;
}

export interface ReportRecord {
  id: string;
  case_id: string;
  job_id: string;
  capsule_sha256: string;
  verification_status: string;
  created_at: string;
  title?: string;
}

export interface AIProposal {
  id: string;
  job_id: string;
  provider: string;
  model: string;
  status: string;
  proposal: {
    schema_version?: string;
    malicious_hypothesis?: {
      statement: string;
      supporting_evidence_ids: string[];
      contradicting_evidence_ids: string[];
    };
    benign_explanation?: {
      statement: string;
      supporting_evidence_ids: string[];
      contradicting_evidence_ids: string[];
    };
    discriminating_test?: string;
    proposed_experiment?: {
      operation_id: string;
      rationale: string;
      requires_analyst_approval: boolean;
    };
    notes?: string;
  };
  validation_errors: string[];
  evidence_ids: string[];
  created_at: string;
}

export interface GuardPath {
  id: string;
  case_id: string;
  job_id: string;
  target_method_id: string;
  guard_ast: Record<string, unknown>;
  solver_status: "sat" | "unsat" | "unknown" | "unsupported" | "timeout";
  supported_subset: number | boolean;
  witness: Record<string, unknown>;
  limitations: string[];
  created_at: string;
}

export interface ToolStatus {
  name: string;
  category: string;
  status: "available" | "configured" | "not_configured" | "fallback" | "isolated";
  version?: string;
  path?: string;
  details?: string;
  remediation?: string;
}

export interface CapabilitiesMap {
  tools: Record<string, ToolStatus>;
  environment: {
    host_isolation_enforced: boolean;
    offline_mode_ready: boolean;
    reportlab_pdf_engine: boolean;
    networkx_graph_engine: boolean;
  };
}

export interface AssistantCitation {
  kind: string;
  id: string;
  label: string;
  href?: string;
}

export interface AssistantToolRun {
  tool: string;
  data?: Record<string, unknown>;
  citations?: AssistantCitation[];
  error?: string;
}

export interface AssistantMessage {
  id: string;
  thread_id: string;
  role: "user" | "assistant";
  content: string;
  mode: "user" | "local_deterministic" | "nvidia_nim" | "local_fallback";
  citations: AssistantCitation[];
  tool_runs: AssistantToolRun[];
  created_at: string;
}

export interface AssistantThread {
  id: string;
  case_id: string | null;
  user_id: string | null;
  title: string;
  created_at: string;
  updated_at: string;
  message_count?: number;
  last_message?: string | null;
}

export interface AssistantTool {
  name: string;
  description: string;
  case_required: boolean;
  parameters: Record<string, unknown>;
}
