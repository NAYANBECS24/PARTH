import {
  type ChangeEvent,
  type DragEvent,
  type FormEvent,
  type ReactNode,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  Activity,
  AlertTriangle,
  Archive,
  ArrowLeftRight,
  BookOpen,
  Boxes,
  Check,
  ChevronRight,
  CircleHelp,
  ClipboardCheck,
  Command,
  Copy,
  FileDown,
  FileSearch,
  FolderSearch,
  GitBranch,
  HeartPulse,
  Home,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Moon,
  Network,
  PanelLeftClose,
  Plus,
  Search,
  Settings,
  ShieldAlert,
  Sun,
  UploadCloud,
} from "lucide-react";
import {
  api,
  type AppSettings,
  type AuditEvent,
  type AuthUser,
  type CaseDetail,
  type Comparison,
  type Health,
  type JobDetail,
  type LibraryIndicator,
  type Overview,
  type SampleRecord,
} from "./api";
import { dateTime, fileSize, shortHash, statusLabel } from "./lib";
import type {
  Blindspot,
  CaseRecord,
  Finding,
  JobStage,
  ReportRecord,
} from "./types";

type Navigate = (path: string) => void;
type Tab =
  | "summary"
  | "genome"
  | "behaviour"
  | "blindspots"
  | "iocs"
  | "evidence"
  | "reports";

const primaryNav = [
  { path: "/app/overview", label: "Overview", icon: Home },
  { path: "/app/scans/new", label: "New investigation", icon: Plus },
  { path: "/app/cases", label: "Investigations", icon: FolderSearch },
  { path: "/app/samples", label: "APK library", icon: Archive },
  { path: "/app/findings", label: "Findings", icon: ShieldAlert },
];

const intelligenceNav = [
  { path: "/app/graph", label: "Evidence graph", icon: GitBranch },
  { path: "/app/indicators", label: "Indicators / IoCs", icon: Network },
  { path: "/app/compare", label: "Comparisons", icon: ArrowLeftRight },
  { path: "/app/reports", label: "Reports & capsules", icon: FileDown },
];

const systemNav = [
  { path: "/app/health", label: "System health", icon: HeartPulse },
  { path: "/app/settings", label: "Settings", icon: Settings },
];

function usePath(): [string, Navigate] {
  const [path, setPath] = useState(() => window.location.pathname);
  useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);
  const navigate: Navigate = (next) => {
    if (next === window.location.pathname) return;
    window.history.pushState({}, "", next);
    setPath(next);
  };
  return [path, navigate];
}

function useTheme(): [string, () => void] {
  const [theme, setTheme] = useState(
    () =>
      localStorage.getItem("shadowpath-theme") ??
      (window.matchMedia("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark"),
  );
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("shadowpath-theme", theme);
  }, [theme]);
  return [
    theme,
    () => setTheme((current) => (current === "dark" ? "light" : "dark")),
  ];
}

function ErrorPanel({ error, retry }: { error: string; retry?: () => void }) {
  return (
    <div className="error-panel" role="alert">
      <AlertTriangle size={18} />
      <div>
        <strong>Unable to load this evidence</strong>
        <p>{error}</p>
        {retry && (
          <button className="text-button" onClick={retry}>
            Try again
          </button>
        )}
      </div>
    </div>
  );
}

function Loading() {
  return (
    <div className="loading-state">
      <LoaderCircle size={24} className="spin" /> Loading persisted records…
    </div>
  );
}

function EmptyState({
  icon = FileSearch,
  title,
  message,
  action,
}: {
  icon?: typeof FileSearch;
  title: string;
  message: string;
  action?: ReactNode;
}) {
  const Icon = icon;
  return (
    <div className="empty-state">
      <div className="empty-icon">
        <Icon size={24} />
      </div>
      <h3>{title}</h3>
      <p>{message}</p>
      {action}
    </div>
  );
}

function StatusPill({ value }: { value: string }) {
  const kind =
    value.includes("failed") || value.includes("critical")
      ? "danger"
      : value.includes("partial") ||
          value.includes("unknown") ||
          value.includes("unavailable") ||
          value.includes("not_configured")
        ? "warning"
        : value.includes("running") || value.includes("queued")
          ? "info"
          : value.includes("completed") ||
              value.includes("verified") ||
              value.includes("observed")
            ? "success"
            : "neutral";
  return (
    <span className={`status-pill ${kind}`}>
      <span className="status-dot" />
      {statusLabel(value)}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  return <span className={`severity ${severity}`}>{severity}</span>;
}

function CopyToken({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  }
  return (
    <button className="copy-token" onClick={copy} title="Copy full value">
      <code>{shortHash(value, 16)}</code>
      {copied ? <Check size={14} /> : <Copy size={14} />}
    </button>
  );
}

function PageHeading({
  eyebrow,
  title,
  description,
  children,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <p className="eyebrow">{eyebrow ?? "INVESTIGATION WORKSPACE"}</p>
        <h1>{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {children && <div className="page-heading-actions">{children}</div>}
    </div>
  );
}

function AppShell({
  path,
  navigate,
  theme,
  toggleTheme,
  user,
  onLogout,
  children,
}: {
  path: string;
  navigate: Navigate;
  theme: string;
  toggleTheme: () => void;
  user: AuthUser;
  onLogout: () => void;
  children: ReactNode;
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((value) => !value);
      }
      if (event.key === "Escape") setPaletteOpen(false);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
  const navGroup = (label: string, records: typeof primaryNav) => (
    <div className="nav-group">
      <p>{!collapsed && label}</p>
      {records.map((item) => {
        const Icon = item.icon;
        const active =
          path === item.path ||
          (item.path === "/app/cases" && path.startsWith("/app/cases/"));
        return (
          <button
            className={`nav-item ${active ? "active" : ""}`}
            onClick={() => navigate(item.path)}
            key={item.path}
            title={collapsed ? item.label : undefined}
          >
            <Icon size={18} />
            <span>{item.label}</span>
          </button>
        );
      })}
    </div>
  );
  return (
    <div className={`app-shell ${collapsed ? "sidebar-collapsed" : ""}`}>
      <aside className="sidebar">
        <div className="brand-row">
          <button
            className="brand"
            onClick={() => navigate("/app/overview")}
            aria-label="Go to overview"
          >
            <span className="brand-mark">
              <i />
              <i />
            </span>
            {!collapsed && (
              <span>
                SHADOWPATH <b>Ω</b>
                <em>NEXUS</em>
              </span>
            )}
          </button>
          <button
            className="sidebar-toggle"
            onClick={() => setCollapsed((value) => !value)}
            aria-label="Toggle navigation"
          >
            <PanelLeftClose size={17} />
          </button>
        </div>
        <nav aria-label="Primary navigation">
          {navGroup("WORKSPACE", primaryNav)}
          {navGroup("INTELLIGENCE", intelligenceNav)}
        </nav>
        <div className="sidebar-bottom">
          {navGroup("SYSTEM", systemNav)}
          <div className="data-mode">
            <span className="mode-led" />
            {!collapsed && <span>LOCAL STATIC MODE</span>}
          </div>
          <small>{!collapsed && "v0.2.0 LOCAL"}</small>
        </div>
      </aside>
      <main className="main">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>SHADOWPATH Ω</span>
            <ChevronRight size={15} />
            <span>
              {path
                .split("/")
                .filter(Boolean)
                .slice(-1)[0]
                ?.replaceAll("-", " ") || "overview"}
            </span>
          </div>
          <div className="topbar-tools">
            <button
              className="command-button"
              onClick={() => setPaletteOpen(true)}
            >
              <Search size={16} />
              <span>Search or command</span>
              <kbd>⌘ K</kbd>
            </button>
            <span className="topbar-status">
              <span className="mode-led" />
              Offline-safe
            </span>
            <button
              className="icon-button"
              onClick={toggleTheme}
              aria-label="Toggle color theme"
            >
              {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
            </button>
            <span className="analyst-button">
              <span>{user.username.slice(0, 2).toUpperCase()}</span>
              <i>
                {user.username} · {user.role}
              </i>
            </span>
            <button
              className="icon-button"
              onClick={onLogout}
              aria-label="Sign out"
              title="Sign out"
            >
              <LogOut size={17} />
            </button>
          </div>
        </header>
        <section className="workspace">{children}</section>
      </main>
      {paletteOpen && (
        <div
          className="palette-backdrop"
          onMouseDown={() => setPaletteOpen(false)}
        >
          <div
            className="command-palette"
            role="dialog"
            aria-modal="true"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="palette-search">
              <Command size={18} />
              <input
                autoFocus
                placeholder="Navigate to…"
                aria-label="Command palette"
              />
            </div>
            <p>QUICK ACTIONS</p>
            {[
              {
                path: "/app/scans/new",
                label: "Start a new investigation",
                icon: Plus,
              },
              {
                path: "/app/cases",
                label: "Browse investigations",
                icon: FolderSearch,
              },
              {
                path: "/app/findings",
                label: "Review findings",
                icon: ShieldAlert,
              },
            ].map((item) => {
              const Icon = item.icon;
              return (
                <button
                  key={item.path}
                  onClick={() => {
                    navigate(item.path);
                    setPaletteOpen(false);
                  }}
                >
                  <Icon size={17} />
                  {item.label}
                  <ChevronRight size={16} />
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

function MetricCard({
  label,
  value,
  detail,
  status,
}: {
  label: string;
  value: string | number;
  detail: string;
  status?: string;
}) {
  return (
    <div className="metric-card">
      <p>{label}</p>
      <div>
        <strong>{value}</strong>
        {status && <StatusPill value={status} />}
      </div>
      <small>{detail}</small>
    </div>
  );
}

function OverviewPage({ navigate }: { navigate: Navigate }) {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState("");
  const load = () => {
    setError("");
    api
      .overview()
      .then(setData)
      .catch((cause: unknown) =>
        setError(cause instanceof Error ? cause.message : "Unknown API error"),
      );
  };
  useEffect(() => {
    void api
      .overview()
      .then(setData)
      .catch((cause: unknown) =>
        setError(cause instanceof Error ? cause.message : "Unknown API error"),
      );
  }, []);
  if (error) return <ErrorPanel error={error} retry={load} />;
  if (!data) return <Loading />;
  const noData = data.counts.cases === 0;
  return (
    <>
      <PageHeading
        title="Analyst command center"
        description="Evidence-backed work only. Risk and inspection completeness are shown as separate dimensions."
      >
        <button
          className="primary-button"
          onClick={() => navigate("/app/scans/new")}
        >
          <Plus size={17} /> New investigation
        </button>
      </PageHeading>
      {noData ? (
        <EmptyState
          icon={UploadCloud}
          title="Begin a controlled investigation"
          message="Upload an APK to create a persistent static-analysis case. The application will not execute it on this host."
          action={
            <button
              className="primary-button"
              onClick={() => navigate("/app/scans/new")}
            >
              <UploadCloud size={17} /> Upload an APK
            </button>
          }
        />
      ) : (
        <>
          <div className="metrics-grid">
            <MetricCard
              label="Active investigations"
              value={data.counts.active_jobs}
              detail="Persisted queued or running jobs"
              status={data.counts.active_jobs ? "running" : "completed"}
            />
            <MetricCard
              label="High-priority review"
              value={data.counts.unreviewed_high_priority_findings}
              detail="Evidence-backed high / critical findings"
            />
            <MetricCard
              label="Unresolved blindspots"
              value={data.counts.open_blindspots}
              detail="Explicit unknowns across all cases"
            />
            <MetricCard
              label="Cases in library"
              value={data.counts.cases}
              detail="Immutable APK hashes, separate case records"
            />
          </div>
          <div className="overview-grid">
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">INVESTIGATION QUEUE</p>
                  <h2>Recent cases</h2>
                </div>
                <button
                  className="text-button"
                  onClick={() => navigate("/app/cases")}
                >
                  View all
                </button>
              </div>
              <CaseTable
                cases={data.recent_cases}
                navigate={navigate}
                compact
              />
            </section>
            <section className="panel action-stack">
              <div className="panel-heading">
                <div>
                  <p className="eyebrow">ACTION REQUIRED</p>
                  <h2>Open work</h2>
                </div>
                <AlertTriangle size={18} />
              </div>
              {data.jobs.length === 0 ? (
                <p className="quiet-message">
                  No queued or running jobs. Completed evidence remains
                  available in investigations.
                </p>
              ) : (
                data.jobs.map((job) => (
                  <button
                    key={job.id}
                    className="action-item"
                    onClick={() => navigate(`/app/jobs/${job.id}`)}
                  >
                    <span className="stage-icon">
                      <Activity size={15} />
                    </span>
                    <span>
                      <strong>
                        {statusLabel(job.current_stage ?? "queued")}
                      </strong>
                      <small>
                        {shortHash(job.id)} · {statusLabel(job.status)}
                      </small>
                    </span>
                    <ChevronRight size={16} />
                  </button>
                ))
              )}
            </section>
          </div>
        </>
      )}
    </>
  );
}

type CaseTableRecord = Pick<
  CaseRecord,
  | "id"
  | "title"
  | "status"
  | "risk_score"
  | "risk_tier"
  | "completeness"
  | "created_at"
  | "original_filename"
> & { sample_sha256?: string; sha_prefix?: string };

function CaseTable({
  cases,
  navigate,
  compact = false,
}: {
  cases: CaseTableRecord[];
  navigate: Navigate;
  compact?: boolean;
}) {
  if (!cases.length)
    return (
      <EmptyState
        title="No matching cases"
        message="Try another filter or create a new investigation."
      />
    );
  return (
    <div className="table-wrap">
      <table className="case-table">
        <thead>
          <tr>
            <th>Case / sample</th>
            <th>Risk</th>
            <th>Completeness</th>
            {!compact && <th>Created</th>}
            <th>Status</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {cases.map((item) => (
            <tr key={item.id}>
              <td>
                <button
                  className="case-link"
                  onClick={() => navigate(`/app/cases/${item.id}`)}
                >
                  <strong>{item.title}</strong>
                  <small>
                    {item.original_filename} ·{" "}
                    <code>
                      {shortHash(
                        item.sample_sha256 ?? item.sha_prefix ?? item.id,
                      )}
                    </code>
                  </small>
                </button>
              </td>
              <td>
                <RiskLabel tier={item.risk_tier} score={item.risk_score} />
              </td>
              <td>
                <div className="coverage-cell">
                  <span>{item.completeness}%</span>
                  <i>
                    <b style={{ width: `${item.completeness}%` }} />
                  </i>
                </div>
              </td>
              {!compact && (
                <td className="muted-cell">{dateTime(item.created_at)}</td>
              )}
              <td>
                <StatusPill value={item.status} />
              </td>
              <td>
                <button
                  className="row-open"
                  onClick={() => navigate(`/app/cases/${item.id}`)}
                  aria-label={`Open ${item.title}`}
                >
                  <ChevronRight size={17} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RiskLabel({ tier, score }: { tier: string; score: number | null }) {
  const unknown = tier === "undetermined";
  return (
    <span className={`risk-label ${unknown ? "unknown" : tier}`}>
      <i />
      {unknown ? "Not assessed" : statusLabel(tier)}
      {score !== null && <b>{score}</b>}
    </span>
  );
}

function NewInvestigationPage({ navigate }: { navigate: Navigate }) {
  const [stage, setStage] = useState(1);
  const [file, setFile] = useState<File | null>(null);
  const [caseName, setCaseName] = useState("");
  const [note, setNote] = useState("");
  const [profile, setProfile] = useState<"lite" | "standard" | "advanced">(
    "standard",
  );
  const [hash, setHash] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);
  useEffect(() => {
    void api
      .settings()
      .then((result) => setProfile(result.values.default_profile))
      .catch(() => undefined);
  }, []);
  function pick(selected: File | null) {
    setError("");
    if (!selected) return;
    if (!selected.name.toLowerCase().endsWith(".apk")) {
      setError("Choose an .apk archive.");
      return;
    }
    setFile(selected);
    if (!caseName) setCaseName(selected.name.replace(/\.apk$/i, ""));
    void selected
      .arrayBuffer()
      .then((buffer) => crypto.subtle.digest("SHA-256", buffer))
      .then((digest) =>
        setHash(
          Array.from(new Uint8Array(digest))
            .map((byte) => byte.toString(16).padStart(2, "0"))
            .join(""),
        ),
      )
      .catch(() => setHash(""));
  }
  function onInput(event: ChangeEvent<HTMLInputElement>) {
    pick(event.target.files?.[0] ?? null);
  }
  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    pick(event.dataTransfer.files?.[0] ?? null);
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!file || !caseName.trim()) {
      setError("Choose an APK and provide a case name.");
      return;
    }
    setSubmitting(true);
    setError("");
    const body = new FormData();
    body.set("file", file);
    body.set("case_name", caseName.trim());
    body.set("analyst_note", note);
    body.set("profile", profile);
    body.set("nvidia_reasoning", "false");
    body.set("isolated_dynamic_lab", "false");
    try {
      const result = await api.intake(body);
      navigate(`/app/jobs/${result.job_id}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Upload failed");
    } finally {
      setSubmitting(false);
    }
  }
  const stages = ["APK intake", "Investigation setup", "Review & start"];
  return (
    <>
      <PageHeading
        title="New investigation"
        description="Static-only intake. Uploaded applications are never executed on this machine."
      />
      <div className="stepper">
        {stages.map((label, index) => (
          <button
            key={label}
            className={
              stage === index + 1 ? "current" : stage > index + 1 ? "done" : ""
            }
            onClick={() =>
              index + 1 < stage || (index + 1 <= 2 && file)
                ? setStage(index + 1)
                : undefined
            }
          >
            <span>{stage > index + 1 ? <Check size={15} /> : index + 1}</span>
            {label}
          </button>
        ))}
      </div>
      <form className="scan-form" onSubmit={submit}>
        {stage === 1 && (
          <section className="panel form-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">STAGE 01</p>
                <h2>Choose an Android package</h2>
              </div>
            </div>
            <div
              className="drop-zone"
              onDragOver={(event) => event.preventDefault()}
              onDrop={onDrop}
            >
              <UploadCloud size={30} />
              <strong>{file ? file.name : "Drop an .apk here"}</strong>
              <p>
                {file
                  ? `${fileSize(file.size)} · hashed locally before upload`
                  : "or browse from a location you are authorised to analyse"}
              </p>
              <label className="secondary-button">
                Browse files
                <input
                  type="file"
                  accept=".apk,application/vnd.android.package-archive"
                  onChange={onInput}
                />
              </label>
            </div>
            {file && (
              <div className="file-proof">
                <span>
                  <Archive size={17} /> {file.name}
                </span>
                <span>{fileSize(file.size)}</span>
                {hash && <CopyToken value={hash} />}
              </div>
            )}
            <div className="privacy-note">
              <LockKeyhole size={17} />
              <p>
                Only static archive processing is supported. Dynamic lab
                analysis is intentionally unavailable until a separate isolated
                environment is configured.
              </p>
            </div>
            <div className="form-actions">
              <span />
              <button
                type="button"
                className="primary-button"
                disabled={!file}
                onClick={() => setStage(2)}
              >
                Continue <ChevronRight size={16} />
              </button>
            </div>
          </section>
        )}
        {stage === 2 && (
          <section className="panel form-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">STAGE 02</p>
                <h2>Scope the analysis</h2>
              </div>
            </div>
            <div className="field-grid">
              <label>
                Case name
                <input
                  value={caseName}
                  onChange={(event) => setCaseName(event.target.value)}
                  maxLength={160}
                  required
                />
              </label>
              <label>
                Processing profile
                <select
                  value={profile}
                  onChange={(event) =>
                    setProfile(event.target.value as typeof profile)
                  }
                >
                  <option value="lite">Lite — inventory and basic rules</option>
                  <option value="standard">
                    Standard — DEX strings, IoCs, ledger
                  </option>
                  <option value="advanced">
                    Advanced — records unsupported research boundaries
                  </option>
                </select>
              </label>
              <label className="full-width">
                Analyst note
                <textarea
                  value={note}
                  onChange={(event) => setNote(event.target.value)}
                  maxLength={4000}
                  placeholder="Context, source, authorisation, or initial question"
                />
              </label>
            </div>
            <div className="setting-state">
              <span>
                <span className="switch off" /> NVIDIA TRI-PROOF reasoning
              </span>
              <StatusPill value="not_configured" />
              <small>No cloud model request will be made.</small>
            </div>
            <div className="setting-state">
              <span>
                <span className="switch off" /> Isolated dynamic lab
              </span>
              <StatusPill value="not_configured" />
              <small>Disabled: this host will not execute APK code.</small>
            </div>
            <div className="form-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setStage(1)}
              >
                Back
              </button>
              <button
                type="button"
                className="primary-button"
                disabled={!caseName.trim()}
                onClick={() => setStage(3)}
              >
                Review <ChevronRight size={16} />
              </button>
            </div>
          </section>
        )}
        {stage === 3 && (
          <section className="panel form-panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">STAGE 03</p>
                <h2>Confirm forensic intake</h2>
              </div>
            </div>
            <div className="review-list">
              <div>
                <span>Case</span>
                <strong>{caseName}</strong>
              </div>
              <div>
                <span>Sample</span>
                <strong>{file?.name}</strong>
              </div>
              <div>
                <span>SHA-256 preview</span>
                {hash ? (
                  <CopyToken value={hash} />
                ) : (
                  <strong>Calculating…</strong>
                )}
              </div>
              <div>
                <span>Profile</span>
                <strong>{statusLabel(profile)}</strong>
              </div>
              <div>
                <span>Data mode</span>
                <StatusPill value="local_static_only" />
              </div>
            </div>
            <div className="privacy-note">
              <CircleHelp size={17} />
              <p>
                Starting a scan creates a persisted case and queued job. It does
                not claim a clean result, execute the APK, or enable AI
                reasoning.
              </p>
            </div>
            <div className="form-actions">
              <button
                type="button"
                className="secondary-button"
                onClick={() => setStage(2)}
              >
                Back
              </button>
              <button
                className="primary-button"
                type="submit"
                disabled={submitting}
              >
                {submitting ? (
                  <LoaderCircle className="spin" size={16} />
                ) : (
                  <Activity size={16} />
                )}
                {submitting
                  ? "Persisting investigation…"
                  : "Create investigation"}
              </button>
            </div>
          </section>
        )}
        {error && <ErrorPanel error={error} />}
      </form>
    </>
  );
}

function JobPage({ id, navigate }: { id: string; navigate: Navigate }) {
  const [data, setData] = useState<JobDetail | null>(null);
  const [error, setError] = useState("");
  const load = () =>
    api
      .job(id)
      .then(setData)
      .catch((cause: unknown) =>
        setError(cause instanceof Error ? cause.message : "Could not load job"),
      );
  useEffect(() => {
    const fetchJob = () => {
      void api
        .job(id)
        .then(setData)
        .catch((cause: unknown) =>
          setError(
            cause instanceof Error ? cause.message : "Could not load job",
          ),
        );
    };
    fetchJob();
    const timer = window.setInterval(fetchJob, 1500);
    return () => window.clearInterval(timer);
  }, [id]);
  async function cancel() {
    try {
      await api.cancel(id);
      load();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Cancellation failed");
    }
  }
  async function retry() {
    try {
      const result = await api.retry(id);
      navigate(`/app/jobs/${result.job_id}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Retry failed");
    }
  }
  if (error && !data) return <ErrorPanel error={error} retry={load} />;
  if (!data) return <Loading />;
  const terminal = ["completed", "partial", "failed", "cancelled"].includes(
    data.job.status,
  );
  return (
    <>
      <PageHeading
        eyebrow="LIVE INVESTIGATION"
        title={terminal ? "Investigation result" : "Analysis in progress"}
        description="Progress reflects persisted worker stages and structured events—not a client-side timer."
      >
        <StatusPill value={data.job.status} />
        {!terminal && (
          <button className="secondary-button danger-button" onClick={cancel}>
            Cancel job
          </button>
        )}
        {terminal && (
          <button className="secondary-button" onClick={retry}>
            Retry analysis
          </button>
        )}
        {terminal && (
          <button
            className="primary-button"
            onClick={() => navigate(`/app/cases/${data.job.case_id}`)}
          >
            Open case <ChevronRight size={16} />
          </button>
        )}
      </PageHeading>
      <div className="job-layout">
        <section className="panel stage-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">EVIDENCE PIPELINE</p>
              <h2>Persisted stages</h2>
            </div>
            <CopyToken value={data.job.id} />
          </div>
          <StageTimeline stages={data.stages} />
        </section>
        <aside className="panel log-panel">
          <div className="panel-heading">
            <div>
              <p className="eyebrow">WORKER EVENT LOG</p>
              <h2>Structured activity</h2>
            </div>
            <Activity size={18} />
          </div>
          {data.events.length === 0 ? (
            <p className="quiet-message">Waiting for a worker event…</p>
          ) : (
            <div className="event-list">
              {data.events.map((event) => (
                <div className={`event ${event.level}`} key={event.id}>
                  <span />
                  <div>
                    <strong>{event.message}</strong>
                    <small>{dateTime(event.created_at)}</small>
                  </div>
                </div>
              ))}
            </div>
          )}
          {data.job.error_detail && (
            <ErrorPanel error={data.job.error_detail} />
          )}
        </aside>
      </div>
    </>
  );
}

function StageTimeline({ stages }: { stages: JobStage[] }) {
  return (
    <ol className="stage-timeline">
      {stages.map((stage) => (
        <li className={stage.status} key={stage.stage_key}>
          <span>
            {stage.status === "completed" ? (
              <Check size={14} />
            ) : stage.status === "running" ? (
              <LoaderCircle size={14} className="spin" />
            ) : stage.status === "partial" ? (
              <AlertTriangle size={14} />
            ) : (
              stage.position
            )}
          </span>
          <div>
            <strong>{statusLabel(stage.stage_key)}</strong>
            <p>
              <StatusPill value={stage.status} />
              {stage.detail && Object.keys(stage.detail).length > 0 && (
                <code>
                  {Object.entries(stage.detail)
                    .map(([key, value]) => `${key}: ${String(value)}`)
                    .join(" · ")}
                </code>
              )}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}

function CasesPage({ navigate }: { navigate: Navigate }) {
  const [records, setRecords] = useState<CaseRecord[] | null>(null);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  const load = () => {
    setError("");
    api
      .cases(search)
      .then((result) => setRecords(result.items))
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error ? cause.message : "Could not load cases",
        ),
      );
  };
  useEffect(() => {
    void api
      .cases(search)
      .then((result) => setRecords(result.items))
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error ? cause.message : "Could not load cases",
        ),
      );
  }, [search]);
  return (
    <>
      <PageHeading
        title="Investigations"
        description="Persistent case records, immutable sample hashes, and explicitly bounded analysis coverage."
      >
        <button
          className="primary-button"
          onClick={() => navigate("/app/scans/new")}
        >
          <Plus size={17} /> New investigation
        </button>
      </PageHeading>
      <section className="panel">
        <div className="table-toolbar">
          <label className="search-field">
            <Search size={16} />
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search title, filename, SHA-256"
            />
          </label>
          <span className="table-count">{records?.length ?? "…"} records</span>
        </div>
        {error ? (
          <ErrorPanel error={error} retry={load} />
        ) : !records ? (
          <Loading />
        ) : (
          <CaseTable cases={records} navigate={navigate} />
        )}
      </section>
    </>
  );
}

function CasePage({ id, navigate }: { id: string; navigate: Navigate }) {
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [tab, setTab] = useState<Tab>("summary");
  const [error, setError] = useState("");
  const load = () =>
    api
      .case(id)
      .then(setDetail)
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error ? cause.message : "Could not load case",
        ),
      );
  useEffect(() => {
    void api
      .case(id)
      .then(setDetail)
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error ? cause.message : "Could not load case",
        ),
      );
  }, [id]);
  if (error) return <ErrorPanel error={error} retry={load} />;
  if (!detail) return <Loading />;
  const tabs: Array<[Tab, string]> = [
    ["summary", "Summary"],
    ["genome", "Static genome"],
    ["behaviour", "Behaviour & paths"],
    ["blindspots", `Blindspot ledger (${detail.blindspots.length})`],
    ["iocs", "Network & IoCs"],
    ["evidence", "Evidence graph"],
    ["reports", "Capsules & reports"],
  ];
  return (
    <>
      <div className="case-hero">
        <div>
          <p className="eyebrow">CASE {shortHash(detail.case.id)}</p>
          <h1>{detail.case.title}</h1>
          <p>
            {detail.case.original_filename} ·{" "}
            <CopyToken value={detail.case.sample_sha256} />
          </p>
        </div>
        <div className="case-hero-state">
          <StatusPill value={detail.case.status} />
          <RiskLabel
            tier={detail.case.risk_tier}
            score={detail.case.risk_score}
          />
        </div>
      </div>
      <div className="case-tabs" role="tablist">
        {tabs.map(([key, label]) => (
          <button
            role="tab"
            aria-selected={tab === key}
            className={tab === key ? "active" : ""}
            onClick={() => setTab(key)}
            key={key}
          >
            {label}
          </button>
        ))}
      </div>
      <section className="case-content">
        {tab === "summary" && (
          <SummaryTab detail={detail} navigate={navigate} />
        )}
        {tab === "genome" && <GenomeTab detail={detail} />}
        {tab === "behaviour" && <BehaviourTab />}
        {tab === "blindspots" && <BlindspotTab records={detail.blindspots} />}
        {tab === "iocs" && <IocTab detail={detail} />}
        {tab === "evidence" && <GraphTab caseId={id} />}
        {tab === "reports" && <ReportsTab records={detail.reports} />}
      </section>
    </>
  );
}

function SummaryTab({
  detail,
  navigate,
}: {
  detail: CaseDetail;
  navigate: Navigate;
}) {
  return (
    <div className="summary-grid">
      <section className="panel summary-risk">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">TRIAGE</p>
            <h2>Risk vs completeness</h2>
          </div>
        </div>
        <div className="risk-completeness">
          <div>
            <span className="metric-label">Evidence-backed risk</span>
            <RiskLabel
              tier={detail.case.risk_tier}
              score={detail.case.risk_score}
            />
            <p>
              {detail.findings.length
                ? "Derived only from persisted deterministic rule observations."
                : "No evidence-backed risk findings were generated; unknowns remain separate."}
            </p>
          </div>
          <div>
            <span className="metric-label">Static inspection completeness</span>
            <strong className="completeness-number">
              {detail.case.completeness}%
            </strong>
            <div className="wide-meter">
              <i style={{ width: `${detail.case.completeness}%` }} />
            </div>
            <p>
              Limited to inventory, manifest, DEX string and IoC scope; not
              behavioral coverage.
            </p>
          </div>
        </div>
      </section>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">PRIORITY FINDINGS</p>
            <h2>Evidence review</h2>
          </div>
          <button
            className="text-button"
            onClick={() => navigate("/app/findings")}
          >
            Open triage
          </button>
        </div>
        {detail.findings.length ? (
          <FindingList findings={detail.findings.slice(0, 4)} />
        ) : (
          <EmptyState
            icon={ClipboardCheck}
            title="No deterministic rule finding"
            message="That is not a claim that the application is safe. Review the blindspot ledger and scope."
          />
        )}
      </section>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <p className="eyebrow">NEXT ACTIONS</p>
            <h2>Unknowns that constrain review</h2>
          </div>
        </div>
        {detail.blindspots.slice(0, 4).map((item) => (
          <div className="next-action" key={item.id}>
            <AlertTriangle size={16} />
            <div>
              <strong>{statusLabel(item.reason_code)}</strong>
              <p>{item.suggested_next_step ?? item.limitation}</p>
            </div>
          </div>
        ))}
      </section>
    </div>
  );
}

function GenomeTab({ detail }: { detail: CaseDetail }) {
  const groups = useMemo(() => {
    const records = new Map<string, typeof detail.artifacts>();
    detail.artifacts.forEach((artifact) => {
      const current = records.get(artifact.artifact_type) ?? [];
      current.push(artifact);
      records.set(artifact.artifact_type, current);
    });
    return [...records.entries()];
  }, [detail]);
  return (
    <div className="panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">STATIC GENOME</p>
          <h2>Extracted archive artifacts</h2>
        </div>
        <StatusPill value={detail.latest_job?.status ?? "unknown"} />
      </div>
      {groups.length === 0 ? (
        <EmptyState
          title="No extracted artifacts yet"
          message="Wait for a worker terminal state or inspect the job error."
        />
      ) : (
        <div className="artifact-groups">
          {groups.map(([type, artifacts]) => (
            <details key={type} open>
              <summary>
                <span>{statusLabel(type)}</span>
                <b>{artifacts.length}</b>
              </summary>
              <div>
                {artifacts.slice(0, 100).map((artifact) => (
                  <article className="artifact-row" key={artifact.id}>
                    <div>
                      <strong>{artifact.subject}</strong>
                      <code>{artifact.source_locator}</code>
                    </div>
                    <div>
                      {artifact.sha256 && <CopyToken value={artifact.sha256} />}
                      <code>
                        {Object.entries(artifact.data)
                          .slice(0, 3)
                          .map(([key, value]) => `${key}: ${String(value)}`)
                          .join(" · ")}
                      </code>
                    </div>
                  </article>
                ))}
              </div>
            </details>
          ))}
        </div>
      )}
    </div>
  );
}

function BehaviourTab() {
  return (
    <div className="panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">BEHAVIOUR & PATHS</p>
          <h2>Guarded-path evaluation</h2>
        </div>
        <StatusPill value="unsupported" />
      </div>
      <EmptyState
        icon={GitBranch}
        title="No reachability claim is available"
        message="This running scope inventories DEX and records limitations but does not construct a resolved DEX call graph, SMT proof, candidate trigger witness, or runtime observation. Those are deliberately distinct states."
      />
    </div>
  );
}

function BlindspotTab({ records }: { records: Blindspot[] }) {
  if (!records.length)
    return (
      <EmptyState
        icon={CircleHelp}
        title="No blindspot records yet"
        message="The job may not have reached its ledger stage."
      />
    );
  return (
    <div className="blindspot-list">
      {records.map((item) => (
        <article className="blindspot-card" key={item.id}>
          <div>
            <span className="unknown-icon">
              <CircleHelp size={17} />
            </span>
            <div>
              <p className="eyebrow">
                {statusLabel(item.scope_type)} · {item.scope_id}
              </p>
              <h3>{statusLabel(item.reason_code)}</h3>
              <p>{item.limitation}</p>
              {item.suggested_next_step && (
                <div className="next-step">
                  <ChevronRight size={15} />
                  {item.suggested_next_step}
                </div>
              )}
            </div>
          </div>
          <StatusPill value="unknown" />
        </article>
      ))}
    </div>
  );
}

function IocTab({ detail }: { detail: CaseDetail }) {
  return (
    <div className="panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">NETWORK & INDICATORS</p>
          <h2>Static-string observations</h2>
        </div>
        <span className="factual-note">Not runtime observed</span>
      </div>
      {detail.indicators.length === 0 ? (
        <EmptyState
          icon={Network}
          title="No static network indicator was extracted"
          message="Absence of a string indicator does not prove the APK makes no network requests."
        />
      ) : (
        <div className="ioc-list">
          {detail.indicators.map((item) => (
            <div className="ioc-row" key={item.id}>
              <StatusPill value={item.observable_level} />
              <span className="ioc-type">{item.indicator_type}</span>
              <code>{item.value}</code>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function GraphTab({ caseId }: { caseId: string }) {
  const [nodes, setNodes] = useState<Array<{
    id: string;
    type: string;
    label: string;
  }> | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    api
      .graph(caseId)
      .then((data) => setNodes(data.nodes))
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error ? cause.message : "Unable to load graph",
        ),
      );
  }, [caseId]);
  if (error) return <ErrorPanel error={error} />;
  if (!nodes) return <Loading />;
  return (
    <div className="panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">EVIDENCE GRAPH</p>
          <h2>Bounded evidence neighborhood</h2>
        </div>
        <span className="factual-note">Table fallback</span>
      </div>
      {nodes.length === 0 ? (
        <EmptyState
          icon={GitBranch}
          title="No graph nodes yet"
          message="Graph nodes are generated only from persisted artifact and finding records."
        />
      ) : (
        <div className="graph-table">
          <div className="graph-legend">
            <span>
              <i className="artifact-node" />
              Artifact
            </span>
            <span>
              <i className="finding-node" />
              Finding
            </span>
          </div>
          {nodes.map((node) => (
            <div key={node.id} className={`graph-node-row ${node.type}`}>
              <span />
              <strong>{node.label}</strong>
              <code>{shortHash(node.id)}</code>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ReportsTab({ records }: { records: ReportRecord[] }) {
  return (
    <div className="panel">
      <div className="panel-heading">
        <div>
          <p className="eyebrow">CAPSULES & REPORTS</p>
          <h2>Forensic exports</h2>
        </div>
      </div>
      {records.length ? (
        <ReportList records={records} />
      ) : (
        <EmptyState
          icon={FileDown}
          title="No capsule has been created"
          message="A report is written once a worker completes the report stage."
        />
      )}
    </div>
  );
}

function FindingList({
  findings,
  reload,
}: {
  findings: Finding[];
  reload?: () => void;
}) {
  async function review(
    id: string,
    decision: "reviewed" | "needs_further_testing" | "false_positive",
  ) {
    await api.reviewFinding(id, decision);
    reload?.();
  }
  return (
    <div className="finding-list">
      {findings.map((finding) => (
        <article className="finding-card" key={finding.id}>
          <div className="finding-top">
            <SeverityBadge severity={finding.severity} />
            <StatusPill value={finding.evidence_status} />
            <code>{finding.rule_id}</code>
          </div>
          <h3>{finding.title}</h3>
          <p>{finding.description}</p>
          <div className="finding-footer">
            <span>
              {finding.artifact_ids.length} evidence artifact
              {finding.artifact_ids.length === 1 ? "" : "s"}
            </span>
            <span>{statusLabel(finding.reviewer_status)}</span>
            <div className="finding-actions">
              <button onClick={() => void review(finding.id, "reviewed")}>
                Mark reviewed
              </button>
              <button
                onClick={() => void review(finding.id, "needs_further_testing")}
              >
                Needs testing
              </button>
            </div>
          </div>
        </article>
      ))}
    </div>
  );
}

function FindingsPage() {
  const [records, setRecords] = useState<Finding[] | null>(null);
  const [error, setError] = useState("");
  const load = () =>
    api
      .findings()
      .then((result) => setRecords(result.items))
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error ? cause.message : "Could not load findings",
        ),
      );
  useEffect(() => {
    void api
      .findings()
      .then((result) => setRecords(result.items))
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error ? cause.message : "Could not load findings",
        ),
      );
  }, []);
  return (
    <>
      <PageHeading
        title="Evidence triage"
        description="Review annotations persist separately from the observed evidence; they never overwrite raw artifacts."
      />
      {error ? (
        <ErrorPanel error={error} retry={load} />
      ) : !records ? (
        <Loading />
      ) : records.length ? (
        <FindingList findings={records} reload={load} />
      ) : (
        <EmptyState
          icon={ClipboardCheck}
          title="No findings in the current library"
          message="A completed scan may have no rule findings and still contain blindspots or uninspected boundaries."
        />
      )}
    </>
  );
}

function ReportList({ records }: { records: ReportRecord[] }) {
  const [verification, setVerification] = useState<Record<string, string>>({});
  async function verify(record: ReportRecord) {
    const result = await api.verifyReport(record.id);
    setVerification((current) => ({
      ...current,
      [record.id]: result.valid ? "verified" : "failed",
    }));
  }
  return (
    <div className="report-list">
      {records.map((record) => (
        <article className="report-row" key={record.id}>
          <div className="report-icon">
            <BookOpen size={19} />
          </div>
          <div>
            <strong>
              {record.title ?? `Evidence capsule ${shortHash(record.id)}`}
            </strong>
            <p>
              {dateTime(record.created_at)} ·{" "}
              <CopyToken value={record.capsule_sha256} />
            </p>
          </div>
          <StatusPill
            value={verification[record.id] ?? record.verification_status}
          />
          <div className="report-actions">
              <button onClick={() => void api.downloadReport(record.id, "json")}>JSON</button>
              <button onClick={() => void api.downloadReport(record.id, "pdf")}>PDF</button>
              <button onClick={() => void api.downloadReport(record.id, "capsule")}>Capsule</button>
            <button onClick={() => void verify(record)}>Verify</button>
          </div>
        </article>
      ))}
    </div>
  );
}

function ReportsPage() {
  const [records, setRecords] = useState<ReportRecord[] | null>(null);
  const [error, setError] = useState("");
  const load = () =>
    api
      .reports()
      .then((result) => setRecords(result.items))
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error ? cause.message : "Could not load reports",
        ),
      );
  useEffect(() => {
    void api
      .reports()
      .then((result) => setRecords(result.items))
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error ? cause.message : "Could not load reports",
        ),
      );
  }, []);
  return (
    <>
      <PageHeading
        title="Reports & capsules"
        description="Capsule verification recalculates file hashes locally on the service; it does not rely on a model provider."
      />
      {error ? (
        <ErrorPanel error={error} retry={load} />
      ) : !records ? (
        <Loading />
      ) : records.length ? (
        <section className="panel">
          <ReportList records={records} />
        </section>
      ) : (
        <EmptyState
          icon={FileDown}
          title="No forensic exports yet"
          message="Reports appear after an analysis worker reaches the report stage."
        />
      )}
    </>
  );
}

function HealthPage() {
  const [data, setData] = useState<Health | null>(null);
  const [error, setError] = useState("");
  const load = () =>
    api
      .health()
      .then(setData)
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error
            ? cause.message
            : "Could not reach the service",
        ),
      );
  useEffect(() => {
    void api
      .health()
      .then(setData)
      .catch((cause: unknown) =>
        setError(
          cause instanceof Error
            ? cause.message
            : "Could not reach the service",
        ),
      );
  }, []);
  if (error) return <ErrorPanel error={error} retry={load} />;
  if (!data) return <Loading />;
  return (
    <>
      <PageHeading
        title="System health"
        description="These states reflect direct service capability checks. Secrets and provider credentials are never shown."
      >
        <button className="secondary-button" onClick={load}>
          Refresh
        </button>
      </PageHeading>
      <div className="health-grid">
        <section className="panel health-card">
          <HeartPulse size={21} />
          <h2>Backend service</h2>
          <StatusPill
            value={data.status === "ok" ? "available" : data.status}
          />
          <p>Local API and SQLite persistence</p>
        </section>
        <section className="panel health-card">
          <Boxes size={21} />
          <h2>Analysis worker</h2>
          <strong>
            {data.worker.queued_jobs} queued · {data.worker.running_jobs}{" "}
            running
          </strong>
          <p>Start the separate worker process to consume persisted jobs.</p>
        </section>
        {Object.entries(data.adapters).map(([name, state]) => {
          const value = typeof state === "string" ? state : state.status;
          const description =
            typeof state === "string"
              ? state
              : (state.reason ?? state.version ?? "");
          return (
            <section className="panel health-card" key={name}>
              <Activity size={21} />
              <h2>{statusLabel(name)}</h2>
              <StatusPill value={value} />
              <p>{description}</p>
            </section>
          );
        })}
      </div>
    </>
  );
}

function SamplesPage({ navigate }: { navigate: Navigate }) {
  const [records, setRecords] = useState<SampleRecord[] | null>(null);
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    void api.samples(search).then((result) => setRecords(result.items)).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "Could not load samples"));
  }, [search]);
  return <><PageHeading title="APK library" description="Content-addressed samples are deduplicated by SHA-256 while each investigation remains a separate case." /><section className="panel"><div className="table-toolbar"><label className="search-field"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search filename or SHA-256" /></label><span className="table-count">{records?.length ?? "…"} samples</span></div>{error ? <ErrorPanel error={error} /> : !records ? <Loading /> : !records.length ? <EmptyState icon={Archive} title="No APK samples stored" message="Create an investigation to add a safely validated, hash-addressed sample." /> : <div className="table-wrap"><table className="case-table"><thead><tr><th>Sample</th><th>Cases</th><th>Evidence</th><th>First seen</th><th>Status</th><th /></tr></thead><tbody>{records.map((item) => <tr key={item.sha256}><td><strong>{item.original_filename}</strong><small><CopyToken value={item.sha256} /> · {fileSize(item.byte_size)} · {item.archive_entry_count} entries</small></td><td>{item.case_count}</td><td><span>{item.finding_count} findings</span><small>{item.blindspot_count} blindspots</small></td><td className="muted-cell">{dateTime(item.created_at)}</td><td><StatusPill value={item.latest_status} /></td><td><button className="row-open" onClick={() => navigate(`/app/cases/${item.latest_case_id}`)} aria-label={`Open ${item.latest_case_title}`}><ChevronRight size={17} /></button></td></tr>)}</tbody></table></div>}</section></>;
}

function IndicatorsPage({ navigate }: { navigate: Navigate }) {
  const [records, setRecords] = useState<LibraryIndicator[] | null>(null);
  const [search, setSearch] = useState("");
  const [type, setType] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    void api.indicators(search, type).then((result) => setRecords(result.items)).catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "Could not load indicators"));
  }, [search, type]);
  return <><PageHeading title="Indicators / IoCs" description="Search static-string observations across investigations. These records are not runtime network observations." /><section className="panel"><div className="table-toolbar"><label className="search-field"><Search size={16} /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search an indicator value" /></label><select className="compact-select" value={type} onChange={(event) => setType(event.target.value)}><option value="">All types</option><option value="url">URL</option><option value="domain">Domain</option><option value="ip">IP address</option></select><span className="factual-note">Static strings only</span></div>{error ? <ErrorPanel error={error} /> : !records ? <Loading /> : !records.length ? <EmptyState icon={Network} title="No matching indicators" message="No persisted string observation matches this filter." /> : <div className="ioc-list">{records.map((item) => <button className="library-ioc" key={item.id} onClick={() => navigate(`/app/cases/${item.case_id}`)}><StatusPill value={item.observable_level} /><span className="ioc-type">{item.indicator_type}</span><code>{item.value}</code><span>{item.case_title}</span><ChevronRight size={15} /></button>)}</div>}</section></>;
}

function GlobalGraphPage() {
  const [cases, setCases] = useState<CaseRecord[] | null>(null);
  const [selected, setSelected] = useState("");
  useEffect(() => { void api.cases().then((result) => { setCases(result.items); setSelected((current) => current || result.items[0]?.id || ""); }); }, []);
  return <><PageHeading title="Evidence graph" description="Choose a case to inspect the bounded artifact-to-finding provenance neighborhood." />{!cases ? <Loading /> : !cases.length ? <EmptyState icon={GitBranch} title="No graph source cases" message="Create and process an investigation first." /> : <><section className="panel selector-panel"><label>Investigation<select value={selected} onChange={(event) => setSelected(event.target.value)}>{cases.map((item) => <option value={item.id} key={item.id}>{item.title} · {shortHash(item.sample_sha256)}</option>)}</select></label></section>{selected && <GraphTab caseId={selected} />}</>}</>;
}

function DiffGroup({ title, values }: { title: string; values: { shared: string[]; left_only: string[]; right_only: string[] } }) {
  return <section className="panel diff-panel"><div className="panel-heading"><div><p className="eyebrow">STATIC DIFFERENCE</p><h2>{title}</h2></div></div><div className="diff-columns"><div><strong>Shared · {values.shared.length}</strong>{values.shared.map((value) => <code key={value}>{value}</code>)}</div><div><strong>Left only · {values.left_only.length}</strong>{values.left_only.map((value) => <code key={value}>{value}</code>)}</div><div><strong>Right only · {values.right_only.length}</strong>{values.right_only.map((value) => <code key={value}>{value}</code>)}</div></div></section>;
}

function ComparePage() {
  const [cases, setCases] = useState<CaseRecord[] | null>(null);
  const [left, setLeft] = useState("");
  const [right, setRight] = useState("");
  const [result, setResult] = useState<Comparison | null>(null);
  const [error, setError] = useState("");
  useEffect(() => { void api.cases().then((response) => { setCases(response.items); setLeft(response.items[0]?.id ?? ""); setRight(response.items[1]?.id ?? response.items[0]?.id ?? ""); }); }, []);
  async function compare() { setError(""); try { setResult(await api.compare(left, right)); } catch (cause) { setError(cause instanceof Error ? cause.message : "Comparison failed"); } }
  return <><PageHeading title="Case comparison" description="Compare deterministic finding rules and static indicators without inferring family or actor attribution." />{!cases ? <Loading /> : cases.length < 2 ? <EmptyState icon={ArrowLeftRight} title="Two investigations are required" message="Create at least two cases before using comparison." /> : <><section className="panel compare-controls"><label>Left case<select value={left} onChange={(event) => setLeft(event.target.value)}>{cases.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}</select></label><ArrowLeftRight size={20} /><label>Right case<select value={right} onChange={(event) => setRight(event.target.value)}>{cases.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}</select></label><button className="primary-button" disabled={left === right} onClick={() => void compare()}>Compare evidence</button></section>{error && <ErrorPanel error={error} />}{result && <><div className="privacy-note"><CircleHelp size={17} /><p>{result.limitation}</p></div><DiffGroup title="Finding rules" values={result.finding_rules} />{Object.entries(result.indicator_diff).map(([kind, values]) => <DiffGroup title={`${kind.toUpperCase()} indicators`} values={values} key={kind} />)}</>}</>}</>;
}

function SettingsPage() {
  const [settingsData, setSettingsData] = useState<AppSettings | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [profile, setProfile] = useState<"lite" | "standard" | "advanced">("standard");
  const [message, setMessage] = useState("");
  useEffect(() => { void api.settings().then((data) => { setSettingsData(data); setProfile(data.values.default_profile); }); void api.audit().then((data) => setAuditEvents(data.items)); }, []);
  async function save() { const data = await api.saveSettings(profile); setSettingsData(data); setMessage("Saved as the default for new investigations."); }
  return <><PageHeading title="Settings" description="Only persisted, validated controls that affect implemented behavior are editable." />{!settingsData ? <Loading /> : <div className="settings-grid"><section className="panel"><div className="panel-heading"><div><p className="eyebrow">ANALYSIS DEFAULTS</p><h2>New investigation profile</h2></div></div><div className="field-grid"><label className="full-width">Default profile<select value={profile} onChange={(event) => setProfile(event.target.value as typeof profile)}><option value="lite">Lite</option><option value="standard">Standard</option><option value="advanced">Advanced</option></select></label></div><div className="form-actions"><span className="saved-message">{message}</span><button className="primary-button" onClick={() => void save()}>Save setting</button></div></section><section className="panel"><div className="panel-heading"><div><p className="eyebrow">ENFORCED BOUNDARIES</p><h2>Service capabilities</h2></div></div><div className="review-list"><div><span>Data mode</span><StatusPill value={settingsData.capabilities.data_mode} /></div><div><span>Upload limit</span><strong>{fileSize(settingsData.capabilities.max_upload_bytes)}</strong></div><div><span>NVIDIA provider</span><StatusPill value={settingsData.capabilities.nvidia} /></div><div><span>Dynamic lab</span><StatusPill value={settingsData.capabilities.dynamic_lab} /></div></div></section><section className="panel audit-panel"><div className="panel-heading"><div><p className="eyebrow">AUDIT TRAIL</p><h2>Recent security and analyst actions</h2></div></div><div className="event-list">{auditEvents.map((event) => <div className="event" key={event.id}><span /><div><strong>{statusLabel(event.action)} · {event.subject_type}</strong><small>{event.username ?? "system"} · {dateTime(event.created_at)}</small></div></div>)}</div></section></div>}</>;
}

function AuthPage({ bootstrap, onAuthenticated }: { bootstrap: boolean; onAuthenticated: (user: AuthUser) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) { event.preventDefault(); if (bootstrap && password !== confirm) { setError("Passwords do not match."); return; } setBusy(true); setError(""); try { const result = bootstrap ? await api.bootstrap(username, password) : await api.login(username, password); onAuthenticated(result.user); } catch (cause) { setError(cause instanceof Error ? cause.message : "Authentication failed"); } finally { setBusy(false); } }
  return <main className="auth-screen"><section className="auth-card panel"><div className="auth-brand"><span className="brand-mark"><i /><i /></span><div><strong>SHADOWPATH Ω</strong><span>NEXUS</span></div></div><p className="eyebrow">{bootstrap ? "FIRST-RUN SECURITY" : "LOCAL ANALYST ACCESS"}</p><h1>{bootstrap ? "Create the administrator" : "Sign in to the workspace"}</h1><p className="page-description">{bootstrap ? "This account protects all case evidence, settings, and report downloads on this installation." : "Use the local account created for this installation."}</p><form onSubmit={submit} className="auth-form"><label>Username<input autoFocus value={username} onChange={(event) => setUsername(event.target.value)} minLength={3} maxLength={40} autoComplete="username" required /></label><label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} minLength={12} maxLength={256} autoComplete={bootstrap ? "new-password" : "current-password"} required /></label>{bootstrap && <label>Confirm password<input type="password" value={confirm} onChange={(event) => setConfirm(event.target.value)} minLength={12} autoComplete="new-password" required /></label>}{error && <ErrorPanel error={error} />}<button className="primary-button" disabled={busy}>{busy && <LoaderCircle className="spin" size={16} />}{bootstrap ? "Secure this installation" : "Sign in"}</button></form><div className="privacy-note"><LockKeyhole size={17} /><p>Passwords are stored as salted PBKDF2 hashes. Sessions expire after 12 hours.</p></div></section></main>;
}

function Route({ path, navigate }: { path: string; navigate: Navigate }) {
  if (path === "/app/overview" || path === "/")
    return <OverviewPage navigate={navigate} />;
  if (path === "/app/scans/new")
    return <NewInvestigationPage navigate={navigate} />;
  if (path === "/app/cases") return <CasesPage navigate={navigate} />;
  if (path.startsWith("/app/cases/"))
    return <CasePage id={path.split("/").pop()!} navigate={navigate} />;
  if (path.startsWith("/app/jobs/"))
    return <JobPage id={path.split("/").pop()!} navigate={navigate} />;
  if (path === "/app/findings") return <FindingsPage />;
  if (path === "/app/samples") return <SamplesPage navigate={navigate} />;
  if (path === "/app/graph") return <GlobalGraphPage />;
  if (path === "/app/indicators") return <IndicatorsPage navigate={navigate} />;
  if (path === "/app/compare") return <ComparePage />;
  if (path === "/app/reports") return <ReportsPage />;
  if (path === "/app/health") return <HealthPage />;
  if (path === "/app/settings") return <SettingsPage />;
  return <EmptyState title="Workspace not found" message="Use the navigation to open an implemented analyst workflow." />;
}

export function App() {
  const [path, navigate] = usePath();
  const [theme, toggleTheme] = useTheme();
  const [auth, setAuth] = useState<{ loading: boolean; bootstrap: boolean; user: AuthUser | null }>({ loading: true, bootstrap: false, user: null });
  const refreshAuth = () => api.authStatus().then((status) => setAuth({ loading: false, bootstrap: status.bootstrap_required, user: status.user })).catch(() => setAuth({ loading: false, bootstrap: false, user: null }));
  useEffect(() => { void refreshAuth(); const expired = () => void refreshAuth(); window.addEventListener("shadowpath-auth-expired", expired); return () => window.removeEventListener("shadowpath-auth-expired", expired); }, []);
  async function logout() { await api.logout(); setAuth((current) => ({ ...current, user: null })); }
  if (auth.loading) return <main className="auth-screen"><Loading /></main>;
  if (!auth.user) return <AuthPage bootstrap={auth.bootstrap} onAuthenticated={(user) => setAuth({ loading: false, bootstrap: false, user })} />;
  return (
    <AppShell
      path={path}
      navigate={navigate}
      theme={theme}
      toggleTheme={toggleTheme}
      user={auth.user}
      onLogout={() => void logout()}
    >
      <Route path={path} navigate={navigate} />
    </AppShell>
  );
}
