import type {
  SparkSnapshot,
  VulnHuntCounts,
  VulnHuntFinding,
  VulnHuntRun,
  VulnHuntRunStatus,
  VulnHuntScanRequest,
  VulnHuntSeverity,
} from "../../api/types";
import type { TagTone } from "../ui/Tag";

/** Most serious first. Findings without a severity sort after all of these. */
export const SEVERITY_ORDER: readonly VulnHuntSeverity[] = ["High+", "High", "Medium", "Low", "Informational"];

const UNRATED_RANK = SEVERITY_ORDER.length;

export function severityRank(severity: VulnHuntSeverity | null | undefined): number {
  const i = severity ? SEVERITY_ORDER.indexOf(severity) : -1;
  return i < 0 ? UNRATED_RANK : i;
}

/** Tag tone per severity (the shared Tag calls the red tone "bad"). */
export function severityTone(severity: VulnHuntSeverity | null | undefined): TagTone {
  switch (severity) {
    case "High+":
    case "High":
      return "bad";
    case "Medium":
      return "warn";
    case "Low":
      return "info";
    default:
      return "neutral";
  }
}

export function severityLabel(severity: VulnHuntSeverity | null | undefined): string {
  return severity ?? "Unrated";
}

/** Stable sort by severity; `desc` puts the most serious first. A new array, the input is untouched. */
export function sortFindings(findings: readonly VulnHuntFinding[], dir: "desc" | "asc" = "desc"): VulnHuntFinding[] {
  const sign = dir === "desc" ? 1 : -1;
  return findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => sign * (severityRank(a.f.severity) - severityRank(b.f.severity)) || a.i - b.i)
    .map((x) => x.f);
}

export function emptyCounts(): VulnHuntCounts {
  return { "High+": 0, High: 0, Medium: 0, Low: 0, Informational: 0, unrated: 0 };
}

/** Counts per severity, computed from the findings themselves (the report view does not trust a separate tally). */
export function countFindings(findings: readonly Pick<VulnHuntFinding, "severity">[]): VulnHuntCounts {
  const counts = emptyCounts();
  for (const f of findings) {
    if (f.severity && f.severity in counts) counts[f.severity] += 1;
    else counts.unrated += 1;
  }
  return counts;
}

/** High+ and High together: the findings that deserve attention first. */
export function seriousCount(counts: Pick<VulnHuntCounts, "High+" | "High"> | null | undefined): number {
  return counts ? (counts["High+"] ?? 0) + (counts.High ?? 0) : 0;
}

/** "2 High+ · 1 High · 3 Medium", or "No findings". Zero buckets are left out. */
export function summarizeCounts(counts: VulnHuntCounts | null | undefined, total?: number): string {
  if (!counts) return "No results";
  const parts = [...SEVERITY_ORDER.map((s) => [s, counts[s] ?? 0] as const), ["Unrated", counts.unrated ?? 0] as const]
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`);
  if (parts.length) return parts.join(" · ");
  return total === 0 || total == null ? "No findings" : `${total} finding${total === 1 ? "" : "s"}`;
}

// ── run status ──

export type StatusTone = "good" | "bad" | "warn" | "acc" | "neutral";

export function statusTone(status: VulnHuntRunStatus): StatusTone {
  switch (status) {
    case "completed":
      return "good";
    case "failed":
      return "bad";
    case "stopped":
    case "gone":
    case "detached":
      return "warn";
    case "running":
      return "acc";
    default:
      return "neutral";
  }
}

export function statusLabel(status: VulnHuntRunStatus): string {
  switch (status) {
    case "running":
      return "Running";
    case "completed":
      return "Completed";
    case "failed":
      return "Failed";
    case "stopped":
      return "Stopped";
    case "detached":
      return "Not watched";
    case "gone":
      return "Gone";
    default:
      return status;
  }
}

/** The run is (or may still be) executing on the unit. */
export function isLive(run: Pick<VulnHuntRun, "status">): boolean {
  return run.status === "running" || run.status === "detached";
}

const STAGE_LABEL: Record<string, string> = {
  starting: "Starting",
  clone: "Cloning",
  hunt: "Hunting",
  collect: "Collecting results",
  done: "Done",
};

export function stageLabel(stage: string | null | undefined): string {
  if (!stage) return "Starting";
  return STAGE_LABEL[stage] ?? stage;
}

export function runTitle(run: Pick<VulnHuntRun, "label" | "source">): string {
  return run.label.trim() || run.source.value;
}

// ── units ──

/** Units a scan can run on: online Linux hosts (a unit without a platform is Linux). */
export function eligibleUnits(sparks: readonly SparkSnapshot[]): SparkSnapshot[] {
  return sparks.filter((s) => s.online && (s.platform ?? "linux") === "linux");
}

// ── scan form ──

export interface ScanFormState {
  sourceType: "url" | "path";
  value: string;
  authorized: boolean;
  readOnly: boolean;
  confirmExecute: boolean;
  label: string;
  /** Kept as typed so an empty or half-typed field is representable. */
  timeoutMinutes: string;
}

export interface ScanLimits {
  defaultTimeoutMinutes: number;
  minTimeoutMinutes: number;
  maxTimeoutMinutes: number;
}

/** Used until /api/vulnhunt/setup answers; the server validates the real range again. */
export const FALLBACK_LIMITS: ScanLimits = { defaultTimeoutMinutes: 240, minTimeoutMinutes: 5, maxTimeoutMinutes: 720 };

export function initialForm(limits: ScanLimits): ScanFormState {
  return {
    sourceType: "url",
    value: "",
    authorized: false,
    readOnly: true,
    confirmExecute: false,
    label: "",
    timeoutMinutes: String(limits.defaultTimeoutMinutes),
  };
}

export const SOURCE_PLACEHOLDER = { url: "https://github.com/org/repo", path: "~/code/project" } as const;

const LOCAL_PATH_RE = /^(~\/|\/)[A-Za-z0-9._@+=,/-]{1,400}$/;

/**
 * A readable hint for a source that the server would refuse, or null when it looks fine.
 * Not authoritative (the server validates again), so a hint never blocks Start by itself.
 */
export function sourceHint(type: "url" | "path", raw: string): string | null {
  const value = raw.trim();
  if (!value) return null;
  if (/[\0\r\n\t ]/.test(value)) return "The source must not contain spaces or line breaks.";
  if (type === "path") {
    if (!value.startsWith("/") && !value.startsWith("~/")) return "Use an absolute path, or one that starts with ~/ (the unit's home).";
    if (value.split("/").some((seg) => seg === "..")) return "The path must not contain .. segments.";
    if (!LOCAL_PATH_RE.test(value)) return "Use only letters, digits and . _ @ + = , / - in the path.";
    return null;
  }
  if (/^git@|^ssh:\/\//i.test(value)) return "SSH addresses are not supported. Use an https:// URL, or a path to a checkout already on the unit.";
  let u: URL;
  try {
    u = new URL(value);
  } catch {
    return "That does not look like a URL. Example: https://github.com/org/repo";
  }
  if (u.protocol !== "https:") return "Only https:// repository URLs are supported (use a path for a checkout already on the unit).";
  if (u.username || u.password) return "Remove the credentials from the URL.";
  if (u.search || u.hash) return "Remove the query or fragment from the URL.";
  if (u.pathname === "/" || u.pathname === "") return "Add the repository path, for example https://github.com/org/repo.";
  if (value.length > 300) return "The URL is too long.";
  return null;
}

export interface ScanFormCheck {
  /** Start may be pressed. */
  ok: boolean;
  /** Why it cannot, in the order the form shows them (empty when ok). */
  blockers: string[];
  /** Soft hint about the source text; does not block. */
  sourceHint: string | null;
  timeoutError: string | null;
  request: VulnHuntScanRequest | null;
}

export function checkScanForm(form: ScanFormState, limits: ScanLimits = FALLBACK_LIMITS): ScanFormCheck {
  const blockers: string[] = [];
  const value = form.value.trim();
  if (!value) blockers.push(form.sourceType === "url" ? "Enter the repository URL." : "Enter the path of a checkout on the unit.");
  if (!form.authorized) blockers.push("Confirm that you are authorized to scan this code.");
  if (!form.readOnly && !form.confirmExecute) blockers.push("Confirm that the scan may execute code on this unit, or keep it read-only.");

  const minutesText = form.timeoutMinutes.trim();
  const minutes = Number(minutesText);
  let timeoutError: string | null = null;
  if (!minutesText || !Number.isInteger(minutes) || minutes < limits.minTimeoutMinutes || minutes > limits.maxTimeoutMinutes) {
    timeoutError = `Use a whole number of minutes between ${limits.minTimeoutMinutes} and ${limits.maxTimeoutMinutes}.`;
    blockers.push(timeoutError);
  }

  const ok = blockers.length === 0;
  let request: VulnHuntScanRequest | null = null;
  if (ok) {
    request = {
      source: { type: form.sourceType, value },
      readOnly: form.readOnly,
      authorized: true,
      timeoutMinutes: minutes,
    };
    if (!form.readOnly) request.confirmExecute = true;
    const label = form.label.trim();
    if (label) request.label = label;
  }
  return { ok, blockers, sourceHint: sourceHint(form.sourceType, value), timeoutError, request };
}

/** Human line about the setup state of a unit, for "not ready" explanations. */
export function setupProblems(status: {
  reachable: boolean;
  installed: boolean;
  git: boolean;
  setsid: boolean;
  hostCommand: { source: string; found: boolean; configured: boolean };
  install?: { python311: string | null; upToDate: boolean } | null;
}): string[] {
  const out: string[] = [];
  if (!status.reachable) return ["The unit could not be reached."];
  if (!status.installed) out.push("VulnHunter is not installed on this unit.");
  else if (status.install && !status.install.upToDate) out.push("The installed VulnHunter is not the revision this dashboard installs.");
  if (status.install && status.install.python311 == null) out.push("Python 3.11 or newer is needed on this unit.");
  if (!status.git) out.push("git is not installed on this unit.");
  if (!status.setsid) out.push("The setsid command (util-linux) is not available on this unit.");
  const h = status.hostCommand;
  if (h.source === "unsafe") out.push("The harness command file is not safe to use: it must be a regular file (not a link), owned by the unit's user, with permissions 600.");
  else if (!h.configured) out.push(h.source !== "none" && !h.found ? "The configured harness program was not found on the unit." : "No harness command is configured.");
  return out;
}

/** First 9 characters of a git revision. */
export const shortRev = (rev: string | null | undefined): string => (rev ? rev.slice(0, 9) : "");

/** Same character rules as the server (it re-validates): absolute or ~/ path, letters, digits and . _ @ + = , / - only. */
const DIR_RE = /^(~\/|\/)[A-Za-z0-9._@+=,/-]+$/;

/** A problem with a directory the user typed for the installer, or null. An empty optional directory is fine. */
export function installDirProblem(value: string, required: boolean): string | null {
  const v = value.trim();
  if (!v) return required ? "Choose a skills directory." : null;
  if (v.length > 400) return "That path is too long.";
  if (!DIR_RE.test(v)) return "Use an absolute path or ~/…, with letters, digits and . _ @ + = , / - only.";
  if (v.split("/").includes("..")) return "The path must not contain “..”.";
  return null;
}

export interface InstallGateInput {
  setup: { startAllowed: boolean; startBlockedReason: string | null } | null;
  setupError: string | null;
  git: boolean;
  python311: string | null;
  skillsDir: string;
  agentsDir: string;
  running: boolean;
}

/** Why changes to a unit (install, harness command) are not allowed from this dashboard, or null. */
export function changeBlockedReason(
  setup: { startAllowed: boolean; startBlockedReason: string | null } | null,
  setupError: string | null
): string | null {
  if (setup && !setup.startAllowed) return setup.startBlockedReason ?? "Changing a unit is not allowed on this dashboard.";
  if (!setup && !setupError) return "Checking whether this dashboard allows changes…";
  return null;
}

/** Why the Install / Update button is disabled, or null when it can be used. */
export function installBlockedReason(i: InstallGateInput): string | null {
  const gate = changeBlockedReason(i.setup, i.setupError);
  if (gate) return gate;
  if (i.running) return "An install is already running on this unit.";
  if (!i.git) return "git is not installed on this unit.";
  if (i.python311 == null) return "Python 3.11 or newer is needed on this unit.";
  return installDirProblem(i.skillsDir, true) ?? installDirProblem(i.agentsDir, false);
}
