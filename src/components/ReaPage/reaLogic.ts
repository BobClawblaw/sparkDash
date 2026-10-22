import type {
  ReaArgSpec,
  ReaExecClass,
  ReaResultShape,
  ReaRun,
  ReaRunRequest,
  ReaRunStatus,
  ReaSetup,
  ReaSpec,
  ReaStatus,
  ReaTarget,
  ReaWorkflowSpec,
} from "../../api/types";
import type { TagTone } from "../ui/Tag";

// ── formatting ──

export function formatBytes(n: number | null | undefined): string {
  if (n == null || !Number.isFinite(n)) return "–";
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

/** Plain text for a value of unknown shape, clipped. Nothing is ever interpreted as markup. */
export function plain(v: unknown, max = 200): string {
  let s: string;
  if (v == null) s = "";
  else if (typeof v === "string") s = v;
  else if (typeof v === "number" || typeof v === "boolean") s = String(v);
  else {
    try {
      s = JSON.stringify(v) ?? "";
    } catch {
      s = "";
    }
  }
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

// ── install ──

/** What each exit code of the on-unit installer means. */
export function installExitExplanation(code: number | null | undefined): string | null {
  switch (code) {
    case 127:
      return "npm was not found next to the Node.js on the unit. Install a complete Node.js 22.19+ (with npm) there, or remove the partial one, then check again.";
    case 3:
      return "A download failed: either Node.js from nodejs.org or the pinned packages from the npm registry (no network access, a proxy, a full disk, or a permissions problem). The output above has the message.";
    case 4:
      return "A check failed: the downloaded Node.js did not match the checksum pinned in this dashboard, or REA's smoke test (rea --version or rea doctor) did not pass. Nothing was switched over; the output above shows which.";
    case 5:
      return "This unit cannot get Node.js from the installer (not Linux, an unsupported CPU, or tar / sha256sum / a downloader is missing). Install Node.js 22.19+ there yourself, then check again.";
    case 6:
      return "The downloaded Node.js could not be unpacked or does not run on this unit (wrong architecture or a missing library). Install Node.js 22.19+ there yourself, then check again.";
    case 124:
      return "The install ran out of time.";
    case 143:
      return "The install was stopped.";
    default:
      return null;
  }
}

/** The unit has everything REA needs to start a run. */
export function reaReady(status: ReaStatus | null | undefined): boolean {
  return Boolean(status && status.reachable && status.node.ok && status.npm && status.installed);
}

/** Blocking problems only: a missing Node.js the installer can fetch is not one (see nodeWillBeInstalled). */
export function readinessProblems(status: ReaStatus, minNode: string): string[] {
  const out: string[] = [];
  if (!status.reachable) {
    out.push("The unit cannot be reached over SSH.");
    return out;
  }
  if (!status.node.ok) {
    if (!status.node.installable) {
      const have = status.node.version ? `Node.js ${status.node.version} is older than ${minNode}` : `Node.js ${minNode} or newer is not installed`;
      out.push(`${have}, and the installer cannot fetch one here${status.node.installReason ? `: ${status.node.installReason}` : ""}.`);
    }
  } else if (!status.npm) {
    out.push("npm is not installed next to Node.js on the unit.");
  }
  return out;
}

/** No usable Node.js, but the install will download the pinned official build into the user's home. */
export function nodeWillBeInstalled(status: ReaStatus | null | undefined): boolean {
  return Boolean(status && status.reachable && !status.node.ok && status.node.installable);
}

// ── run status ──

export const isLive = (r: Pick<ReaRun, "status">): boolean => r.status === "running";

export function statusLabel(s: ReaRunStatus): string {
  switch (s) {
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
      return String(s);
  }
}

export function statusTone(s: ReaRunStatus): TagTone {
  switch (s) {
    case "running":
      return "acc";
    case "completed":
      return "good";
    case "failed":
      return "bad";
    case "stopped":
    case "detached":
      return "warn";
    default:
      return "neutral";
  }
}

export function stageLabel(stage: string | null | undefined): string {
  if (!stage) return "Working";
  return stage.charAt(0).toUpperCase() + stage.slice(1);
}

export function runTitle(r: Pick<ReaRun, "label" | "workflowLabel" | "workflowId">): string {
  return r.label || r.workflowLabel || r.workflowId;
}

export const EXEC_LABEL: Record<ReaExecClass, string> = {
  static: "static",
  "native-provider": "native provider",
  "executes-target": "executes target",
  device: "device",
  network: "network",
};

export function execTone(c: ReaExecClass): TagTone {
  switch (c) {
    case "static":
      return "good";
    case "native-provider":
      return "info";
    default:
      return "bad";
  }
}

export const needsConfirm = (c: ReaExecClass): boolean => c === "executes-target" || c === "device" || c === "network";

// ── paths on the unit (mirrors the server's narrow charset) ──

const PATH_BODY_RE = /^[A-Za-z0-9._@+=,/ ()-]+$/;
const CONTROL_RE = /[\u0000-\u001f\u007f]/;

/** null when the path is acceptable, else a sentence saying why not. */
export function unitPathProblem(raw: string): string | null {
  if (!raw) return null;
  if (raw.length > 400) return "The path is too long (400 characters at most).";
  if (CONTROL_RE.test(raw)) return "The path must not contain control characters or line breaks.";
  if (raw !== raw.trim()) return "The path must not start or end with a space.";
  const home = raw.startsWith("~/");
  if (!home && !raw.startsWith("/")) return "Use an absolute path, or one that starts with ~/.";
  let body = raw.slice(home ? 2 : 1);
  if (body.endsWith("/")) body = body.slice(0, -1);
  if (!body) return "Name a file or folder, not the root or the home directory itself.";
  if (!PATH_BODY_RE.test(body)) return "Only letters, digits and . _ @ + = , ( ) - space and / are accepted.";
  for (const seg of body.split("/")) {
    if (!seg.trim()) return "The path must not contain empty segments.";
    if (seg === "." || seg === "..") return "The path must not contain . or .. segments.";
  }
  return null;
}

// ── uploads ──

const UPLOAD_SEGMENT_RE = /^[A-Za-z0-9._-]{1,128}$/;
const UPLOAD_REL_RE = /^[A-Za-z0-9._-]{1,128}(\/[A-Za-z0-9._-]{1,128}){0,15}$/;
const ARCHIVE_RE = /\.(zip|tar|tar\.gz|tgz)$/i;

/** null when a path inside an upload is acceptable (same rule as the server); empty is fine (it means the whole upload). */
export function uploadRelProblem(rel: string): string | null {
  if (!rel) return null;
  if (!UPLOAD_REL_RE.test(rel)) return "Use letters, digits and . _ - with / between folders (at most 16 levels, 128 characters per name).";
  if (rel.split("/").some((s) => s === "." || s === "..")) return "The path must not contain . or .. segments.";
  return null;
}

export const isArchiveName = (name: string): boolean => ARCHIVE_RE.test(name);

export interface UploadCandidate {
  /** Path as the browser reports it (folder drops: `folder/sub/file`). */
  path: string;
  file: File;
}

export interface PlannedUpload {
  file: File;
  relPath: string;
  archive: boolean;
  size: number;
}

export interface UploadPlan {
  entries: PlannedUpload[];
  totalBytes: number;
  /** Names that had unsupported characters replaced by `_`. */
  adjusted: number;
  /** Reasons the selection cannot be uploaded; empty when it can. */
  problems: string[];
}

/** Upload paths: only [A-Za-z0-9._-] per segment, at most 16 levels, no `.`/`..`. Other characters become `_`. */
export function sanitizeUploadPath(path: string): { path: string; changed: boolean } | null {
  const segs = path.split("/").filter((s) => s !== "");
  if (!segs.length || segs.length > 16) return null;
  let changed = false;
  const out: string[] = [];
  for (const s of segs) {
    let seg = s.replace(/[^A-Za-z0-9._-]/g, "_");
    if (seg !== s) changed = true;
    if (seg === "." || seg === "..") {
      seg = seg.replace(/\./g, "_");
      changed = true;
    }
    if (!UPLOAD_SEGMENT_RE.test(seg)) return null;
    out.push(seg);
  }
  return { path: out.join("/"), changed };
}

/** Check a selection against the server's limits before anything is sent. */
export function planUpload(candidates: readonly UploadCandidate[], limits: { maxBytes: number; maxFiles: number }): UploadPlan {
  const problems: string[] = [];
  const entries: PlannedUpload[] = [];
  const seen = new Set<string>();
  let adjusted = 0;
  let total = 0;
  for (const c of candidates) {
    const s = sanitizeUploadPath(c.path);
    if (!s) {
      problems.push(`"${plain(c.path, 80)}" has a name or folder depth the unit cannot accept (names up to 128 characters, at most 16 folders deep).`);
      continue;
    }
    if (s.changed) adjusted += 1;
    if (seen.has(s.path)) {
      problems.push(`Two files would be stored as "${s.path}". Rename one of them.`);
      continue;
    }
    seen.add(s.path);
    total += c.file.size;
    entries.push({ file: c.file, relPath: s.path, archive: isArchiveName(s.path), size: c.file.size });
  }
  if (!candidates.length) problems.push("Nothing was selected.");
  if (candidates.length > limits.maxFiles) problems.push(`That is ${candidates.length.toLocaleString()} files; at most ${limits.maxFiles.toLocaleString()} are accepted in one upload.`);
  if (total > limits.maxBytes) problems.push(`That is ${formatBytes(total)}; at most ${formatBytes(limits.maxBytes)} are accepted in one upload.`);
  return { entries, totalBytes: total, adjusted, problems };
}

// ── catalog ──

export function groupWorkflows(spec: ReaSpec, query: string): Array<{ id: string; label: string; help?: string; workflows: ReaWorkflowSpec[] }> {
  const q = query.trim().toLowerCase();
  const match = (w: ReaWorkflowSpec) =>
    !q || w.label.toLowerCase().includes(q) || w.blurb.toLowerCase().includes(q) || w.id.toLowerCase().includes(q) || w.command.toLowerCase().includes(q);
  return spec.groups
    .map((g) => ({ ...g, workflows: spec.workflows.filter((w) => w.group === g.id && match(w)) }))
    .filter((g) => g.workflows.length > 0);
}

export interface Availability {
  ok: boolean;
  /** "needs Ghidra, Hopper or IDA" and the like; null when nothing is missing. */
  reason: string | null;
}

const PROVIDER_ENGINES = ["ghidra", "hopper", "ida"];

/** Whether the unit has what a workflow needs. Unknown status does not block (the run is gated on readiness anyway). */
export function workflowAvailability(w: ReaWorkflowSpec, status: ReaStatus | null, setup?: ReaSetup | null): Availability {
  if (w.effects.mutatesDevice && setup && !setup.deviceWritesEnabled) {
    return { ok: false, reason: "changing a device is switched off on this dashboard (the server needs REA_ENABLE_DEVICE_WRITES=1)" };
  }
  if (!status) return { ok: true, reason: null };
  const label = (id: string) => status.engines.find((e) => e.id === id)?.label ?? id;
  const found = (id: string) => status.engines.find((e) => e.id === id)?.found === true;
  const missing = w.prerequisites.filter((id) => !found(id));
  if (missing.length) return { ok: false, reason: `needs ${missing.map(label).join(" and ")}` };
  if (w.needsProvider) {
    const any = status.providers.some((p) => p.available && p.id !== "auto") || PROVIDER_ENGINES.some(found);
    if (!any) return { ok: false, reason: "needs Ghidra, Hopper or IDA" };
  }
  return { ok: true, reason: null };
}

export function targetKindHint(w: ReaWorkflowSpec): string {
  if (w.targets === 0) return "Needs no file or folder.";
  const kinds = w.targetKinds.length ? w.targetKinds : (["path", "upload"] as const);
  const where = kinds.includes("path") && kinds.includes("upload") ? "a path on the unit or an upload" : kinds.includes("upload") ? "an upload" : "a path on the unit";
  if (w.targets === 2) return `Needs two targets: ${w.targetLabel ?? "first"} and ${w.target2Label ?? "second"} (each ${where}).`;
  return `${w.targetLabel ?? "Target"}: ${where}.`;
}

// ── option forms ──

export type OptionValues = Record<string, string | boolean>;

export function defaultOptionValues(w: ReaWorkflowSpec): OptionValues {
  const out: OptionValues = {};
  for (const a of w.args) {
    if (a.kind === "bool") out[a.name] = false;
    else out[a.name] = "";
  }
  return out;
}

const splitWords = (s: string) => s.split(/[\s,]+/).filter(Boolean);

const hasDotSegment = (v: string) => v.split("/").some((s) => s === "." || s === "..");

/**
 * Text checks the server applies to a string option and to each entry of a list option.
 * `noDotDot` comes from the spec; when an older spec lacks it, an option whose pattern is a path shape gets the same check.
 */
function textProblem(a: ArgLike, v: string): string | null {
  if (v.length > (a.maxLength ?? 300)) return `At most ${a.maxLength ?? 300} characters.`;
  if (CONTROL_RE.test(v)) return "No control characters or line breaks.";
  if (a.positional && v.startsWith("-")) return 'Must not start with "-".';
  if (a.pattern) {
    try {
      if (!new RegExp(a.pattern).test(v)) return "That text has a shape the unit will not accept.";
    } catch {
      /* a pattern the browser cannot compile: leave it to the server */
    }
  }
  const noDot = a.noDotDot ?? Boolean(a.pattern && a.pattern.includes("/"));
  if (noDot && hasDotSegment(v)) return "Must not contain . or .. segments.";
  return null;
}

/** Per-field error for an option value; null when fine (empty optional fields are fine). */
export function optionProblem(a: ArgLike, raw: string | boolean | undefined): string | null {
  if (a.kind === "bool") return null;
  const v = typeof raw === "string" ? raw : "";
  if (v.trim() === "") return a.required && !a.allowEmpty ? "Required." : null;
  switch (a.kind) {
    case "int": {
      if (!/^-?[0-9]{1,15}$/.test(v.trim())) return "Enter a whole number.";
      const n = Number(v);
      if (a.min !== undefined && n < a.min) return `At least ${a.min}.`;
      if (a.max !== undefined && n > a.max) return `At most ${a.max}.`;
      return null;
    }
    case "intlist": {
      const items = splitWords(v);
      if (a.maxItems !== undefined && items.length > a.maxItems) return `At most ${a.maxItems} numbers.`;
      for (const it of items) {
        if (!/^[0-9]{1,15}$/.test(it)) return "Enter whole numbers separated by spaces or commas.";
        const n = Number(it);
        if (n < (a.min ?? 0) || n > (a.max ?? 1e9)) return `Each number must be between ${a.min ?? 0} and ${a.max ?? 1e9}.`;
      }
      return null;
    }
    case "list": {
      const items = v.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (a.maxItems !== undefined && items.length > a.maxItems) return `At most ${a.maxItems} entries.`;
      if (items.length > (a.maxItems ?? 20)) return `At most ${a.maxItems ?? 20} entries.`;
      for (const it of items) {
        const p = textProblem(a, it);
        if (p) return `${plain(it, 40)}: ${p}`;
      }
      return null;
    }
    case "json": {
      const cap = a.maxLength ?? 8000;
      if (v.length > cap) return `At most ${cap} characters.`;
      try {
        const parsed = JSON.parse(v);
        const isArr = Array.isArray(parsed);
        const isObj = !!parsed && typeof parsed === "object" && !isArr;
        if (a.jsonType === "array" ? !isArr : !isObj) return `Must be a JSON ${a.jsonType === "array" ? "array" : "object"}.`;
        if (isArr && parsed.length > 200) return "At most 200 items.";
        if (JSON.stringify(parsed).length > cap) return `At most ${cap} characters once compacted.`;
      } catch {
        return "Not valid JSON.";
      }
      return null;
    }
    case "path":
      return unitPathProblem(v.trim());
    case "choice":
      return a.choices && !a.choices.includes(v) ? "Pick one of the choices." : null;
    case "string":
      return textProblem(a, v);
    default:
      return null;
  }
}

type ArgLike = Pick<ReaArgSpec, "kind" | "required" | "positional" | "noDotDot" | "allowEmpty" | "min" | "max" | "maxItems" | "maxLength" | "pattern" | "choices" | "jsonType">;

export interface BuiltOptions {
  options: Record<string, string | number | boolean | string[] | number[]>;
  /** Field name -> message. */
  errors: Record<string, string>;
  /** Form-level problems (requireOneOf, `with`). */
  blockers: string[];
}

/** Turn the form values into the request's `options`, with the same checks the server will apply. */
export function buildOptions(w: ReaWorkflowSpec, values: OptionValues): BuiltOptions {
  const options: BuiltOptions["options"] = {};
  const errors: Record<string, string> = {};
  const blockers: string[] = [];
  for (const a of w.args) {
    const raw = values[a.name];
    if (a.kind === "bool") {
      if (raw === true) options[a.name] = true;
      continue;
    }
    const v = typeof raw === "string" ? raw : "";
    const problem = optionProblem(a, v);
    if (problem) {
      errors[a.name] = problem;
      continue;
    }
    if (v.trim() === "" && !(a.allowEmpty && a.required && a.positional)) continue;
    switch (a.kind) {
      case "int":
        options[a.name] = Number(v.trim());
        break;
      case "intlist":
        options[a.name] = splitWords(v).map(Number);
        break;
      case "list":
        options[a.name] = v.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
        break;
      case "path":
        options[a.name] = v.trim();
        break;
      default:
        options[a.name] = v;
    }
  }
  for (const a of w.args) {
    if (a.with && options[a.name] !== undefined && options[a.with] === undefined) blockers.push(`"${a.name}" also needs "${a.with}".`);
  }
  if (w.requireOneOf && w.requireOneOf.length && !w.requireOneOf.some((k) => options[k] !== undefined)) {
    blockers.push(`Fill in at least one of: ${w.requireOneOf.join(", ")}.`);
  }
  return { options, errors, blockers };
}

// ── the run request ──

export interface RunFormState {
  workflow: ReaWorkflowSpec;
  targets: [ReaTarget | null, ReaTarget | null];
  provider: string;
  values: OptionValues;
  timeoutMinutes: string;
  label: string;
  authorized: boolean;
  confirmed: boolean;
}

export interface RunCheck {
  ok: boolean;
  blockers: string[];
  fieldErrors: Record<string, string>;
  timeoutError: string | null;
  request: ReaRunRequest | null;
}

export function checkRunForm(f: RunFormState, setup: ReaSetup | null): RunCheck {
  const w = f.workflow;
  const blockers: string[] = [];
  const built = buildOptions(w, f.values);
  blockers.push(...built.blockers);
  if (w.targets >= 1 && !f.targets[0]) blockers.push(`Choose ${w.targets === 2 ? "the first target" : "a target"}.`);
  if (w.targets === 2 && !f.targets[1]) blockers.push("Choose the second target.");
  if (Object.keys(built.errors).length) blockers.push("Fix the highlighted options.");

  const max = setup?.limits.maxTimeoutMinutes ?? 240;
  let timeout: number | undefined;
  let timeoutError: string | null = null;
  if (f.timeoutMinutes.trim() !== "") {
    if (!/^[0-9]{1,6}$/.test(f.timeoutMinutes.trim())) timeoutError = "Enter a whole number of minutes.";
    else {
      timeout = Number(f.timeoutMinutes.trim());
      if (timeout < 1 || timeout > max) timeoutError = `Between 1 and ${max} minutes.`;
    }
  }
  if (timeoutError) blockers.push(timeoutError);

  if (!f.authorized) blockers.push("Confirm that you are authorized to analyze this target.");
  const confirm = needsConfirm(w.execClass);
  if (confirm && !f.confirmed) blockers.push("Confirm that you accept this workflow runs or interacts with the target.");
  if (w.effects.mutatesDevice && setup && !setup.deviceWritesEnabled) {
    blockers.push("Changing a device is switched off on this dashboard (the server needs REA_ENABLE_DEVICE_WRITES=1).");
  }

  const ok = blockers.length === 0;
  let request: ReaRunRequest | null = null;
  if (ok) {
    request = { workflowId: w.id, authorized: true };
    if (w.targets >= 1 && f.targets[0]) request.target = f.targets[0];
    if (w.targets === 2 && f.targets[1]) request.target2 = f.targets[1];
    if (w.needsProvider) request.provider = (f.provider || "auto") as ReaRunRequest["provider"];
    if (Object.keys(built.options).length) request.options = built.options;
    if (timeout !== undefined) request.timeoutMinutes = timeout;
    if (confirm) request.confirmExecute = true;
    const label = f.label.trim();
    if (label) request.label = label;
  }
  return { ok, blockers, fieldErrors: built.errors, timeoutError, request };
}

// ── results ──

export interface ViewSource {
  id: string;
  label: string;
  /** Which query parameter the id travels in. */
  param: "collection" | "facet";
}

// Mirrors server/rea/validate.js: the only sources `GET …/view` accepts, per result shape.
const COLLECTIONS_BY_SHAPE: Record<ReaResultShape, string[]> = { "javascript-app": ["modules"], layout: ["sections", "symbols"], "native-function": [], generic: [] };
const NATIVE_FACETS = [
  "procedure", "pseudocode", "assembly", "basic_blocks", "comments", "callers", "callees", "incoming_references",
  "outgoing_references", "unresolved_calls", "referenced_strings", "referenced_names", "native_api", "value_flow_summary",
  "value_flow_operations", "value_flow_def_use", "value_flow_effects", "value_flow_parameters", "value_flow_parameter_uses",
];
const LAYOUT_FACETS = ["mitigations", "linkage"];

/**
 * What can be paged for a finished run: only sources the server accepts for this result shape (a summary table id that
 * is not one of them is not offered, so nothing offered can answer 400). Table labels are used where an id matches.
 */
export function viewSources(shape: ReaResultShape, tables: ReadonlyArray<{ id: string; label: string }> | undefined): ViewSource[] {
  const labels = new Map<string, string>();
  for (const t of tables ?? []) if (t.label && !labels.has(t.id)) labels.set(t.id, t.label);
  const out: ViewSource[] = [];
  const seen = new Set<string>();
  for (const id of COLLECTIONS_BY_SHAPE[shape] ?? []) {
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({ id, label: labels.get(id) ?? id, param: "collection" });
  }
  const facets = shape === "native-function" ? NATIVE_FACETS : shape === "layout" ? LAYOUT_FACETS : [];
  for (const id of facets) {
    if (seen.has(`facet:${id}`)) continue;
    seen.add(`facet:${id}`);
    out.push({ id, label: id.replace(/_/g, " "), param: "facet" });
  }
  return out;
}

/** The biggest array of plain objects in a view (it is the page); null when there is none. */
export function findRows(view: unknown, depth = 0): Array<Record<string, unknown>> | null {
  if (Array.isArray(view)) {
    return view.length > 0 && view.every((r) => r && typeof r === "object" && !Array.isArray(r)) ? (view as Array<Record<string, unknown>>) : null;
  }
  if (!view || typeof view !== "object" || depth > 3) return null;
  let best: Array<Record<string, unknown>> | null = null;
  for (const v of Object.values(view as Record<string, unknown>)) {
    const rows = findRows(v, depth + 1);
    if (rows && (!best || rows.length > best.length)) best = rows;
  }
  return best;
}

export function rowColumns(rows: ReadonlyArray<Record<string, unknown>>, declared?: readonly string[]): string[] {
  if (declared && declared.length) return declared.slice(0, 10);
  const cols: string[] = [];
  for (const r of rows.slice(0, 20)) for (const k of Object.keys(r)) if (!cols.includes(k)) cols.push(k);
  return cols.slice(0, 8);
}

/** A total the view reports for its collection, when it has one. */
export function findTotal(view: unknown): number | null {
  if (!view || typeof view !== "object") return null;
  for (const k of ["total", "totalCount", "count"]) {
    const v = (view as Record<string, unknown>)[k];
    if (typeof v === "number" && Number.isFinite(v)) return v;
  }
  for (const v of Object.values(view as Record<string, unknown>)) {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const t = findTotal(v);
      if (t != null) return t;
    }
  }
  return null;
}

/** JSON text of anything, bounded so a huge structure cannot freeze the page. */
export function boundedJson(v: unknown, max = 60_000): string {
  let s: string;
  try {
    s = JSON.stringify(v, null, 2) ?? "";
  } catch {
    s = "";
  }
  return s.length > max ? `${s.slice(0, max)}\n… (${(s.length - max).toLocaleString()} more characters not shown; use Export for everything)` : s;
}

const UPLOAD_DISPLAY_RE = /^upload (up-[0-9]{8}-[0-9]{6}-[a-z0-9]{6})(?:\/(.+))?$/;

/** Rebuild a target from a stored run's display string (for "Run again"). */
export function targetFromDisplay(t: { kind: "path" | "upload"; display: string } | null | undefined): ReaTarget | null {
  if (!t) return null;
  if (t.kind === "path") return unitPathProblem(t.display) ? null : { kind: "path", value: t.display };
  const m = UPLOAD_DISPLAY_RE.exec(t.display);
  if (!m) return null;
  return m[2] ? { kind: "upload", uploadId: m[1], relPath: m[2] } : { kind: "upload", uploadId: m[1] };
}

export function targetLabel(t: ReaTarget): string {
  return t.kind === "path" ? t.value : `upload ${t.uploadId}${t.relPath ? `/${t.relPath}` : ""}`;
}

export function isFinishedRun(r: ReaRun): boolean {
  return r.status === "completed";
}
