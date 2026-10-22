import crypto from "crypto";
import { StringDecoder } from "node:string_decoder";
import { ToolEvalManager } from "../tooleval/ToolEvalManager.js";
import {
  REA_VERSION,
  UPLOAD_ID_RE,
  REL_PATH_RE,
  exitToken,
  installPayload,
  runDirRef,
  buildAttachProgram,
  buildCheckProgram,
  buildCompareProgram,
  buildDeleteRunProgram,
  buildExportProgram,
  buildInstallProgram,
  buildReadResultProgram,
  buildRunProgram,
  buildStatusProgram,
  buildStopProgram,
  buildUploadCommitProgram,
  buildUploadCreateProgram,
  buildUploadDeleteProgram,
  buildUploadPutProgram,
  buildUploadSweepProgram,
  buildViewProgram,
} from "./commands.js";
import { ENGINES } from "./providers.js";
import { workflowById } from "./spec.js";
import { reaViewObject } from "./validate.js";
import { newUploadId } from "./ReaStore.js";
import { clip, compactSummary, summarizeResult } from "./summarize.js";

const RUN_WATCH_MAX_MS = 13 * 60 * 60 * 1000;
const MAX_LINE_CHARS = 8 * 1024;
const MAX_BUFFER_CHARS = 2 * 1024 * 1024;
const MAX_BUFFER_LINES = 5000;
const STOP_TIMEOUT_MS = 70_000;
const INSTALL_MAX_MS = 30 * 60 * 1000;
const STATUS_TIMEOUT_MS = 150_000;
const READ_TIMEOUT_MS = 120_000;
const VIEW_TIMEOUT_MS = 150_000;
const COMPARE_TIMEOUT_MS = 170_000;
const EXPORT_TIMEOUT_MS = 15 * 60 * 1000;
const VIEW_CAP = 4 * 1024 * 1024;
const COMPARE_CAP = 16 * 1024 * 1024;
const SECTION_SLACK = 64 * 1024;
const DEFAULT_MAX_INLINE = 8 * 1024 * 1024;
const DEFAULT_EXPORT_MAX = 256 * 1024 * 1024;
const DEFAULT_UPLOAD_MAX_BYTES = 1024 * 1024 * 1024;
const DEFAULT_UPLOAD_MAX_FILES = 5000;
const UPLOAD_IDLE_MS = 5 * 60 * 1000;
const UPLOAD_TTL_HOURS = 24;
const MAX_TRACKED_UPLOADS = 64;
const KILL_WAIT_MS = 6000;

const newNonce = () => crypto.randomBytes(9).toString("hex");
const sentinel = () => `__REA_${newNonce()}_`;
const b64 = (v) => Buffer.from(String(v), "utf8").toString("base64");
const posIntEnv = (name, def) => {
  const n = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isInteger(n) && n > 0 ? n : def;
};

/** Failures of upload operations carry a stable `code` and a plain `message` the route can show. */
export class ReaError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "ReaError";
    this.code = code;
  }
}

/** Exit codes the on-unit wrapper uses (and rea's own error code, when it printed one), as a sentence. */
export function explainExit(code, reaCode = null) {
  const tail = reaCode ? ` (rea: ${clip(reaCode, 60)})` : "";
  switch (code) {
    case 0:
      return null;
    case 2:
      return `The target was not usable on the unit${tail}.`;
    case 10:
      return `REA exited with an error${tail}; see the output.`;
    case 11:
      return "The result exceeded the size limit and was cut off.";
    case 124:
      return "The run hit its time limit.";
    case 126:
      return `An analysis engine or provider this workflow needs is missing${tail}.`;
    case 127:
      return "REA, node or setsid is not installed on the unit.";
    case 143:
      return "The run was stopped.";
    default:
      return code != null ? `The run ended with code ${code}${tail}.` : null;
  }
}

/** Sections of a short program's output: `<S>NAME` lines with their values, and an optional trailing BODY. */
export function parseSections(buf, S) {
  const marker = Buffer.from(`${S}BODY\n`, "utf8");
  let headBuf = buf;
  let body = null;
  let at = -1;
  if (buf.subarray(0, marker.length).equals(marker)) at = 0;
  else {
    const i = buf.indexOf(Buffer.concat([Buffer.from("\n"), marker]));
    if (i >= 0) at = i + 1;
  }
  if (at >= 0) {
    headBuf = buf.subarray(0, at);
    body = buf.subarray(at + marker.length);
  }
  const head = {};
  let name = null;
  for (const line of headBuf.toString("utf8").split("\n")) {
    if (line.startsWith(S)) {
      name = line.slice(S.length);
      head[name] = [];
    } else if (name) head[name].push(line);
  }
  for (const k of Object.keys(head)) head[k] = head[k].join("\n").replace(/\n+$/, "");
  return { head, body };
}

/** Stable JSON text of a value (sorted keys), for cache keys. */
export function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v) ?? "null";
}

const kvOf = (text) => {
  const kv = {};
  for (const line of String(text).split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) kv[line.slice(0, i)] = line.slice(i + 1).trim();
  }
  return kv;
};

function decodeJson(b64text) {
  if (!b64text) return null;
  try {
    return JSON.parse(Buffer.from(b64text, "base64").toString("utf8"));
  } catch {
    return null;
  }
}

/** A rea error object ({code,message,...}) in parsed JSON, as {code,message}, or null. */
function reaErrorOf(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || "normalized_result" in value) return null;
  const code = typeof value.code === "string" ? value.code : typeof value.error === "string" ? value.error : null;
  if (!code) return null;
  return { code: clip(code, 80), message: clip(typeof value.message === "string" ? value.message : "", 300) };
}

/**
 * Runs REA workflows on a unit and keeps the dashboard's view of them. Built on the Tool Eval
 * manager's process plumbing (one live job per unit, detached on-unit run, re-attach), with REA's
 * own programs, result capture, views and uploads on top. The tool-eval JSONL logic never runs.
 */
export class ReaManager extends ToolEvalManager {
  constructor(opts = {}) {
    super(opts);
    this.maxInline = Number.isInteger(opts.maxInline) && opts.maxInline > 0 ? opts.maxInline : DEFAULT_MAX_INLINE;
    this.exportMaxBytes = Number.isInteger(opts.exportMaxBytes) && opts.exportMaxBytes > 0 ? opts.exportMaxBytes : posIntEnv("REA_EXPORT_MAX_BYTES", DEFAULT_EXPORT_MAX);
    this.uploadMaxBytes = Number.isInteger(opts.uploadMaxBytes) && opts.uploadMaxBytes > 0 ? opts.uploadMaxBytes : posIntEnv("REA_UPLOAD_MAX_BYTES", DEFAULT_UPLOAD_MAX_BYTES);
    this.uploadMaxFiles = Number.isInteger(opts.uploadMaxFiles) && opts.uploadMaxFiles > 0 ? opts.uploadMaxFiles : posIntEnv("REA_UPLOAD_MAX_FILES", DEFAULT_UPLOAD_MAX_FILES);
    this.viewMaxBytes = Number.isInteger(opts.viewMaxBytes) && opts.viewMaxBytes > 0 ? opts.viewMaxBytes : VIEW_CAP;
    this.uploadIdleMs = Number.isInteger(opts.uploadIdleMs) && opts.uploadIdleMs > 0 ? opts.uploadIdleMs : UPLOAD_IDLE_MS;
    /** @type {Map<string, Map<string, object>>} sparkId -> uploadId -> record (in memory: unit-bound) */
    this.uploads = new Map();
  }

  // ── not applicable (Tool Eval's own) ─────────────────────────────────────────────────────

  install() {
    return { ok: false, reason: "unsupported" };
  }
  startRun() {
    return { ok: false, reason: "unsupported" };
  }
  checkUpdate() {
    return Promise.resolve({ installed: false, error: null });
  }
  once() {
    return Promise.resolve({ ok: false, code: null, output: "", error: "unsupported" });
  }

  summary(job) {
    const base = super.summary(job);
    // Exit 143 is the wrapper's "stopped on request", whether or not this process saw the request.
    const status = base.status === "failed" && base.exitCode === 143 ? "stopped" : base.status;
    return { ...base, status, stage: job.progress?.stage ?? null, phase: job.progress?.phase ?? null, message: job.progress?.message ?? null };
  }

  _newJob(spark, opts) {
    const job = super._newJob(spark, opts);
    job.progress = { stage: "starting", phase: null, message: null };
    job.reaError = null;
    return job;
  }

  /** One line of output: the exit marker, the wrapper's `stage:` lines and rea's progress events are ours. */
  _line(job, line) {
    const token = exitToken(job.nonce);
    const at = line.lastIndexOf(token);
    if (at >= 0) {
      const n = Number.parseInt(line.slice(at + token.length), 10);
      job.markerExit = Number.isFinite(n) ? n : -1;
      line = line.slice(0, at);
      if (!line) return;
    }
    const stage = /^\[sparkdash\] stage: (.{1,200})$/.exec(line);
    if (stage) job.progress = { ...job.progress, stage: stage[1].startsWith("rea ") ? "running" : clip(stage[1], 40) };
    const reported = /^\[sparkdash\] rea reported: ([A-Za-z0-9_.-]{1,80})$/.exec(line);
    if (reported) job.reaError = reported[1];
    let text = line;
    if (line.startsWith('{"rea_progress":')) {
      try {
        const p = JSON.parse(line).rea_progress;
        if (p && typeof p === "object") {
          const msg = clip(p.message ?? p.phase ?? "", 200);
          job.progress = { ...job.progress, phase: clip(p.phase ?? "", 80) || null, message: msg || null };
          text = `[rea] ${msg}${Number.isFinite(p.total) && p.total > 1 ? ` (${Number(p.completed) || 0}/${p.total})` : ""}`;
        }
      } catch {
        /* a raw line */
      }
    }
    if (text.length > MAX_LINE_CHARS) text = `${text.slice(0, MAX_LINE_CHARS)} … [line truncated]`;
    job.lseq += 1;
    job.lines.push({ seq: job.lseq, text, stream: "out" });
    job.bufChars = (job.bufChars ?? 0) + text.length;
    while (job.lines.length > MAX_BUFFER_LINES || (job.bufChars > MAX_BUFFER_CHARS && job.lines.length > 1)) {
      job.bufChars -= job.lines.shift().text.length;
    }
  }

  // ── plumbing ─────────────────────────────────────────────────────────────────────────────

  /**
   * Run a short program and collect its stdout as bytes (stderr ignored). Bounded by time and size:
   * past `maxBytes` the process group is ended and `overflow` is set. Never leaves a child behind.
   */
  _runBuf(spark, cmd, { stdin = null, timeoutMs = READ_TIMEOUT_MS, maxBytes = DEFAULT_MAX_INLINE + SECTION_SLACK } = {}) {
    return new Promise((resolve) => {
      let child;
      try {
        child = this.spawnProcess(spark, cmd, { stdin: stdin != null });
      } catch (err) {
        resolve({ ok: false, code: null, buf: Buffer.alloc(0), overflow: false, timedOut: false, error: err instanceof Error ? err.message : String(err) });
        return;
      }
      const chunks = [];
      let size = 0;
      let overflow = false;
      let timedOut = false;
      let done = false;
      child.stdout?.on("data", (b) => {
        if (overflow) return;
        size += b.length;
        if (size > maxBytes) {
          overflow = true;
          chunks.length = 0;
          this._killGroup(child);
          return;
        }
        chunks.push(b);
      });
      child.stderr?.on("data", () => {});
      const finish = (code, error) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        resolve({
          ok: !timedOut && !overflow && !error && code === 0,
          code,
          buf: Buffer.concat(chunks),
          overflow,
          timedOut,
          error: error ?? (overflow ? "The output was too large to read" : timedOut ? "The unit did not answer in time" : null),
        });
      };
      const timer = setTimeout(() => {
        timedOut = true;
        this._killGroup(child);
      }, timeoutMs);
      timer.unref?.();
      child.on("error", (err) => finish(null, err.message));
      child.on("close", (code) => finish(code, null));
      if (stdin != null && child.stdin) {
        child.stdin.on("error", () => {});
        child.stdin.end(stdin);
      }
    });
  }

  // ── status ───────────────────────────────────────────────────────────────────────────────

  async _status(spark) {
    const res = await this.runOnce(spark, buildStatusProgram(), { timeoutMs: STATUS_TIMEOUT_MS, stdoutOnly: true });
    const out = res.output;
    const kv = kvOf(out);
    const reachable = res.ok || kv.NODE !== undefined || kv.NODE_OK !== undefined;
    const version = /^[0-9A-Za-z.+-]{1,40}$/.test(kv.INSTALLED_VERSION ?? "") ? kv.INSTALLED_VERSION : null;
    const doctor = decodeJson(kv.DOCTOR_B64);
    const providers = decodeJson(kv.PROVIDERS_B64);

    let doctorOut = null;
    if (doctor && typeof doctor === "object" && !Array.isArray(doctor)) {
      const checks = (Array.isArray(doctor.scope_checks) ? doctor.scope_checks : Array.isArray(doctor.checks) ? doctor.checks : []).slice(0, 100).map((c) => ({
        name: clip(c?.name, 80),
        ok: c?.ok === true,
        classification: clip(c?.classification, 80),
        ...(c?.detail ? { detail: clip(c.detail) } : {}),
        ...(c?.remediation ? { remediation: clip(c.remediation) } : {}),
      }));
      doctorOut = { healthy: doctor.healthy === true, environmentHealthy: doctor.environment_healthy === true, checks };
    }
    const providerList = [];
    if (providers && typeof providers === "object" && Array.isArray(providers.capabilities)) {
      for (const c of providers.capabilities.slice(0, 200)) {
        if (!c || typeof c.operation !== "string") continue;
        providerList.push({
          id: clip(c.operation, 80),
          label: clip(c.operation.replace(/[_-]+/g, " "), 80),
          available: c.available === true,
          ...(c.reason ? { reason: clip(c.reason) } : {}),
          ...(c.availability_code ? { code: clip(c.availability_code, 60) } : {}),
        });
      }
    }
    const engines = [];
    for (const e of ENGINES) {
      const key = `ENGINE_${e.id}`;
      if (kv[key] === undefined && !out.includes(`${key}=`)) continue;
      const p = kv[key] ?? "";
      engines.push({ id: e.id, label: e.label, found: p !== "", ...(p ? { path: clip(p, 300) } : {}), unlocks: e.unlocks });
    }
    return {
      reachable,
      node: { path: kv.NODE || null, version: kv.NODE_VERSION || null, ok: kv.NODE_OK === "1" },
      npm: Boolean(kv.NPM),
      installed: Boolean(kv.LAUNCHER),
      version,
      pinnedVersion: REA_VERSION,
      upToDate: version === REA_VERSION,
      launcher: kv.LAUNCHER || null,
      doctor: doctorOut,
      providers: providerList,
      engines,
      error: res.error,
    };
  }

  // ── install ──────────────────────────────────────────────────────────────────────────────

  /**
   * Install the pinned rea-agents on the unit (payload on stdin), streamed like any job.
   * @returns {{ ok: true, job: object } | { ok: false, reason: "busy", active: object }}
   */
  installRea(spark) {
    const free = this.canStart(spark);
    if (!free.ok) return free;
    const busy = this.activeJob(spark.id);
    if (busy) this._detach(busy, spark);
    const job = this._newJob(spark, { id: `install-${crypto.randomBytes(3).toString("hex")}`, kind: "install", type: "rea" });
    let payload;
    try {
      payload = installPayload();
    } catch (err) {
      this.jobs.set(spark.id, job);
      this._finish(job, spark, { error: `The install payload could not be read: ${err instanceof Error ? err.message : String(err)}` });
      return { ok: true, job };
    }
    this._startJob(spark, job, buildInstallProgram({ nonce: job.nonce }), { stdin: payload, maxMs: INSTALL_MAX_MS });
    return { ok: true, job };
  }

  // ── runs ─────────────────────────────────────────────────────────────────────────────────

  /**
   * Could a run start on this unit right now? Checked by the route BEFORE the run is stored, so a
   * refused request never evicts history.
   * @returns {{ ok: true } | { ok: false, reason: "busy", active: object }}
   */
  canStart(spark) {
    const busy = this.activeJob(spark.id);
    if (busy && busy.kind !== "attach") return { ok: false, reason: "busy", active: this.summary(busy) };
    // A run whose watcher ended (detached, cancelled) may still be running on the unit.
    const orphan = this.store.list({ sparkId: spark.id }).find((r) => r.status === "running");
    if (orphan) return { ok: false, reason: "busy", active: { id: orphan.id, sparkId: spark.id, kind: "run", status: "running" } };
    return { ok: true };
  }

  /**
   * Start a run (detached on the unit) and follow it. The record was stored by the caller before this
   * call, so it is excluded from the orphan check.
   * @param {{ run: object, argv: string[], paths?: string[], timeoutSeconds: number, resultCapBytes?: number }} req
   * @returns {{ ok: true, job: object } | { ok: false, reason: "busy", active: object }}
   */
  startReaRun(spark, { run, argv, paths = [], timeoutSeconds, resultCapBytes }) {
    const busy = this.activeJob(spark.id);
    if (busy && busy.kind !== "attach") return { ok: false, reason: "busy", active: this.summary(busy) };
    const orphan = this.store.list({ sparkId: spark.id }).find((r) => r.status === "running" && r.id !== run.id);
    if (orphan) return { ok: false, reason: "busy", active: { id: orphan.id, sparkId: spark.id, kind: "run", status: "running" } };
    const nulB64 = (list) => (list.length ? Buffer.from(`${list.join("\0")}\0`, "utf8").toString("base64") : "");
    const job = this._newJob(spark, { id: run.id, kind: "run", type: "rea" });
    let cmd;
    try {
      cmd = buildRunProgram({
      runId: run.id,
      argvB64: nulB64(argv),
      pathsB64: nulB64(paths),
      displayLine: run.command ?? `rea ${argv[0] ?? ""}`,
      timeoutSeconds,
      ...(resultCapBytes ? { resultCapBytes } : {}),
      nonce: job.nonce,
      });
    } catch (err) {
      return { ok: false, reason: "invalid", error: err instanceof Error ? err.message : String(err) };
    }
    if (busy) this._detach(busy, spark);
    this._startJob(spark, job, cmd, { maxMs: RUN_WATCH_MAX_MS });
    this.onEvent({
      type: "rea.run.started",
      severity: "info",
      sparkId: spark.id,
      message: `REA ${run.workflowLabel ?? "run"} started${run.label ? ` (${run.label})` : ""}`,
    });
    return { ok: true, job };
  }

  /** Re-open the output of a run that was started earlier. */
  attachRun(spark, run) {
    const busy = this.activeJob(spark.id);
    if (busy) {
      if (busy.id === run.id) return { ok: true, job: busy };
      if (busy.kind === "run" || busy.kind === "install") return { ok: false, reason: "busy", active: this.summary(busy) };
      this._detach(busy, spark);
    }
    const job = this._newJob(spark, { id: run.id, kind: "attach", type: "rea" });
    this._startJob(spark, job, buildAttachProgram({ runId: run.id, nonce: job.nonce }), { maxMs: RUN_WATCH_MAX_MS });
    return { ok: true, job };
  }

  /**
   * Ask the run to stop (TERM, then KILL after the wrapper's grace) via the unit, regardless of who
   * is watching. `stopRequested` is set first because the job can end before this call returns; it is
   * taken back when the stop did not happen, so a later natural failure is not shown as "stopped".
   */
  async stopRun(spark, runId, { timeoutMs = STOP_TIMEOUT_MS } = {}) {
    const live = this.jobs.get(spark.id);
    const mine = live && live.id === runId ? live : null;
    if (mine) mine.stopRequested = true;
    const res = await this.runOnce(spark, buildStopProgram({ runId }), { timeoutMs, stdoutOnly: true });
    const stopped = res.ok && /\b(stopped|killed)\b/.test(res.output);
    if (mine && !stopped && mine.status === "running") mine.stopRequested = false;
    return { ok: res.ok && stopped, output: res.output };
  }

  async _afterJob(job, spark) {
    if (job.kind === "install") {
      if (job.status === "cancelled" || job.status === "detached") return;
      const ok = job.status === "completed";
      this.onEvent({
        type: `rea.install.${ok ? "completed" : "failed"}`,
        severity: ok ? "success" : "error",
        sparkId: job.sparkId,
        message: ok ? `REA ${REA_VERSION} installed` : "REA install failed",
      });
      return;
    }
    const run = this.store.get(job.id);
    if (!run) return;
    // Nothing is known yet: the run may still be going (watcher closed, connection lost, dashboard
    // shutting down). The record and Activity stay as they are; checkRun() settles it later.
    if (job.status === "detached" || job.status === "cancelled") return;
    // Re-opening the output of a run that was already settled must not settle it a second time.
    if (job.kind === "attach" && ["completed", "failed", "stopped", "gone"].includes(run.status)) return;
    const code = job.exitCode;
    const finalStatus =
      job.status === "stopped" || code === 143
        ? "stopped"
        : code === 0
          ? "completed"
          : code == null && job.status !== "failed"
            ? run.status
            : "failed";
    this.store.update(job.id, {
      status: finalStatus,
      exitCode: code,
      finishedAt: job.finishedAt ?? this.now(),
      note: code != null ? explainExit(code, job.reaError) : (job.error ?? null),
    });
    await this.captureResult(spark, job.id);
    const fresh = this.store.get(job.id);
    if (fresh && finalStatus === "failed" && code != null && !job.reaError) {
      // The error object rea printed names the cause when the wrapper line was not in the buffer.
      const f = fresh.summary?.findings?.find((x) => x?.code);
      if (f) this.store.update(job.id, { note: explainExit(code, f.code) });
    }
    if (fresh && finalStatus === "completed" && !fresh.resultCached) {
      this.store.update(job.id, { note: "The run finished but no result could be read from the unit." });
    }
    const label = run.workflowLabel ?? "REA run";
    this.onEvent({
      type: `rea.run.${finalStatus}`,
      severity: finalStatus === "completed" ? "success" : finalStatus === "stopped" ? "info" : "error",
      sparkId: job.sparkId,
      message:
        finalStatus === "completed"
          ? `REA ${label} finished`
          : finalStatus === "stopped"
            ? `REA ${label} stopped`
            : `REA ${label} failed${code != null ? ` (exit ${code})` : ""}`,
    });
  }

  /** Settle a run whose watcher was lost: is it still alive, or how did it end? */
  async checkRun(spark, runId) {
    const res = await this.runOnce(spark, buildCheckProgram({ runId }), { timeoutMs: 40_000, stdoutOnly: true });
    const out = res.output.trim().split("\n").pop() ?? "";
    if (out === "ALIVE") return { state: "running" };
    if (out === "GONE") {
      this.store.update(runId, { status: "gone", finishedAt: this.now() });
      return { state: "gone" };
    }
    const m = /^EXIT=(-?\d+)$/.exec(out);
    if (!m) return { state: "unknown" };
    const code = Number.parseInt(m[1], 10);
    const run = this.store.get(runId);
    if (run && run.status === "running") {
      // No exit file (code -1) means the wrapper never got to write one: the unit restarted or the
      // process was killed. That is a failure with an explanation, not a stop.
      this.store.update(runId, {
        status: code === 0 ? "completed" : code === 143 ? "stopped" : "failed",
        exitCode: code >= 0 ? code : null,
        finishedAt: this.now(),
        note: code >= 0 ? explainExit(code) : "The run ended without reporting a result (the unit may have restarted, or the process was killed).",
      });
      await this.captureResult(spark, runId);
    }
    return { state: "finished", exitCode: code };
  }

  async removeRemote(spark, runId) {
    if (spark) await this.runOnce(spark, buildDeleteRunProgram({ runId }), { timeoutMs: 40_000, stdoutOnly: true }).catch(() => {});
  }

  // ── results ──────────────────────────────────────────────────────────────────────────────

  /**
   * Pull the result from the unit, summarize it, cache the bundle and keep the headline numbers.
   * A result larger than `maxInline` stays on the unit: only a summary projection (viewable workflows)
   * or its size and hash are used, and `summary.truncated` says so.
   * @returns {Promise<{ ok: boolean, reason?: string }>}
   */
  captureResult(spark, runId) {
    return this._once(`result:${spark.id}:${runId}`, () => this._captureResult(spark, runId));
  }

  async _captureResult(spark, runId) {
    const run = this.store.get(runId);
    if (!run) return { ok: false, reason: "deleted" };
    const wf = workflowById(run.workflowId);
    const S = sentinel();
    const res = await this._runBuf(spark, buildReadResultProgram({ runId, sentinel: S, maxBytes: this.maxInline }), {
      timeoutMs: READ_TIMEOUT_MS,
      maxBytes: this.maxInline + SECTION_SLACK,
    });
    if (res.overflow) return { ok: false, reason: "too-big" };
    if (res.error || res.code !== 0) return { ok: false, reason: "unreachable", error: res.error };
    const { head, body } = parseSections(res.buf, S);
    if (head.NORESULT !== undefined || head.SIZE === undefined) return { ok: false, reason: "no-result" };
    const size = Number.parseInt(head.SIZE, 10);
    const sha = /^[0-9a-f]{64}$/i.test(head.SHA256 ?? "") ? head.SHA256.toLowerCase() : null;
    if (!Number.isFinite(size) || size <= 0) return { ok: false, reason: "no-result" };
    const cutOff = run.exitCode === 11;

    let summary;
    let text = null;
    if (body) {
      text = body.toString("utf8");
      summary = summarizeResult(wf, text, { size, ...(sha ? { sha256: sha } : {}), truncated: cutOff, note: cutOff ? "The result exceeded the size limit and was cut off." : undefined });
    } else {
      // Too big to pull: the bytes stay on the unit.
      let viaView = null;
      if (wf?.viewable && !cutOff) {
        const v = await this._viewRaw(spark, run, reaViewObject({ kind: "summary" }));
        if (v.ok) viaView = v.view;
      }
      const note = cutOff
        ? "The result exceeded the size limit and was cut off; it stays on the unit."
        : viaView
          ? "The result is large and stays on the unit; this summary comes from its summary view."
          : "The result is large and stays on the unit; only its size and hash are shown.";
      summary = summarizeResult(viaView ? wf : null, viaView ?? "", { size, ...(sha ? { sha256: sha } : {}), truncated: true, note });
      if (!viaView) summary.limitations = summary.limitations.filter((l) => l !== "The run printed no result.");
    }
    // The run may have been deleted while the file was being read: do not resurrect its cache.
    if (!this.store.get(runId)) return { ok: false, reason: "deleted" };
    const bundle = { version: 1, runId, workflowId: run.workflowId ?? null, capturedAt: this.now(), size, sha256: sha, onUnit: text === null, summary, result: text };
    if (!this.store.saveBundle(runId, bundle)) return { ok: false, reason: "deleted" };
    this.store.update(runId, { resultCached: true, resultBytes: size, ...(sha ? { resultSha256: sha } : {}), summary: compactSummary(summary) });
    return { ok: true };
  }

  /** The cached bundle of a run: { summary, result (text or null when it stays on the unit), size, sha256 }. */
  loadResult(runId) {
    const b = this.store.loadBundle(runId);
    if (!b || typeof b !== "object") return null;
    return { summary: b.summary ?? null, result: typeof b.result === "string" ? b.result : null, size: b.size ?? null, sha256: b.sha256 ?? null, onUnit: b.onUnit === true };
  }

  _capText(bytes) {
    return bytes >= 1024 * 1024 ? `${Math.round((bytes / (1024 * 1024)) * 10) / 10} MiB` : `${Math.round(bytes / 1024)} KiB`;
  }

  /** `rea inspect-analysis-view` on the unit for this run's result. Never partial JSON. */
  async _viewRaw(spark, run, viewObject) {
    let viewB64;
    try {
      const json = JSON.stringify({ source: { kind: "file", path: `${runDirRef(run.id)}/result.json` }, view: viewObject });
      viewB64 = Buffer.from(json, "utf8").toString("base64");
    } catch {
      return { ok: false, error: "The view request could not be encoded." };
    }
    const S = sentinel();
    let cmd;
    try {
      cmd = buildViewProgram({ runId: run.id, viewB64, sentinel: S, maxBytes: this.viewMaxBytes });
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "The view request is not valid." };
    }
    const res = await this._runBuf(spark, cmd, { timeoutMs: VIEW_TIMEOUT_MS, maxBytes: this.viewMaxBytes + SECTION_SLACK });
    if (res.overflow) return { ok: false, error: `The view is larger than ${this._capText(this.viewMaxBytes)}; ask for a smaller page.` };
    if (res.error || res.code !== 0) return { ok: false, error: res.error || "The unit did not answer." };
    const { head, body } = parseSections(res.buf, S);
    if (head.NORESULT !== undefined) return { ok: false, error: "The result is no longer on the unit." };
    if (head.TOOBIG !== undefined) return { ok: false, error: `The view is larger than ${this._capText(this.viewMaxBytes)}; ask for a smaller page.` };
    const status = Number.parseInt(head.STATUS ?? "", 10);
    let parsed = null;
    let parseOk = false;
    if (body) {
      try {
        parsed = JSON.parse(body.toString("utf8"));
        parseOk = true;
      } catch {
        parseOk = false;
      }
    }
    const reaErr = parseOk ? reaErrorOf(parsed) : null;
    if (reaErr) return { ok: false, error: `REA reported an error (${reaErr.code}): ${reaErr.message}`.trim() };
    switch (status) {
      case 0:
        break;
      case 127:
        return { ok: false, error: "REA or node is not installed on the unit." };
      case 124:
        return { ok: false, error: "The view timed out after 120 seconds." };
      case 11:
        return { ok: false, error: `The view is larger than ${this._capText(this.viewMaxBytes)}; ask for a smaller page.` };
      case 2:
        return { ok: false, error: "The view request was not valid." };
      case 3:
        return { ok: false, error: "The view does not refer to this run's result." };
      default:
        return { ok: false, error: `REA exited with code ${Number.isFinite(status) ? status : "unknown"}.` };
    }
    if (!parseOk) return { ok: false, error: "REA did not print valid JSON for this view." };
    return { ok: true, view: parsed };
  }

  /**
   * A bounded view of a finished run's result, cached by (run, view). `viewObject` is what
   * `reaViewObject(validateViewRequest(...).view)` produced.
   * @returns {Promise<{ ok: true, view: any, cached: boolean } | { ok: false, error: string }>}
   */
  async readView(spark, run, viewObject) {
    if (!run || typeof run.id !== "string") return { ok: false, error: "Unknown run." };
    if (run.status === "running") return { ok: false, error: "The run is still going." };
    if (!viewObject || typeof viewObject !== "object") return { ok: false, error: "The view request is not valid." };
    const hash = crypto.createHash("sha256").update(`${run.id}\n${canonicalJson(viewObject)}`).digest("hex");
    const hit = this.store.loadView(run.id, hash);
    if (hit !== null) return { ok: true, view: hit, cached: true };
    return this._once(`view:${spark.id}:${run.id}:${hash}`, async () => {
      const res = await this._viewRaw(spark, run, viewObject);
      if (!res.ok) return res;
      if (this.store.get(run.id)) this.store.saveView(run.id, hash, res.view);
      return { ok: true, view: res.view, cached: false };
    });
  }

  /**
   * The result file as bytes for download (from the local cache when it holds the body, else from the unit).
   * @returns {Promise<{ ok: true, text: Buffer, bytes: number } | { ok: false, error: string }>}
   */
  async exportResult(spark, run) {
    if (!run || typeof run.id !== "string") return { ok: false, error: "Unknown run." };
    if (run.status === "running") return { ok: false, error: "The run is still going." };
    const cached = this.loadResult(run.id);
    if (cached && typeof cached.result === "string") {
      const text = Buffer.from(cached.result, "utf8");
      if (text.length > this.exportMaxBytes) return { ok: false, error: `The result is larger than the export limit (${this.exportMaxBytes} bytes).` };
      return { ok: true, text, bytes: text.length };
    }
    const S = sentinel();
    let cmd;
    try {
      cmd = buildExportProgram({ runId: run.id, sentinel: S, maxBytes: this.exportMaxBytes });
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "The export could not be requested." };
    }
    const res = await this._runBuf(spark, cmd, { timeoutMs: EXPORT_TIMEOUT_MS, maxBytes: this.exportMaxBytes + SECTION_SLACK });
    if (res.overflow) return { ok: false, error: `The result is larger than the export limit (${this.exportMaxBytes} bytes).` };
    if (res.error || res.code !== 0) return { ok: false, error: res.error || "The unit did not answer." };
    const { head, body } = parseSections(res.buf, S);
    if (head.NORESULT !== undefined) return { ok: false, error: "The result is no longer on the unit." };
    if (head.TOOBIG !== undefined) return { ok: false, error: `The result is larger than the export limit (${this.exportMaxBytes} bytes).` };
    const size = Number.parseInt(head.SIZE ?? "", 10);
    if (!body || !Number.isFinite(size) || body.length !== size) return { ok: false, error: "The result changed while it was being read." };
    return { ok: true, text: body, bytes: body.length };
  }

  /**
   * `rea compare` of two finished runs of this unit.
   * @returns {Promise<{ ok: true, result: any } | { ok: false, error: string }>}
   */
  async compareRuns(spark, left, right) {
    if (!left || !right || typeof left.id !== "string" || typeof right.id !== "string") return { ok: false, error: "Unknown run." };
    if (left.id === right.id) return { ok: false, error: "Choose two different runs." };
    if (left.sparkId !== spark.id || right.sparkId !== spark.id) return { ok: false, error: "Both runs must belong to this unit." };
    for (const r of [left, right]) {
      if (r.status !== "completed") return { ok: false, error: "Both runs must have finished successfully." };
    }
    const S = sentinel();
    let cmd;
    try {
      cmd = buildCompareProgram({ leftRunId: left.id, rightRunId: right.id, sentinel: S, maxBytes: COMPARE_CAP });
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : "The comparison could not be requested." };
    }
    const res = await this._runBuf(spark, cmd, { timeoutMs: COMPARE_TIMEOUT_MS, maxBytes: COMPARE_CAP + SECTION_SLACK });
    if (res.overflow) return { ok: false, error: "The comparison is too large to return." };
    if (res.error || res.code !== 0) return { ok: false, error: res.error || "The unit did not answer." };
    const { head, body } = parseSections(res.buf, S);
    if (head.NORESULT !== undefined) return { ok: false, error: "A result is no longer on the unit." };
    if (head.TOOBIG !== undefined) return { ok: false, error: "The comparison is too large to return." };
    const status = Number.parseInt(head.STATUS ?? "", 10);
    let parsed = null;
    let parseOk = false;
    if (body) {
      try {
        parsed = JSON.parse(body.toString("utf8"));
        parseOk = true;
      } catch {
        parseOk = false;
      }
    }
    const reaErr = parseOk ? reaErrorOf(parsed) : null;
    if (reaErr) return { ok: false, error: `REA reported an error (${reaErr.code}): ${reaErr.message}`.trim() };
    if (status === 127) return { ok: false, error: "REA or node is not installed on the unit." };
    if (status === 124) return { ok: false, error: "The comparison timed out after 120 seconds." };
    if (status !== 0) return { ok: false, error: `REA exited with code ${Number.isFinite(status) ? status : "unknown"}.` };
    if (!parseOk) return { ok: false, error: "REA did not print valid JSON for the comparison." };
    return { ok: true, result: parsed };
  }

  // ── uploads ──────────────────────────────────────────────────────────────────────────────

  _uploadMap(sparkId) {
    let m = this.uploads.get(sparkId);
    if (!m) {
      m = new Map();
      this.uploads.set(sparkId, m);
    }
    return m;
  }

  _upload(sparkId, uploadId) {
    const up = typeof uploadId === "string" && UPLOAD_ID_RE.test(uploadId) ? this.uploads.get(sparkId)?.get(uploadId) : null;
    if (!up) throw new ReaError("unknown-upload", "That upload does not exist on this unit (it may have expired).");
    return up;
  }

  /** Allocate an upload on the unit. @returns {Promise<{ uploadId: string, maxBytes: number, maxFiles: number }>} */
  async createUpload(spark) {
    const map = this._uploadMap(spark.id);
    if (map.size >= MAX_TRACKED_UPLOADS) {
      // Forget the oldest upload that has no open writer (and remove it on the unit, best effort).
      const old = [...map.values()].filter((u) => u.writers.size === 0).sort((a, b) => a.createdAt - b.createdAt)[0];
      if (!old) throw new ReaError("too-many-uploads", "Too many uploads are in progress on this unit.");
      map.delete(old.id);
      void this.runOnce(spark, buildUploadDeleteProgram({ uploadId: old.id }), { timeoutMs: 40_000, stdoutOnly: true }).catch(() => {});
    }
    for (let attempt = 0; attempt < 4; attempt += 1) {
      const id = newUploadId(this.now());
      const res = await this.runOnce(spark, buildUploadCreateProgram({ uploadId: id }), { timeoutMs: 40_000, stdoutOnly: true });
      const kv = kvOf(res.output);
      if (kv.ERROR === "exists") continue;
      if (!res.ok || kv.UPLOAD !== id) {
        throw new ReaError("unit-error", res.error || (kv.ERROR ? `The unit could not create the upload (${clip(kv.ERROR, 40)}).` : "The unit could not create the upload."));
      }
      map.set(id, { id, sparkId: spark.id, createdAt: this.now(), committed: false, root: null, files: new Map(), writers: new Set(), result: null });
      return { uploadId: id, maxBytes: this.uploadMaxBytes, maxFiles: this.uploadMaxFiles };
    }
    throw new ReaError("unit-error", "The unit could not allocate an upload id.");
  }

  /**
   * Stream one file into an upload. The bytes are counted here as well as on the unit; past the cap or
   * on a disconnect the child is ended and its `.part` removed. Nothing is left open on any path.
   * @param {import("stream").Readable} readable
   * @returns {Promise<{ bytes: number, sha256: string }>}
   */
  putUpload(spark, uploadId, relPath, readable, { maxBytes, archive = false, idleMs } = {}) {
    return new Promise((resolve, reject) => {
      let up;
      try {
        up = this._upload(spark.id, uploadId);
      } catch (err) {
        reject(err);
        return;
      }
      if (up.committed) {
        reject(new ReaError("committed", "This upload is already committed."));
        return;
      }
      if (typeof relPath !== "string" || !REL_PATH_RE.test(relPath)) {
        reject(new ReaError("invalid-path", "That upload path is not valid."));
        return;
      }
      let others = 0;
      for (const [p, n] of up.files) if (p !== relPath) others += n;
      if (!up.files.has(relPath) && up.files.size + [...up.writers].filter((w) => w.rel !== relPath).length >= this.uploadMaxFiles) {
        reject(new ReaError("too-many-files", `An upload may hold at most ${this.uploadMaxFiles} files.`));
        return;
      }
      const perFile = Number.isInteger(maxBytes) && maxBytes > 0 ? Math.min(maxBytes, this.uploadMaxBytes) : this.uploadMaxBytes;
      const cap = Math.min(perFile, this.uploadMaxBytes - others);
      if (cap < 1) {
        reject(new ReaError("too-big", "The upload already holds as many bytes as it may."));
        return;
      }
      let cmd;
      try {
        cmd = buildUploadPutProgram({ uploadId, relPath, maxBytes: cap, archive });
      } catch (err) {
        reject(new ReaError("invalid-path", err instanceof Error ? err.message : "That upload path is not valid."));
        return;
      }
      let child;
      try {
        child = this.spawnProcess(spark, cmd, { stdin: true });
      } catch (err) {
        reject(new ReaError("unit-error", err instanceof Error ? err.message : String(err)));
        return;
      }
      const writer = { rel: relPath, abort: null };
      up.writers.add(writer);

      const stdin = child.stdin;
      const outDec = new StringDecoder("utf8");
      let out = "";
      let count = 0;
      let ended = false;
      let settled = false;
      let abortErr = null;
      let closed = false;
      let idle = null;
      const idleLimit = Number.isInteger(idleMs) && idleMs > 0 ? idleMs : this.uploadIdleMs;

      child.stdout?.on("data", (b) => {
        if (out.length < 16 * 1024) out += outDec.write(b);
      });
      child.stderr?.on("data", () => {});
      stdin?.on("error", () => {});

      const detach = () => {
        clearTimeout(idle);
        readable.removeListener("data", onData);
        readable.removeListener("end", onEnd);
        readable.removeListener("error", onReadableError);
        readable.removeListener("close", onClose);
      };
      const settle = (fn, value) => {
        if (settled) return;
        settled = true;
        detach();
        up.writers.delete(writer);
        fn(value);
      };
      const cleanup = async () => {
        const prog = `
UD="$HOME/.cache/sparkdash/rea/uploads/${uploadId}"
REL=$(printf %s '${b64(relPath)}' | base64 -d)
[ -d "$UD" ] && [ ! -L "$UD" ] || exit 0
rm -f -- "$UD/$REL.part"
find "$UD" -type f -name '*.part' 2>/dev/null | grep -q . || rm -f "$UD/.writing"
echo ok`;
        const cmd2 = `bash -c "$(printf %s '${b64(prog)}' | base64 -d)"`;
        await this.runOnce(spark, cmd2, { timeoutMs: 30_000, stdoutOnly: true }).catch(() => {});
      };
      const abort = (err) => {
        if (abortErr || settled) return;
        abortErr = err;
        detach();
        try {
          readable.pause?.();
        } catch {
          /* gone */
        }
        try {
          stdin?.destroy();
        } catch {
          /* gone */
        }
        if (closed) return;
        this._killGroup(child);
        // A child that ignores TERM is ended by _killGroup's KILL; do not wait forever for it.
        const t = setTimeout(() => finish(null), KILL_WAIT_MS);
        t.unref?.();
      };
      writer.abort = abort;

      const fail = async (err) => {
        await cleanup();
        settle(reject, err);
      };
      const finish = (code) => {
        if (closed) return;
        closed = true;
        stdin?.destroy?.();
        if (abortErr) {
          void fail(abortErr);
          return;
        }
        const kv = kvOf(out + outDec.end());
        if (code === 0 && /^[0-9]+$/.test(kv.BYTES ?? "") && /^[0-9a-f]{64}$/.test(kv.SHA256 ?? "")) {
          const n = Number.parseInt(kv.BYTES, 10);
          if (n !== count) {
            void fail(new ReaError("unit-error", "The unit stored a different number of bytes than were sent."));
            return;
          }
          up.files.set(relPath, n);
          settle(resolve, { bytes: n, sha256: kv.SHA256 });
          return;
        }
        const map = {
          toobig: ["too-big", "The file is larger than the upload limit."],
          committed: ["committed", "This upload is already committed."],
          nouploaddir: ["unknown-upload", "That upload does not exist on the unit."],
          outside: ["invalid-path", "That upload path is not valid."],
          isdir: ["invalid-path", "That upload path is a folder."],
          mkdir: ["unit-error", "The unit could not create the folder."],
          write: ["unit-error", "The unit could not write the file."],
          rename: ["unit-error", "The unit could not store the file."],
        };
        const [codeName, message] = map[kv.ERROR] ?? ["unit-error", "The unit did not store the file."];
        void fail(new ReaError(codeName, message));
      };

      const onData = (chunk) => {
        if (abortErr || settled) return;
        count += chunk.length;
        if (count > cap) {
          abort(new ReaError("too-big", `The file is larger than the limit (${cap} bytes).`));
          return;
        }
        clearTimeout(idle);
        idle = setTimeout(() => abort(new ReaError("timeout", "The upload stalled and was stopped.")), idleLimit);
        idle.unref?.();
        if (stdin && !stdin.destroyed && !stdin.write(chunk)) {
          readable.pause();
          stdin.once("drain", () => {
            if (!abortErr && !settled) readable.resume();
          });
        }
      };
      const onEnd = () => {
        ended = true;
        clearTimeout(idle);
        try {
          stdin?.end();
        } catch {
          /* gone */
        }
      };
      const onReadableError = () => abort(new ReaError("aborted", "The upload was interrupted."));
      const onClose = () => {
        if (!ended) abort(new ReaError("aborted", "The upload was interrupted."));
      };

      child.on("error", (err) => {
        if (closed) return;
        closed = true;
        abortErr = abortErr ?? new ReaError("unit-error", err.message);
        void fail(abortErr);
      });
      child.on("close", (code) => finish(code));

      idle = setTimeout(() => abort(new ReaError("timeout", "The upload stalled and was stopped.")), idleLimit);
      idle.unref?.();
      readable.on("data", onData);
      readable.on("end", onEnd);
      readable.on("error", onReadableError);
      readable.on("close", onClose);
      if (readable.readableEnded) onEnd();
      else if (readable.destroyed && !ended) onClose();
    });
  }

  /**
   * Verify an upload, extract flagged archives (listed first, refused on unsafe entries) and mark it committed.
   * @returns {Promise<{ root: string, files: number, bytes: number, extracted: boolean }>}
   */
  async commitUpload(spark, uploadId, limits = {}) {
    const up = this._upload(spark.id, uploadId);
    if (up.writers.size > 0) throw new ReaError("writing", "A file of this upload is still being written.");
    if (up.committed && up.result) return { ...up.result };
    const maxFiles = Number.isInteger(limits.maxFiles) && limits.maxFiles > 0 ? Math.min(limits.maxFiles, this.uploadMaxFiles) : this.uploadMaxFiles;
    const maxBytes = Number.isInteger(limits.maxBytes) && limits.maxBytes > 0 ? Math.min(limits.maxBytes, this.uploadMaxBytes) : this.uploadMaxBytes;
    const res = await this.runOnce(spark, buildUploadCommitProgram({ uploadId, maxFiles, maxBytes }), { timeoutMs: 15 * 60 * 1000, stdoutOnly: true });
    const kv = kvOf(res.output);
    if (res.ok && kv.ROOT && /^\//.test(kv.ROOT) && /^[0-9]+$/.test(kv.FILES ?? "") && /^[0-9]+$/.test(kv.BYTES ?? "")) {
      const result = { root: kv.ROOT, files: Number.parseInt(kv.FILES, 10), bytes: Number.parseInt(kv.BYTES, 10), extracted: kv.EXTRACTED === "1" };
      up.committed = true;
      up.root = result.root;
      up.result = result;
      return { ...result };
    }
    const detail = clip(kv.DETAIL ?? "", 200);
    const byError = {
      nouploaddir: ["unknown-upload", "That upload does not exist on the unit."],
      writing: ["writing", "A file of this upload is still being written."],
      empty: ["empty", "Nothing was uploaded."],
      toomany: ["too-many-files", detail || "The upload has too many files."],
      toobig: ["too-big", detail || "The upload is too large."],
      archive: ["archive-refused", detail || "The archive was refused."],
      badentry: ["archive-refused", detail || "The upload contains a link or special file."],
      nopython: ["unit-error", "python3 is required on the unit to verify archives."],
    };
    const [code, message] = byError[kv.ERROR] ?? ["unit-error", res.error || detail || "The unit could not commit the upload."];
    throw new ReaError(code, message);
  }

  /** Remove an upload on the unit (best effort) and forget it. Open writers are ended. */
  async deleteUpload(spark, uploadId) {
    const map = this.uploads.get(spark.id);
    const up = typeof uploadId === "string" && UPLOAD_ID_RE.test(uploadId) ? map?.get(uploadId) : null;
    if (up) {
      for (const w of [...up.writers]) w.abort?.(new ReaError("aborted", "The upload was deleted."));
      map.delete(uploadId);
    }
    if (typeof uploadId !== "string" || !UPLOAD_ID_RE.test(uploadId)) return { ok: false };
    const res = await this.runOnce(spark, buildUploadDeleteProgram({ uploadId }), { timeoutMs: 40_000, stdoutOnly: true });
    return { ok: res.ok };
  }

  /** Remove uploads past the TTL on the unit (those with an open writer are kept) and forget them here. */
  async sweepUploads(spark) {
    const res = await this.runOnce(spark, buildUploadSweepProgram({ ttlHours: UPLOAD_TTL_HOURS }), { timeoutMs: 60_000, stdoutOnly: true });
    const map = this.uploads.get(spark.id);
    if (map) {
      const cutoff = this.now() - UPLOAD_TTL_HOURS * 3600 * 1000;
      for (const [id, up] of map) if (up.writers.size === 0 && up.createdAt < cutoff) map.delete(id);
    }
    const kv = kvOf(res.output);
    return { ok: res.ok, swept: Number.parseInt(kv.SWEPT ?? "0", 10) || 0, kept: Number.parseInt(kv.KEPT ?? "0", 10) || 0 };
  }

  /** Is this upload known to this process, bound to this unit and committed? */
  isCommittedUpload(sparkId, uploadId) {
    const up = typeof uploadId === "string" ? this.uploads.get(sparkId)?.get(uploadId) : null;
    return Boolean(up && up.committed && up.root);
  }

  /** Absolute path on the unit to analyse for a committed upload, or null. */
  uploadRoot(sparkId, uploadId) {
    const up = typeof uploadId === "string" ? this.uploads.get(sparkId)?.get(uploadId) : null;
    return up && up.committed && up.root ? up.root : null;
  }

  _abortWriters(sparkId = null) {
    for (const [sid, map] of this.uploads) {
      if (sparkId && sid !== sparkId) continue;
      for (const up of map.values()) for (const w of [...up.writers]) w.abort?.(new ReaError("aborted", "The dashboard is shutting down."));
    }
  }

  removeSpark(sparkId) {
    this._abortWriters(sparkId);
    this.uploads.delete(sparkId);
    super.removeSpark(sparkId);
  }

  shutdown() {
    this._abortWriters();
    super.shutdown();
  }
}
