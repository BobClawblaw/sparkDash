import crypto from "crypto";
import { ToolEvalManager } from "../tooleval/ToolEvalManager.js";
import {
  VULNHUNTER_REV,
  exitToken,
  buildAttachProgram,
  buildClearHostCommandProgram,
  buildInstallProgram,
  buildSetHostCommandProgram,
  buildCheckProgram,
  buildDeleteRunProgram,
  buildReadReportProgram,
  buildRunProgram,
  buildStatusProgram,
  buildStopProgram,
} from "./commands.js";
import { summarizeReport } from "./report.js";

const RUN_WATCH_MAX_MS = 13 * 60 * 60 * 1000;
/** Harness transcripts can be one huge JSON object per line: a displayed line is clipped, and the whole buffer has a byte budget. */
const MAX_LINE_CHARS = 8 * 1024;
const MAX_BUFFER_CHARS = 2 * 1024 * 1024;
const MAX_BUFFER_LINES = 5000;
const STOP_TIMEOUT_MS = 70_000;
const INSTALL_MAX_MS = 15 * 60 * 1000;
const STAGES = new Set(["clone", "hunt", "collect", "done"]);

/** Exit codes the on-unit wrapper uses, as a sentence. */
export function explainExit(code) {
  switch (code) {
    case 0:
      return null;
    case 2:
      return "The source was not usable on the unit.";
    case 3:
      return "The repository could not be cloned.";
    case 4:
      return "The hunt finished but produced no results folder.";
    case 10:
      return "The harness command exited with an error (see the output).";
    case 124:
      return "The hunt hit its time limit.";
    case 126:
      return "The harness command is not configured safely on the unit.";
    case 127:
      return "VulnHunter, git or setsid is not set up on the unit.";
    case 143:
      return "The scan was stopped.";
    default:
      return code != null ? `The scan ended with code ${code}.` : null;
  }
}

/**
 * Runs VulnHunter scans on a unit and keeps the dashboard's view of them. Built on the Tool
 * Eval manager's process plumbing (one live job per unit, detached on-unit run, re-attach,
 * result capture), with VulnHunter's own programs, stages and report parsing on top.
 */
export class VulnHuntManager extends ToolEvalManager {
  /** Tool Eval's own installer does not apply; VulnHunter has `installVulnHunt`. */
  install() {
    return { ok: false, reason: "unsupported" };
  }

  /**
   * Install VulnHunter on the unit (pinned revision, minimal: skill + `vh`), streamed like any job.
   * @returns {{ ok: true, job: object } | { ok: false, reason: "busy", active: object }}
   */
  installVulnHunt(spark, { skillsDir, agentsDir = "", source = {} }) {
    const free = this.canStart(spark);
    if (!free.ok) return free;
    const busy = this.activeJob(spark.id);
    if (busy) this._detach(busy, spark);
    const job = this._newJob(spark, { id: `install-${crypto.randomBytes(3).toString("hex")}`, kind: "install", type: "vulnhunt" });
    this._startJob(spark, job, buildInstallProgram({ skillsDir, agentsDir, nonce: job.nonce, ...source }), { maxMs: INSTALL_MAX_MS });
    return { ok: true, job };
  }

  /** Save (or clear) the harness command on the unit. The command is only written, never read back. */
  async setHostCommand(spark, command) {
    const nonce = crypto.randomBytes(9).toString("hex");
    const res = await this.runOnce(spark, buildSetHostCommandProgram({ command, nonce }), { nonce, timeoutMs: 30_000, stdoutOnly: true });
    return { ok: res.ok, message: res.ok ? null : res.output.split("\n").pop() || res.error || "The unit did not accept the command" };
  }

  async clearHostCommand(spark) {
    const nonce = crypto.randomBytes(9).toString("hex");
    const res = await this.runOnce(spark, buildClearHostCommandProgram({ nonce }), { nonce, timeoutMs: 30_000, stdoutOnly: true });
    return { ok: res.ok };
  }

  summary(job) {
    const base = super.summary(job);
    // Exit 143 is the wrapper's "stopped on request", whether or not this process saw the request.
    const status = base.status === "failed" && base.exitCode === 143 ? "stopped" : base.status;
    return { ...base, status, stage: job.progress?.stage ?? null };
  }

  _newJob(spark, opts) {
    const job = super._newJob(spark, opts);
    job.progress = { stage: "starting" };
    return job;
  }

  /** One line of output: the exit marker and the wrapper's `stage:` lines are ours, the rest is the harness's. */
  _line(job, line) {
    const token = exitToken(job.nonce);
    const at = line.lastIndexOf(token);
    if (at >= 0) {
      const n = Number.parseInt(line.slice(at + token.length), 10);
      job.markerExit = Number.isFinite(n) ? n : -1;
      line = line.slice(0, at);
      if (!line) return;
    }
    const m = /^\[sparkdash\] stage: ([a-z]+)$/.exec(line);
    if (m && STAGES.has(m[1])) job.progress = { ...job.progress, stage: m[1] };
    const text = line.length > MAX_LINE_CHARS ? `${line.slice(0, MAX_LINE_CHARS)} … [line truncated]` : line;
    job.lseq += 1;
    job.lines.push({ seq: job.lseq, text, stream: "out" });
    job.bufChars = (job.bufChars ?? 0) + text.length;
    while (job.lines.length > MAX_BUFFER_LINES || (job.bufChars > MAX_BUFFER_CHARS && job.lines.length > 1)) {
      job.bufChars -= job.lines.shift().text.length;
    }
  }

  async _status(spark) {
    const res = await this.runOnce(spark, buildStatusProgram(), { timeoutMs: 40_000, stdoutOnly: true });
    const kv = {};
    for (const line of res.output.split("\n")) {
      const i = line.indexOf("=");
      if (i > 0) kv[line.slice(0, i)] = line.slice(i + 1).trim();
    }
    const source = kv.HOSTCMD_SOURCE || "none";
    const hostConfigured = (source === "env" || source === "file") && kv.HOSTCMD_FOUND === "1";
    const installed = Boolean(kv.VH);
    return {
      reachable: res.ok || kv.VH !== undefined,
      installed,
      path: kv.VH || null,
      git: Boolean(kv.GIT),
      setsid: Boolean(kv.SETSID),
      hostCommand: {
        source,
        program: kv.HOSTCMD_PROGRAM || null,
        found: kv.HOSTCMD_FOUND === "1",
        file: kv.HOSTCMD_FILE || null,
        configured: hostConfigured,
      },
      ready: installed && Boolean(kv.GIT) && Boolean(kv.SETSID) && hostConfigured,
      runRoot: kv.RUNROOT || null,
      install: {
        pinnedRev: VULNHUNTER_REV,
        installedRev: /^[0-9a-f]{40}$/.test(kv.INSTALLED_REV ?? "") ? kv.INSTALLED_REV : null,
        upToDate: kv.INSTALLED_REV === VULNHUNTER_REV,
        skillsDir: kv.INSTALLED_SKILLS_DIR || null,
        agentsDir: kv.INSTALLED_AGENTS_DIR || null,
        python311: kv.PYTHON311 || null,
        skillsDirCandidates: res.output
          .split("\n")
          .filter((l) => l.startsWith("SKILLSDIR="))
          .map((l) => l.slice("SKILLSDIR=".length).trim())
          .filter((d) => /^\/[A-Za-z0-9._@+=,/-]{1,300}$/.test(d))
          .slice(0, 8),
      },
      error: res.error,
    };
  }

  /**
   * Could a scan start on this unit right now? Checked by the route BEFORE the run is stored, so a
   * refused request never evicts history.
   * @returns {{ ok: true } | { ok: false, reason: "busy", active: object }}
   */
  canStart(spark) {
    const busy = this.activeJob(spark.id);
    if (busy && busy.kind !== "attach") return { ok: false, reason: "busy", active: this.summary(busy) };
    // A scan whose watcher ended (detached, cancelled) may still be running on the unit.
    const orphan = this.store.list({ sparkId: spark.id }).find((r) => r.status === "running");
    if (orphan) return { ok: false, reason: "busy", active: { id: orphan.id, sparkId: spark.id, kind: "run", status: "running" } };
    return { ok: true };
  }

  /**
   * Start a scan (detached on the unit) and follow it.
   * @returns {{ ok: true, job: object } | { ok: false, reason: "busy", active: object }}
   */
  startScan(spark, { run, argv }) {
    const busy = this.activeJob(spark.id);
    if (busy && busy.kind !== "attach") return { ok: false, reason: "busy", active: this.summary(busy) };
    // The record was stored by the caller before this call, so it is excluded from the orphan check.
    const orphan = this.store.list({ sparkId: spark.id }).find((r) => r.status === "running" && r.id !== run.id);
    if (orphan) return { ok: false, reason: "busy", active: { id: orphan.id, sparkId: spark.id, kind: "run", status: "running" } };
    if (busy) this._detach(busy, spark);
    const argvB64 = Buffer.from(argv.join("\0") + "\0", "utf8").toString("base64");
    const job = this._newJob(spark, { id: run.id, kind: "run", type: "vulnhunt" });
    const cmd = buildRunProgram({ runId: run.id, argvB64, displayLine: run.command, nonce: job.nonce });
    this._startJob(spark, job, cmd, { maxMs: RUN_WATCH_MAX_MS });
    this.onEvent({
      type: "vulnhunt.scan.started",
      severity: "info",
      sparkId: spark.id,
      message: `VulnHunter scan started${run.label ? ` (${run.label})` : ""}`,
    });
    return { ok: true, job };
  }

  attachScan(spark, run) {
    const busy = this.activeJob(spark.id);
    if (busy) {
      if (busy.id === run.id) return { ok: true, job: busy };
      if (busy.kind === "run") return { ok: false, reason: "busy", active: this.summary(busy) };
      this._detach(busy, spark);
    }
    const job = this._newJob(spark, { id: run.id, kind: "attach", type: "vulnhunt" });
    this._startJob(spark, job, buildAttachProgram({ runId: run.id, nonce: job.nonce }), { maxMs: RUN_WATCH_MAX_MS });
    return { ok: true, job };
  }

  /**
   * Ask the scan to stop (TERM, then KILL after the wrapper's grace) via the unit, regardless of who
   * is watching. `stopRequested` is set first because the job can end before this call returns; it is
   * taken back when the stop did not happen, so a later natural failure is not shown as "stopped".
   */
  async stopRun(spark, runId, { timeoutMs = STOP_TIMEOUT_MS } = {}) {
    const live = this.jobs.get(spark.id);
    const mine = live && live.id === runId ? live : null;
    if (mine) mine.stopRequested = true;
    const res = await this.runOnce(spark, buildStopProgram({ runId }), { timeoutMs });
    const stopped = res.ok && /\b(stopped|killed)\b/.test(res.output);
    if (mine && !stopped && mine.status === "running") mine.stopRequested = false;
    return { ok: res.ok && stopped, output: res.output };
  }

  async _afterJob(job, spark) {
    if (job.kind === "install") {
      if (job.status === "cancelled" || job.status === "detached") return;
      const ok = job.status === "completed";
      this.onEvent({
        type: `vulnhunt.install.${ok ? "completed" : "failed"}`,
        severity: ok ? "success" : "error",
        sparkId: job.sparkId,
        message: ok ? "VulnHunter installed" : "VulnHunter install failed",
      });
      return;
    }
    const run = this.store.get(job.id);
    if (!run) return;
    // Nothing is known yet: the scan may still be running (watcher closed, connection lost, dashboard
    // shutting down). The record and Activity stay as they are; checkRun() settles it later.
    if (job.status === "detached" || job.status === "cancelled") return;
    // Re-opening the output of a scan that was already settled must not settle it a second time.
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
      note: code != null ? explainExit(code) : job.error ?? null,
    });
    await this.captureResult(spark, job.id);
    const fresh = this.store.get(job.id);
    const total = fresh?.summary?.total;
    const c = fresh?.summary?.counts;
    const serious = c ? (c["High+"] ?? 0) + (c.High ?? 0) : 0;
    // A scan that finished but whose report could not be read says so, instead of a bare "Completed".
    if (finalStatus === "completed" && fresh && !fresh.resultCached) {
      this.store.update(job.id, { note: "The scan finished but no report could be read from the unit." });
    }
    this.onEvent({
      type: `vulnhunt.scan.${finalStatus}`,
      severity: finalStatus === "completed" ? (serious > 0 ? "warn" : "success") : finalStatus === "stopped" ? "info" : "error",
      sparkId: job.sparkId,
      message:
        finalStatus === "completed"
          ? `VulnHunter scan finished: ${total != null ? `${total} confirmed finding${total === 1 ? "" : "s"}` : "no report"}${serious > 0 ? ` (${serious} High or above)` : ""}`
          : finalStatus === "stopped"
            ? "VulnHunter scan stopped"
            : `VulnHunter scan failed${code != null ? ` (exit ${code})` : ""}`,
    });
  }

  /** Pull the report bundle from the unit, parse it, cache it locally and keep the headline numbers. */
  async _captureResult(spark, runId) {
    const nonce = crypto.randomBytes(9).toString("hex");
    const S = `__VH_${nonce}_`;
    const res = await this.runOnce(spark, buildReadReportProgram({ runId, sentinel: S }), { timeoutMs: 90_000, stdoutOnly: true });
    if (res.overflow) return { ok: false, reason: "too-big" };
    const text = res.output;
    if (!text.includes(`${S}DIR`)) return { ok: false, reason: "no-result" };

    // The report is last and agent-written; everything before it is parsed by sentinel order.
    const repAt = text.indexOf(`${S}REPORT\n`);
    const head = repAt >= 0 ? text.slice(0, repAt) : text;
    let report = repAt >= 0 ? text.slice(repAt + `${S}REPORT\n`.length) : "";
    if (report.startsWith("__TOOBIG__")) report = "";
    const section = (name, next) => {
      const a = head.indexOf(`${S}${name}\n`);
      if (a < 0) return "";
      const from = a + `${S}${name}\n`.length;
      const b = next ? head.indexOf(`${S}${next}\n`, from) : head.length;
      return head.slice(from, b < 0 ? head.length : b).trim();
    };
    const dir = section("DIR", "MANIFEST").split("\n")[0] ?? "";
    const manifestText = section("MANIFEST", "FILES");
    const files = section("FILES", null)
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);

    if (!this.store.get(runId)) return { ok: false, reason: "deleted" };
    const full = summarizeReport({ report, manifestText, files });
    const bundle = { dir, report, findings: full.findings, artifacts: full.artifacts, header: full.header, manifest: full.manifest };
    if (!this.store.saveBundle(runId, bundle)) return { ok: false, reason: "deleted" };
    this.store.update(runId, {
      resultCached: true,
      summary: {
        hasReport: full.hasReport,
        header: full.header,
        manifest: full.manifest,
        total: full.total,
        counts: full.counts,
        exploitPass: full.exploitPass,
        artifactCount: full.artifacts.length,
        resultsDir: dir || null,
      },
    });
    return { ok: true };
  }

  /** Settle a scan whose watcher was lost: is it still alive, or how did it end? */
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
        note: code >= 0 ? explainExit(code) : "The scan ended without reporting a result (the unit may have restarted, or the process was killed).",
      });
      await this.captureResult(spark, runId);
    }
    return { state: "finished", exitCode: code };
  }

  async removeRemote(spark, runId) {
    if (spark) await this.runOnce(spark, buildDeleteRunProgram({ runId }), { timeoutMs: 40_000, stdoutOnly: true }).catch(() => {});
  }
}
