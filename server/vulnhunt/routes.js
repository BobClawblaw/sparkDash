import { configuredToken, isLoopbackBind } from "../auth.js";
import {
  displayLine,
  parseAllowedHosts,
  scanArgv,
  validateHostCommand,
  validateInstallRequest,
  validateScanRequest,
  DEFAULT_TIMEOUT_MINUTES,
  MAX_TIMEOUT_MINUTES,
  MIN_TIMEOUT_MINUTES,
} from "./validate.js";
import { HOST_CMD_FILE, VULNHUNTER_REPO, VULNHUNTER_REV, runDirRef } from "./commands.js";
import { isValidRunId, newRunId } from "./VulnHuntStore.js";

/** What the setup card shows. Plain data: the dashboard never runs the installer for the user. */
export const SETUP = {
  repository: "https://github.com/nealbridges/VulnHunter",
  hostCommandFile: "~/.config/sparkdash/vulnhunt-host-cmd",
  steps: [
    "git clone https://github.com/nealbridges/VulnHunter.git ~/VulnHunter && cd ~/VulnHunter",
    'VULNHUNT_SKILLS_DIR="<your harness skills dir>" VULNHUNT_AGENTS_DIR="<your harness agents dir>" ./install.sh',
    "mkdir -p ~/.config/sparkdash && (umask 077; printf '%s\\n' '<your harness headless one-shot command>' > ~/.config/sparkdash/vulnhunt-host-cmd)",
  ],
};

/**
 * HTTP surface for VulnHunter scans (github.com/nealbridges/VulnHunter run on a unit):
 *   GET  /api/vulnhunt/setup                         install / configuration steps (static)
 *   GET  /api/sparks/:id/vulnhunt/status             is `vh` installed, is a harness command configured
 *   GET/POST /api/sparks/:id/vulnhunt/runs           list / start a scan
 *   GET  …/runs/:rid, …/stream, …/report             one scan, its live output, its parsed report
 *   POST …/runs/:rid/(attach|stop|refresh), DELETE …/runs/:rid, DELETE …/watch
 *
 * A scan clones a repository and lets an agent harness work on it, as the unit's user, so
 * unlike the read-only routes it is NOT offered on an open dashboard: starting one needs
 * SPARKDASH_TOKEN, or a loopback bind. The request carries an explicit authorization
 * attestation (kept on the run record with a time and the requester), the harness command is
 * kept in a file the unit's user owns and is write-only through the API (never read back or echoed),
 * installing and saving that command need the same gate, and VULNHUNT_ALLOWED_HOSTS can pin the
 * hosts a scan may clone from.
 */
export function registerVulnHuntRoutes(app, { registry, manager, store, allowRun, principalKey, rejectLimited, bindHost = process.env.BIND_HOST || "127.0.0.1" }) {
  const base = "/api/sparks/:id/vulnhunt";

  /** Starting scans needs a token, or a dashboard only this machine can reach (which trusts its local users). */
  const startGate = () =>
    configuredToken() || isLoopbackBind(bindHost)
      ? null
      : "Starting scans needs SPARKDASH_TOKEN to be set (or a dashboard bound to loopback): without it anyone who can reach this port could run an agent on your units.";
  const allowedHosts = () => parseAllowedHosts(process.env.VULNHUNT_ALLOWED_HOSTS);

  const sparkOr404 = (req, res) => {
    const spark = registry.getSpark(req.params.id);
    if (!spark) {
      res.status(404).json({ error: "Spark not found" });
      return null;
    }
    if (spark.platform && spark.platform !== "linux") {
      res.status(400).json({ error: `VulnHunter scans are only supported on Linux units (this one is ${String(spark.platform).slice(0, 20)})` });
      return null;
    }
    return spark;
  };
  const runOr404 = (req, res, spark) => {
    const rid = req.params.rid;
    const run = isValidRunId(rid) ? store.get(rid) : null;
    if (!run || run.sparkId !== spark.id) {
      res.status(404).json({ error: "Scan not found" });
      return null;
    }
    return run;
  };
  const limited = (req, res) => {
    if (allowRun(principalKey(req))) return false;
    rejectLimited(res, "Too many requests; try again shortly");
    return true;
  };

  app.get("/api/vulnhunt/setup", (_req, res) => {
    res.json({
      ...SETUP,
      hostCommandFile: HOST_CMD_FILE.replace("$HOME", "~"),
      limits: { defaultTimeoutMinutes: DEFAULT_TIMEOUT_MINUTES, minTimeoutMinutes: MIN_TIMEOUT_MINUTES, maxTimeoutMinutes: MAX_TIMEOUT_MINUTES },
      pinnedRev: VULNHUNTER_REV,
      startAllowed: startGate() == null,
      startBlockedReason: startGate(),
      allowedHosts: allowedHosts(),
    });
  });

  app.get(`${base}/status`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    if (limited(req, res)) return;
    res.json(await manager.status(spark));
  });

  // ── installing VulnHunter and saving the harness command, from the UI ──
  // Both change what runs on the unit as its user, so they need the same gate as starting a scan.

  app.post(`${base}/install`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    if (limited(req, res)) return;
    const blocked = startGate();
    if (blocked) return res.status(403).json({ error: blocked });
    const request = validateInstallRequest(req.body);
    if (!request.ok) return res.status(400).json({ error: request.error });
    const result = manager.installVulnHunt(spark, request);
    if (!result.ok) return res.status(409).json({ error: "Another VulnHunter job is running on this unit. Wait for it or stop it first.", active: result.active });
    res.status(202).json({ job: manager.summary(result.job), revision: VULNHUNTER_REV, repository: VULNHUNTER_REPO });
  });

  app.get(`${base}/install/stream`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const job = manager.latestJob(spark.id);
    if (!job || job.kind !== "install") return res.status(404).json({ error: "No install has run since the dashboard started" });
    res.json(manager.readJob(spark.id, job.id, { lineSince: Number.parseInt(String(req.query.lineSince ?? "0"), 10) || 0 }));
  });

  app.put(`${base}/host-command`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    if (limited(req, res)) return;
    const blocked = startGate();
    if (blocked) return res.status(403).json({ error: blocked });
    const request = validateHostCommand(req.body);
    if (!request.ok) return res.status(400).json({ error: request.error });
    const saved = await manager.setHostCommand(spark, request.command);
    if (!saved.ok) return res.status(400).json({ error: saved.message });
    res.json({ success: true });
  });

  app.delete(`${base}/host-command`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    if (limited(req, res)) return;
    const blocked = startGate();
    if (blocked) return res.status(403).json({ error: blocked });
    res.json({ success: (await manager.clearHostCommand(spark)).ok });
  });

  app.get(`${base}/runs`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const active = manager.activeJob(spark.id);
    res.json({ runs: store.list({ sparkId: spark.id }), active: active ? manager.summary(active) : null });
  });

  app.post(`${base}/runs`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    if (limited(req, res)) return;
    const blocked = startGate();
    if (blocked) return res.status(403).json({ error: blocked });
    const request = validateScanRequest(req.body, { allowedHosts: allowedHosts() });
    if (!request.ok) return res.status(400).json({ error: request.error });
    // Checked before anything is stored: a refused request must not evict history.
    const free = manager.canStart(spark);
    if (!free.ok) return res.status(409).json({ error: "Another VulnHunter job is running on this unit. Wait for it or stop it first.", active: free.active });

    const id = newRunId();
    const run = {
      id,
      sparkId: spark.id,
      status: "running",
      startedAt: Date.now(),
      finishedAt: null,
      exitCode: null,
      note: null,
      label: request.label,
      source: { type: request.kind, value: request.value },
      readOnly: request.readOnly,
      timeoutMinutes: request.timeoutMinutes,
      authorization: { at: Date.now(), by: String(principalKey(req)).slice(0, 100) },
      command: displayLine(request),
      runDir: runDirRef(id),
      summary: null,
      resultCached: false,
    };
    // Stored before the job starts: a job that fails at once settles this record itself.
    const evicted = store.add(run);
    for (const old of Array.isArray(evicted) ? evicted : []) {
      const owner = registry.getSpark(old.sparkId);
      if (owner?.online) void manager.removeRemote(owner, old.id);
    }
    const started = manager.startScan(spark, { run, argv: scanArgv(request) });
    if (!started.ok) {
      store.remove(run.id);
      return res.status(409).json({ error: "Another VulnHunter job is running on this unit. Wait for it or stop it first.", active: started.active });
    }
    res.status(202).json({ run: store.get(run.id) ?? run, job: manager.summary(started.job) });
  });

  app.get(`${base}/runs/:rid`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    const job = manager.latestJob(spark.id);
    res.json({ run, job: job && job.id === run.id ? manager.summary(job) : null });
  });

  app.get(`${base}/runs/:rid/stream`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    const read = manager.readJob(spark.id, run.id, {
      lineSince: Number.parseInt(String(req.query.lineSince ?? "0"), 10) || 0,
    });
    // No live job in memory (finished long ago or the server restarted): the client falls back to the stored run.
    res.json({ run: store.get(run.id), live: read });
  });

  app.post(`${base}/runs/:rid/attach`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    if (limited(req, res)) return;
    const result = manager.attachScan(spark, run);
    if (!result.ok) return res.status(409).json({ error: "Another VulnHunter job is running on this unit", active: result.active });
    res.status(202).json({ job: manager.summary(result.job) });
  });

  app.post(`${base}/runs/:rid/stop`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    if (limited(req, res)) return;
    const result = await manager.stopRun(spark, run.id);
    res.json({ success: result.ok, output: result.output });
  });

  app.post(`${base}/runs/:rid/refresh`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    if (limited(req, res)) return;
    const state = await manager.checkRun(spark, run.id);
    res.json({ state, run: store.get(run.id) });
  });

  app.get(`${base}/runs/:rid/report`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    let bundle = store.loadBundle(run.id);
    if (!bundle && run.status === "running") {
      // A report read mid-scan could cache a partial result.
      return res.status(409).json({ error: "The scan is still running; its report is read when it finishes.", reason: "running" });
    }
    if (!bundle) {
      if (limited(req, res)) return;
      const captured = await manager.captureResult(spark, run.id);
      if (!captured.ok) {
        const why = captured.reason === "too-big" ? "The report is too large to load here." : "No report exists for this scan (yet).";
        return res.status(404).json({ error: why, reason: captured.reason });
      }
      bundle = store.loadBundle(run.id);
    }
    if (!bundle) return res.status(500).json({ error: "The stored report could not be read" });
    res.json({ run: store.get(run.id), report: bundle });
  });

  app.delete(`${base}/runs/:rid`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    if (limited(req, res)) return;
    const live = manager.activeJob(spark.id);
    const force = req.query.force === "1" || req.query.force === "true";
    const maybeRunning = run.status === "running" || (live && live.id === run.id && live.kind === "run");
    let reachable = Boolean(spark.online);
    if (maybeRunning) {
      let state = "unknown";
      if (spark.online) {
        try {
          state = (await manager.checkRun(spark, run.id)).state;
        } catch {
          state = "unknown";
        }
      }
      if (state === "running" && !force) return res.status(409).json({ error: "Stop the scan before deleting it." });
      if (!force && state === "unknown") {
        const why = spark.online ? "Could not confirm the scan has ended." : "The unit is offline, so the scan may still be running there.";
        return res.status(409).json({ error: `${why} Stop it, or delete again with force.`, canForce: true });
      }
      if (live && live.id === run.id) manager.cancelWatch(spark.id);
      // A forced delete must not leave the hunt running unseen on the unit: stop it first. An offline
      // unit gets one short attempt (it may only be a stale status), and is cleaned up if it answered.
      if (state !== "finished" && state !== "gone") {
        const stopped = await manager.stopRun(spark, run.id, { timeoutMs: spark.online ? undefined : 8000 });
        if (stopped.ok) reachable = true;
      }
    }
    await manager.deleteRun(reachable ? spark : null, run.id);
    res.json({ success: true });
  });

  app.delete(`${base}/watch`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    res.json({ success: manager.cancelWatch(spark.id) });
  });
}
