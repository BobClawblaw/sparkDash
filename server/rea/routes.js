import { getSettings } from "../settings.js";
import { REA_VERSION, runDirRef } from "./commands.js";
import { publicSpec, workflowById } from "./spec.js";
import { isValidRunId, newRunId } from "./ReaStore.js";
import {
  MAX_TIMEOUT_MINUTES,
  MIN_TIMEOUT_MINUTES,
  reaViewObject,
  validateCompareRequest,
  validateRunRequest,
  validateViewRequest,
} from "./validate.js";

/**
 * HTTP surface for REA (Reverse Engineer Anything, github.com/morluto/rea) on a unit.
 *
 *   GET  /api/rea/setup, GET /api/rea/spec                      static data (not unit specific)
 *   GET  /api/sparks/:id/rea/status                             node / npm / installed / doctor / providers
 *   POST /api/sparks/:id/rea/install, GET …/install/stream      install the pinned version (streamed job)
 *   GET/POST …/runs, GET …/runs/:rid(/stream|/result|/view|/export)
 *   POST …/runs/:rid/(attach|stop|refresh), DELETE …/runs/:rid, DELETE …/watch, POST …/compare
 *
 * The upload routes (create / PUT bytes / commit / delete) live in uploads.js, which must be mounted
 * BEFORE express.json(); everything here goes after it and after the auth middleware.
 *
 * Analyzing a target can run code on the unit (some workflows execute the target or drive a device),
 * so the feature is an explicit opt-in (Settings -> REA, off by default): while it is off, install,
 * start, uploads, views, export and compare answer 403 with what to do. Reading the status, the run
 * list and a run's own output stays possible, and so do stopping and deleting.
 */

/** Plain-text clip for anything echoed back from the unit. */
const clipText = (v, n = 300) => String(v ?? "").replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, n);

const GATE_MESSAGE =
  "REA is turned off. It can run analysis tools (and, for some workflows, the target itself) on your units, so it is opt-in: turn it on in Settings. Anyone who can reach this dashboard can then use it, so set SPARKDASH_TOKEN if others can.";

/**
 * Helpers shared by routes.js and uploads.js: the opt-in gate, the unit lookup, rate limiting.
 * `deps` is the same object both register functions take.
 */
export function reaGuards(deps) {
  const { registry, allowRun, principalKey, rejectLimited } = deps;
  const isEnabled = deps.isEnabled ?? (() => getSettings().reaEnabled === true);
  const deviceWritesEnabled = deps.deviceWritesEnabled ?? (() => process.env.REA_ENABLE_DEVICE_WRITES === "1");

  /** null when REA is turned on, otherwise why it is refused. */
  const startGate = () => (isEnabled() ? null : GATE_MESSAGE);
  /** Send the 403 and return true when the feature is off. */
  const gated = (res) => {
    const blocked = startGate();
    if (!blocked) return false;
    res.status(403).json({ error: blocked });
    return true;
  };
  const sparkOr404 = (req, res) => {
    const spark = registry.getSpark(req.params.id);
    if (!spark) {
      res.status(404).json({ error: "Spark not found" });
      return null;
    }
    if (spark.platform && spark.platform !== "linux") {
      res.status(400).json({ error: `REA runs are only supported on Linux units (this one is ${clipText(spark.platform, 20)})` });
      return null;
    }
    return spark;
  };
  const limiter = (check, message = "Too many requests; try again shortly") => (req, res) => {
    if (check(principalKey(req))) return false;
    rejectLimited(res, message);
    return true;
  };
  const limited = limiter((k) => allowRun(k));
  return { isEnabled, deviceWritesEnabled, startGate, gated, sparkOr404, limited, limiter };
}

const nonNegInt = (v) => {
  const n = Number.parseInt(String(Array.isArray(v) ? v[0] : (v ?? "0")), 10);
  return Number.isInteger(n) && n > 0 ? n : 0;
};

export function registerReaRoutes(app, deps) {
  const { registry, manager, store, principalKey } = deps;
  const base = "/api/sparks/:id/rea";
  const { deviceWritesEnabled, startGate, gated, sparkOr404, limited } = reaGuards(deps);

  const runOr404 = (req, res, spark) => {
    const rid = req.params.rid;
    const run = isValidRunId(rid) ? store.get(rid) : null;
    if (!run || run.sparkId !== spark.id) {
      res.status(404).json({ error: "Run not found" });
      return null;
    }
    return run;
  };
  const busyBody = (active) => ({ error: "Another REA job is running on this unit. Wait for it or stop it first.", active });

  let specCache = null;

  // ── static data ──────────────────────────────────────────────────────────────────────────

  app.get("/api/rea/setup", (_req, res) => {
    const blocked = startGate();
    res.json({
      repository: "https://github.com/morluto/rea",
      pinnedVersion: REA_VERSION,
      node: { min: "22.19" },
      limits: {
        defaultTimeoutMinutes: 10,
        minTimeoutMinutes: MIN_TIMEOUT_MINUTES,
        maxTimeoutMinutes: MAX_TIMEOUT_MINUTES,
        uploadMaxBytes: manager.uploadMaxBytes,
        uploadMaxFiles: manager.uploadMaxFiles,
      },
      enabled: blocked == null,
      startAllowed: blocked == null,
      startBlockedReason: blocked,
      deviceWritesEnabled: deviceWritesEnabled() === true,
    });
  });

  app.get("/api/rea/spec", (_req, res) => {
    specCache ??= publicSpec();
    res.json(specCache);
  });

  // ── status and install ───────────────────────────────────────────────────────────────────

  app.get(`${base}/status`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    if (limited(req, res)) return;
    try {
      res.json(await manager.status(spark));
    } catch {
      res.status(502).json({ error: "The unit's REA status could not be read" });
    }
  });

  app.post(`${base}/install`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    if (gated(res)) return;
    if (limited(req, res)) return;
    const result = manager.installRea(spark);
    if (!result.ok) return res.status(409).json(busyBody(result.active));
    res.status(202).json({ job: manager.summary(result.job), version: REA_VERSION });
  });

  app.get(`${base}/install/stream`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const job = manager.latestJob(spark.id);
    if (!job || job.kind !== "install") return res.status(404).json({ error: "No install has run since the dashboard started" });
    const read = manager.readJob(spark.id, job.id, { lineSince: nonNegInt(req.query.lineSince) });
    if (!read) return res.status(404).json({ error: "No install has run since the dashboard started" });
    res.json({ job: read.job, lines: read.lines, partial: read.partial, nextLine: read.nextLine });
  });

  // ── runs ─────────────────────────────────────────────────────────────────────────────────

  app.get(`${base}/runs`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const active = manager.activeJob(spark.id);
    res.json({ runs: store.list({ sparkId: spark.id }), active: active ? manager.summary(active) : null });
  });

  app.post(`${base}/runs`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    if (gated(res)) return;
    if (limited(req, res)) return;
    const resolveUpload = (uploadId, relPath) => {
      // Only a COMMITTED upload of THIS unit resolves; the path is re-joined from the validated parts.
      if (!manager.isCommittedUpload(spark.id, uploadId)) return null;
      const root = manager.uploadRoot(spark.id, uploadId);
      if (typeof root !== "string" || !root) return null;
      return relPath ? `${root}/${relPath}` : root;
    };
    const request = validateRunRequest(req.body, { deviceWritesEnabled: deviceWritesEnabled() === true, resolveUpload });
    if (!request.ok) return res.status(400).json({ error: request.error });
    // Checked before anything is stored: a refused request must not evict history.
    const free = manager.canStart(spark);
    if (!free.ok) return res.status(409).json(busyBody(free.active));

    let id = newRunId();
    for (let i = 0; i < 5 && store.get(id); i += 1) id = newRunId();
    const now = Date.now();
    const run = {
      id,
      sparkId: spark.id,
      status: "running",
      startedAt: now,
      finishedAt: null,
      exitCode: null,
      note: null,
      label: request.label,
      workflowId: request.workflow.id,
      workflowLabel: request.workflow.label,
      command: request.display,
      target: request.target,
      target2: request.target2,
      provider: request.provider,
      execClass: request.execClass,
      effects: request.effects,
      authorization: { at: now, by: String(principalKey(req)).slice(0, 100) },
      confirmedExecute: request.confirmExecute,
      timeoutMinutes: request.timeoutMinutes,
      resultBytes: null,
      resultCached: false,
      summary: null,
      runDir: runDirRef(id),
    };
    // Stored before the job starts: a job that fails at once settles this record itself.
    const evicted = store.add(run);
    for (const old of Array.isArray(evicted) ? evicted : []) {
      const owner = registry.getSpark(old.sparkId);
      if (owner?.online) void manager.removeRemote(owner, old.id);
    }
    const started = manager.startReaRun(spark, {
      run,
      argv: request.argv,
      paths: request.paths,
      timeoutSeconds: request.timeoutMinutes * 60,
    });
    if (!started.ok) {
      store.remove(run.id);
      if (started.reason === "busy") return res.status(409).json(busyBody(started.active));
      return res.status(400).json({ error: clipText(started.error || "The run could not be started") });
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
    const read = manager.readJob(spark.id, run.id, { lineSince: nonNegInt(req.query.lineSince) });
    // No live job in memory (finished long ago or the server restarted): the client falls back to the stored run.
    const live = read
      ? { job: read.job, lines: read.lines, partial: read.partial, progress: { stage: read.progress?.stage ?? null }, nextLine: read.nextLine }
      : null;
    res.json({ run: store.get(run.id), live });
  });

  app.post(`${base}/runs/:rid/attach`, (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    if (limited(req, res)) return;
    const result = manager.attachRun(spark, run);
    if (!result.ok) return res.status(409).json(busyBody(result.active));
    res.status(202).json({ job: manager.summary(result.job) });
  });

  app.post(`${base}/runs/:rid/stop`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    if (limited(req, res)) return;
    const result = await manager.stopRun(spark, run.id);
    res.json({ success: result.ok, output: clipText(result.output, 500) });
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
      if (state === "running" && !force) return res.status(409).json({ error: "Stop the run before deleting it.", canForce: false });
      if (!force && state === "unknown") {
        const why = spark.online ? "Could not confirm the run has ended." : "The unit is offline, so the run may still be going there.";
        return res.status(409).json({ error: `${why} Stop it, or delete again with force.`, canForce: true });
      }
      if (live && live.id === run.id) manager.cancelWatch(spark.id);
      // A forced delete must not leave the analysis running unseen on the unit: stop it first. An
      // offline unit gets one short attempt (it may only be a stale status).
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

  // ── result, views, export, compare ───────────────────────────────────────────────────────

  app.get(`${base}/runs/:rid/result`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    if (run.status === "running") {
      // A read mid-run could cache a partial result.
      return res.status(409).json({ error: "The run is still going; its result is read when it finishes.", reason: "running" });
    }
    let loaded = manager.loadResult(run.id);
    if (!loaded?.summary) {
      if (limited(req, res)) return;
      const captured = await manager.captureResult(spark, run.id);
      if (!captured.ok) {
        if (captured.reason === "unreachable") return res.status(502).json({ error: "The unit could not be reached to read the result.", reason: captured.reason });
        const why = captured.reason === "too-big" ? "The result is too large to load here." : "No result exists for this run (yet).";
        return res.status(404).json({ error: why, reason: captured.reason });
      }
      loaded = manager.loadResult(run.id);
    }
    if (!loaded?.summary) return res.status(500).json({ error: "The stored result could not be read" });
    res.json({ run: store.get(run.id), summary: loaded.summary });
  });

  app.get(`${base}/runs/:rid/view`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    if (gated(res)) return;
    const workflow = workflowById(run.workflowId);
    const query = { ...req.query };
    // `selector` is one value: a number picks an item by index, anything else by name.
    const sel = Array.isArray(query.selector) ? query.selector[0] : query.selector;
    if (typeof sel === "string" && sel && query.name === undefined && query.index === undefined) {
      if (/^[0-9]{1,9}$/.test(sel)) query.index = sel;
      else query.name = sel;
    }
    delete query.selector;
    const view = validateViewRequest(query, workflow);
    if (!view.ok) return res.status(400).json({ error: view.error });
    if (run.status === "running") return res.status(409).json({ error: "The run is still going; views are available when it finishes.", reason: "running" });
    if (limited(req, res)) return;
    const result = await manager.readView(spark, run, reaViewObject(view.view));
    if (!result.ok) return res.status(502).json({ error: clipText(result.error || "The view could not be read") });
    res.json({ view: result.view, cached: result.cached === true });
  });

  app.get(`${base}/runs/:rid/export`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    const run = runOr404(req, res, spark);
    if (!run) return;
    if (gated(res)) return;
    if (run.status === "running") return res.status(409).json({ error: "The run is still going; it can be exported when it finishes.", reason: "running" });
    if (limited(req, res)) return;
    const out = await manager.exportResult(spark, run);
    if (!out.ok) {
      const message = clipText(out.error || "The result could not be exported");
      return res.status(/export limit/.test(message) ? 413 : 502).json({ error: message });
    }
    res.set({
      "Content-Type": "application/json",
      "Content-Disposition": `attachment; filename="${run.id}.json"`,
      "Content-Length": String(out.text.length),
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    });
    res.send(out.text);
  });

  app.post(`${base}/compare`, async (req, res) => {
    const spark = sparkOr404(req, res);
    if (!spark) return;
    if (gated(res)) return;
    const request = validateCompareRequest(req.body);
    if (!request.ok) return res.status(400).json({ error: request.error });
    const left = store.get(request.leftRunId);
    const right = store.get(request.rightRunId);
    if (!left || !right || left.sparkId !== spark.id || right.sparkId !== spark.id) return res.status(404).json({ error: "Run not found" });
    if (limited(req, res)) return;
    const out = await manager.compareRuns(spark, left, right);
    if (!out.ok) {
      const message = clipText(out.error || "The runs could not be compared");
      const status = /must have finished/.test(message) ? 409 : /Choose two|Unknown run|belong to this unit/.test(message) ? 400 : 502;
      return res.status(status).json({ error: message });
    }
    res.json({ result: out.result });
  });
}
