import test, { after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import http from "node:http";
import { execFileSync, spawn } from "node:child_process";
import express from "express";
import { createRateLimiter } from "../../validate.js";
import { ReaStore } from "../ReaStore.js";
import { ReaManager } from "../ReaManager.js";
import { registerReaRoutes } from "../routes.js";
import { registerReaUploadRoutes } from "../uploads.js";
import { REA_VERSION } from "../commands.js";
import { installFakeRea } from "./fakeRea.js";

// ── harness: a small Express app over a real ReaManager + ReaStore, the "unit" is a temp HOME ──

const made = [];
const homes = [];
const servers = new Set();
const spawned = new Set();
const tmp = (p) => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
  made.push(d);
  return d;
};
const killGroup = (pid) => {
  for (const t of [-pid, pid]) {
    try {
      process.kill(t, "SIGKILL");
    } catch {
      /* gone */
    }
  }
};
const reap = (home) => {
  const base = path.join(home, ".cache", "sparkdash", "rea", "runs");
  let ids = [];
  try {
    ids = fs.readdirSync(base);
  } catch {
    /* none */
  }
  for (const id of ids) {
    try {
      const pid = Number(fs.readFileSync(path.join(base, id, "pid"), "utf8"));
      if (pid > 1) killGroup(pid);
    } catch {
      /* none */
    }
  }
  try {
    const pid = Number(fs.readFileSync(path.join(home, "rea.pid"), "utf8"));
    if (pid > 1) killGroup(pid);
  } catch {
    /* none */
  }
};
after(() => {
  for (const s of servers) {
    try {
      s.closeAllConnections?.();
      s.close();
    } catch {
      /* closed */
    }
  }
  for (const c of spawned) if (c.pid) killGroup(c.pid);
  for (const h of homes) reap(h);
  for (const d of made) fs.rmSync(d, { recursive: true, force: true });
});

const until = async (fn, ms = 25_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("timed out");
};
const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const hasPython = (() => {
  try {
    execFileSync("python3", ["-I", "-c", "import zipfile, tarfile"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

const NODE_DIR = path.dirname(process.execPath);
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const RUN_ID = /^rea-[0-9]{8}-[0-9]{6}-[a-z0-9]{4}$/;
const UP_ID = /^up-[0-9]{8}-[0-9]{6}-[a-z0-9]{6}$/;

async function startApp(t, { enabled = true, manager = {}, limits = {}, deviceWrites = false } = {}) {
  const home = tmp("rea-api-home-");
  homes.push(home);
  installFakeRea(home);
  fs.mkdirSync(path.join(home, "data"), { recursive: true });
  fs.writeFileSync(path.join(home, "data", "sample.bin"), "hello rea\n");
  const state = tmp("rea-api-state-");
  const store = new ReaStore({ file: path.join(state, "runs.json"), resultsDir: path.join(state, "res") });
  const PATH = [NODE_DIR, "/usr/local/bin", "/usr/bin", "/bin"].join(":");
  const spawnProcess = (_s, cmd, opts = {}) => {
    const child = spawn("bash", ["-c", cmd], {
      env: { HOME: home, PATH, LANG: "C", SPARKDASH_REA_GRACE: "2", SPARKDASH_REA_TICK: "1", SPARKDASH_REA_LOGMAX: "100000" },
      stdio: [opts.stdin ? "pipe" : "ignore", "pipe", "pipe"],
      detached: true,
    });
    spawned.add(child);
    child.on("close", () => spawned.delete(child));
    return child;
  };
  const events = [];
  const mgr = new ReaManager({ store, onEvent: (e) => events.push(e), spawnProcess, ...manager });
  const sparks = new Map([
    ["s1", { id: "s1", name: "one", isLocal: true, online: true, ssh: { user: "u" } }],
    ["s2", { id: "s2", name: "two", isLocal: true, online: true, ssh: { user: "u" } }],
    ["win", { id: "win", name: "win", platform: "win32", online: true }],
  ]);
  const flags = { enabled, deviceWrites };
  const deps = {
    registry: { getSpark: (id) => sparks.get(id) ?? null },
    manager: mgr,
    store,
    allowRun: limits.allowRun ?? createRateLimiter(1000, 60_000),
    allowUpload: limits.allowUpload ?? createRateLimiter(1000, 60_000),
    principalKey: () => "tester",
    rejectLimited: (res, message) => res.status(429).json({ error: message }),
    isEnabled: () => flags.enabled,
    deviceWritesEnabled: () => flags.deviceWrites,
    authMiddleware: (req, res, next) => {
      if (req.headers["x-test-deny"]) return res.status(401).json({ error: "denied" });
      next();
    },
  };
  const app = express();
  registerReaUploadRoutes(app, deps);
  app.use(express.json());
  registerReaRoutes(app, deps);
  const server = await new Promise((resolve) => {
    const s = http.createServer(app);
    s.listen(0, "127.0.0.1", () => resolve(s));
  });
  servers.add(server);
  t.after(async () => {
    mgr.shutdown();
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
    servers.delete(server);
  });
  const port = server.address().port;
  const h = { home, store, mgr, events, flags, port, sparks, state };
  h.api = (p, { method = "GET", body, headers = {}, raw = false } = {}) => api(port, p, { method, body, headers, raw });
  return h;
}

async function api(port, pathname, { method = "GET", body, headers = {}, raw = false } = {}) {
  const isBuf = Buffer.isBuffer(body);
  const res = await fetch(`http://127.0.0.1:${port}${pathname}`, {
    method,
    signal: AbortSignal.timeout(30_000),
    headers: { ...(body !== undefined && !isBuf ? { "Content-Type": "application/json" } : {}), ...headers },
    body: body === undefined ? undefined : isBuf ? body : JSON.stringify(body),
  });
  if (raw) return { status: res.status, headers: res.headers, text: await res.text() };
  return { status: res.status, headers: res.headers, body: await res.json().catch(() => ({})) };
}

const reaCalls = (h) => {
  try {
    return fs.readFileSync(path.join(h.home, "rea.argv"), "utf8").split("\n").filter(Boolean);
  } catch {
    return [];
  }
};
const upDir = (h, id) => path.join(h.home, ".cache", "sparkdash", "rea", "uploads", id);
const walk = (dir) => {
  const out = [];
  const rec = (d) => {
    let names = [];
    try {
      names = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of names) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) rec(p);
      else out.push(p);
    }
  };
  rec(dir);
  return out;
};

const R = "/api/sparks/s1/rea";
const jsRun = (h, over = {}) => ({
  workflowId: "analyze-javascript-application",
  target: { kind: "path", value: path.join(h.home, "data", "sample.bin") },
  authorized: true,
  ...over,
});
const finished = async (h, runId) => {
  await until(async () => (await h.api(`${R}/runs/${runId}`)).body.run?.status !== "running");
  return (await h.api(`${R}/runs/${runId}`)).body.run;
};
const startFinished = async (h, over = {}) => {
  const r = await h.api(`${R}/runs`, { method: "POST", body: jsRun(h, over) });
  assert.equal(r.status, 202, JSON.stringify(r.body));
  const run = await finished(h, r.body.run.id);
  assert.equal(run.status, "completed", JSON.stringify(run));
  return run.id;
};

// ── the gate ─────────────────────────────────────────────────────────────────

test("gate off: starting, installing, uploads, views, export and compare answer 403; reading stays possible", async (t) => {
  const h = await startApp(t, { enabled: false });
  const setup = await h.api("/api/rea/setup");
  assert.equal(setup.status, 200);
  assert.equal(setup.body.enabled, false);
  assert.equal(setup.body.startAllowed, false);
  assert.match(setup.body.startBlockedReason, /Settings/);
  assert.equal(setup.body.pinnedVersion, REA_VERSION);
  assert.equal(setup.body.deviceWritesEnabled, false);
  assert.deepEqual(setup.body.node, { min: "22.19" });
  assert.equal(setup.body.limits.maxTimeoutMinutes, 240);
  assert.ok(setup.body.limits.uploadMaxBytes > 0 && setup.body.limits.uploadMaxFiles > 0);
  assert.match(setup.body.repository, /morluto\/rea/);

  const spec = await h.api("/api/rea/spec");
  assert.equal(spec.status, 200);
  assert.ok(spec.body.workflows.length > 10);
  assert.ok(spec.body.workflows.some((w) => w.id === "analyze-javascript-application"));

  // Reads
  const status = await h.api(`${R}/status`);
  assert.equal(status.status, 200);
  assert.equal(status.body.reachable, true);
  assert.equal(status.body.installed, true);
  assert.equal(status.body.pinnedVersion, REA_VERSION);
  assert.equal((await h.api(`${R}/runs`)).status, 200);
  assert.equal((await h.api(`${R}/install/stream`)).status, 404);
  assert.equal((await h.api(`${R}/watch`, { method: "DELETE" })).status, 200);

  // Writes
  const stored = { id: "rea-20261012-101010-aaaa", sparkId: "s1", status: "completed", startedAt: 1, workflowId: "analyze-javascript-application" };
  h.store.add(stored);
  const other = { ...stored, id: "rea-20261012-101011-bbbb" };
  h.store.add(other);
  const refused = [
    h.api(`${R}/install`, { method: "POST", body: {} }),
    h.api(`${R}/runs`, { method: "POST", body: jsRun(h) }),
    h.api(`${R}/uploads`, { method: "POST", body: {} }),
    h.api(`${R}/uploads/up-20261012-101010-abc123/files?path=a.txt`, { method: "PUT", body: Buffer.from("x") }),
    h.api(`${R}/uploads/up-20261012-101010-abc123/commit`, { method: "POST", body: {} }),
    h.api(`${R}/uploads/up-20261012-101010-abc123`, { method: "DELETE" }),
    h.api(`${R}/runs/${stored.id}/view`),
    h.api(`${R}/runs/${stored.id}/export`),
    h.api(`${R}/compare`, { method: "POST", body: { leftRunId: stored.id, rightRunId: other.id } }),
  ];
  for (const r of await Promise.all(refused)) {
    assert.equal(r.status, 403);
    assert.match(r.body.error, /turned off/);
  }
  assert.equal(h.store.list().length, 2, "nothing was stored");
  assert.equal(reaCalls(h).filter((l) => l.startsWith("analyze")).length, 0);

  // Turning it on opens it
  h.flags.enabled = true;
  assert.equal((await h.api("/api/rea/setup")).body.startAllowed, true);
  assert.equal((await h.api(`${R}/uploads`, { method: "POST", body: {} })).status, 201);
});

test("auth middleware is applied to the upload routes (they run before the app-wide one)", async (t) => {
  const h = await startApp(t);
  const deny = { "x-test-deny": "1" };
  assert.equal((await h.api(`${R}/uploads`, { method: "POST", body: {}, headers: deny })).status, 401);
  assert.equal((await h.api(`${R}/uploads/up-20261012-101010-abc123/files?path=a`, { method: "PUT", body: Buffer.from("x"), headers: deny })).status, 401);
  assert.equal((await h.api(`${R}/uploads/up-20261012-101010-abc123/commit`, { method: "POST", body: {}, headers: deny })).status, 401);
  assert.equal((await h.api(`${R}/uploads/up-20261012-101010-abc123`, { method: "DELETE", headers: deny })).status, 401);
  assert.throws(() => registerReaUploadRoutes(express(), { registry: {}, manager: {}, store: {}, allowRun() {}, allowUpload() {}, principalKey() {}, rejectLimited() {} }), /authMiddleware/);
});

// ── validation ───────────────────────────────────────────────────────────────

test("validation: 400s for bad requests, 404 for unknown units and ids, 400 for non-Linux units", async (t) => {
  const h = await startApp(t);
  const post = (body) => h.api(`${R}/runs`, { method: "POST", body });
  const bad = async (body, re) => {
    const r = await post(body);
    assert.equal(r.status, 400, JSON.stringify(r.body));
    assert.match(r.body.error, re);
  };
  await bad(jsRun(h, { workflowId: "nope" }), /Unknown workflow/);
  await bad(jsRun(h, { workflowId: "__proto__" }), /Unknown workflow/);
  await bad(jsRun(h, { authorized: false }), /authorized/);
  await bad(jsRun(h, { bogus: 1 }), /Unknown field/);
  await bad(jsRun(h, { target: { kind: "path", value: "relative/x" } }), /absolute/);
  await bad(jsRun(h, { target: { kind: "path", value: "/home/../etc/passwd" } }), /\.\./);
  await bad(jsRun(h, { target: { kind: "upload", uploadId: "up-20261012-101010-abc123" } }), /upload is not available/);
  await bad(jsRun(h, { options: { "no-such-option": true } }), /Unknown option/);
  await bad({ workflowId: "capture-process", target: { kind: "path", value: "/bin/true" }, authorized: true }, /Confirm that separately/);
  await bad({ workflowId: "list-adb-devices", authorized: true }, /REA_ENABLE_DEVICE_WRITES|device|Unknown workflow/);
  assert.equal((await h.api(`${R}/runs`, { method: "POST", body: [1, 2] })).status, 400);
  assert.equal(h.store.list().length, 0);

  assert.equal((await h.api("/api/sparks/nope/rea/status")).status, 404);
  assert.equal((await h.api("/api/sparks/win/rea/runs")).status, 400);
  assert.equal((await h.api("/api/sparks/win/rea/runs", { method: "POST", body: jsRun(h) })).status, 400);
  for (const id of ["nope", "..%2F..%2Fetc", "%2e%2e", "rea-20261012-101010-AAAA", "rea-20261012-101010-aaaa"]) {
    assert.equal((await h.api(`${R}/runs/${id}`)).status, 404, id);
    assert.equal((await h.api(`${R}/runs/${id}/stream`)).status, 404, id);
    assert.equal((await h.api(`${R}/runs/${id}/result`)).status, 404, id);
    assert.equal((await h.api(`${R}/runs/${id}/view`)).status, 404, id);
    assert.equal((await h.api(`${R}/runs/${id}`, { method: "DELETE" })).status, 404, id);
  }
  // a run of another unit is not found through this one
  h.store.add({ id: "rea-20261012-101010-cccc", sparkId: "s2", status: "completed", startedAt: 1, workflowId: "analyze-javascript-application" });
  assert.equal((await h.api(`${R}/runs/rea-20261012-101010-cccc`)).status, 404);
  assert.equal((await h.api(`/api/sparks/s2/rea/runs/rea-20261012-101010-cccc`)).status, 200);
});

test("device writes are refused unless the server enables them", async (t) => {
  const h = await startApp(t);
  const spec = (await h.api("/api/rea/spec")).body;
  const dev = spec.workflows.find((w) => w.effects.mutatesDevice);
  if (!dev) return;
  const body = { workflowId: dev.id, authorized: true, confirmExecute: true, target: { kind: "path", value: "/bin/true" } };
  const r = await h.api(`${R}/runs`, { method: "POST", body });
  assert.equal(r.status, 400);
  assert.match(r.body.error, /REA_ENABLE_DEVICE_WRITES/);
  assert.equal((await h.api("/api/rea/setup")).body.deviceWritesEnabled, false);
  h.flags.deviceWrites = true;
  assert.equal((await h.api("/api/rea/setup")).body.deviceWritesEnabled, true);
});

// ── a run, end to end ────────────────────────────────────────────────────────

test("a run: 202, stream, result, view (cached the second time), export, compare, delete", async (t) => {
  const h = await startApp(t);
  const r = await h.api(`${R}/runs`, { method: "POST", body: jsRun(h, { label: "first", timeoutMinutes: 5 }) });
  assert.equal(r.status, 202, JSON.stringify(r.body));
  const run = r.body.run;
  assert.match(run.id, RUN_ID);
  assert.equal(run.sparkId, "s1");
  assert.equal(run.status, "running");
  assert.equal(run.workflowId, "analyze-javascript-application");
  assert.ok(run.workflowLabel);
  assert.equal(run.label, "first");
  assert.equal(run.timeoutMinutes, 5);
  assert.equal(run.execClass, "static");
  assert.equal(run.effects.mutatesDevice, false);
  assert.equal(run.confirmedExecute, false);
  assert.equal(run.authorization.by, "tester");
  assert.ok(run.authorization.at > 0);
  assert.equal(run.target.kind, "path");
  assert.match(run.command, /^rea analyze-javascript-application /);
  assert.equal(r.body.job.id, run.id);

  const done = await finished(h, run.id);
  assert.equal(done.status, "completed");
  assert.equal(done.exitCode, 0);

  const stream = await h.api(`${R}/runs/${run.id}/stream?lineSince=0`);
  assert.equal(stream.status, 200);
  assert.equal(stream.body.run.id, run.id);
  assert.ok(stream.body.live === null || Array.isArray(stream.body.live.lines));
  if (stream.body.live) assert.equal(typeof stream.body.live.nextLine, "number");
  assert.ok(stream.body.live, "the finished job is still in memory");
  assert.ok(stream.body.live.lines.length > 0);
  const since = stream.body.live.nextLine;
  assert.equal((await h.api(`${R}/runs/${run.id}/stream?lineSince=${since}`)).body.live.lines.length, 0);

  const result = await h.api(`${R}/runs/${run.id}/result`);
  assert.equal(result.status, 200, JSON.stringify(result.body).slice(0, 300));
  assert.equal(result.body.run.id, run.id);
  assert.equal(typeof result.body.summary.kind, "string");
  assert.ok(Array.isArray(result.body.summary.tables));

  const v1 = await h.api(`${R}/runs/${run.id}/view?collection=modules&offset=0&limit=2`);
  assert.equal(v1.status, 200, JSON.stringify(v1.body));
  assert.equal(v1.body.cached, false);
  assert.equal(v1.body.view.view, "ok");
  assert.deepEqual(v1.body.view.request.view, { kind: "page", collection: "modules", offset: 0, limit: 2 });
  const v2 = await h.api(`${R}/runs/${run.id}/view?collection=modules&offset=0&limit=2`);
  assert.equal(v2.body.cached, true);
  assert.deepEqual(v2.body.view, v1.body.view);
  assert.equal(reaCalls(h).filter((l) => l.startsWith("inspect-analysis-view")).length, 1);
  const v3 = await h.api(`${R}/runs/${run.id}/view?kind=summary`);
  assert.equal(v3.status, 200);
  assert.equal((await h.api(`${R}/runs/${run.id}/view?collection=../x`)).status, 400);
  assert.equal((await h.api(`${R}/runs/${run.id}/view?collection=modules&limit=99999`)).status, 400);
  assert.equal((await h.api(`${R}/runs/${run.id}/view?kind=bogus`)).status, 400);

  const exp = await h.api(`${R}/runs/${run.id}/export`, { raw: true });
  assert.equal(exp.status, 200);
  assert.equal(exp.headers.get("content-disposition"), `attachment; filename="${run.id}.json"`);
  assert.match(exp.headers.get("content-type"), /^application\/json/);
  const parsed = JSON.parse(exp.text);
  assert.equal(parsed.kind, "javascript-app");

  // a second run, then compare
  const second = await startFinished(h);
  const cmp = await h.api(`${R}/compare`, { method: "POST", body: { leftRunId: run.id, rightRunId: second } });
  assert.equal(cmp.status, 200, JSON.stringify(cmp.body));
  assert.equal(cmp.body.result.kind, "compare");
  assert.equal((await h.api(`${R}/compare`, { method: "POST", body: { leftRunId: run.id, rightRunId: run.id } })).status, 400);
  assert.equal((await h.api(`${R}/compare`, { method: "POST", body: { leftRunId: run.id, rightRunId: "rea-20261012-101010-zzzz" } })).status, 404);
  assert.equal((await h.api(`${R}/compare`, { method: "POST", body: { leftRunId: "x", rightRunId: second } })).status, 400);

  const list = await h.api(`${R}/runs`);
  assert.equal(list.body.runs.length, 2);
  assert.equal((await h.api(`${R}/runs/${run.id}/refresh`, { method: "POST", body: {} })).body.state.state, "finished");

  const del = await h.api(`${R}/runs/${run.id}`, { method: "DELETE" });
  assert.equal(del.status, 200);
  assert.equal(del.body.success, true);
  assert.equal(h.store.get(run.id), null);
  assert.equal((await h.api(`${R}/runs/${run.id}`)).status, 404);
  assert.equal(fs.existsSync(path.join(h.home, ".cache", "sparkdash", "rea", "runs", run.id)), false);

  // activity events are the manager's
  assert.ok(h.events.some((e) => e.type === "rea.run.started"));
  assert.ok(h.events.some((e) => e.type === "rea.run.completed"));
});

test("a workflow without a paged view answers 400", async (t) => {
  const h = await startApp(t);
  const id = await startFinished(h, { workflowId: "inspect-artifact" });
  const r = await h.api(`${R}/runs/${id}/view`);
  assert.equal(r.status, 400);
  assert.match(r.body.error, /no paged view/);
});

// ── busy, stop, force delete ────────────────────────────────────────────────

test("busy: a second start is 409 and evicts nothing; stop; result/view/export are 409 while running; force delete stops first", async (t) => {
  const h = await startApp(t);
  const first = await startFinished(h);
  fs.writeFileSync(path.join(h.home, "rea-slow"), "");
  const a = await h.api(`${R}/runs`, { method: "POST", body: jsRun(h) });
  assert.equal(a.status, 202);
  // The on-unit liveness check reads "finished" for a few ms right after the start (reported to the lead); give it a moment.
  await new Promise((r) => setTimeout(r, 400));
  const before = h.store.list().map((r) => r.id).sort();
  assert.equal(before.length, 2);

  const b = await h.api(`${R}/runs`, { method: "POST", body: jsRun(h) });
  assert.equal(b.status, 409);
  assert.match(b.body.error, /Another REA job/);
  assert.ok(b.body.active);
  assert.deepEqual(h.store.list().map((r) => r.id).sort(), before, "a refused start stores nothing and evicts nothing");
  assert.equal((await h.api(`${R}/install`, { method: "POST", body: {} })).status, 409);

  const rid = a.body.run.id;
  for (const p of ["result", "view?collection=modules", "export"]) {
    const r = await h.api(`${R}/runs/${rid}/${p}`);
    assert.equal(r.status, 409, p);
  }

  // delete without force while running
  const noForce = await h.api(`${R}/runs/${rid}`, { method: "DELETE" });
  assert.equal(noForce.status, 409);
  assert.equal(noForce.body.canForce, false);
  assert.ok(h.store.get(rid));

  // stop
  const stopped = await h.api(`${R}/runs/${rid}/stop`, { method: "POST", body: {} });
  assert.equal(stopped.status, 200);
  assert.equal(stopped.body.success, true);
  const settled = await finished(h, rid);
  assert.equal(settled.status, "stopped");

  // a new slow run, then a forced delete stops it on the unit before removing it
  const c = await h.api(`${R}/runs`, { method: "POST", body: jsRun(h) });
  assert.equal(c.status, 202, JSON.stringify(c.body));
  const cid = c.body.run.id;
  const pidFile = path.join(h.home, ".cache", "sparkdash", "rea", "runs", cid, "pid");
  const pid = Number(await until(() => (fs.existsSync(pidFile) ? fs.readFileSync(pidFile, "utf8").trim() : "")));
  assert.ok(pid > 1 && alive(pid));
  const del = await h.api(`${R}/runs/${cid}?force=1`, { method: "DELETE" });
  assert.equal(del.status, 200);
  assert.equal(h.store.get(cid), null);
  await until(() => !alive(pid));
  assert.equal(h.store.get(first)?.status, "completed");
});

// ── uploads ──────────────────────────────────────────────────────────────────

const U = (id) => `${R}/uploads/${id}`;
const put = (h, id, rel, body, extra = "") => h.api(`${U(id)}/files?path=${encodeURIComponent(rel)}${extra}`, { method: "PUT", body, headers: { "Content-Type": "text/plain" } });

test("uploads end to end: create, put, commit, run on the upload, delete", async (t) => {
  const h = await startApp(t, { manager: { uploadMaxBytes: 5_000_000, uploadMaxFiles: 10 } });
  const c = await h.api(`${R}/uploads`, { method: "POST", body: {} });
  assert.equal(c.status, 201);
  assert.match(c.body.uploadId, UP_ID);
  assert.equal(c.body.maxBytes, 5_000_000);
  assert.equal(c.body.maxFiles, 10);
  const id = c.body.uploadId;

  const bytes = crypto.randomBytes(40_000);
  const p = await put(h, id, "sub/app.bin", bytes);
  assert.equal(p.status, 200, JSON.stringify(p.body));
  assert.deepEqual(p.body, { path: "sub/app.bin", bytes: 40_000, sha256: sha(bytes) });
  assert.equal(fs.readFileSync(path.join(upDir(h, id), "sub", "app.bin")).equals(bytes), true);

  // not committed: cannot be run on
  const early = await h.api(`${R}/runs`, { method: "POST", body: jsRun(h, { target: { kind: "upload", uploadId: id, relPath: "sub/app.bin" } }) });
  assert.equal(early.status, 400);
  assert.match(early.body.error, /not available/);

  const done = await h.api(`${U(id)}/commit`, { method: "POST", body: {} });
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.equal(done.body.uploadId, id);
  assert.equal(done.body.files, 1);
  assert.equal(done.body.bytes, 40_000);
  assert.equal(done.body.extracted, false);
  assert.equal(done.body.root, upDir(h, id));
  // committed: no more files
  assert.equal((await put(h, id, "late.bin", Buffer.from("x"))).status, 409);
  assert.equal((await h.api(`${U(id)}/commit`, { method: "POST", body: {} })).status, 200, "commit is idempotent");

  const r = await h.api(`${R}/runs`, { method: "POST", body: jsRun(h, { target: { kind: "upload", uploadId: id, relPath: "sub/app.bin" } }) });
  assert.equal(r.status, 202, JSON.stringify(r.body));
  assert.equal(r.body.run.target.kind, "upload");
  assert.equal(r.body.run.target.display, `upload ${id}/sub/app.bin`);
  const run = await finished(h, r.body.run.id);
  assert.equal(run.status, "completed");
  assert.ok(reaCalls(h).some((l) => l.includes(path.join(upDir(h, id), "sub", "app.bin"))));

  const del = await h.api(U(id), { method: "DELETE" });
  assert.equal(del.status, 200);
  assert.equal(del.body.success, true);
  assert.equal(fs.existsSync(upDir(h, id)), false);
  assert.equal((await put(h, id, "x.bin", Buffer.from("x"))).status, 404);
  assert.equal((await h.api(`${U(id)}/commit`, { method: "POST", body: {} })).status, 404);
});

test("uploads: archives are extracted on commit; a zip-slip archive is refused and nothing escapes", { skip: !hasPython }, async (t) => {
  const h = await startApp(t);
  const work = tmp("rea-api-arc-");
  const good = path.join(work, "good");
  fs.mkdirSync(path.join(good, "sub"), { recursive: true });
  fs.writeFileSync(path.join(good, "a.txt"), "alpha\n");
  fs.writeFileSync(path.join(good, "sub", "b.txt"), "beta\n");
  const tgz = path.join(work, "good.tar.gz");
  execFileSync("tar", ["czf", tgz, "-C", good, "."]);

  const id = (await h.api(`${R}/uploads`, { method: "POST", body: {} })).body.uploadId;
  const put1 = await put(h, id, "good.tar.gz", fs.readFileSync(tgz), "&archive=1");
  assert.equal(put1.status, 200, JSON.stringify(put1.body));
  const done = await h.api(`${U(id)}/commit`, { method: "POST", body: {} });
  assert.equal(done.status, 200, JSON.stringify(done.body));
  assert.equal(done.body.extracted, true);
  assert.equal(done.body.files, 2);
  assert.equal(done.body.root, path.join(upDir(h, id), "extracted"));
  // the extracted tree can be analyzed through the upload id
  const run = await h.api(`${R}/runs`, { method: "POST", body: jsRun(h, { target: { kind: "upload", uploadId: id, relPath: "a.txt" } }) });
  assert.equal(run.status, 202, JSON.stringify(run.body));
  await finished(h, run.body.run.id);

  // zip slip
  const py = `import zipfile, sys
z = zipfile.ZipFile(sys.argv[1], "w")
z.writestr("../escape.txt", "x"); z.writestr("ok.txt", "y"); z.close()`;
  const evil = path.join(work, "evil.zip");
  execFileSync("python3", ["-I", "-c", py, evil]);
  const id2 = (await h.api(`${R}/uploads`, { method: "POST", body: {} })).body.uploadId;
  assert.equal((await put(h, id2, "evil.zip", fs.readFileSync(evil), "&archive=1")).status, 200);
  const refused = await h.api(`${U(id2)}/commit`, { method: "POST", body: {} });
  assert.equal(refused.status, 400, JSON.stringify(refused.body));
  assert.equal(refused.body.code, "archive-refused");
  assert.equal(fs.existsSync(path.join(upDir(h, id2), "extracted")), false);
  assert.equal(fs.existsSync(path.join(upDir(h, id2), "..", "escape.txt")), false);
  assert.equal(fs.existsSync(path.join(upDir(h, id2), "escape.txt")), false);
  // never usable
  const use = await h.api(`${R}/runs`, { method: "POST", body: jsRun(h, { target: { kind: "upload", uploadId: id2 } }) });
  assert.equal(use.status, 400);
});

test("uploads: oversize is 413 (declared and cumulative), a missing Content-Length is 411, empty commit is 400", async (t) => {
  const h = await startApp(t, { manager: { uploadMaxBytes: 1000, uploadMaxFiles: 2 } });
  const id = (await h.api(`${R}/uploads`, { method: "POST", body: {} })).body.uploadId;

  const big = await put(h, id, "big.bin", Buffer.alloc(5000, 1));
  assert.equal(big.status, 413);
  assert.equal(big.body.code, "too-big");
  assert.deepEqual(walk(upDir(h, id)).filter((f) => !/\/\.(meta|writing)$/.test(f)), []);

  // chunked body: no Content-Length
  const status = await new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: h.port, method: "PUT", path: `${U(id)}/files?path=chunk.bin`, headers: { "Transfer-Encoding": "chunked" } }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", reject);
    req.setTimeout(15_000, () => req.destroy(new Error("timeout")));
    req.write("abc");
    req.end();
  });
  assert.equal(status, 411);

  assert.equal((await h.api(`${U(id)}/commit`, { method: "POST", body: {} })).status, 400, "nothing uploaded");

  assert.equal((await put(h, id, "a.bin", Buffer.alloc(600, 1))).status, 200);
  const second = await put(h, id, "b.bin", Buffer.alloc(600, 2));
  assert.equal(second.status, 413, JSON.stringify(second.body));
  assert.equal((await put(h, id, "b.bin", Buffer.alloc(300, 2))).status, 200);
  const third = await put(h, id, "c.bin", Buffer.alloc(1, 3));
  assert.equal(third.status, 413, "too many files");
  assert.equal(third.body.code, "too-many-files");
  assert.deepEqual(walk(upDir(h, id)).filter((f) => f.endsWith(".part")), []);
});

test("uploads: a browser that disconnects mid-file leaves no .part or marker, and the child is gone", async (t) => {
  const h = await startApp(t);
  const id = (await h.api(`${R}/uploads`, { method: "POST", body: {} })).body.uploadId;
  const before = new Set(spawned);
  const req = http.request({
    host: "127.0.0.1",
    port: h.port,
    method: "PUT",
    path: `${U(id)}/files?path=partial.bin`,
    headers: { "Content-Length": "5000000", "Content-Type": "application/octet-stream" },
  });
  req.on("error", () => {});
  req.write(Buffer.alloc(100_000, 7));
  const part = path.join(upDir(h, id), "partial.bin.part");
  await until(() => fs.existsSync(part));
  req.destroy();
  await until(() => !fs.existsSync(part) && !fs.existsSync(path.join(upDir(h, id), ".writing")));
  await until(() => [...spawned].every((c) => before.has(c) || c.exitCode !== null || c.signalCode !== null));
  assert.equal(fs.existsSync(path.join(upDir(h, id), "partial.bin")), false);
  // the upload is still usable
  assert.equal((await put(h, id, "fine.bin", Buffer.from("fine"))).status, 200);
});

test("uploads: paths and ids are validated before anything is touched", async (t) => {
  const h = await startApp(t);
  const id = (await h.api(`${R}/uploads`, { method: "POST", body: {} })).body.uploadId;
  for (const rel of ["../x", "a/../b", "/abs", "a//b", ".", "a/./b", "a b", "a\\b", "x".repeat(200), "a/".repeat(20) + "z"]) {
    const r = await put(h, id, rel, Buffer.from("x"));
    assert.equal(r.status, 400, rel);
  }
  assert.equal((await h.api(`${U(id)}/files`, { method: "PUT", body: Buffer.from("x") })).status, 400, "no path");
  assert.equal((await h.api(`${U(id)}/files?path=a&path=b`, { method: "PUT", body: Buffer.from("x") })).status, 400, "two paths");
  for (const bad of ["nope", "..%2F..%2Fetc", "%2e%2e", "up-20261012-101010-ABCDEF", "up-20261012-101010-abc12"]) {
    assert.equal((await put(h, bad, "a.txt", Buffer.from("x"))).status, 404, bad);
    assert.equal((await h.api(`${U(bad)}/commit`, { method: "POST", body: {} })).status, 404, bad);
    assert.equal((await h.api(U(bad), { method: "DELETE" })).status, 404, bad);
  }
  // well formed but unknown
  assert.equal((await put(h, "up-20261012-101010-abc123", "a.txt", Buffer.from("x"))).status, 404);
  assert.deepEqual(walk(upDir(h, id)).filter((f) => !/\/\.(meta|writing)$/.test(f)), []);
});

test("uploads are bound to the unit: another unit cannot write to, commit, delete or run on them", async (t) => {
  const h = await startApp(t);
  const id = (await h.api(`${R}/uploads`, { method: "POST", body: {} })).body.uploadId;
  assert.equal((await put(h, id, "a.bin", Buffer.from("aaa"))).status, 200);
  const S2 = "/api/sparks/s2/rea";
  assert.equal((await h.api(`${S2}/uploads/${id}/files?path=b.bin`, { method: "PUT", body: Buffer.from("x") })).status, 404);
  assert.equal((await h.api(`${S2}/uploads/${id}/commit`, { method: "POST", body: {} })).status, 404);
  // this unit still owns it
  assert.equal((await h.api(`${U(id)}/commit`, { method: "POST", body: {} })).status, 200);
});

test("uploads: a committed upload of one unit cannot be used as a target on another", async (t) => {
  const h = await startApp(t);
  const id = (await h.api(`${R}/uploads`, { method: "POST", body: {} })).body.uploadId;
  assert.equal((await put(h, id, "a.bin", Buffer.from("aaa"))).status, 200);
  assert.equal((await h.api(`${U(id)}/commit`, { method: "POST", body: {} })).status, 200);
  const body = jsRun(h, { target: { kind: "upload", uploadId: id } });
  assert.equal((await h.api("/api/sparks/s2/rea/runs", { method: "POST", body })).status, 400);
  assert.equal((await h.api(`${R}/runs`, { method: "POST", body })).status, 202);
  await until(async () => h.store.list().every((r) => r.status !== "running"));
});

// ── rate limits ──────────────────────────────────────────────────────────────

test("rate limits: upload creation and run starts answer 429 past their limits", async (t) => {
  const h = await startApp(t, { limits: { allowUpload: createRateLimiter(2, 60_000), allowRun: createRateLimiter(3, 60_000) } });
  assert.equal((await h.api(`${R}/uploads`, { method: "POST", body: {} })).status, 201);
  assert.equal((await h.api(`${R}/uploads`, { method: "POST", body: {} })).status, 201);
  const third = await h.api(`${R}/uploads`, { method: "POST", body: {} });
  assert.equal(third.status, 429);
  assert.match(third.body.error, /Too many/);
  // run-limited operations: status, then the start
  assert.equal((await h.api(`${R}/status`)).status, 200);
  assert.equal((await h.api(`${R}/runs`, { method: "POST", body: { workflowId: "nope", authorized: true } })).status, 400);
  assert.equal((await h.api(`${R}/runs`, { method: "POST", body: { workflowId: "nope", authorized: true } })).status, 400);
  assert.equal((await h.api(`${R}/runs`, { method: "POST", body: { workflowId: "nope", authorized: true } })).status, 429);
});
