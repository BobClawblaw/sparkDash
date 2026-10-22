import test, { after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import { Readable } from "node:stream";
import { ReaStore, newRunId } from "../ReaStore.js";
import { ReaManager, ReaError, explainExit, parseSections, canonicalJson } from "../ReaManager.js";
import { REA_PKG, REA_VERSION } from "../commands.js";
import { installFakeRea } from "./fakeRea.js";

// ── harness ─────────────────────────────────────────────────────────────────

const made = [];
const homes = [];
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
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const alive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

const NODE_DIR = path.dirname(process.execPath);
const spark = { id: "s1", name: "Spark 1" };

/**
 * A manager whose "unit" is a temp HOME on this machine (real bash, the fake rea launcher).
 * `extraBin`: directories put first on PATH; `onlyBin`: use exactly this PATH instead.
 */
function setup({ manager = {}, env = {}, extraBin = [], onlyBin = null, fake = true } = {}) {
  const home = tmp("rea-home-");
  homes.push(home);
  if (fake) installFakeRea(home);
  fs.mkdirSync(path.join(home, "data"), { recursive: true });
  fs.writeFileSync(path.join(home, "data", "sample.bin"), "hello rea\n");
  const state = tmp("rea-state-");
  const store = new ReaStore({ file: path.join(state, "runs.json"), resultsDir: path.join(state, "res") });
  const events = [];
  const stdoutBytes = [];
  const PATH = onlyBin ?? [...extraBin, NODE_DIR, "/usr/local/bin", "/usr/bin", "/bin"].join(":");
  const spawnProcess = (_s, cmd, opts = {}) => {
    const child = spawn("bash", ["-c", cmd], {
      env: { HOME: home, PATH, LANG: "C", SPARKDASH_REA_GRACE: "2", SPARKDASH_REA_NODE_SYSTEM_DIRS: "", SPARKDASH_REA_TICK: "1", SPARKDASH_REA_LOGMAX: "100000", ...env },
      stdio: [opts.stdin ? "pipe" : "ignore", "pipe", "pipe"],
      detached: true,
    });
    spawned.add(child);
    let n = 0;
    child.stdout.on("data", (b) => {
      n += b.length;
    });
    child.on("close", () => {
      stdoutBytes.push(n);
      spawned.delete(child);
    });
    return child;
  };
  const mgr = new ReaManager({ store, onEvent: (e) => events.push(e), spawnProcess, ...manager });
  const self = { home, store, mgr, events, stdoutBytes, spawnProcess, state };
  return self;
}

const evTypes = (h) => h.events.map((e) => e.type);
const reaCalls = (h) => {
  try {
    return fs.readFileSync(path.join(h.home, "rea.argv"), "utf8").split("\n").filter(Boolean);
  } catch {
    return [];
  }
};

function startRun(h, { workflowId = "inspect-artifact", label = "Inspect an application package", argv, paths, timeoutSeconds = 60, runId = newRunId(), mgr = h.mgr } = {}) {
  const target = path.join(h.home, "data", "sample.bin");
  const run = {
    id: runId,
    sparkId: spark.id,
    status: "running",
    startedAt: Date.now(),
    finishedAt: null,
    exitCode: null,
    note: null,
    workflowId,
    workflowLabel: label,
    command: `rea ${workflowId} sample.bin`,
    resultCached: false,
    summary: null,
  };
  h.store.add(run);
  const r = mgr.startReaRun(spark, { run, argv: argv ?? [workflowId, target, "--json"], paths: paths ?? [target], timeoutSeconds });
  return { id: runId, r };
}
const settled = (h, id) => until(() => h.store.get(id).status !== "running");
const finishedRun = async (h, opts) => {
  const { id, r } = startRun(h, opts);
  assert.equal(r.ok, true, String(r.reason));
  await settled(h, id);
  await until(() => h.store.get(id).resultCached || h.store.get(id).status !== "completed");
  await until(() => h.events.some((e) => /^rea\.run\.(completed|failed|stopped)$/.test(e.type) && e.sparkId === spark.id) || h.store.get(id).status !== "running");
  return id;
};

// ── pure helpers ────────────────────────────────────────────────────────────

test("explainExit: every wrapper exit code reads as a sentence; rea's own code is appended", () => {
  assert.equal(explainExit(0), null);
  for (const c of [2, 10, 11, 124, 126, 127, 143]) assert.ok(explainExit(c), String(c));
  assert.match(explainExit(10, "target_unavailable"), /target_unavailable/);
  assert.match(explainExit(126, "missing_analysis_engine"), /missing_analysis_engine/);
  assert.match(explainExit(99), /99/);
  assert.equal(explainExit(null), null);
});

test("parseSections and canonicalJson", () => {
  const S = "__S_";
  const buf = Buffer.from(`${S}STATUS\n0\n${S}SIZE\n5\n${S}BODY\nab\ncd`, "utf8");
  const { head, body } = parseSections(buf, S);
  assert.deepEqual(head, { STATUS: "0", SIZE: "5" });
  assert.equal(body.toString(), "ab\ncd");
  const none = parseSections(Buffer.from(`${S}NORESULT\n`), S);
  assert.equal(none.body, null);
  assert.notEqual(none.head.NORESULT, undefined);
  // a body that merely looks like a section is still the body (the first BODY marker wins)
  const tricky = parseSections(Buffer.from(`${S}SIZE\n1\n${S}BODY\n${S}STATUS\n9\n`), S);
  assert.deepEqual(tricky.head, { SIZE: "1" });
  assert.equal(canonicalJson({ b: 1, a: { d: [2, { y: 1, x: 2 }], c: null } }), '{"a":{"c":null,"d":[2,{"x":2,"y":1}]},"b":1}');
});

// ── status ──────────────────────────────────────────────────────────────────

test("status: node, launcher, version, doctor checks, providers and engines are parsed", async () => {
  const bin = tmp("rea-bin-");
  fs.writeFileSync(path.join(bin, "adb"), "#!/bin/bash\nexit 0\n", { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "jadx"), "#!/bin/bash\nexit 0\n", { mode: 0o755 });
  const h = setup({ extraBin: [bin] });
  const s = await h.mgr.status(spark);
  assert.equal(s.reachable, true);
  assert.equal(s.node.ok, true);
  assert.equal(s.node.path, process.execPath);
  assert.match(s.node.version, /^v\d+\./);
  assert.equal(s.installed, true);
  assert.equal(s.version, "6.4.0");
  assert.equal(s.pinnedVersion, REA_VERSION);
  assert.equal(s.upToDate, true);
  assert.equal(s.launcher, path.join(h.home, ".local", "bin", "rea-sparkdash"));
  assert.equal(s.doctor.healthy, false);
  assert.equal(s.doctor.environmentHealthy, true);
  assert.deepEqual(s.doctor.checks.map((c) => [c.name, c.ok, c.classification]), [["node", true, "healthy"], ["ghidra", false, "missing_analysis_engine"]]);
  assert.equal(s.doctor.checks[1].remediation, "Set GHIDRA_INSTALL_DIR.");
  assert.equal(s.providers.length, 1);
  assert.equal(s.providers[0].id, "disassemble");
  assert.equal(s.providers[0].available, false);
  assert.equal(s.providers[0].reason, "no provider");
  const eng = Object.fromEntries(s.engines.map((e) => [e.id, e]));
  assert.equal(eng.adb.found, true);
  assert.equal(eng.adb.path, path.join(bin, "adb"));
  assert.equal(eng.jadx.found, true);
  assert.equal(eng.ghidra.found, false);
  assert.equal(eng.ghidra.path, undefined);
  assert.match(eng.ghidra.unlocks, /native analysis/i);
  assert.equal(s.error, null);
  // concurrent callers share one in-flight call
  const [a, b] = [h.mgr.status(spark), h.mgr.status(spark)];
  assert.strictEqual(a, b);
  await a;
});

test("status: an old version is not up to date; no launcher means not installed and no reports", async () => {
  const old = setup({ fake: false });
  installFakeRea(old.home, { version: "6.3.0" });
  const s1 = await old.mgr.status(spark);
  assert.equal(s1.installed, true);
  assert.equal(s1.version, "6.3.0");
  assert.equal(s1.upToDate, false);
  const none = setup({ fake: false });
  const s2 = await none.mgr.status(spark);
  assert.equal(s2.reachable, true);
  assert.equal(s2.installed, false);
  assert.equal(s2.version, null);
  assert.equal(s2.upToDate, false);
  assert.equal(s2.doctor, null);
  assert.deepEqual(s2.providers, []);
  assert.ok(s2.engines.length > 0);
});

test("status: a unit that cannot be spawned reports unreachable, never throws", async () => {
  const store = new ReaStore({ file: path.join(tmp("rea-state-"), "r.json"), resultsDir: path.join(tmp("rea-state-"), "res") });
  const mgr = new ReaManager({
    store,
    spawnProcess: () => {
      throw new Error("no route to host");
    },
  });
  const s = await mgr.status(spark);
  assert.equal(s.reachable, false);
  assert.equal(s.installed, false);
  assert.match(s.error, /no route/);
});

// ── runs ────────────────────────────────────────────────────────────────────

test("run: result is captured, summarized, cached; events and the index carry only headline numbers", async () => {
  const h = setup();
  const target = path.join(h.home, "data", "sample.bin");
  const { id, r } = startRun(h);
  assert.equal(r.ok, true);
  assert.equal(r.job.kind, "run");
  await settled(h, id);
  await until(() => h.store.get(id).resultCached);
  const run = h.store.get(id);
  assert.equal(run.status, "completed");
  assert.equal(run.exitCode, 0);
  assert.equal(run.note, null);
  assert.ok(run.finishedAt);
  assert.equal(run.summary.kind, "generic");
  assert.equal(run.summary.headline.bytes, 10);
  assert.equal(run.summary.headline.kind, "artifact");
  assert.equal(run.summary.tables.every((t) => t.rows === undefined), true);
  assert.equal(run.resultBytes > 10, true);
  assert.match(run.resultSha256, /^[0-9a-f]{64}$/);
  const bundle = h.store.loadBundle(id);
  const text = bundle.result;
  assert.equal(JSON.parse(text).path, target);
  assert.equal(crypto.createHash("sha256").update(text).digest("hex"), run.resultSha256);
  assert.equal(bundle.size, run.resultBytes);
  assert.equal(h.mgr.loadResult(id).summary.headline.bytes, 10);
  await until(() => h.events.some((e) => e.type === "rea.run.completed"));
  assert.deepEqual(evTypes(h).filter((t) => t.startsWith("rea.run")), ["rea.run.started", "rea.run.completed"]);
  const live = h.mgr.readJob(spark.id, id, {});
  assert.equal(live.progress.stage, "done");
  assert.ok(live.lines.some((l) => /\[sparkdash\] rea inspect-artifact sample\.bin/.test(l.text)));
  assert.equal(live.lines.some((l) => l.text.includes("__SPARKDASH")), false, "the exit marker is not shown");
  assert.match(reaCalls(h).at(-1), /inspect-artifact .*sample\.bin --json/);
});

test("run: a javascript-app workflow keeps the shape; an error object printed with exit 0 settles as failed with its code", async () => {
  const h = setup();
  const id = await finishedRun(h, { workflowId: "analyze-javascript-application", label: "Analyze a JavaScript/Electron application" });
  let run = h.store.get(id);
  assert.equal(run.status, "completed");
  // the stand-in prints a plain object, not an Evidence envelope: shown generically, facts kept
  assert.equal(run.summary.kind, "generic");
  assert.equal(run.summary.headline.path, path.join(h.home, "data", "sample.bin"));
  assert.equal(run.summary.tables.find((t) => t.id === "modules").total, 2);
  assert.deepEqual(h.store.loadBundle(id).summary.limitations, ["fake"]);

  fs.writeFileSync(path.join(h.home, "rea-error-zero"), "");
  const bad = await finishedRun(h, {});
  run = h.store.get(bad);
  assert.equal(run.status, "failed");
  assert.equal(run.exitCode, 10);
  assert.match(run.note, /forced/);
  assert.equal(run.summary.findings[0].severity, "error");
  assert.equal(run.summary.findings[0].code, "forced");
  assert.ok(h.events.some((e) => e.type === "rea.run.failed" && e.severity === "error" && /exit 10/.test(e.message)));
});

test("run: failures map the wrapper's exit code to a note (target missing -> 2, engine missing -> 126, time limit -> 124)", async () => {
  const h = setup();
  const missing = path.join(h.home, "data", "nope.bin");
  const a = startRun(h, { argv: ["inspect-artifact", missing, "--json"], paths: [missing] });
  await settled(h, a.id);
  assert.equal(h.store.get(a.id).exitCode, 2);
  assert.equal(h.store.get(a.id).status, "failed");
  assert.match(h.store.get(a.id).note, /not usable/);

  fs.writeFileSync(path.join(h.home, "rea-error-code"), "missing_analysis_engine");
  const b = startRun(h);
  await settled(h, b.id);
  await until(() => h.store.get(b.id).note);
  assert.equal(h.store.get(b.id).exitCode, 126);
  assert.match(h.store.get(b.id).note, /missing_analysis_engine/);
  fs.rmSync(path.join(h.home, "rea-error-code"));

  fs.writeFileSync(path.join(h.home, "rea-slow"), "");
  const c = startRun(h, { timeoutSeconds: 2 });
  await settled(h, c.id);
  assert.equal(h.store.get(c.id).exitCode, 124);
  assert.match(h.store.get(c.id).note, /time limit/);
});

test("run: a unit without REA installed fails with 127 and the wrapper's explanation", async () => {
  const h = setup({ fake: false });
  const { id } = startRun(h);
  await settled(h, id);
  const run = h.store.get(id);
  assert.equal(run.status, "failed");
  assert.equal(run.exitCode, 127);
  assert.match(run.note, /not installed/);
  assert.ok(h.mgr.readJob(spark.id, id, {}).lines.some((l) => /REA is not installed/.test(l.text)));
});

test("run: a big result is never pulled; the summary comes from ONE view-summary projection", async () => {
  const h = setup({ manager: { maxInline: 1000 } });
  fs.writeFileSync(path.join(h.home, "rea-big"), "");
  const id = await finishedRun(h, { workflowId: "analyze-javascript-application", label: "Analyze" });
  await until(() => h.store.get(id).resultCached);
  const run = h.store.get(id);
  assert.equal(run.status, "completed");
  assert.ok(run.resultBytes > 300_000);
  assert.equal(run.summary.truncated, true);
  assert.equal(run.summary.headline.resultBytes, run.resultBytes);
  assert.equal(run.summary.headline.view, "ok", "facts of the projection are the summary");
  assert.match(run.summary.limitations.join(" "), /stays on the unit/);
  const bundle = h.store.loadBundle(id);
  assert.equal(bundle.result, null);
  assert.equal(bundle.onUnit, true);
  assert.equal(reaCalls(h).filter((l) => l.startsWith("inspect-analysis-view ")).length, 1);
  assert.ok(Math.max(...h.stdoutBytes) < 200_000, "no program ever printed the 300 KB body");
  // the on-unit file is still intact
  assert.ok(fs.statSync(path.join(h.home, ".cache", "sparkdash", "rea", "runs", id, "result.json")).size > 300_000);
});

test("run: a big result of a workflow with no view keeps only size and hash", async () => {
  const h = setup({ manager: { maxInline: 1000 } });
  fs.writeFileSync(path.join(h.home, "rea-big"), "");
  const id = await finishedRun(h, { workflowId: "inspect-artifact" });
  await until(() => h.store.get(id).resultCached);
  const run = h.store.get(id);
  assert.equal(run.summary.truncated, true);
  assert.match(run.summary.limitations.join(" "), /only its size and hash/);
  assert.match(run.resultSha256, /^[0-9a-f]{64}$/);
  assert.equal(reaCalls(h).filter((l) => l.startsWith("inspect-analysis-view")).length, 0);
  assert.equal(h.store.loadBundle(id).result, null);
});

test("run: a result cut at the size cap (exit 11) is failed, flagged truncated and not pulled", async () => {
  const h = setup();
  fs.writeFileSync(path.join(h.home, "rea-big"), "");
  const target = path.join(h.home, "data", "sample.bin");
  const run = { id: newRunId(), sparkId: spark.id, status: "running", startedAt: Date.now(), workflowId: "analyze-javascript-application", workflowLabel: "Analyze", command: "rea x" };
  h.store.add(run);
  const r = h.mgr.startReaRun(spark, { run, argv: ["analyze-javascript-application", target, "--json"], paths: [target], timeoutSeconds: 60, resultCapBytes: 5000 });
  assert.equal(r.ok, true);
  await settled(h, run.id);
  await until(() => h.store.get(run.id).resultCached);
  const got = h.store.get(run.id);
  assert.equal(got.status, "failed");
  assert.equal(got.exitCode, 11);
  assert.match(got.note, /size limit/);
  assert.equal(got.summary.truncated, true);
  assert.equal(reaCalls(h).filter((l) => l.startsWith("inspect-analysis-view")).length, 0, "a cut-off result is not projected");
});

test("stop: TERM reaches rea, the run settles as stopped (143) with its event; stopping a finished run is a no-op", async () => {
  const h = setup();
  fs.writeFileSync(path.join(h.home, "rea-slow"), "");
  const { id } = startRun(h);
  await until(() => reaCalls(h).length > 0);
  const stop = await h.mgr.stopRun(spark, id);
  assert.equal(stop.ok, true, JSON.stringify(stop));
  await settled(h, id);
  const run = h.store.get(id);
  assert.equal(run.status, "stopped");
  assert.equal(run.exitCode, 143);
  assert.match(run.note, /stopped/);
  await until(() => h.events.some((e) => e.type === "rea.run.stopped"));
  assert.equal(h.mgr.summary(h.mgr.latestJob(spark.id)).status, "stopped");
  const again = await h.mgr.stopRun(spark, id);
  assert.equal(again.ok, false);
  assert.match(again.output, /not running/);
});

test("stop: a stop request that did not happen is taken back, so a later failure is not shown as stopped", async () => {
  const h = setup();
  fs.writeFileSync(path.join(h.home, "rea-slow"), "");
  const { id } = startRun(h, { timeoutSeconds: 3 });
  await until(() => reaCalls(h).length > 0);
  const miss = await h.mgr.stopRun(spark, id, { timeoutMs: 1 });
  assert.equal(miss.ok, false);
  assert.equal(h.mgr.activeJob(spark.id).stopRequested, false);
  await settled(h, id);
  assert.equal(h.store.get(id).status, "failed", "the time limit ended it, nobody stopped it");
  assert.equal(h.store.get(id).exitCode, 124);
});

test("stop: a rea that ignores TERM is ended after the grace period and the run still settles as stopped", async () => {
  const h = setup();
  fs.writeFileSync(path.join(h.home, "rea-ignore-term"), "");
  const { id } = startRun(h);
  await until(() => reaCalls(h).length > 0);
  const stop = await h.mgr.stopRun(spark, id);
  assert.equal(stop.ok, true);
  await settled(h, id);
  assert.equal(h.store.get(id).status, "stopped");
  assert.equal(h.store.get(id).exitCode, 143);
  const pid = Number(fs.readFileSync(path.join(h.home, "rea.pid"), "utf8"));
  await until(() => !alive(pid));
});

test("attach: a settled run is not settled twice (no second event, record untouched)", async () => {
  const h = setup();
  const id = await finishedRun(h, {});
  await until(() => h.events.some((e) => e.type === "rea.run.completed"));
  const before = h.store.get(id);
  const nEvents = h.events.length;
  const att = h.mgr.attachRun(spark, before);
  assert.equal(att.ok, true);
  assert.equal(att.job.kind, "attach");
  await until(() => h.mgr.latestJob(spark.id).status !== "running");
  await sleep(300);
  assert.equal(h.events.length, nEvents);
  assert.deepEqual(h.store.get(id), before);
  assert.ok(h.mgr.readJob(spark.id, id, {}).lines.some((l) => /\[sparkdash\] rea inspect-artifact/.test(l.text)), "the output was replayed");
});

test("attach: a new manager (dashboard restart) re-attaches to a live run and settles it when it ends; canStart sees the orphan", async () => {
  const h = setup();
  fs.writeFileSync(path.join(h.home, "rea-slow"), "");
  const { id } = startRun(h);
  await until(() => reaCalls(h).length > 0);
  assert.equal(h.mgr.cancelWatch(spark.id), true);
  await until(() => h.mgr.latestJob(spark.id).status !== "running");
  assert.equal(h.store.get(id).status, "running", "a lost watcher leaves the run as it is");
  assert.equal(h.events.filter((e) => /^rea\.run\.(completed|failed|stopped)$/.test(e.type)).length, 0);
  assert.equal(h.mgr.canStart(spark).ok, false);
  assert.equal(h.mgr.canStart(spark).reason, "busy");

  const mgr2 = new ReaManager({ store: h.store, onEvent: (e) => h.events.push(e), spawnProcess: h.spawnProcess });
  assert.equal(mgr2.canStart(spark).ok, false, "an orphaned running record blocks a new run");
  const att = mgr2.attachRun(spark, h.store.get(id));
  assert.equal(att.ok, true);
  await sleep(300);
  const stop = await mgr2.stopRun(spark, id);
  assert.equal(stop.ok, true);
  await settled(h, id);
  assert.equal(h.store.get(id).status, "stopped");
  await until(() => h.events.some((e) => e.type === "rea.run.stopped"));
  assert.equal(h.events.filter((e) => e.type === "rea.run.stopped").length, 1);
  assert.equal(mgr2.canStart(spark).ok, true);
});

test("check: a killed wrapper settles as failed with an explanation; gone and finished are mapped", async () => {
  const h = setup();
  fs.writeFileSync(path.join(h.home, "rea-slow"), "");
  const { id } = startRun(h);
  const pidFile = path.join(h.home, ".cache", "sparkdash", "rea", "runs", id, "pid");
  const pid = await until(() => {
    try {
      const n = Number(fs.readFileSync(pidFile, "utf8"));
      return n > 1 ? n : 0;
    } catch {
      return 0;
    }
  });
  await until(() => reaCalls(h).length > 0);
  killGroup(pid);
  await until(() => h.mgr.latestJob(spark.id).status !== "running");
  assert.equal(h.store.get(id).status, "running", "the watcher only knows the connection ended");
  const chk = await h.mgr.checkRun(spark, id);
  assert.deepEqual(chk, { state: "finished", exitCode: -1 });
  const run = h.store.get(id);
  assert.equal(run.status, "failed");
  assert.equal(run.exitCode, null);
  assert.match(run.note, /without reporting a result/);

  // finished runs: re-settle from the exit file (and capture the result)
  fs.rmSync(path.join(h.home, "rea-slow"));
  const ok = await finishedRun(h, {});
  h.store.update(ok, { status: "running", resultCached: false, summary: null, exitCode: null });
  const c2 = await h.mgr.checkRun(spark, ok);
  assert.deepEqual(c2, { state: "finished", exitCode: 0 });
  assert.equal(h.store.get(ok).status, "completed");
  assert.equal(h.store.get(ok).resultCached, true);

  // stopped (143) and gone
  const rd = path.join(h.home, ".cache", "sparkdash", "rea", "runs");
  const idStopped = newRunId();
  fs.mkdirSync(path.join(rd, idStopped), { recursive: true });
  fs.writeFileSync(path.join(rd, idStopped, "exit"), "143\n");
  h.store.add({ id: idStopped, sparkId: spark.id, status: "running", workflowId: "inspect-artifact" });
  assert.equal((await h.mgr.checkRun(spark, idStopped)).exitCode, 143);
  assert.equal(h.store.get(idStopped).status, "stopped");
  const idGone = newRunId();
  h.store.add({ id: idGone, sparkId: spark.id, status: "running" });
  assert.deepEqual(await h.mgr.checkRun(spark, idGone), { state: "gone" });
  assert.equal(h.store.get(idGone).status, "gone");
});

test("canStart: free, then busy with a live job or an orphaned record; a busy start changes nothing", async () => {
  const h = setup();
  assert.deepEqual(h.mgr.canStart(spark), { ok: true });
  fs.writeFileSync(path.join(h.home, "rea-slow"), "");
  const a = startRun(h);
  assert.equal(a.r.ok, true);
  const busy = h.mgr.canStart(spark);
  assert.equal(busy.ok, false);
  assert.equal(busy.active.id, a.id);
  // another start (record stored by the caller first) is refused and the live job is untouched
  const second = startRun(h);
  assert.equal(second.r.ok, false);
  assert.equal(second.r.reason, "busy");
  assert.equal(h.mgr.activeJob(spark.id).id, a.id);
  assert.equal(h.events.filter((e) => e.type === "rea.run.started").length, 1);
  assert.equal(h.mgr.installRea(spark).ok, false, "no install while a run is live");
  await h.mgr.stopRun(spark, a.id);
  await settled(h, a.id);
  // the refused record the test stored is still "running": a real route removes it; do the same
  h.store.remove(second.id);
  assert.deepEqual(h.mgr.canStart(spark), { ok: true });
  // bad arguments are reported, not thrown
  const run = { id: newRunId(), sparkId: spark.id, status: "running", command: "x" };
  h.store.add(run);
  const bad = h.mgr.startReaRun(spark, { run, argv: ["inspect-artifact"], paths: [], timeoutSeconds: 0 });
  assert.equal(bad.ok, false);
  assert.equal(bad.reason, "invalid");
});

// ── views, export, compare ──────────────────────────────────────────────────

const viewReq = (v) => v;

test("view: projected on the unit, cached by (run, view) and served without touching the unit again", async () => {
  const h = setup();
  const id = await finishedRun(h, { workflowId: "analyze-javascript-application", label: "Analyze" });
  const run = h.store.get(id);
  const page = viewReq({ kind: "page", collection: "modules", offset: 0, limit: 5 });
  const r1 = await h.mgr.readView(spark, run, page);
  assert.equal(r1.ok, true, JSON.stringify(r1));
  assert.equal(r1.view.view, "ok");
  assert.equal(r1.cached, false);
  assert.equal(r1.view.request.source.kind, "inline", "REA 6.4.0 takes inline evidence: the unit program streams result.json in");
  assert.deepEqual(r1.view.request.view, page);
  const before = reaCalls(h).filter((l) => l.startsWith("inspect-analysis-view")).length;
  const r2 = await h.mgr.readView(spark, run, { limit: 5, offset: 0, collection: "modules", kind: "page" });
  assert.equal(r2.ok, true);
  assert.equal(r2.cached, true, "key order does not matter");
  assert.deepEqual(r2.view, r1.view);
  assert.equal(reaCalls(h).filter((l) => l.startsWith("inspect-analysis-view")).length, before);
  const r3 = await h.mgr.readView(spark, run, { kind: "summary" });
  assert.equal(r3.cached, false);
  assert.equal(r3.view.request.view.kind, "summary");
  // concurrent identical requests run once
  const other = { kind: "page", collection: "modules", offset: 5, limit: 5 };
  const [x, y] = await Promise.all([h.mgr.readView(spark, run, other), h.mgr.readView(spark, run, other)]);
  assert.equal(x.ok && y.ok, true);
  assert.equal(reaCalls(h).filter((l) => l.startsWith("inspect-analysis-view")).length, before + 2);
});

test("view: over the cap is an error, never partial JSON, and nothing is cached; rea errors and running runs are errors", async () => {
  const h = setup({ manager: { viewMaxBytes: 100_000 } });
  const id = await finishedRun(h, { workflowId: "analyze-javascript-application", label: "Analyze" });
  const run = h.store.get(id);
  fs.writeFileSync(path.join(h.home, "rea-bigview"), "");
  const big = await h.mgr.readView(spark, run, { kind: "summary" });
  assert.equal(big.ok, false);
  assert.match(big.error, /larger than/);
  assert.equal(big.view, undefined);
  fs.rmSync(path.join(h.home, "rea-bigview"));
  const small = await h.mgr.readView(spark, run, { kind: "summary" });
  assert.equal(small.ok, true, "the failed attempt was not cached");
  assert.equal(small.cached, false);

  fs.writeFileSync(path.join(h.home, "rea-error-code"), "invalid_request");
  const err = await h.mgr.readView(spark, run, { kind: "page", collection: "modules", offset: 0, limit: 1 });
  assert.equal(err.ok, false);
  assert.match(err.error, /invalid_request/);
  fs.rmSync(path.join(h.home, "rea-error-code"));
  const again = await h.mgr.readView(spark, run, { kind: "page", collection: "modules", offset: 0, limit: 1 });
  assert.equal(again.ok, true);

  assert.equal((await h.mgr.readView(spark, { ...run, status: "running" }, { kind: "summary" })).ok, false);
  const noFile = newRunId();
  h.store.add({ id: noFile, sparkId: spark.id, status: "failed" });
  const none = await h.mgr.readView(spark, h.store.get(noFile), { kind: "summary" });
  assert.equal(none.ok, false);
  assert.match(none.error, /no longer on the unit/);
  assert.equal((await h.mgr.readView(spark, run, null)).ok, false);
});

test("export: from the cached body when there is one, else from the unit; over the limit is an error", async () => {
  const h = setup();
  const id = await finishedRun(h, {});
  const onDisk = fs.readFileSync(path.join(h.home, ".cache", "sparkdash", "rea", "runs", id, "result.json"));
  const e1 = await h.mgr.exportResult(spark, h.store.get(id));
  assert.equal(e1.ok, true);
  assert.deepEqual(e1.text, onDisk);
  assert.equal(e1.bytes, onDisk.length);
  const callsBefore = h.stdoutBytes.length;
  assert.ok(callsBefore > 0);

  // body kept on the unit (maxInline small): the export program streams it
  const h2 = setup({ manager: { maxInline: 500 } });
  fs.writeFileSync(path.join(h2.home, "rea-big"), "");
  const id2 = await finishedRun(h2, {});
  await until(() => h2.store.get(id2).resultCached);
  const e2 = await h2.mgr.exportResult(spark, h2.store.get(id2));
  assert.equal(e2.ok, true, JSON.stringify(e2).slice(0, 200));
  assert.equal(e2.bytes, fs.statSync(path.join(h2.home, ".cache", "sparkdash", "rea", "runs", id2, "result.json")).size);
  assert.ok(Buffer.isBuffer(e2.text));
  assert.equal(JSON.parse(e2.text.toString("utf8")).kind, "artifact");

  const h3 = setup({ manager: { maxInline: 500, exportMaxBytes: 1000 } });
  fs.writeFileSync(path.join(h3.home, "rea-big"), "");
  const id3 = await finishedRun(h3, {});
  await until(() => h3.store.get(id3).resultCached);
  const e3 = await h3.mgr.exportResult(spark, h3.store.get(id3));
  assert.equal(e3.ok, false);
  assert.match(e3.error, /export limit/);
  assert.equal((await h.mgr.exportResult(spark, { ...h.store.get(id), status: "running" })).ok, false);
});

test("compare: two finished runs of this unit are compared by rea; everything else is refused", async () => {
  const h = setup();
  const a = await finishedRun(h, {});
  const b = await finishedRun(h, {});
  const left = h.store.get(a);
  const right = h.store.get(b);
  const res = await h.mgr.compareRuns(spark, left, right);
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.equal(res.result.kind, "compare");
  assert.equal(typeof res.result.left, "number");
  assert.match(reaCalls(h).at(-1), /^compare /);
  assert.equal((await h.mgr.compareRuns(spark, left, left)).ok, false);
  assert.equal((await h.mgr.compareRuns(spark, left, { ...right, status: "running" })).ok, false);
  assert.equal((await h.mgr.compareRuns(spark, left, { ...right, sparkId: "other" })).ok, false);
  assert.equal((await h.mgr.compareRuns({ id: "other" }, left, right)).ok, false);
  const gone = newRunId();
  h.store.add({ id: gone, sparkId: spark.id, status: "completed" });
  const miss = await h.mgr.compareRuns(spark, left, h.store.get(gone));
  assert.equal(miss.ok, false);
  assert.match(miss.error, /no longer on the unit/);
});

// ── install ─────────────────────────────────────────────────────────────────

const FAKE_REA_MJS = `
const a = process.argv.slice(2);
if (a[0] === "--version") console.log("6.4.0");
else if (a[0] === "doctor") console.log(JSON.stringify({ healthy: true, scope_checks: [] }));
else console.log(JSON.stringify({ argv: a }));
`;
function stubTools() {
  const dir = tmp("rea-stub-");
  const tree = path.join(dir, "tree");
  fs.mkdirSync(path.join(tree, "node_modules", REA_PKG, "scripts"), { recursive: true });
  fs.writeFileSync(path.join(tree, "node_modules", REA_PKG, "scripts", "rea.mjs"), FAKE_REA_MJS);
  const bin = path.join(dir, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, "node"), `#!/bin/bash\nexec "${process.execPath}" "$@"\n`, { mode: 0o755 });
  fs.writeFileSync(
    path.join(bin, "npm"),
    `#!/bin/bash
[ "$1" = ci ] || exit 9
[ -f package.json ] && [ -f package-lock.json ] || exit 8
if [ -n "$FAKE_NPM_FAIL" ]; then echo "npm ERR! network"; exit 1; fi
mkdir -p node_modules && cp -R "${tree}/node_modules/." node_modules/
echo "added 144 packages"
`,
    { mode: 0o755 }
  );
  return bin;
}

test("install: success streams the output, emits rea.install.completed and leaves a working launcher", async () => {
  const bin = stubTools();
  const h = setup({ fake: false, onlyBin: `${bin}:/usr/bin:/bin` });
  const r = h.mgr.installRea(spark);
  assert.equal(r.ok, true);
  assert.equal(r.job.kind, "install");
  assert.equal(h.mgr.installRea(spark).ok, false, "one job per unit");
  assert.equal(h.mgr.installRea(spark).reason, "busy");
  await until(() => r.job.status !== "running", 60_000);
  assert.equal(r.job.status, "completed");
  assert.equal(r.job.exitCode, 0);
  await until(() => h.events.some((e) => e.type === "rea.install.completed"));
  const ev = h.events.find((e) => e.type === "rea.install.completed");
  assert.equal(ev.severity, "success");
  assert.equal(ev.sparkId, spark.id);
  assert.ok(h.mgr.readJob(spark.id, r.job.id, {}).lines.some((l) => /npm ci --ignore-scripts/.test(l.text)));
  assert.ok(fs.existsSync(path.join(h.home, ".local", "bin", "rea-sparkdash")));
  const st = await h.mgr.status(spark);
  assert.equal(st.installed, true);
  assert.equal(st.version, "6.4.0");
  assert.equal(st.upToDate, true);
});

test("install: a failing npm or a missing node emits rea.install.failed with the program's exit code", async () => {
  const bin = stubTools();
  const h = setup({ fake: false, onlyBin: `${bin}:/usr/bin:/bin`, env: { FAKE_NPM_FAIL: "1" } });
  const r = h.mgr.installRea(spark);
  await until(() => r.job.status !== "running", 60_000);
  assert.equal(r.job.status, "failed");
  assert.equal(r.job.exitCode, 3);
  await until(() => h.events.some((e) => e.type === "rea.install.failed"));
  assert.equal(h.events.find((e) => e.type === "rea.install.failed").severity, "error");
  assert.equal(fs.existsSync(path.join(h.home, ".local", "bin", "rea-sparkdash")), false);

  const nonode = setup({ fake: false, onlyBin: "/usr/bin:/bin" });
  // /usr/bin may hold a system node; only assert when it does not
  const hasNode = fs.existsSync("/usr/bin/node") || fs.existsSync("/bin/node");
  if (!hasNode) {
    const r2 = nonode.mgr.installRea(spark);
    await until(() => r2.job.status !== "running", 30_000);
    assert.equal(r2.job.exitCode, 127);
    await until(() => nonode.events.some((e) => e.type === "rea.install.failed"));
  }
});

// ── uploads (real programs) ─────────────────────────────────────────────────

const upDir = (h, id) => path.join(h.home, ".cache", "sparkdash", "rea", "uploads", id);
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");
const bodyOf = (...bufs) => Readable.from(bufs);
const noPart = (dir) => {
  const parts = [];
  const walk = (d) => {
    for (const f of fs.readdirSync(d, { withFileTypes: true })) {
      if (f.isDirectory()) walk(path.join(d, f.name));
      else if (f.name.endsWith(".part")) parts.push(path.join(d, f.name));
    }
  };
  walk(dir);
  return parts;
};
const hasPython = (() => {
  try {
    execFileSync("python3", ["-c", "import zipfile, tarfile"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();

test("uploads: create, put (with backpressure), commit; the id is server-allocated and bound to the unit", async () => {
  const h = setup({ manager: { uploadMaxBytes: 50_000_000, uploadMaxFiles: 100 } });
  const up = await h.mgr.createUpload(spark);
  assert.match(up.uploadId, /^up-[0-9]{8}-[0-9]{6}-[a-z0-9]{6}$/);
  assert.equal(up.maxBytes, 50_000_000);
  assert.equal(up.maxFiles, 100);
  assert.ok(fs.statSync(upDir(h, up.uploadId)).isDirectory());
  assert.equal(h.mgr.isCommittedUpload(spark.id, up.uploadId), false);
  assert.equal(h.mgr.uploadRoot(spark.id, up.uploadId), null);

  const small = Buffer.from("small file\n");
  const r1 = await h.mgr.putUpload(spark, up.uploadId, "a/small.txt", bodyOf(small), { maxBytes: 1000 });
  assert.deepEqual(r1, { bytes: small.length, sha256: sha(small) });
  assert.deepEqual(fs.readFileSync(path.join(upDir(h, up.uploadId), "a", "small.txt")), small);

  // 3 MiB in 64 KiB chunks from a slow, paused-and-resumed source
  const big = crypto.randomBytes(3 * 1024 * 1024);
  let off = 0;
  let pausedSeen = 0;
  const src = new Readable({
    highWaterMark: 16 * 1024,
    read() {
      if (this.isPaused()) pausedSeen += 1;
      if (off >= big.length) return this.push(null);
      this.push(big.subarray(off, off + 65_536));
      off += 65_536;
    },
  });
  const r2 = await h.mgr.putUpload(spark, up.uploadId, "big.bin", src, { maxBytes: 10_000_000 });
  assert.equal(r2.bytes, big.length);
  assert.equal(r2.sha256, sha(big));
  assert.equal(sha(fs.readFileSync(path.join(upDir(h, up.uploadId), "big.bin"))), sha(big));
  assert.deepEqual(noPart(upDir(h, up.uploadId)), []);

  await assert.rejects(h.mgr.putUpload(spark, up.uploadId, "x", bodyOf(Buffer.alloc(0)), { maxBytes: 10 }).then(() => h.mgr.putUpload(spark, "up-20261012-000000-zzzzzz", "x", bodyOf(small), {})), (e) => e instanceof ReaError && e.code === "unknown-upload");

  const done = await h.mgr.commitUpload(spark, up.uploadId, { maxFiles: 100, maxBytes: 50_000_000 });
  assert.equal(done.files, 3);
  assert.equal(done.bytes, small.length + big.length);
  assert.equal(done.extracted, false);
  assert.equal(done.root, fs.realpathSync(upDir(h, up.uploadId)));
  assert.equal(h.mgr.isCommittedUpload(spark.id, up.uploadId), true);
  assert.equal(h.mgr.uploadRoot(spark.id, up.uploadId), done.root);
  assert.equal(h.mgr.isCommittedUpload("other-spark", up.uploadId), false, "bound to the unit");
  assert.equal(h.mgr.uploadRoot("other-spark", up.uploadId), null);
  assert.deepEqual(await h.mgr.commitUpload(spark, up.uploadId), done, "commit is idempotent");
  await assert.rejects(h.mgr.putUpload(spark, up.uploadId, "late.txt", bodyOf(small), {}), (e) => e.code === "committed");

  const del = await h.mgr.deleteUpload(spark, up.uploadId);
  assert.equal(del.ok, true);
  assert.equal(fs.existsSync(upDir(h, up.uploadId)), false);
  assert.equal(h.mgr.isCommittedUpload(spark.id, up.uploadId), false);
});

test("uploads: invalid paths, unknown ids and unit-side limits are refused with codes", async () => {
  const h = setup({ manager: { uploadMaxFiles: 2 } });
  const up = await h.mgr.createUpload(spark);
  const one = Buffer.from("x");
  for (const bad of ["../x", "a//b", "/abs", ".committed", "a/./b", "x.part", ""]) {
    await assert.rejects(h.mgr.putUpload(spark, up.uploadId, bad, bodyOf(one), {}), (e) => e instanceof ReaError && e.code === "invalid-path", bad);
  }
  await assert.rejects(h.mgr.putUpload(spark, up.uploadId, "a.txt", bodyOf(one), { archive: true }), (e) => e.code === "invalid-path");
  await assert.rejects(h.mgr.putUpload(spark, "nope", "a.txt", bodyOf(one), {}), (e) => e.code === "unknown-upload");
  await assert.rejects(h.mgr.commitUpload(spark, up.uploadId), (e) => e.code === "empty");
  await h.mgr.putUpload(spark, up.uploadId, "1.txt", bodyOf(one), {});
  await h.mgr.putUpload(spark, up.uploadId, "2.txt", bodyOf(one), {});
  await assert.rejects(h.mgr.putUpload(spark, up.uploadId, "3.txt", bodyOf(one), {}), (e) => e.code === "too-many-files");
  await h.mgr.putUpload(spark, up.uploadId, "2.txt", bodyOf(Buffer.from("replaced")), {});
  await assert.rejects(h.mgr.commitUpload(spark, up.uploadId, { maxFiles: 1 }), (e) => e.code === "too-many-files");
  assert.equal(h.mgr.isCommittedUpload(spark.id, up.uploadId), false);
  const ok = await h.mgr.commitUpload(spark, up.uploadId, { maxFiles: 2 });
  assert.equal(ok.files, 2);
});

test("uploads: over the byte cap aborts, ends the child and removes the .part", async () => {
  const h = setup({ manager: { uploadMaxBytes: 1_000_000 } });
  const up = await h.mgr.createUpload(spark);
  const before = new Set(spawned);
  const src = new Readable({ read() {} });
  const p = h.mgr.putUpload(spark, up.uploadId, "too-big.bin", src, { maxBytes: 100 });
  const assertion = assert.rejects(p, (e) => e instanceof ReaError && e.code === "too-big");
  src.push(Buffer.alloc(60));
  await sleep(100);
  src.push(Buffer.alloc(60));
  await assertion;
  const child = [...spawned].find((c) => !before.has(c));
  if (child) await until(() => child.exitCode !== null || child.signalCode !== null);
  assert.deepEqual(noPart(upDir(h, up.uploadId)), []);
  assert.equal(fs.existsSync(path.join(upDir(h, up.uploadId), "too-big.bin")), false);
  assert.equal(fs.existsSync(path.join(upDir(h, up.uploadId), ".writing")), false);
  // the whole upload is still usable
  const r = await h.mgr.putUpload(spark, up.uploadId, "fine.bin", bodyOf(Buffer.from("fine")), { maxBytes: 100 });
  assert.equal(r.bytes, 4);
});

test("uploads: a client that disconnects mid-file leaves nothing behind (child ended, .part and marker removed)", async () => {
  const h = setup();
  const up = await h.mgr.createUpload(spark);
  const before = new Set(spawned);
  const src = new Readable({ read() {} });
  const p = h.mgr.putUpload(spark, up.uploadId, "partial.bin", src, { maxBytes: 1_000_000 });
  const assertion = assert.rejects(p, (e) => e instanceof ReaError && e.code === "aborted");
  src.push(Buffer.alloc(10_000, 1));
  await until(() => fs.existsSync(path.join(upDir(h, up.uploadId), "partial.bin.part")));
  src.destroy();
  await assertion;
  const child = [...spawned].find((c) => !before.has(c));
  if (child) await until(() => child.exitCode !== null || child.signalCode !== null);
  assert.deepEqual(noPart(upDir(h, up.uploadId)), []);
  assert.equal(fs.existsSync(path.join(upDir(h, up.uploadId), "partial.bin")), false);
  assert.equal(fs.existsSync(path.join(upDir(h, up.uploadId), ".writing")), false);
  // an error on the source behaves the same
  const src2 = new Readable({ read() {} });
  const p2 = h.mgr.putUpload(spark, up.uploadId, "err.bin", src2, {});
  const a2 = assert.rejects(p2, (e) => e.code === "aborted");
  src2.push(Buffer.alloc(100));
  await sleep(100);
  src2.destroy(new Error("reset"));
  await a2;
  assert.deepEqual(noPart(upDir(h, up.uploadId)), []);
});

test("uploads: a stalled writer is ended by the idle timeout", async () => {
  const h = setup({ manager: { uploadIdleMs: 400 } });
  const up = await h.mgr.createUpload(spark);
  const src = new Readable({ read() {} });
  const p = h.mgr.putUpload(spark, up.uploadId, "stall.bin", src, {});
  const assertion = assert.rejects(p, (e) => e.code === "timeout");
  src.push(Buffer.alloc(10));
  await assertion;
  assert.deepEqual(noPart(upDir(h, up.uploadId)), []);
  src.destroy();
});

test("uploads: delete ends open writers; commit refuses while one is open", async () => {
  const h = setup();
  const up = await h.mgr.createUpload(spark);
  const src = new Readable({ read() {} });
  const p = h.mgr.putUpload(spark, up.uploadId, "open.bin", src, {});
  const assertion = assert.rejects(p, (e) => e instanceof ReaError);
  src.push(Buffer.alloc(100));
  await until(() => fs.existsSync(path.join(upDir(h, up.uploadId), "open.bin.part")));
  await assert.rejects(h.mgr.commitUpload(spark, up.uploadId), (e) => e.code === "writing");
  const del = await h.mgr.deleteUpload(spark, up.uploadId);
  assert.equal(del.ok, true);
  await assertion;
  assert.equal(fs.existsSync(upDir(h, up.uploadId)), false);
  src.destroy();
});

test("uploads: sweep reports counts and keeps fresh uploads; the in-memory table is bounded per unit", async () => {
  const h = setup();
  const up = await h.mgr.createUpload(spark);
  const s = await h.mgr.sweepUploads(spark);
  assert.equal(s.ok, true);
  assert.equal(s.swept, 0);
  assert.equal(s.kept, 1);
  assert.ok(fs.existsSync(upDir(h, up.uploadId)));
  h.mgr.removeSpark(spark.id);
  assert.equal(h.mgr.isCommittedUpload(spark.id, up.uploadId), false);
});

test("uploads: archives are verified and extracted on commit; unsafe ones are refused and nothing is extracted", { skip: !hasPython }, async () => {
  const h = setup();
  const work = tmp("rea-arc-");
  const good = path.join(work, "good");
  fs.mkdirSync(path.join(good, "sub"), { recursive: true });
  fs.writeFileSync(path.join(good, "a.txt"), "alpha\n");
  fs.writeFileSync(path.join(good, "sub", "b.txt"), "beta\n");
  const tgz = path.join(work, "good.tar.gz");
  execFileSync("tar", ["czf", tgz, "-C", good, "."]);

  const up = await h.mgr.createUpload(spark);
  await h.mgr.putUpload(spark, up.uploadId, "good.tar.gz", bodyOf(fs.readFileSync(tgz)), { archive: true });
  const done = await h.mgr.commitUpload(spark, up.uploadId, {});
  assert.equal(done.extracted, true);
  assert.equal(done.root, path.join(fs.realpathSync(upDir(h, up.uploadId)), "extracted"));
  assert.equal(done.files, 2);
  assert.equal(fs.readFileSync(path.join(done.root, "sub", "b.txt"), "utf8"), "beta\n");
  assert.equal(h.mgr.uploadRoot(spark.id, up.uploadId), done.root);

  // a link entry
  const evil = path.join(work, "evil");
  fs.mkdirSync(evil);
  fs.writeFileSync(path.join(evil, "ok.txt"), "x");
  fs.symlinkSync("/etc/passwd", path.join(evil, "link"));
  const bad = path.join(work, "bad.tar.gz");
  execFileSync("tar", ["czf", bad, "-C", evil, "."]);
  const up2 = await h.mgr.createUpload(spark);
  await h.mgr.putUpload(spark, up2.uploadId, "bad.tar.gz", bodyOf(fs.readFileSync(bad)), { archive: true });
  await assert.rejects(h.mgr.commitUpload(spark, up2.uploadId, {}), (e) => e instanceof ReaError && e.code === "archive-refused" && /link or special/.test(e.message));
  assert.equal(fs.existsSync(path.join(upDir(h, up2.uploadId), "extracted")), false);
  assert.equal(h.mgr.isCommittedUpload(spark.id, up2.uploadId), false);

  // an entry that climbs out (built by hand: tar --transform keeps the ".." in the member name)
  const up3 = await h.mgr.createUpload(spark);
  const py = `import tarfile, io, sys
t = tarfile.open(sys.argv[1], "w:gz")
i = tarfile.TarInfo("../escape.txt"); d = b"x"; i.size = len(d)
t.addfile(i, io.BytesIO(d)); t.close()`;
  const esc = path.join(work, "esc.tar.gz");
  execFileSync("python3", ["-I", "-c", py, esc]);
  await h.mgr.putUpload(spark, up3.uploadId, "esc.tar.gz", bodyOf(fs.readFileSync(esc)), { archive: true });
  await assert.rejects(h.mgr.commitUpload(spark, up3.uploadId, {}), (e) => e.code === "archive-refused" && /leaves the folder/.test(e.message));
  assert.equal(fs.existsSync(path.join(upDir(h, up3.uploadId), "escape.txt")), false);
  assert.equal(fs.existsSync(path.join(path.dirname(upDir(h, up3.uploadId)), "escape.txt")), false);

  // a high compression ratio (zip bomb shape)
  const up4 = await h.mgr.createUpload(spark);
  const zbomb = path.join(work, "bomb.zip");
  const pz = `import zipfile, sys
z = zipfile.ZipFile(sys.argv[1], "w", zipfile.ZIP_DEFLATED)
z.writestr("zeros.bin", b"\\0" * (20 * 1024 * 1024)); z.close()`;
  execFileSync("python3", ["-I", "-c", pz, zbomb]);
  await h.mgr.putUpload(spark, up4.uploadId, "bomb.zip", bodyOf(fs.readFileSync(zbomb)), { archive: true });
  await assert.rejects(h.mgr.commitUpload(spark, up4.uploadId, {}), (e) => e.code === "archive-refused" && /ratio/.test(e.message));
  assert.equal(fs.existsSync(path.join(upDir(h, up4.uploadId), "extracted")), false);
});

test("shutdown: ends the live watcher and open uploads without leaving children", async () => {
  const h = setup();
  fs.writeFileSync(path.join(h.home, "rea-slow"), "");
  const { id } = startRun(h);
  await until(() => reaCalls(h).length > 0);
  const up = await h.mgr.createUpload(spark);
  const src = new Readable({ read() {} });
  const p = h.mgr.putUpload(spark, up.uploadId, "x.bin", src, {});
  const assertion = assert.rejects(p, (e) => e instanceof ReaError);
  src.push(Buffer.alloc(10));
  await sleep(150);
  h.mgr.shutdown();
  await assertion;
  await until(() => h.mgr.latestJob(spark.id).status !== "running");
  assert.equal(h.store.get(id).status, "running", "the run itself keeps going on the unit; only the watcher ended");
  await h.mgr.stopRun(spark, id);
  await until(() => fs.existsSync(path.join(h.home, ".cache", "sparkdash", "rea", "runs", id, "exit")));
  src.destroy();
});
