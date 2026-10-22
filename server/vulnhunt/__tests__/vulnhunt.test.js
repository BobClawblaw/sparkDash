import test, { after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawn } from "node:child_process";
import { validateScanRequest, validateSource, scanArgv, displayLine } from "../validate.js";
import { parseFindings, parseHeader, parseManifest, countBySeverity, summarizeReport } from "../report.js";
import { isBlockedCloneHost, parseAllowedHosts, validateHostCommand, validateInstallRequest } from "../validate.js";
import { VulnHuntStore, isValidRunId, newRunId } from "../VulnHuntStore.js";
import { VulnHuntManager, explainExit } from "../VulnHuntManager.js";
import { buildInstallProgram } from "../commands.js";
import { installFakeUnit, REPORT } from "./fakeVulnHunt.js";

const made = [];
const tmp = (p) => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), p));
  made.push(d);
  return d;
};
after(() => {
  for (const d of made) fs.rmSync(d, { recursive: true, force: true });
});
const until = async (fn, ms = 25_000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 60));
  }
  throw new Error("timed out");
};

// ── validation ──────────────────────────────────────────────────────────────

test("source: accepts https repository URLs and absolute checkout paths, normalised", () => {
  assert.deepEqual(validateSource({ type: "url", value: " https://github.com/org/repo.git " }), { ok: true, kind: "url", value: "https://github.com/org/repo.git" });
  assert.equal(validateSource({ type: "url", value: "https://git.lan:8443/team/proj" }).ok, true);
  assert.equal(validateSource({ type: "path", value: "~/code/project" }).ok, true);
  assert.equal(validateSource({ type: "path", value: "/home/me/src/app-1.2" }).ok, true);
});

test("source: rejects transports, credentials, queries, blocked hosts, traversal and shell-looking text", () => {
  const bad = (v) => validateSource(v);
  for (const value of [
    "http://github.com/org/repo",
    "git@github.com:org/repo.git",
    "ssh://git@github.com/org/repo",
    "file:///etc",
    "ext::sh -c id",
    "https://user:pw@github.com/org/repo",
    "https://github.com/org/repo?x=1",
    "https://github.com/org/repo#frag",
    "https://169.254.169.254/latest/meta-data",
    "https://[fe80::1]/x",
    "https://github.com/org/../etc",
    "https://github.com/org/re po",
    "https://github.com/org/repo;id",
    "-u",
    "",
  ]) {
    assert.equal(bad({ type: "url", value }).ok, false, value);
  }
  for (const value of ["relative/path", "/a/../b", "/home/me/a b", "/home/me/$(id)", "/home/me/`id`", "/x;y", "/x\ny", "~", "~root/x"]) {
    assert.equal(bad({ type: "path", value }).ok, false, value);
  }
  assert.equal(bad({ type: "ftp", value: "x" }).ok, false);
  assert.equal(bad(null).ok, false);
});

test("request: needs the authorization attestation; executing code needs its own confirmation", () => {
  const src = { type: "url", value: "https://github.com/org/repo" };
  assert.match(validateScanRequest({ source: src }).error, /authorized/);
  assert.match(validateScanRequest({ source: src, authorized: "yes" }).error, /authorized/);
  const ro = validateScanRequest({ source: src, authorized: true });
  assert.equal(ro.ok, true);
  assert.equal(ro.readOnly, true, "read-only is the default");
  assert.equal(ro.timeoutMinutes, 240);
  assert.match(validateScanRequest({ source: src, authorized: true, readOnly: false }).error, /execute code/);
  assert.equal(validateScanRequest({ source: src, authorized: true, readOnly: false, confirmExecute: true }).readOnly, false);
});

test("request: time limit and label are bounded; control characters never reach the label", () => {
  const base = { source: { type: "path", value: "~/x" }, authorized: true };
  assert.equal(validateScanRequest({ ...base, timeoutMinutes: 4 }).ok, false);
  assert.equal(validateScanRequest({ ...base, timeoutMinutes: 721 }).ok, false);
  assert.equal(validateScanRequest({ ...base, timeoutMinutes: 1.5 }).ok, false);
  assert.equal(validateScanRequest({ ...base, timeoutMinutes: 30 }).timeoutMinutes, 30);
  const r = validateScanRequest({ ...base, label: `a\u0000b\nc${"x".repeat(500)}` });
  assert.ok(r.label.length <= 120 && !/[\u0000-\u001f]/.test(r.label));
  assert.deepEqual(scanArgv({ kind: "url", value: "https://h/x", readOnly: true, timeoutMinutes: 5 }), ["url", "https://h/x", "1", "300"]);
  assert.match(displayLine({ kind: "path", value: "~/x", readOnly: false, timeoutMinutes: 5 }), /may execute code/);
});

// ── report parsing ──────────────────────────────────────────────────────────

test("report: header, findings table and counts are read; markup stays plain text", () => {
  const h = parseHeader(REPORT);
  assert.equal(h.repository, "https://example.com/org/repo");
  assert.equal(h.model, "test-model");
  const f = parseFindings(REPORT);
  assert.deepEqual(f.map((x) => [x.id, x.severity, x.cwe]), [["VULN-001", "High", "CWE-89"], ["VULN-002", "Medium", "CWE-79"]]);
  assert.equal(f[0].measuredImpact, "3 of 20 payloads returned rows");
  assert.equal(f[1].title, "<img src=x onerror=alert(1)> reflected", "kept verbatim as text for the UI to escape");
  assert.deepEqual(countBySeverity(f), { "High+": 0, High: 1, Medium: 1, Low: 0, Informational: 0, unrated: 0 });
});

test("report: tolerant of other layouts, repeated tables and garbage; never throws", () => {
  assert.deepEqual(parseFindings(""), []);
  assert.deepEqual(parseFindings(null), []);
  assert.deepEqual(parseFindings("| not | a | findings | table |\n|---|---|---|---|\n| 1 | 2 | 3 | 4 |"), []);
  const twice = `${REPORT}\n\n| ID | Title | CWE | Severity | Status |\n|---|---|---|---|---|\n| **VULN-001** | SQL injection in search (README) | CWE-89 | **High+** | Fixed |\n`;
  const f = parseFindings(twice);
  assert.equal(f.length, 2, "same id twice is one finding");
  assert.equal(f.find((x) => x.id === "VULN-001").severity, "High+");
  const huge = Array.from({ length: 500 }, (_, i) => `| VULN-${String(i).padStart(3, "0")} | t | CWE-1 | Low | static | PASS | n | Confirmed |`).join("\n");
  assert.ok(parseFindings(`| ID | Title | CWE | Severity | Runtime | Exploit Test | Measured Impact | Status |\n|---|---|---|---|---|---|---|---|\n${huge}`).length <= 200, "bounded");
  assert.equal(parseManifest("{not json"), null);
  assert.deepEqual(parseManifest('{"scan_id":"a_VULNHUNT_RESULTS_b","agent_exit_code":0,"cost_usd":0}'), { scanId: "a_VULNHUNT_RESULTS_b", agentExitCode: 0, costUsd: 0 });
  const s = summarizeReport({ report: REPORT, manifestText: "", files: ["poc/a.md"] });
  assert.equal(s.total, 2);
  assert.equal(s.exploitPass, 2);
});

test("store: ids, index limits, bundle round trip and removal", () => {
  const home = tmp("vh-store-");
  const store = new VulnHuntStore({ file: path.join(home, "runs.json"), resultsDir: path.join(home, "res") });
  const id = newRunId();
  assert.ok(isValidRunId(id));
  assert.equal(isValidRunId("../../etc/passwd"), false);
  assert.equal(isValidRunId("te-20260101-000000-abcd"), false);
  store.add({ id, sparkId: "s1", status: "running" });
  assert.equal(store.saveBundle("vh-20200101-000000-zzzz", {}), false, "unknown run");
  assert.equal(store.saveBundle(id, { report: "x", findings: [] }), true);
  assert.deepEqual(store.loadBundle(id), { report: "x", findings: [] });
  assert.equal(fs.statSync(path.join(home, "runs.json")).mode & 0o077, 0, "index is private");
  assert.equal(store.remove(id), true);
  assert.equal(store.loadBundle(id), null);
});

test("explainExit: every wrapper exit code reads as a sentence", () => {
  for (const c of [2, 3, 4, 124, 126, 127, 143]) assert.ok(explainExit(c));
  assert.equal(explainExit(0), null);
});

// ── pipeline against a fake unit (real bash, real git) ──────────────────────

const spark = { id: "s1", name: "Spark 1" };

function realManager(home, extraEnv) {
  const store = new VulnHuntStore({ file: path.join(home, "runs.json"), resultsDir: path.join(home, "results") });
  const events = [];
  const mgr = new VulnHuntManager({
    store,
    onEvent: (e) => events.push(e),
    spawnProcess: (_s, cmd, opts = {}) =>
      spawn("bash", ["-c", cmd], {
        env: {
          ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith("VULNHUNT_") && !k.startsWith("SPARKDASH_VULNHUNT_"))),
          HOME: home,
          PATH: `/usr/local/bin:/usr/bin:/bin`,
          SPARKDASH_VULNHUNT_GRACE: "2",
          SPARKDASH_VULNHUNT_TICK: "1",
          SPARKDASH_VULNHUNT_LOGMAX: "100000",
          ...(extraEnv ?? {}),
        },
        stdio: [opts.stdin ? "pipe" : "ignore", "pipe", "pipe"],
        detached: true,
      }),
  });
  return { mgr, store, events };
}

function startScan(mgr, store, over = {}) {
  const request = { kind: "url", value: "https://example.com/org/repo", readOnly: true, timeoutMinutes: 5, ...over.request };
  const id = newRunId();
  const run = { id, sparkId: spark.id, status: "running", startedAt: Date.now(), command: displayLine(request), summary: null };
  store.add(run);
  const argv = over.argv ?? scanArgv(request);
  return { id, started: mgr.startScan(spark, { run, argv }) };
}

const settled = (mgr) => until(() => mgr.latestJob("s1").status !== "running");

test("pipeline: clone -> hunt -> collect; the report is captured and parsed, the prompt is the benchmark prompt", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  const { mgr, store, events } = realManager(home);
  const { id, started } = startScan(mgr, store);
  assert.equal(started.ok, true);
  await settled(mgr);
  await until(() => store.get(id).resultCached);
  const run = store.get(id);
  assert.equal(run.status, "completed");
  assert.equal(run.exitCode, 0);
  assert.equal(run.summary.total, 2);
  assert.equal(run.summary.counts.High, 1);
  assert.equal(run.summary.header.model, "test-model");
  assert.equal(run.summary.manifest.agentExitCode, 0);
  assert.equal(run.summary.findings, undefined, "the index stays small; findings live in the bundle");
  const bundle = store.loadBundle(id);
  assert.equal(bundle.findings.length, 2);
  assert.ok(bundle.artifacts.includes("poc/VULN-001_sql_injection.md"));
  assert.ok(bundle.artifacts.includes("scan_manifest.json"));
  // The prompt the harness received: the skill invocation on the checkout, headless wording, read-only sentence.
  const prompt = fs.readFileSync(path.join(home, "prompt.seen"), "utf8");
  assert.match(prompt, new RegExp(`^/vulnhunt ${home.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}/\\.cache/sparkdash/vulnhunt/${id}/src\\n`));
  assert.match(prompt, /non-interactive headless mode/);
  assert.match(prompt, /Perform a read-only scan/);
  const live = mgr.readJob("s1", id, {});
  assert.ok(live.lines.some((l) => /cloned https:\/\/example\.com\/org\/repo/.test(l.text)));
  assert.ok(live.lines.some((l) => /harness: done/.test(l.text)));
  assert.equal(live.progress.stage, "done");
  assert.ok(events.some((e) => e.type === "vulnhunt.scan.completed" && e.severity === "warn" && /2 confirmed findings/.test(e.message)), JSON.stringify(events));
});

test("pipeline: a scan that may execute code does not carry the read-only sentence", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store, { request: { readOnly: false } });
  await settled(mgr);
  await until(() => store.get(id).status !== "running");
  const prompt = fs.readFileSync(path.join(home, "prompt.seen"), "utf8");
  assert.doesNotMatch(prompt, /read-only scan/);
  assert.match(prompt, /--no-read-only/, "names its mode so the upstream skill does not stop at its menu");
});

test("pipeline: a results folder shipped inside the repository is never mistaken for this hunt's", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "plant-results"), "");
  fs.writeFileSync(path.join(home, "no-results"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await settled(mgr);
  await until(() => store.get(id).status !== "running");
  const run = store.get(id);
  assert.equal(run.status, "failed");
  assert.equal(run.exitCode, 4);
  assert.match(run.note, /no results/);
  assert.equal(store.loadBundle(id), null, "the planted report was not captured");
  assert.ok(mgr.readJob("s1", id, {}).lines.some((l) => /no new \*_VULNHUNT_RESULTS_\* directory/.test(l.text)));
});

test("pipeline: a README that is a symlink is not followed out of the results folder", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "symlink-readme"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await settled(mgr);
  await until(() => store.get(id).resultCached);
  const bundle = store.loadBundle(id);
  assert.equal(bundle.report, "");
  assert.ok(!JSON.stringify(bundle).includes("TOP-SECRET-DO-NOT-LEAK"));
  assert.equal(store.get(id).summary.hasReport, false);
});

test("pipeline: not set up -> clear message and exit 127 / 126, nothing is started", async () => {
  // no vh at all
  let home = tmp("vh-home-");
  let { mgr, store } = realManager(home);
  let r = startScan(mgr, store);
  await settled(mgr);
  assert.equal(mgr.latestJob("s1").exitCode, 127);
  assert.ok(mgr.readJob("s1", r.id, {}).lines.some((l) => /vh .* is not installed/.test(l.text)));
  assert.equal((await mgr.status(spark)).ready, false);

  // vh present, no host command configured
  home = tmp("vh-home-");
  installFakeUnit(home, { hostCmd: null });
  ({ mgr, store } = realManager(home));
  r = startScan(mgr, store);
  await settled(mgr);
  assert.equal(mgr.latestJob("s1").exitCode, 126);
  assert.ok(mgr.readJob("s1", r.id, {}).lines.some((l) => /No harness command is configured/.test(l.text)));
  const st = await mgr.status(spark);
  assert.equal(st.installed, true);
  assert.equal(st.hostCommand.configured, false);
  assert.equal(st.setsid, true);
  assert.equal(st.ready, false);
});

test("pipeline: a host command file anyone else can write is refused, and only the program name is reported", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home, { hostCmd: "fake-harness --api-key sk-SECRET-VALUE" });
  const { mgr, store } = realManager(home);
  let st = await mgr.status(spark);
  assert.equal(st.ready, true);
  assert.equal(st.hostCommand.program, "fake-harness");
  assert.ok(!JSON.stringify(st).includes("sk-SECRET-VALUE"), "arguments of the harness command never leave the unit");

  fs.chmodSync(path.join(home, ".config", "sparkdash", "vulnhunt-host-cmd"), 0o666);
  st = await mgr.status(spark);
  assert.equal(st.hostCommand.source, "unsafe");
  assert.equal(st.ready, false);
  const r = startScan(mgr, store);
  await settled(mgr);
  assert.equal(mgr.latestJob("s1").exitCode, 126);
  assert.ok(mgr.readJob("s1", r.id, {}).lines.some((l) => /must not be writable/.test(l.text)));
});

test("pipeline: local checkout mode scans a clone of HEAD, only inside the user's home", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  const repo = path.join(home, "code", "proj");
  fs.mkdirSync(repo, { recursive: true });
  execFileSync("git", ["init", "-q", repo]);
  execFileSync("git", ["-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x"]);
  const { mgr, store } = realManager(home);

  const ok = startScan(mgr, store, { request: { kind: "path", value: "~/code/proj" } });
  await settled(mgr);
  await until(() => store.get(ok.id).status !== "running");
  assert.equal(store.get(ok.id).status, "completed");
  assert.ok(!fs.readdirSync(repo).some((n) => /VULNHUNT_RESULTS/.test(n)), "the original checkout is left alone");

  const outside = tmp("vh-outside-");
  execFileSync("git", ["init", "-q", outside]);
  const bad = startScan(mgr, store, { request: { kind: "path", value: outside } });
  await settled(mgr);
  assert.equal(mgr.latestJob("s1").exitCode, 2);
  assert.ok(mgr.readJob("s1", bad.id, {}).lines.some((l) => /inside this unit user's home/.test(l.text)));
});

test("pipeline: stop reaches the harness and everything it started; a second scan is refused while one runs", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "slow"), "");
  const { mgr, store } = realManager(home);
  const first = startScan(mgr, store);
  await until(() => fs.existsSync(path.join(home, "harness.pid")));
  const hp = Number(fs.readFileSync(path.join(home, "harness.pid"), "utf8"));
  assert.ok(hp > 0);
  const second = startScan(mgr, store);
  assert.equal(second.started.ok, false);
  assert.equal(second.started.reason, "busy");
  store.remove(second.id);

  const res = await mgr.stopRun(spark, first.id);
  assert.match(res.output, /stopped|killed/);
  await settled(mgr);
  await until(() => store.get(first.id).status !== "running");
  assert.equal(store.get(first.id).status, "stopped");
  let alive = true;
  try {
    process.kill(hp, 0);
  } catch {
    alive = false;
  }
  assert.equal(alive, false, "the harness process is gone");
});

test("pipeline: the time limit ends the hunt (exit 124) and still collects what exists", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "slow"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store, { argv: ["url", "https://example.com/org/repo", "1", "2"] });
  await settled(mgr);
  await until(() => store.get(id).status !== "running");
  const run = store.get(id);
  assert.equal(run.exitCode, 124);
  assert.equal(run.status, "failed");
  assert.match(run.note, /time limit/);
});

test("pipeline: closing the watcher leaves the scan going; attach and refresh settle it", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "slow"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await until(() => fs.existsSync(path.join(home, "harness.pid")));
  mgr.cancelWatch("s1");
  await until(() => mgr.latestJob("s1").status === "cancelled");
  assert.equal((await mgr.checkRun(spark, id)).state, "running");
  const attach = mgr.attachScan(spark, store.get(id));
  assert.equal(attach.ok, true);
  mgr.cancelWatch("s1");
  await mgr.stopRun(spark, id);
  await until(async () => (await mgr.checkRun(spark, id)).state === "finished");
  assert.notEqual(store.get(id).status, "running");
});

test("pipeline: a clone failure is reported and settles as failed (exit 3)", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  const { mgr, store } = realManager(home);
  const prev = process.env.FAKE_CLONE_FAIL;
  process.env.FAKE_CLONE_FAIL = "1";
  try {
    const { id } = startScan(mgr, store);
    await settled(mgr);
    await until(() => store.get(id).status !== "running");
    assert.equal(store.get(id).exitCode, 3);
    assert.match(store.get(id).note, /could not be cloned/);
  } finally {
    if (prev === undefined) delete process.env.FAKE_CLONE_FAIL;
    else process.env.FAKE_CLONE_FAIL = prev;
  }
});

// ── review fixes: regression tests ──────────────────────────────────────────

const runDirOf = (home, id) => path.join(home, ".cache", "sparkdash", "vulnhunt", id);
const pidAlive = (pid) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
const processesMentioning = (needle) =>
  execFileSync("ps", ["-eo", "args"], { encoding: "utf8" })
    .split("\n")
    .filter((l) => l.includes(needle) && !l.includes("ps -eo"));

test("pipeline: only the results folder is kept; the clone is deleted, run files are private, nothing is left running", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await settled(mgr);
  await until(() => store.get(id).resultCached);
  const rd = runDirOf(home, id);
  assert.equal(fs.existsSync(path.join(rd, "src")), false, "the clone is gone");
  const kept = fs.readdirSync(path.join(rd, "results"));
  assert.equal(kept.length, 1);
  assert.match(kept[0], /_VULNHUNT_RESULTS_/);
  assert.ok(fs.existsSync(path.join(rd, "results", kept[0], "README.md")));
  assert.equal(fs.statSync(path.join(rd, "output.log")).mode & 0o077, 0, "the log is private");
  assert.equal(fs.statSync(rd).mode & 0o077, 0, "the run directory is private");
  await until(() => processesMentioning(rd).length === 0, 5000);
});

test("pipeline: a wrapper that was SIGKILLed stops reading as running, and the unit is free again", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "slow"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await until(() => fs.existsSync(path.join(home, "harness.pid")));
  const wrapperPid = Number(fs.readFileSync(path.join(runDirOf(home, id), "pid"), "utf8"));
  const harnessPid = Number(fs.readFileSync(path.join(home, "harness.pid"), "utf8"));
  mgr.cancelWatch("s1");
  await until(() => mgr.latestJob("s1").status === "cancelled");
  process.kill(wrapperPid, "SIGKILL");
  // The watchdog notices within a tick; until then it is still in the group.
  const state = await until(async () => {
    const r = await mgr.checkRun(spark, id);
    return r.state !== "running" ? r : null;
  }, 15_000);
  assert.equal(state.state, "finished");
  const run = store.get(id);
  assert.equal(run.status, "failed");
  assert.match(run.note, /without reporting a result/);
  assert.equal(mgr.canStart(spark).ok, true);
  try {
    process.kill(harnessPid, "SIGKILL");
  } catch {
    /* already gone */
  }
});

test("pipeline: re-opening the output of a settled scan does not settle it again", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  const { mgr, store, events } = realManager(home);
  const { id } = startScan(mgr, store);
  await settled(mgr);
  await until(() => store.get(id).resultCached);
  const before = { ...store.get(id) };
  const eventsBefore = events.length;
  const attach = mgr.attachScan(spark, store.get(id));
  assert.equal(attach.ok, true);
  await until(() => mgr.latestJob("s1").status !== "running");
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(events.length, eventsBefore, "no second Activity event");
  assert.equal(store.get(id).finishedAt, before.finishedAt);
  assert.equal(store.get(id).status, "completed");
});

test("pipeline: stop during the collect stage reads as stopped, and the manifest is still finished", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "slow-manifest"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await until(() => mgr.readJob("s1", id, {})?.progress.stage === "collect");
  await new Promise((r) => setTimeout(r, 500));
  await mgr.stopRun(spark, id);
  await settled(mgr);
  await until(() => store.get(id).status !== "running");
  const run = store.get(id);
  assert.equal(run.exitCode, 143);
  assert.equal(run.status, "stopped");
  await until(() => store.get(id).resultCached);
  const bundle = store.loadBundle(id);
  assert.equal(bundle.manifest?.agentExitCode, 0, "the manifest was written despite the stop");
  assert.ok(!mgr.readJob("s1", id, {}).lines.some((l) => /Terminated|Killed/.test(l.text)));
});

test("pipeline: a symlinked ~/.cache does not hide the report (both sides of the location check are resolved)", async () => {
  const home = tmp("vh-home-");
  const elsewhere = tmp("vh-cache-");
  fs.symlinkSync(elsewhere, path.join(home, ".cache"));
  installFakeUnit(home);
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await settled(mgr);
  await until(() => store.get(id).status !== "running");
  await until(() => store.get(id).resultCached);
  assert.equal(store.get(id).status, "completed");
  assert.equal(store.get(id).summary.total, 2);
});

test("pipeline: a symlinked $HOME does not make the user's own checkout read as outside it", async () => {
  const real = tmp("vh-real-");
  const linkParent = tmp("vh-link-");
  const link = path.join(linkParent, "home");
  fs.symlinkSync(real, link);
  installFakeUnit(real);
  const repo = path.join(real, "code", "proj");
  fs.mkdirSync(repo, { recursive: true });
  execFileSync("git", ["init", "-q", repo]);
  execFileSync("git", ["-C", repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x"]);
  const { mgr, store } = realManager(link);
  const { id } = startScan(mgr, store, { request: { kind: "path", value: "~/code/proj" } });
  await settled(mgr);
  await until(() => store.get(id).status !== "running");
  assert.equal(store.get(id).status, "completed", JSON.stringify(mgr.readJob("s1", id, {}).lines.slice(-4)));
});

test("pipeline: stopping during the clone reads as stopped (143), not as a hunt that exited with 1", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "slow-clone"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await until(() => mgr.readJob("s1", id, {})?.progress.stage === "clone");
  await new Promise((r) => setTimeout(r, 500));
  const res = await mgr.stopRun(spark, id);
  assert.equal(res.ok, true, res.output);
  await settled(mgr);
  await until(() => store.get(id).status !== "running");
  const run = store.get(id);
  assert.equal(run.exitCode, 143);
  assert.equal(run.status, "stopped");
  assert.match(run.note, /stopped/);
});

test("pipeline: a harness that ignores TERM is ended after the grace period and the scan still settles as stopped", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "ignore-term"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await until(() => fs.existsSync(path.join(home, "harness.pid")));
  const hp = Number(fs.readFileSync(path.join(home, "harness.pid"), "utf8"));
  const t0 = Date.now();
  const res = await mgr.stopRun(spark, id);
  assert.match(res.output, /stopped/, "the wrapper wound itself down; the stop did not have to end the whole group");
  await settled(mgr);
  await until(() => store.get(id).status !== "running");
  assert.equal(store.get(id).exitCode, 143);
  assert.equal(store.get(id).status, "stopped");
  assert.equal(pidAlive(hp), false, "the harness is gone");
  assert.ok(Date.now() - t0 < 60_000, "bounded by the grace periods, with room for a loaded machine");
  assert.ok(!mgr.readJob("s1", id, {}).lines.some((l) => /Killed|Terminated/.test(l.text)), "no job-control noise from the wrapper being killed");
});

test("pipeline: the harness's own exit code never stands in for the wrapper's", async () => {
  for (const code of [2, 3, 127]) {
    const home = tmp("vh-home-");
    installFakeUnit(home);
    fs.writeFileSync(path.join(home, "exit-code"), String(code));
    const { mgr, store } = realManager(home);
    const { id } = startScan(mgr, store);
    await settled(mgr);
    await until(() => store.get(id).status !== "running");
    const run = store.get(id);
    assert.equal(run.exitCode, 10, `harness exit ${code}`);
    assert.match(run.note, /harness command exited with an error/);
    assert.ok(mgr.readJob("s1", id, {}).lines.some((l) => new RegExp(`harness command exited with code ${code}`).test(l.text)));
  }
});

test("pipeline: 'stop watching' leaves the record and Activity alone, and the scan keeps going", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "slow"), "");
  const { mgr, store, events } = realManager(home);
  const { id } = startScan(mgr, store);
  await until(() => fs.existsSync(path.join(home, "harness.pid")));
  mgr.cancelWatch("s1");
  await until(() => mgr.latestJob("s1").status === "cancelled");
  await new Promise((r) => setTimeout(r, 300));
  const run = store.get(id);
  assert.equal(run.status, "running");
  assert.ok(run.finishedAt == null, "elapsed time keeps counting");
  assert.deepEqual(events.map((e) => e.type), ["vulnhunt.scan.started"], "no failure event");
  await mgr.stopRun(spark, id);
});

test("pipeline: canStart refuses while a scan runs, so a refused request never has to evict history", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "slow"), "");
  const { mgr, store } = realManager(home);
  assert.equal(mgr.canStart(spark).ok, true);
  const { id } = startScan(mgr, store);
  assert.equal(mgr.canStart(spark).ok, false);
  assert.equal(mgr.canStart(spark).reason, "busy");
  await mgr.stopRun(spark, id);
  await settled(mgr);
  await until(() => store.get(id).status !== "running");
  assert.equal(mgr.canStart(spark).ok, true);
});

test("pipeline: a stop that did not happen is not remembered as a stop", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "slow"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await until(() => fs.existsSync(path.join(home, "harness.pid")));
  const real = mgr.runOnce.bind(mgr);
  mgr.runOnce = async () => ({ ok: false, code: 255, output: "ssh: connect to host x port 22: Connection refused", error: null });
  const res = await mgr.stopRun(spark, id);
  assert.equal(res.ok, false);
  assert.equal(mgr.latestJob("s1").stopRequested, false);
  mgr.runOnce = real;
  await mgr.stopRun(spark, id);
});

test("pipeline: output.log is kept bounded on the unit and the in-memory buffer has a byte budget", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home);
  fs.writeFileSync(path.join(home, "spew"), "");
  fs.writeFileSync(path.join(home, "spew-wait"), "");
  const { mgr, store } = realManager(home);
  const { id } = startScan(mgr, store);
  await settled(mgr);
  await until(() => store.get(id).status !== "running", 60_000);
  const log = fs.readFileSync(path.join(runDirOf(home, id), "output.log"), "utf8");
  assert.ok(log.length < 300_000, `log is ${log.length} bytes`);
  assert.match(log, /output trimmed/);

  // The browser-facing buffer: long lines are clipped, the total is budgeted.
  const job = mgr._newJob({ id: "s1" }, { id: "vh-20260101-000000-abcd", kind: "run", type: "vulnhunt" });
  for (let i = 0; i < 400; i++) mgr._line(job, "y".repeat(50_000));
  assert.ok(job.lines.every((l) => l.text.length <= 8 * 1024 + 40));
  assert.ok(job.lines.reduce((n, l) => n + l.text.length, 0) <= 2 * 1024 * 1024 + 8200);
  assert.ok(job.lines.length >= 100);
});

test("clone policy: metadata names and addresses (including IPv6 forms that embed them) are blocked, private hosts are not", () => {
  for (const host of [
    "metadata.google.internal",
    "metadata",
    "169.254.169.254",
    "100.100.100.200",
    "168.63.129.16",
    "fd00:ec2::254",
    "64:ff9b::a9fe:a9fe",
    "2002:a9fe:a9fe::",
    "::a9fe:a9fe",
    "::ffff:169.254.169.254",
    "fe80::1",
  ]) {
    assert.equal(isBlockedCloneHost(host), true, host);
  }
  for (const host of ["github.com", "git.corp.internal", "gitlab.example.org", "10.0.0.5", "192.168.1.20", "127.0.0.1", "100.64.1.2", "git.lan", "fd12:3456::1", "2001:db8::1", "::1"]) {
    assert.equal(isBlockedCloneHost(host), false, host);
  }
  assert.equal(validateSource({ type: "url", value: "https://metadata.google.internal/computeMetadata/v1" }).ok, false);
  assert.equal(validateSource({ type: "url", value: "https://github.com/a/%2e%2e/c" }).ok, false, "encoded dot segments are not collapsed silently");
});

test("allowed hosts: when pinned, only those hosts (and *.suffix patterns) may be cloned from", () => {
  const allowed = parseAllowedHosts(" github.com, *.corp.example ,bad host!, ");
  assert.deepEqual(allowed, ["github.com", "*.corp.example"]);
  const ok = (value) => validateSource({ type: "url", value }, { allowedHosts: allowed }).ok;
  assert.equal(ok("https://github.com/o/r"), true);
  assert.equal(ok("https://git.corp.example/o/r"), true);
  assert.equal(ok("https://corp.example/o/r"), false);
  assert.equal(ok("https://evilgithub.com/o/r"), false);
  assert.equal(ok("https://github.com.evil.example/o/r"), false);
  assert.equal(validateSource({ type: "url", value: "https://anything.example/o/r" }, { allowedHosts: [] }).ok, true, "empty list means any host the policy allows");
  assert.deepEqual(parseAllowedHosts("git.lan:8443, [::1]"), ["git.lan", "[::1]"], "a port is dropped: entries are host names");
  assert.equal(validateSource({ type: "url", value: "https://git.lan:8443/o/r" }, { allowedHosts: parseAllowedHosts("git.lan:8443") }).ok, true);
  assert.equal(validateScanRequest({ source: { type: "path", value: "~/x" }, authorized: true, timeoutMinutes: "0x20" }).ok, false);
  assert.equal(validateScanRequest({ source: { type: "path", value: "~/x" }, authorized: true, timeoutMinutes: [30] }).ok, false);
  assert.equal(validateScanRequest({ source: { type: "path", value: "~/x" }, authorized: true, timeoutMinutes: "30" }).timeoutMinutes, 30);
});

test("report: a later sparse row never erases values, escaped pipes and code spans keep their cell, header colon may be bold", () => {
  const md = [
    "**Run ID:** r1",
    "**Model**: m",
    "",
    "| ID | Title | CWE | Severity | Runtime | Exploit Test | Measured Impact | Status |",
    "|---|---|---|---|---|---|---|---|",
    "| VULN-001 | a \\| b | CWE-89 | High | in-process:node | PASS | 3 of 20 | Confirmed |",
    "| VULN-002 | uses `x | y` | CWE-79 | Medium | static | PASS | n | Confirmed |",
    "",
    "| ID | Title | CWE | Severity | Status |",
    "|---|---|---|---|---|",
    "| VULN-001 | a \\| b | CWE-89 | High+ | Fixed |",
  ].join("\n");
  const f = parseFindings(md);
  assert.equal(f.length, 2);
  const a = f.find((x) => x.id === "VULN-001");
  assert.equal(a.title, "a | b");
  assert.equal(a.severity, "High+", "the later row's value wins");
  assert.equal(a.status, "Fixed");
  assert.equal(a.runtime, "in-process:node", "an absent column does not erase it");
  assert.equal(a.exploitTest, "PASS");
  assert.equal(a.measuredImpact, "3 of 20");
  assert.equal(f.find((x) => x.id === "VULN-002").severity, "Medium", "a pipe in a code span does not shift the columns");
  assert.equal(summarizeReport({ report: md, manifestText: "", files: [] }).exploitPass, 2);
  const h = parseHeader(md);
  assert.equal(h.runId, "r1");
  assert.equal(h.model, "m");
});

// ── installing VulnHunter and saving the harness command from the UI ────────

/** A tiny stand-in for the VulnHunter repository (local, no network); returns its path and commit hash. */
function fakeUpstream() {
  const dir = tmp("vh-upstream-");
  const w = (rel, text) => {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  };
  w("vulnhunt/SKILL.md", "# vulnhunt\n");
  w("vulnhunt/phases/phase1_recon.md", "recon\n");
  w("agents/vulnhunter.md", "# agent\n");
  w("vh/__init__.py", "");
  w("vh/__main__.py", "import sys\nprint('vh stand-in', sys.argv[1:])\n");
  w("vh/cli.py", "# stand-in\n");
  execFileSync("git", ["init", "-q", dir]);
  execFileSync("git", ["-C", dir, "add", "-A"]);
  execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "x"]);
  const rev = execFileSync("git", ["-C", dir, "rev-parse", "HEAD"], { encoding: "utf8" }).trim();
  return { dir, rev };
}

async function runInstall(mgr, opts) {
  const res = mgr.installVulnHunt(spark, opts);
  assert.equal(res.ok, true);
  await until(() => mgr.latestJob("s1").status !== "running");
  const job = mgr.latestJob("s1");
  return { job, lines: mgr.readJob("s1", job.id, {}).lines.map((l) => l.text) };
}

test("install: the pinned revision is fetched by hash, the skill and vh are installed, and the unit reports it", async () => {
  const home = tmp("vh-home-");
  const up = fakeUpstream();
  const { mgr, events } = realManager(home);
  const { job, lines } = await runInstall(mgr, {
    skillsDir: "~/.claude/skills",
    agentsDir: "~/.claude/agents",
    source: { repo: `file://${up.dir}`, rev: up.rev, protocol: "file" },
  });
  assert.equal(job.status, "completed", lines.slice(-4).join("\n"));
  assert.ok(fs.existsSync(path.join(home, ".claude/skills/vulnhunt/SKILL.md")));
  assert.equal(fs.readFileSync(path.join(home, ".claude/skills/vulnhunt/.installed-from"), "utf8").trim(), up.rev);
  assert.ok(fs.existsSync(path.join(home, ".claude/agents/vulnhunter.md")));
  const launcher = path.join(home, ".local/bin/vh");
  assert.ok(fs.statSync(launcher).mode & 0o100, "vh is executable");
  assert.match(execFileSync(launcher, ["find-results", "x"], { encoding: "utf8" }), /vh stand-in/);
  assert.ok(events.some((e) => e.type === "vulnhunt.install.completed"));

  // The unit's status now says what is installed and where.
  fs.writeFileSync(path.join(home, ".config/sparkdash/vulnhunt-host-cmd"), "fake-harness\n", { mode: 0o600 });
  installFakeUnit(home);
  const st = await mgr.status(spark);
  assert.equal(st.installed, true);
  assert.equal(st.install.installedRev, up.rev);
  assert.equal(st.install.upToDate, false, "not the pinned revision of this build");
  assert.equal(st.install.skillsDir, path.join(home, ".claude/skills"));
  assert.ok(st.install.skillsDirCandidates.includes(path.join(home, ".claude/skills")));
  assert.match(st.install.python311, /^3\.\d+$/);

  // Re-running replaces the copy instead of failing.
  const again = await runInstall(mgr, { skillsDir: "~/.claude/skills", source: { repo: `file://${up.dir}`, rev: up.rev, protocol: "file" } });
  assert.equal(again.job.status, "completed");
});

test("install: destinations outside the home directory, and a revision that is not the one asked for, are refused", async () => {
  const home = tmp("vh-home-");
  const outside = tmp("vh-outside-");
  const up = fakeUpstream();
  const { mgr } = realManager(home);
  const src = { repo: `file://${up.dir}`, rev: up.rev, protocol: "file" };

  const bad = await runInstall(mgr, { skillsDir: outside, source: src });
  assert.equal(bad.job.exitCode, 2);
  assert.ok(bad.lines.some((l) => /inside this unit user's home/.test(l)));
  assert.equal(fs.existsSync(path.join(outside, "vulnhunt")), false);
  assert.equal(fs.existsSync(path.join(home, ".local/bin/vh")), false, "nothing was installed");

  const wrongRev = await runInstall(mgr, { skillsDir: "~/skills", source: { ...src, rev: "0".repeat(40) } });
  assert.equal(wrongRev.job.exitCode, 3);
  assert.equal(fs.existsSync(path.join(home, "skills/vulnhunt")), false);
});

test("install: arguments that would reach the program text are rejected before it is built", () => {
  assert.throws(() => buildInstallProgram({ skillsDir: "~/s", rev: "abc; rm -rf /" }), /invalid revision/);
  assert.throws(() => buildInstallProgram({ skillsDir: "~/s", repo: "https://x.example/a b" }), /invalid repository/);
  assert.throws(() => buildInstallProgram({ skillsDir: "~/s", protocol: "ext" }), /invalid protocol/);
});

test("install request and harness command: validated before they reach a unit", () => {
  assert.deepEqual(validateInstallRequest({ skillsDir: "~/.claude/skills/", agentsDir: "" }), { ok: true, skillsDir: "~/.claude/skills", agentsDir: "" });
  for (const skillsDir of ["", "relative", "/a/../b", "~", "/", "~/a b", "~/$(id)", "~/x;y", "/home/u/./x"]) {
    assert.equal(validateInstallRequest({ skillsDir }).ok, false, skillsDir);
  }
  assert.equal(validateInstallRequest({ skillsDir: "~/s", agentsDir: "../x" }).ok, false);
  assert.equal(validateHostCommand({ command: "  opencode run --file  " }).command, "opencode run --file");
  for (const command of ["", "   ", "a\nb", "a\u0000b", "-rf x", "x".repeat(501), 5]) {
    assert.equal(validateHostCommand({ command }).ok, false, JSON.stringify(command).slice(0, 30));
  }
});

test("harness command: saved private on the unit, only its program name comes back, refused when the program is missing", async () => {
  const home = tmp("vh-home-");
  installFakeUnit(home, { hostCmd: null });
  const { mgr } = realManager(home);
  const missing = await mgr.setHostCommand(spark, "no-such-harness --key sk-SECRET");
  assert.equal(missing.ok, false);
  assert.match(missing.message, /no-such-harness was not found/);
  assert.ok(!missing.message.includes("sk-SECRET"));

  const saved = await mgr.setHostCommand(spark, "fake-harness --headless --api-key sk-SECRET-VALUE");
  assert.equal(saved.ok, true);
  const file = path.join(home, ".config/sparkdash/vulnhunt-host-cmd");
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(file, "utf8"), "fake-harness --headless --api-key sk-SECRET-VALUE\n");
  const st = await mgr.status(spark);
  assert.equal(st.hostCommand.configured, true);
  assert.equal(st.hostCommand.program, "fake-harness");
  assert.ok(!JSON.stringify(st).includes("sk-SECRET-VALUE"));

  assert.equal((await mgr.clearHostCommand(spark)).ok, true);
  assert.equal(fs.existsSync(file), false);
  assert.equal((await mgr.status(spark)).hostCommand.configured, false);
});
