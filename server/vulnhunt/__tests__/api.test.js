import assert from "node:assert/strict";
import { isolatedConfigEnv } from "../../__tests__/isolatedEnv.js";
import { once } from "node:events";
import fs from "node:fs";
import { mkdtemp } from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { installFakeUnit } from "./fakeVulnHunt.js";

async function freePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  await new Promise((resolve) => server.close(resolve));
  return port;
}

async function startServer(t, extraEnv = {}) {
  const tmp = await mkdtemp(path.join(os.tmpdir(), "sparkdash-vh-"));
  fs.writeFileSync(path.join(tmp, "sparks.json"), "[]\n");
  installFakeUnit(tmp);
  const port = await freePort();
  const child = spawn(process.execPath, ["server/index.js"], {
    cwd: path.resolve(import.meta.dirname, "../../.."),
    env: {
      // The developer's own VulnHunter / dashboard settings must never reach a test server.
      ...Object.fromEntries(
        Object.entries(process.env).filter(([k]) => !k.startsWith("VULNHUNT_") && !k.startsWith("SPARKDASH_") && k !== "DASHBOARD_TOKEN" && k !== "BIND_HOST")
      ),
      ...isolatedConfigEnv(tmp),
      HOME: tmp,
      BIND_HOST: "127.0.0.1",
      PORT: String(port),
      SPARKS_JSON_PATH: path.join(tmp, "sparks.json"),
      SPARKS_SECRETS_PATH: path.join(tmp, "sparks-secrets.json"),
      SECRETS_KEY_PATH: path.join(tmp, ".secrets-key"),
      LLM_DAILY_JSON_PATH: path.join(tmp, "llm-daily.json"),
      LLM_TOKEN_JSON_PATH: path.join(tmp, "llm-tokens.json"),
      FLEET_ENERGY_JSON_PATH: path.join(tmp, "fleet-energy.json"),
      FLEET_ENERGY_MONTHLY_JSON_PATH: path.join(tmp, "fleet-energy-monthly.json"),
      EVENTS_JSON_PATH: path.join(tmp, "events.json"),
      GPU_HISTORY_JSON_PATH: path.join(tmp, "gpu-history.json"),
      LLM_LAUNCHERS_JSON_PATH: path.join(tmp, "llm-launchers.json"),
      VULNHUNT_RUNS_PATH: path.join(tmp, "vulnhunt-runs.json"),
      VULNHUNT_RESULTS_DIR: path.join(tmp, "vulnhunt-results"),
      SPARKDASH_VULNHUNT_GRACE: "2",
      ...extraEnv,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(async () => {
    child.kill("SIGTERM");
    // Bounded: a server stuck in its graceful shutdown must not hang the whole suite.
    await new Promise((resolve) => {
      if (child.exitCode != null || child.signalCode != null) return resolve();
      const hard = setTimeout(() => child.kill("SIGKILL"), 5_000);
      child.once("exit", () => {
        clearTimeout(hard);
        resolve();
      });
    });
    fs.rmSync(tmp, { recursive: true, force: true });
  });
  let output = "";
  child.stdout.on("data", (c) => (output += c));
  child.stderr.on("data", (c) => (output += c));
  await Promise.race([
    new Promise((resolve) => {
      const check = () => (output.includes("server listening") ? resolve() : setTimeout(check, 10));
      check();
    }),
    new Promise((_, reject) => setTimeout(() => reject(new Error(`server did not start:\n${output}`)), 6_000)),
  ]);
  return { port, tmp };
}

async function api(port, pathname, init) {
  // Bounded: an unanswered request must fail this test, not hang the suite.
  const response = await fetch(`http://127.0.0.1:${port}${pathname}`, {
    signal: AbortSignal.timeout(45_000),
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
  });
  return { status: response.status, body: await response.json().catch(() => ({})) };
}

async function until(fn, ms = 20_000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await new Promise((r) => setTimeout(r, 80));
  }
  throw new Error("timed out");
}

test("VulnHunter over HTTP: setup, status, validation, a streamed scan, its parsed report, and delete", async (t) => {
  const { port } = await startServer(t);
  const created = await api(port, "/api/sparks", {
    method: "POST",
    body: JSON.stringify({ id: "alpha", name: "alpha", lanIp: "127.0.0.1", isLocal: true, ssh: { host: "127.0.0.1", user: os.userInfo().username, auth: "key" } }),
  });
  assert.equal(created.status, 200);
  const base = "/api/sparks/alpha/vulnhunt";

  const setup = await api(port, "/api/vulnhunt/setup");
  assert.equal(setup.status, 200);
  assert.match(setup.body.repository, /VulnHunter/);
  assert.ok(setup.body.steps.length >= 3);
  assert.equal(setup.body.hostCommandFile, "~/.config/sparkdash/vulnhunt-host-cmd");

  assert.equal((await api(port, "/api/sparks/nope/vulnhunt/status")).status, 404);
  const status = await api(port, `${base}/status`);
  assert.equal(status.body.installed, true);
  assert.equal(status.body.ready, true);
  assert.equal(status.body.hostCommand.program, "fake-harness");

  // Validation: attestation, transport, code execution and bounds are all refused with a readable 400.
  const post = (body) => api(port, `${base}/runs`, { method: "POST", body: JSON.stringify(body) });
  const src = { type: "url", value: "https://example.com/org/repo" };
  assert.match((await post({ source: src })).body.error, /authorized/);
  assert.equal((await post({ source: { type: "url", value: "http://example.com/x" }, authorized: true })).status, 400);
  assert.equal((await post({ source: { type: "url", value: "git@example.com:x/y.git" }, authorized: true })).status, 400);
  assert.equal((await post({ source: { type: "path", value: "../../etc" }, authorized: true })).status, 400);
  assert.equal((await post({ source: src, authorized: true, readOnly: false })).status, 400);
  assert.equal((await post({ source: src, authorized: true, timeoutMinutes: 1 })).status, 400);
  assert.equal((await api(port, `${base}/runs`)).body.runs.length, 0, "nothing was stored for refused requests");

  const start = await post({ source: src, authorized: true, label: "ci" });
  assert.equal(start.status, 202);
  const rid = start.body.run.id;
  assert.equal(start.body.run.readOnly, true);
  assert.equal(start.body.run.label, "ci");
  const before = (await api(port, `${base}/runs`)).body.runs.length;
  assert.equal((await post({ source: src, authorized: true })).status, 409, "one job per unit");
  assert.equal((await api(port, `${base}/runs`)).body.runs.length, before, "a refused start stores nothing");
  assert.equal(typeof start.body.run.authorization.at, "number", "the attestation is kept on the run");
  assert.equal(typeof start.body.run.authorization.by, "string");
  assert.equal((await api(port, `${base}/runs/${rid}/report`)).status, 409, "no report is read mid-scan");

  const done = await until(async () => {
    const s = await api(port, `${base}/runs/${rid}/stream?lineSince=0`);
    return s.body.live?.job?.status === "completed" ? s.body : null;
  });
  assert.ok(done.live.lines.some((l) => /harness: done/.test(l.text)));
  assert.equal(done.live.progress.stage, "done");

  const fin = await until(async () => {
    const r = await api(port, `${base}/runs/${rid}`);
    return r.body.run.summary ? r.body.run : null;
  });
  assert.equal(fin.status, "completed");
  assert.equal(fin.summary.total, 2);
  assert.equal(fin.summary.counts.High, 1);

  const report = await api(port, `${base}/runs/${rid}/report`);
  assert.equal(report.status, 200);
  assert.equal(report.body.report.findings.length, 2);
  assert.equal(report.body.report.header.model, "test-model");
  assert.ok(report.body.report.artifacts.includes("poc/VULN-001_sql_injection.md"));
  assert.ok(!JSON.stringify(report.body).includes("TOP-SECRET"));

  const events = await api(port, "/api/events?limit=20");
  assert.ok(events.body.events.some((e) => e.type === "vulnhunt.scan.started"));
  assert.ok(events.body.events.some((e) => e.type === "vulnhunt.scan.completed" && /2 confirmed findings/.test(e.message)));

  assert.equal((await api(port, `${base}/runs/${rid}`, { method: "DELETE" })).status, 200);
  assert.equal((await api(port, `${base}/runs/${rid}`)).status, 404);
  assert.equal((await api(port, `${base}/runs/not-a-run-id`)).status, 404);
  assert.equal((await api(port, `${base}/runs`)).body.runs.length, 0);
});

/** Scans are detached on purpose: end one and wait, so no wrapper is still writing when its temp dir is removed. */
async function settleScan(port, rid, headers = {}) {
  const base = "/api/sparks/alpha/vulnhunt";
  await api(port, `${base}/runs/${rid}/stop`, { method: "POST", headers, body: "{}" });
  await until(async () => (await api(port, `${base}/runs/${rid}`, { headers })).body.run?.status !== "running");
}

async function addLocalSpark(port, headers = {}) {
  const created = await api(port, "/api/sparks", {
    method: "POST",
    headers,
    body: JSON.stringify({ id: "alpha", name: "alpha", lanIp: "127.0.0.1", isLocal: true, ssh: { host: "127.0.0.1", user: os.userInfo().username, auth: "key" } }),
  });
  assert.equal(created.status, 200);
}

test("VulnHunter over HTTP: starting a scan needs a token or a loopback bind, and the pinned host list is enforced", async (t) => {
  const body = JSON.stringify({ source: { type: "url", value: "https://example.com/org/repo" }, authorized: true });

  // Reachable from the network and no token: the dashboard is open, so scans are not offered.
  const open = await startServer(t, { BIND_HOST: "0.0.0.0" });
  await addLocalSpark(open.port);
  const setup = await api(open.port, "/api/vulnhunt/setup");
  assert.equal(setup.body.startAllowed, false);
  assert.match(setup.body.startBlockedReason, /SPARKDASH_TOKEN/);
  const refused = await api(open.port, "/api/sparks/alpha/vulnhunt/runs", { method: "POST", body });
  assert.equal(refused.status, 403);
  assert.match(refused.body.error, /SPARKDASH_TOKEN/);
  assert.equal((await api(open.port, "/api/sparks/alpha/vulnhunt/runs")).body.runs.length, 0);

  // Same bind with a token: allowed for a caller that has it.
  const token = "t0ken-for-tests";
  const guarded = await startServer(t, { BIND_HOST: "0.0.0.0", SPARKDASH_TOKEN: token });
  const auth = { Authorization: `Bearer ${token}` };
  await addLocalSpark(guarded.port, auth);
  assert.equal((await api(guarded.port, "/api/sparks/alpha/vulnhunt/runs", { method: "POST", body })).status, 401);
  const ok = await api(guarded.port, "/api/sparks/alpha/vulnhunt/runs", { method: "POST", body, headers: auth });
  assert.equal(ok.status, 202);
  assert.equal((await api(guarded.port, "/api/vulnhunt/setup", { headers: auth })).body.startAllowed, true);
  await settleScan(guarded.port, ok.body.run.id, auth);

  // A pinned host list.
  const pinned = await startServer(t, { VULNHUNT_ALLOWED_HOSTS: "git.example.org, *.corp.example" });
  await addLocalSpark(pinned.port);
  const ps = await api(pinned.port, "/api/vulnhunt/setup");
  assert.deepEqual(ps.body.allowedHosts, ["git.example.org", "*.corp.example"]);
  const no = await api(pinned.port, "/api/sparks/alpha/vulnhunt/runs", { method: "POST", body });
  assert.equal(no.status, 400);
  assert.match(no.body.error, /VULNHUNT_ALLOWED_HOSTS/);
  const yes = await api(pinned.port, "/api/sparks/alpha/vulnhunt/runs", {
    method: "POST",
    body: JSON.stringify({ source: { type: "url", value: "https://git.example.org/org/repo" }, authorized: true }),
  });
  assert.equal(yes.status, 202);
  await settleScan(pinned.port, yes.body.run.id);
});

test("VulnHunter over HTTP: deleting a running scan needs force, and a forced delete stops it first", async (t) => {
  const { port, tmp } = await startServer(t);
  await addLocalSpark(port);
  fs.writeFileSync(path.join(tmp, "slow"), "");
  const base = "/api/sparks/alpha/vulnhunt";
  const start = await api(port, `${base}/runs`, {
    method: "POST",
    body: JSON.stringify({ source: { type: "url", value: "https://example.com/org/repo" }, authorized: true }),
  });
  assert.equal(start.status, 202);
  const rid = start.body.run.id;
  await until(() => fs.existsSync(path.join(tmp, "harness.pid")));
  const hp = Number(fs.readFileSync(path.join(tmp, "harness.pid"), "utf8"));

  const plain = await api(port, `${base}/runs/${rid}`, { method: "DELETE" });
  assert.equal(plain.status, 409, "a running scan is not deleted without saying so");
  assert.equal(await api(port, `${base}/runs/${rid}`).then((r) => r.status), 200);

  const forced = await api(port, `${base}/runs/${rid}?force=1`, { method: "DELETE" });
  assert.equal(forced.status, 200);
  await until(() => {
    try {
      process.kill(hp, 0);
      return false;
    } catch {
      return true;
    }
  });
  assert.equal((await api(port, `${base}/runs`)).body.runs.length, 0);
  // Nothing may still be running on the unit, so a new scan is allowed.
  fs.rmSync(path.join(tmp, "slow"));
  const again = await api(port, `${base}/runs`, {
    method: "POST",
    body: JSON.stringify({ source: { type: "url", value: "https://example.com/org/repo" }, authorized: true }),
  });
  assert.equal(again.status, 202);
  await settleScan(port, again.body.run.id);
});

test("VulnHunter over HTTP: install and harness-command endpoints are gated, validated and never echo the command", async (t) => {
  // Open network bind, no token: refused like starting a scan.
  const open = await startServer(t, { BIND_HOST: "0.0.0.0" });
  await addLocalSpark(open.port);
  const post = (port, p, body, headers) => api(port, p, { method: "POST", body: JSON.stringify(body), headers });
  assert.equal((await post(open.port, "/api/sparks/alpha/vulnhunt/install", { skillsDir: "~/.claude/skills" })).status, 403);
  const putOpen = await api(open.port, "/api/sparks/alpha/vulnhunt/host-command", { method: "PUT", body: JSON.stringify({ command: "fake-harness" }) });
  assert.equal(putOpen.status, 403);
  assert.equal((await api(open.port, "/api/sparks/alpha/vulnhunt/host-command", { method: "DELETE" })).status, 403);

  // Loopback bind (the default here): validation, then the real thing against a stand-in harness.
  const { port, tmp } = await startServer(t);
  await addLocalSpark(port);
  const base = "/api/sparks/alpha/vulnhunt";
  assert.equal((await api(port, `${base}/install/stream`)).status, 404, "no install yet");
  assert.equal((await post(port, `${base}/install`, { skillsDir: "../../etc" })).status, 400);
  assert.equal((await post(port, `${base}/install`, { skillsDir: "~/ok", agentsDir: "/a/../b" })).status, 400);
  assert.equal((await api(port, `${base}/host-command`, { method: "PUT", body: JSON.stringify({ command: "a\nb" }) })).status, 400);
  assert.equal((await api(port, `${base}/host-command`, { method: "PUT", body: JSON.stringify({}) })).status, 400);

  const secret = "sk-TOP-SECRET-FOR-TEST";
  const bad = await api(port, `${base}/host-command`, { method: "PUT", body: JSON.stringify({ command: `not-a-program --key ${secret}` }) });
  assert.equal(bad.status, 400);
  assert.ok(!JSON.stringify(bad.body).includes(secret), "the command is never echoed, not even in an error");

  const good = await api(port, `${base}/host-command`, { method: "PUT", body: JSON.stringify({ command: `fake-harness --headless --key ${secret}` }) });
  assert.equal(good.status, 200);
  const status = await api(port, `${base}/status`);
  assert.equal(status.body.hostCommand.configured, true);
  assert.equal(status.body.hostCommand.program, "fake-harness");
  assert.ok(!JSON.stringify(status.body).includes(secret));
  assert.equal(fs.statSync(path.join(tmp, ".config/sparkdash/vulnhunt-host-cmd")).mode & 0o077, 0);
  assert.equal(status.body.install.pinnedRev.length, 40);
  assert.equal(status.body.install.installedRev, null);

  assert.equal((await api(port, `${base}/host-command`, { method: "DELETE" })).body.success, true);
  assert.equal((await api(port, `${base}/status`)).body.hostCommand.configured, false);
});
