import test, { after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync, spawn } from "node:child_process";
import {
  REA_PKG,
  REA_VERSION,
  RUN_ROOT,
  UPLOAD_ROOT,
  LAUNCHER,
  exitToken,
  runDirRef,
  uploadDirRef,
  installPayload,
  buildInstallProgram,
  buildStatusProgram,
  buildRunProgram,
  buildAttachProgram,
  buildStopProgram,
  buildCheckProgram,
  buildDeleteRunProgram,
  buildReadResultProgram,
  buildViewProgram,
  buildExportProgram,
  buildCompareProgram,
  buildUploadCreateProgram,
  buildUploadPutProgram,
  buildUploadCommitProgram,
  buildUploadDeleteProgram,
  buildUploadSweepProgram,
} from "../commands.js";
import { installFakeRea } from "./fakeRea.js";

// ── harness ─────────────────────────────────────────────────────────────────

const made = [];
const procs = new Set();
const tmp = (p) => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), p)));
  made.push(d);
  return d;
};
const homes = [];
const newHome = (opts) => {
  const h = tmp("rea-home-");
  homes.push(h);
  installFakeRea(h, opts);
  fs.mkdirSync(path.join(h, "data"), { recursive: true });
  fs.writeFileSync(path.join(h, "data", "sample.bin"), "hello rea\n");
  fs.writeFileSync(path.join(h, "secret.txt"), "TOP-SECRET-DO-NOT-LEAK\n");
  return h;
};
const killGroup = (pid) => {
  for (const target of [-pid, pid]) {
    try {
      process.kill(target, "SIGKILL");
    } catch {}
  }
};
const reap = (home) => {
  for (const base of [path.join(home, ".cache", "sparkdash", "rea", "runs")]) {
    let ids = [];
    try {
      ids = fs.readdirSync(base);
    } catch {}
    for (const id of ids) {
      try {
        const pid = Number(fs.readFileSync(path.join(base, id, "pid"), "utf8"));
        if (pid > 1) killGroup(pid);
      } catch {}
    }
  }
  try {
    const pid = Number(fs.readFileSync(path.join(home, "rea.pid"), "utf8"));
    if (pid > 1) killGroup(pid);
  } catch {}
};
after(() => {
  for (const p of procs) killGroup(p);
  for (const h of homes) reap(h);
  for (const d of made) fs.rmSync(d, { recursive: true, force: true });
});

const NODE_DIR = path.dirname(process.execPath);
const BASE_PATH = `${NODE_DIR}:/usr/local/bin:/usr/bin:/bin`;
const unitEnv = (home, extra = {}) => ({
  HOME: home,
  PATH: BASE_PATH,
  LANG: "C",
  SPARKDASH_REA_GRACE: "2",
  SPARKDASH_REA_TICK: "1",
  SPARKDASH_REA_LOGMAX: "100000",
  ...extra,
});

/** Run a program (real bash), bounded. Resolves {code, out, err}. */
function exec(cmd, { home, env, stdin, timeoutMs = 60_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn("/bin/bash", ["-c", cmd], {
      env: unitEnv(home, env),
      stdio: [stdin == null ? "ignore" : "pipe", "pipe", "pipe"],
      detached: true,
    });
    procs.add(child.pid);
    let out = "";
    let err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    const timer = setTimeout(() => {
      killGroup(child.pid);
      reject(new Error(`program timed out\n${out}\n${err}`));
    }, timeoutMs);
    child.on("close", (code) => {
      clearTimeout(timer);
      procs.delete(child.pid);
      resolve({ code, out, err });
    });
    if (stdin != null) {
      child.stdin.on("error", () => {});
      child.stdin.end(stdin);
    }
  });
}

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

let idCounter = 0;
const rnd = () => (++idCounter).toString(36).padStart(4, "0").slice(-4);
const newRunId = () => `rea-20261012-120000-${rnd()}`;
const newUploadId = () => `up-20261012-120000-${rnd()}ab`;
const nulB64 = (...a) => Buffer.from(a.join("\0"), "utf8").toString("base64");
const NONCE = "n1";
const TX = exitToken(NONCE);
const exitOf = (out) => {
  const m = out.trimEnd().split("\n").at(-1);
  assert.ok(m.startsWith(TX), `no exit token in: ${out.slice(-300)}`);
  return Number(m.slice(TX.length));
};
const runDir = (home, id) => path.join(home, ".cache", "sparkdash", "rea", "runs", id);
const upDir = (home, id) => path.join(home, ".cache", "sparkdash", "rea", "uploads", id);
const sentinel = () => `__S${crypto.randomBytes(8).toString("hex")}__:`;

function runProgram(home, { id = newRunId(), argv, paths = [], timeoutSeconds = 30, cap = 1_000_000, display = "rea test" }) {
  return buildRunProgram({
    runId: id,
    argvB64: nulB64(...argv),
    pathsB64: paths.length ? nulB64(...paths) : "",
    displayLine: display,
    timeoutSeconds,
    resultCapBytes: cap,
    nonce: NONCE,
  });
}

/** Split `<S>NAME\nvalue...` sections. */
function sections(out, S) {
  const res = {};
  const lines = out.split("\n");
  let name = null;
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith(S)) {
      name = lines[i].slice(S.length);
      res[name] = [];
    } else if (name) res[name].push(lines[i]);
  }
  for (const k of Object.keys(res)) res[k] = res[k].join("\n").replace(/\n$/, "");
  return res;
}
const kv = (out) => Object.fromEntries(out.split("\n").filter((l) => /^[A-Za-z0-9_]+=/.test(l)).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));

// ── constants & builders ────────────────────────────────────────────────────

test("constants and id validation", () => {
  assert.equal(REA_PKG, "rea-agents");
  assert.equal(REA_VERSION, "6.4.0");
  assert.match(RUN_ROOT, /^\$HOME\/\.cache\/sparkdash\/rea\/runs$/);
  assert.match(UPLOAD_ROOT, /^\$HOME\/\.cache\/sparkdash\/rea\/uploads$/);
  assert.equal(LAUNCHER, "$HOME/.local/bin/rea-sparkdash");
  assert.equal(runDirRef("rea-20261012-120000-abcd"), "~/.cache/sparkdash/rea/runs/rea-20261012-120000-abcd");
  assert.equal(uploadDirRef("up-20261012-120000-abcdef"), "~/.cache/sparkdash/rea/uploads/up-20261012-120000-abcdef");
  assert.throws(() => buildCheckProgram({ runId: "../../etc" }), /invalid run id/);
  assert.throws(() => buildDeleteRunProgram({ runId: "rea-1; rm -rf /" }), /invalid run id/);
  assert.throws(() => buildUploadDeleteProgram({ uploadId: "x" }), /invalid upload id/);
  assert.throws(() => buildUploadPutProgram({ uploadId: newUploadId(), relPath: "../x", maxBytes: 1 }), /invalid path/);
  assert.throws(() => buildUploadPutProgram({ uploadId: newUploadId(), relPath: "a/./b", maxBytes: 1 }), /invalid path/);
  assert.throws(() => buildUploadPutProgram({ uploadId: newUploadId(), relPath: ".committed", maxBytes: 1 }), /reserved/);
  assert.throws(() => buildUploadPutProgram({ uploadId: newUploadId(), relPath: "a.txt", maxBytes: 1, archive: true }), /archive/);
  assert.throws(() => buildReadResultProgram({ runId: newRunId(), sentinel: "short", maxBytes: 1 }), /sentinel/);
  const payload = installPayload();
  assert.match(payload, /^PKG \d+\n\{/);
  assert.ok(payload.includes("\nLOCK "));
  assert.ok(payload.length > 60_000, "the lockfile travels in the payload");
  assert.ok(!buildInstallProgram({ nonce: "x" }).includes("lockfileVersion"));
});

// ── run ─────────────────────────────────────────────────────────────────────

test("run: happy path writes result.json and exit 0; the path is handed over resolved", async () => {
  const home = newHome();
  const id = newRunId();
  const target = path.join(home, "data", "sample.bin");
  const r = await exec(runProgram(home, { id, argv: ["inspect-artifact", target, "--json"], paths: [target], display: "inspect-artifact sample.bin" }), { home });
  assert.equal(exitOf(r.out), 0, r.out);
  const rd = runDir(home, id);
  const res = JSON.parse(fs.readFileSync(path.join(rd, "result.json"), "utf8"));
  assert.equal(res.path, target);
  assert.equal(fs.readFileSync(path.join(rd, "exit"), "utf8").trim(), "0");
  assert.ok(!fs.existsSync(path.join(rd, "pid")), "pid file removed at the end");
  assert.match(fs.readFileSync(path.join(rd, "output.log"), "utf8"), /\[sparkdash\] inspect-artifact sample\.bin/);
  assert.match(fs.readFileSync(path.join(home, "rea.argv"), "utf8"), /inspect-artifact .*sample\.bin --json/);
  assert.equal(fs.statSync(path.join(rd, "result.json")).mode & 0o077, 0, "umask 077");
  // attach and check on a finished run
  const att = await exec(buildAttachProgram({ runId: id, nonce: NONCE }), { home });
  assert.match(att.out, /inspect-artifact sample\.bin/);
  assert.equal(exitOf(att.out), 0);
  const chk = await exec(buildCheckProgram({ runId: id }), { home });
  assert.equal(chk.out.trim(), "EXIT=0");
  const gone = await exec(buildCheckProgram({ runId: newRunId() }), { home });
  assert.equal(gone.out.trim(), "GONE");
  // delete
  const del = await exec(buildDeleteRunProgram({ runId: id }), { home });
  assert.equal(del.out.trim(), "ok");
  assert.ok(!fs.existsSync(rd));
});

test("run: ~/ paths and the run-owned output placeholder are expanded by the wrapper; zero-target runs work", async () => {
  const home = newHome();
  const id = newRunId();
  const r = await exec(
    runProgram(home, { id, argv: ["inspect-artifact", "~/data/sample.bin", "--output-directory", "@@REA_RUN_OUT@@/dump", "--json"], paths: ["~/data/sample.bin"] }),
    { home }
  );
  assert.equal(exitOf(r.out), 0, r.out);
  const logged = fs.readFileSync(path.join(home, "rea.argv"), "utf8");
  assert.ok(logged.includes(`${path.join(home, "data", "sample.bin")} --output-directory ${runDir(home, id)}/out/dump --json`), logged);
  assert.ok(fs.statSync(path.join(runDir(home, id), "out")).isDirectory());
  assert.ok(!fs.existsSync(path.join(runDir(home, id), "out", "dump")), "the leaf is not pre-created");
  const bad = await exec(runProgram(home, { argv: ["inspect-artifact", "~/../etc/passwd"], paths: ["~/../etc/passwd"] }), { home });
  assert.equal(exitOf(bad.out), 2);
  const none = await exec(runProgram(home, { argv: ["providers", "--json"], paths: [] }), { home });
  assert.equal(exitOf(none.out), 0, none.out);
});

test("run: a path outside the unit user's home is refused with exit 2 and rea is never started", async () => {
  const home = newHome();
  const outside = tmp("rea-outside-");
  fs.writeFileSync(path.join(outside, "x.bin"), "x");
  const id = newRunId();
  const target = path.join(outside, "x.bin");
  const r = await exec(runProgram(home, { id, argv: ["inspect-artifact", target, "--json"], paths: [target] }), { home });
  assert.equal(exitOf(r.out), 2);
  assert.match(r.out, /inside this unit user's home/);
  assert.equal(fs.readFileSync(path.join(runDir(home, id), "exit"), "utf8").trim(), "2");
  assert.ok(!fs.existsSync(path.join(home, "rea.argv")));
  // a relative path and a missing path are refused too
  const rel = await exec(runProgram(home, { argv: ["inspect-artifact", "data/sample.bin", "--json"], paths: ["data/sample.bin"] }), { home });
  assert.equal(exitOf(rel.out), 2);
  const missing = path.join(home, "data", "nope.bin");
  const miss = await exec(runProgram(home, { argv: ["inspect-artifact", missing], paths: [missing] }), { home });
  assert.equal(exitOf(miss.out), 2);
  assert.match(miss.out, /does not exist/);
});

test("run: a symlinked HOME works; a link inside home that points outside is refused", async () => {
  const real = newHome();
  const holder = tmp("rea-link-");
  const link = path.join(holder, "home-link");
  fs.symlinkSync(real, link);
  const viaLink = path.join(link, "data", "sample.bin");
  const ok = await exec(runProgram(link, { argv: ["inspect-artifact", viaLink, "--json"], paths: [viaLink] }), { home: link });
  assert.equal(exitOf(ok.out), 0, ok.out);
  assert.match(fs.readFileSync(path.join(real, "rea.argv"), "utf8"), new RegExp(`${path.join(real, "data", "sample.bin").replace(/\./g, "\\.")} --json`), "rea gets the resolved path");

  const outside = tmp("rea-outside-");
  fs.writeFileSync(path.join(outside, "o.bin"), "o");
  fs.symlinkSync(path.join(outside, "o.bin"), path.join(real, "data", "evil-link.bin"));
  const bad = path.join(link, "data", "evil-link.bin");
  const r = await exec(runProgram(link, { argv: ["inspect-artifact", bad], paths: [bad] }), { home: link });
  assert.equal(exitOf(r.out), 2);
});

test("run: a symlinked ~/.cache inside home works end to end; one pointing outside refuses targets under it", async () => {
  const home = newHome();
  fs.mkdirSync(path.join(home, "store"), { recursive: true });
  fs.symlinkSync(path.join(home, "store"), path.join(home, ".cache"));
  const id = newRunId();
  const target = path.join(home, "data", "sample.bin");
  const r = await exec(runProgram(home, { id, argv: ["inspect-artifact", target, "--json"], paths: [target] }), { home });
  assert.equal(exitOf(r.out), 0, r.out);
  assert.ok(fs.existsSync(path.join(home, "store", "sparkdash", "rea", "runs", id, "result.json")));
  const S = sentinel();
  const rd = await exec(buildReadResultProgram({ runId: id, sentinel: S, maxBytes: 100000 }), { home });
  const sec = sections(rd.out, S);
  assert.ok(sec.BODY, rd.out);
  assert.equal(JSON.parse(sec.BODY).path, target);

  const home2 = newHome();
  const outCache = tmp("rea-outcache-");
  fs.symlinkSync(outCache, path.join(home2, ".cache"));
  fs.mkdirSync(path.join(outCache, "up"), { recursive: true });
  fs.writeFileSync(path.join(outCache, "up", "f.bin"), "x");
  const t2 = path.join(home2, ".cache", "up", "f.bin");
  const r2 = await exec(runProgram(home2, { argv: ["inspect-artifact", t2], paths: [t2] }), { home: home2 });
  assert.equal(exitOf(r2.out), 2);
});

test("run: stop reaches rea and settles as 143 (the wrapper survives to write it)", async () => {
  const home = newHome();
  fs.writeFileSync(path.join(home, "rea-slow"), "");
  const id = newRunId();
  const target = path.join(home, "data", "sample.bin");
  const run = exec(runProgram(home, { id, argv: ["inspect-artifact", target, "--json"], paths: [target] }), { home });
  await until(() => fs.existsSync(path.join(home, "rea.pid")));
  const rp = Number(fs.readFileSync(path.join(home, "rea.pid"), "utf8"));
  const again = await exec(runProgram(home, { id, argv: ["inspect-artifact", target, "--json"], paths: [target] }), { home });
  assert.match(again.out, /already running/, "a second start of the same run is refused");
  const chk = await exec(buildCheckProgram({ runId: id }), { home });
  assert.equal(chk.out.trim(), "ALIVE");
  const stop = await exec(buildStopProgram({ runId: id }), { home });
  assert.match(stop.out, /stopped|killed/);
  const r = await run;
  assert.equal(exitOf(r.out), 143);
  assert.equal(fs.readFileSync(path.join(runDir(home, id), "exit"), "utf8").trim(), "143");
  assert.equal(alive(rp), false, "rea is gone");
  const after = await exec(buildStopProgram({ runId: id }), { home });
  assert.equal(after.out.trim(), "not running");
});

test("run: a tool that ignores TERM is killed after the grace period; the wrapper still settles 143", async () => {
  const home = newHome();
  fs.writeFileSync(path.join(home, "rea-ignore-term"), "");
  const id = newRunId();
  const target = path.join(home, "data", "sample.bin");
  const run = exec(runProgram(home, { id, argv: ["inspect-artifact", target], paths: [target] }), { home, env: { SPARKDASH_REA_GRACE: "1" } });
  await until(() => fs.existsSync(path.join(home, "rea.pid")));
  const rp = Number(fs.readFileSync(path.join(home, "rea.pid"), "utf8"));
  const t0 = Date.now();
  const stop = await exec(buildStopProgram({ runId: id }), { home, env: { SPARKDASH_REA_GRACE: "1" } });
  assert.match(stop.out, /stopped|killed/);
  const r = await run;
  assert.equal(exitOf(r.out), 143);
  assert.ok(Date.now() - t0 < 20_000);
  assert.equal(alive(rp), false);
  assert.equal(fs.readFileSync(path.join(runDir(home, id), "exit"), "utf8").trim(), "143");
});

test("run: the time limit ends the run with 124", async () => {
  const home = newHome();
  fs.writeFileSync(path.join(home, "rea-slow"), "");
  const id = newRunId();
  const target = path.join(home, "data", "sample.bin");
  const t0 = Date.now();
  const r = await exec(runProgram(home, { id, argv: ["inspect-artifact", target], paths: [target], timeoutSeconds: 2 }), { home });
  assert.equal(exitOf(r.out), 124, r.out);
  assert.ok(Date.now() - t0 < 25_000);
  assert.match(fs.readFileSync(path.join(runDir(home, id), "output.log"), "utf8"), /time limit/);
  assert.equal(fs.readFileSync(path.join(runDir(home, id), "exit"), "utf8").trim(), "124");
});

test("run: a result over the cap is cut off and the run settles 11", async () => {
  const home = newHome();
  fs.writeFileSync(path.join(home, "rea-big"), "");
  const id = newRunId();
  const target = path.join(home, "data", "sample.bin");
  const r = await exec(runProgram(home, { id, argv: ["inspect-artifact", target], paths: [target], cap: 50_000 }), { home });
  assert.equal(exitOf(r.out), 11, r.out);
  assert.equal(fs.statSync(path.join(runDir(home, id), "result.json")).size, 50_000);
  assert.match(r.out, /size limit/);
});

test("run: rea's own failures are mapped by the wrapper (10, 2, 126, 127), never passed through", async () => {
  const target = (h) => path.join(h, "data", "sample.bin");
  const cases = [
    { marker: ["rea-exit-code", "3"], want: 10 },
    { marker: ["rea-error-zero", ""], want: 10 },
    { marker: ["rea-error-code", "weird_failure"], want: 10 },
    { marker: ["rea-error-code", "target_unavailable"], want: 2 },
    { marker: ["rea-error-code", "provider_missing"], want: 126 },
  ];
  for (const c of cases) {
    const home = newHome();
    fs.writeFileSync(path.join(home, c.marker[0]), c.marker[1]);
    const r = await exec(runProgram(home, { argv: ["inspect-artifact", target(home)], paths: [target(home)] }), { home });
    assert.equal(exitOf(r.out), c.want, `${c.marker.join("=")}: ${r.out}`);
  }
  // a command rea does not know: error object + exit 1
  const home = newHome();
  const r = await exec(runProgram(home, { argv: ["frobnicate", "--json"] }), { home });
  assert.equal(exitOf(r.out), 10);
  assert.match(fs.readFileSync(path.join(home, ".cache/sparkdash/rea/runs", fs.readdirSync(path.join(home, ".cache/sparkdash/rea/runs"))[0], "result.json"), "utf8"), /COMMAND_NOT_FOUND/);
});

test("run: REA not installed -> 127 recorded in the exit file", async () => {
  const home = tmp("rea-home-");
  homes.push(home);
  const id = newRunId();
  const r = await exec(runProgram(home, { id, argv: ["inspect-artifact", "/x"] }), { home });
  assert.equal(exitOf(r.out), 127);
  assert.match(r.out, /not installed/);
  assert.equal(fs.readFileSync(path.join(runDir(home, id), "exit"), "utf8").trim(), "127");
});

test("run: a wrapper that was SIGKILLed settles through check (EXIT=-1), not ALIVE", async () => {
  const home = newHome();
  fs.writeFileSync(path.join(home, "rea-slow"), "");
  const id = newRunId();
  const target = path.join(home, "data", "sample.bin");
  const run = exec(runProgram(home, { id, argv: ["inspect-artifact", target], paths: [target] }), { home });
  const pidFile = path.join(runDir(home, id), "pid");
  await until(() => fs.existsSync(pidFile) && fs.existsSync(path.join(home, "rea.pid")));
  const pid = Number(fs.readFileSync(pidFile, "utf8"));
  process.kill(pid, "SIGKILL");
  const chk = await until(async () => {
    const c = await exec(buildCheckProgram({ runId: id }), { home });
    return c.out.trim() === "ALIVE" ? null : c.out.trim();
  });
  assert.equal(chk, "EXIT=-1");
  const r = await run;
  assert.equal(exitOf(r.out), -1);
  reap(home);
});

// ── reading ─────────────────────────────────────────────────────────────────

async function completedRun(home, extraArgs = []) {
  const id = newRunId();
  const target = path.join(home, "data", "sample.bin");
  const r = await exec(runProgram(home, { id, argv: ["inspect-artifact", target, "--json", ...extraArgs], paths: [target] }), { home });
  assert.equal(exitOf(r.out), 0, r.out);
  return id;
}

test("read-result: SIZE, SHA256 and BODY; TOOBIG above the limit; symlinks are never followed", async () => {
  const home = newHome();
  const id = await completedRun(home);
  const file = path.join(runDir(home, id), "result.json");
  const bytes = fs.readFileSync(file);
  let S = sentinel();
  let r = await exec(buildReadResultProgram({ runId: id, sentinel: S, maxBytes: 100_000 }), { home });
  let sec = sections(r.out, S);
  assert.equal(Number(sec.SIZE), bytes.length);
  assert.equal(sec.SHA256, crypto.createHash("sha256").update(bytes).digest("hex"));
  assert.equal(sec.BODY.replace(/\n$/, ""), bytes.toString("utf8").replace(/\n$/, ""));
  assert.ok(r.out.lastIndexOf(`${S}BODY`) > r.out.lastIndexOf(`${S}SHA256`), "body comes last");

  S = sentinel();
  r = await exec(buildReadResultProgram({ runId: id, sentinel: S, maxBytes: 10 }), { home });
  sec = sections(r.out, S);
  assert.ok("TOOBIG" in sec && !("BODY" in sec));
  assert.equal(Number(sec.SIZE), bytes.length);

  // result.json replaced by a link to a secret
  fs.rmSync(file);
  fs.symlinkSync(path.join(home, "secret.txt"), file);
  S = sentinel();
  r = await exec(buildReadResultProgram({ runId: id, sentinel: S, maxBytes: 100_000 }), { home });
  assert.ok(r.out.includes(`${S}NORESULT`));
  assert.ok(!r.out.includes("TOP-SECRET"));
  r = await exec(buildExportProgram({ runId: id, sentinel: S, maxBytes: 100_000 }), { home });
  assert.ok(r.out.includes(`${S}NORESULT`) && !r.out.includes("TOP-SECRET"));

  // a run directory that is itself a link to somewhere else
  const other = tmp("rea-otherrun-");
  fs.writeFileSync(path.join(other, "result.json"), '{"secret":true}');
  const id2 = newRunId();
  fs.mkdirSync(path.dirname(runDir(home, id2)), { recursive: true });
  fs.symlinkSync(other, runDir(home, id2));
  r = await exec(buildReadResultProgram({ runId: id2, sentinel: S, maxBytes: 100_000 }), { home });
  assert.ok(r.out.includes(`${S}NORESULT`) && !r.out.includes("secret"));
});

test("view: only this run's result.json is accepted; output is bounded; ~/ form works", async () => {
  const home = newHome();
  const id = await completedRun(home);
  const resultPath = path.join(runDir(home, id), "result.json");
  const view = (source) => Buffer.from(JSON.stringify({ source, view: { kind: "summary" } })).toString("base64");

  let S = sentinel();
  let r = await exec(buildViewProgram({ runId: id, viewB64: view({ kind: "file", path: resultPath }), sentinel: S, nonce: NONCE }), { home });
  let sec = sections(r.out, S);
  assert.equal(sec.STATUS, "0", r.out);
  const body = JSON.parse(sec.BODY);
  assert.equal(body.view, "ok");
  // The program streams result.json into the inline-evidence form REA 6.4.0 requires.
  assert.equal(body.request.source.kind, "inline");
  assert.deepEqual(body.request.view, { kind: "summary" });
  const sent = JSON.parse(fs.readFileSync(path.join(runDir(home, id), "view-req.json"), "utf8"));
  assert.deepEqual(sent.source.evidence, JSON.parse(fs.readFileSync(resultPath, "utf8")));

  S = sentinel();
  r = await exec(buildViewProgram({ runId: id, viewB64: view({ kind: "file", path: `~/.cache/sparkdash/rea/runs/${id}/result.json` }), sentinel: S, nonce: NONCE }), { home });
  assert.equal(sections(r.out, S).STATUS, "0");

  for (const src of [{ kind: "file", path: path.join(home, "secret.txt") }, { kind: "inline", evidence: { a: 1 } }, { kind: "file", path: path.join(runDir(home, id), "..", "x", "result.json") }]) {
    S = sentinel();
    r = await exec(buildViewProgram({ runId: id, viewB64: view(src), sentinel: S, nonce: NONCE }), { home });
    sec = sections(r.out, S);
    assert.equal(sec.STATUS, "3", JSON.stringify(src));
    assert.ok(!("BODY" in sec));
  }
  S = sentinel();
  r = await exec(buildViewProgram({ runId: id, viewB64: Buffer.from("not json").toString("base64"), sentinel: S, nonce: NONCE }), { home });
  assert.equal(sections(r.out, S).STATUS, "2");

  fs.writeFileSync(path.join(home, "rea-bigview"), "");
  S = sentinel();
  r = await exec(buildViewProgram({ runId: id, viewB64: view({ kind: "file", path: resultPath }), sentinel: S, nonce: NONCE, maxBytes: 100_000 }), { home });
  sec = sections(r.out, S);
  assert.equal(sec.STATUS, "11");
  assert.ok("TOOBIG" in sec && !("BODY" in sec));
  assert.ok(r.out.length < 1000);
});

test("view: launcher missing reports STATUS 127; a run with no result reports NORESULT", async () => {
  const home = tmp("rea-home-");
  homes.push(home);
  const id = newRunId();
  fs.mkdirSync(runDir(home, id), { recursive: true });
  fs.writeFileSync(path.join(runDir(home, id), "result.json"), "{}");
  const v = Buffer.from(JSON.stringify({ source: { kind: "file", path: path.join(runDir(home, id), "result.json") }, view: { kind: "summary" } })).toString("base64");
  let S = sentinel();
  let r = await exec(buildViewProgram({ runId: id, viewB64: v, sentinel: S, nonce: NONCE }), { home });
  assert.equal(sections(r.out, S).STATUS, "127");
  S = sentinel();
  r = await exec(buildViewProgram({ runId: newRunId(), viewB64: v, sentinel: S, nonce: NONCE }), { home });
  assert.ok(r.out.includes(`${S}NORESULT`));
});

test("export streams result.json up to the cap; compare runs rea on two runs", async () => {
  const home = newHome();
  const a = await completedRun(home);
  const b = await completedRun(home);
  const bytes = fs.readFileSync(path.join(runDir(home, a), "result.json"), "utf8");
  let S = sentinel();
  let r = await exec(buildExportProgram({ runId: a, sentinel: S, maxBytes: 100_000 }), { home });
  let sec = sections(r.out, S);
  assert.equal(Number(sec.SIZE), Buffer.byteLength(bytes));
  assert.equal(sec.BODY.replace(/\n$/, ""), bytes.replace(/\n$/, ""));
  S = sentinel();
  r = await exec(buildExportProgram({ runId: a, sentinel: S, maxBytes: 5 }), { home });
  sec = sections(r.out, S);
  assert.ok("TOOBIG" in sec && !("BODY" in sec));

  S = sentinel();
  r = await exec(buildCompareProgram({ leftRunId: a, rightRunId: b, sentinel: S }), { home });
  sec = sections(r.out, S);
  assert.equal(sec.STATUS, "0", r.out);
  assert.equal(JSON.parse(sec.BODY).kind, "compare");
  assert.match(fs.readFileSync(path.join(home, "rea.argv"), "utf8"), /compare .*compare-left\.bundle\.json .*compare-right\.bundle\.json --json/);
  S = sentinel();
  r = await exec(buildCompareProgram({ leftRunId: a, rightRunId: newRunId(), sentinel: S }), { home });
  assert.ok(r.out.includes(`${S}NORESULT`));
  S = sentinel();
  fs.writeFileSync(path.join(home, "rea-bigview"), "");
  r = await exec(buildCompareProgram({ leftRunId: a, rightRunId: b, sentinel: S, maxBytes: 1000 }), { home });
  assert.ok(sections(r.out, S).STATUS === "0", "compare output of this size fits");
});

// ── status ──────────────────────────────────────────────────────────────────

test("status: key=value lines, base64 reports, engine grid, no environment values", async () => {
  const home = newHome();
  const ghidra = tmp("rea-ghidra-");
  fs.mkdirSync(path.join(ghidra, "support"));
  fs.writeFileSync(path.join(ghidra, "support", "analyzeHeadless"), "#!/bin/sh\n", { mode: 0o755 });
  fs.writeFileSync(path.join(home, ".local", "bin", "jadx"), "#!/bin/sh\n", { mode: 0o755 });
  fs.writeFileSync(path.join(home, ".local", "bin", "idat64"), "#!/bin/sh\n", { mode: 0o755 });
  const r = await exec(buildStatusProgram(), { home, env: { GHIDRA_INSTALL_DIR: ghidra, SOME_API_TOKEN: "hunter2-secret" } });
  assert.equal(r.code, 0, r.err);
  assert.ok(!r.out.includes("hunter2-secret"));
  const v = kv(r.out);
  assert.equal(v.NODE_OK, "1");
  assert.match(v.NODE_VERSION, /^v\d+\.\d+\.\d+$/);
  assert.equal(v.LAUNCHER, path.join(home, ".local", "bin", "rea-sparkdash"));
  assert.equal(v.INSTALLED_VERSION, "6.4.0");
  assert.equal(v.ENGINE_ghidra, path.join(ghidra, "support", "analyzeHeadless"));
  assert.equal(v.ENGINE_jadx, path.join(home, ".local", "bin", "jadx"));
  assert.equal(v.ENGINE_ida, path.join(home, ".local", "bin", "idat64"));
  assert.equal(v.ENGINE_hopper, "");
  for (const e of ["apktool", "binwalk", "unblob", "adb", "jeb"]) assert.ok(`ENGINE_${e}` in v);
  const doctor = JSON.parse(Buffer.from(v.DOCTOR_B64, "base64").toString("utf8"));
  assert.equal(doctor.scope_checks.length, 2);
  const providers = JSON.parse(Buffer.from(v.PROVIDERS_B64, "base64").toString("utf8"));
  assert.equal(providers.capabilities[0].operation, "disassemble");
  assert.ok(!/\n[^\n]*DOCTOR_B64=[^\n]*\n[^\n]*DOCTOR_B64/.test(r.out));
  const light = await exec(buildStatusProgram({ deep: false }), { home });
  assert.ok(!("DOCTOR_B64" in kv(light.out)));
});

test("status: nothing installed reports empty values and exits 0", async () => {
  const home = tmp("rea-home-");
  homes.push(home);
  const r = await exec(buildStatusProgram(), { home });
  assert.equal(r.code, 0, r.err);
  const v = kv(r.out);
  assert.equal(v.LAUNCHER, "");
  assert.equal(v.INSTALLED_VERSION, "");
  assert.ok(!("DOCTOR_B64" in v));
});

test("status: a bounded report does not run away", async () => {
  const home = newHome();
  // a doctor that prints 3 MB
  const launcher = path.join(home, ".local", "bin", "rea-sparkdash");
  fs.writeFileSync(launcher, '#!/bin/bash\n[ "$1" = --version ] && { echo 6.4.0; exit 0; }\nhead -c 3000000 /dev/zero | tr "\\0" a\n', { mode: 0o755 });
  const r = await exec(buildStatusProgram(), { home });
  const v = kv(r.out);
  assert.ok(Buffer.from(v.DOCTOR_B64, "base64").length <= 262_144);
  assert.ok(r.out.length < 1_000_000);
});

// ── uploads ─────────────────────────────────────────────────────────────────

const put = (home, id, rel, data, { maxBytes = 10_000, archive = false } = {}) =>
  exec(buildUploadPutProgram({ uploadId: id, relPath: rel, maxBytes, archive }), { home, stdin: data });
const commit = (home, id, over = {}) => exec(buildUploadCommitProgram({ uploadId: id, maxFiles: 50, maxBytes: 5_000_000, ...over }), { home });

async function newUpload(home) {
  const id = newUploadId();
  const r = await exec(buildUploadCreateProgram({ uploadId: id }), { home });
  assert.equal(r.code, 0, r.out);
  assert.equal(kv(r.out).UPLOAD, id);
  return id;
}

function makeArchive(file, kind, script) {
  execFileSync("python3", ["-I", "-c", script, file, kind], { stdio: "pipe" });
}
const PY_ARCHIVES = `
import sys, zipfile, tarfile, io, os
out, kind = sys.argv[1], sys.argv[2]
def zadd(z, name, data=b"x", mode=None):
    zi = zipfile.ZipInfo(name)
    if mode is not None:
        zi.external_attr = mode << 16
    z.writestr(zi, data, zipfile.ZIP_DEFLATED)
if kind == "zip-good":
    with zipfile.ZipFile(out, "w") as z:
        zadd(z, "app/index.js", b"console.log(1)\\n" * 20)
        zadd(z, "app/lib/util.js", b"module.exports = 1\\n" * 20)
elif kind == "zip-slip":
    with zipfile.ZipFile(out, "w") as z:
        zadd(z, "ok.txt", b"ok")
        zadd(z, "../../evil.txt", b"evil")
elif kind == "zip-abs":
    with zipfile.ZipFile(out, "w") as z:
        zadd(z, "/tmp/rea-abs-evil.txt", b"evil")
elif kind == "zip-symlink":
    with zipfile.ZipFile(out, "w") as z:
        zadd(z, "ok.txt", b"ok")
        zadd(z, "link", b"/etc/passwd", 0o120777)
elif kind == "zip-bomb":
    with zipfile.ZipFile(out, "w") as z:
        zadd(z, "zeros.bin", b"\\0" * 10_000_000)
elif kind == "zip-many":
    with zipfile.ZipFile(out, "w") as z:
        for i in range(30):
            zadd(z, "f%d.txt" % i, b"%d" % i * 50)
elif kind in ("tar-good", "tgz-good", "tar-symlink", "tar-abs", "tar-hardlink", "tar-dotdot"):
    mode = "w:gz" if kind.startswith("tgz") else "w"
    with tarfile.open(out, mode) as t:
        def add(name, data=b"x" * 100, typ=tarfile.REGTYPE, linkname=""):
            ti = tarfile.TarInfo(name)
            ti.type = typ
            ti.linkname = linkname
            ti.size = len(data) if typ == tarfile.REGTYPE else 0
            t.addfile(ti, io.BytesIO(data) if typ == tarfile.REGTYPE else None)
        if kind in ("tar-good", "tgz-good"):
            add("src/a.js", b"a" * 200)
            add("src/b.js", b"b" * 200)
        elif kind == "tar-symlink":
            add("ok.txt")
            add("evil", typ=tarfile.SYMTYPE, linkname="/etc/passwd")
        elif kind == "tar-hardlink":
            add("ok.txt")
            add("hl", typ=tarfile.LNKTYPE, linkname="ok.txt")
        elif kind == "tar-abs":
            add("/tmp/rea-abs-evil.txt")
        elif kind == "tar-dotdot":
            add("a/../../evil.txt")
`;

test("upload: create, put, commit plain files; put after commit and over the cap are refused; delete", async () => {
  const home = newHome();
  const id = await newUpload(home);
  assert.equal(fs.statSync(upDir(home, id)).mode & 0o777, 0o700);
  const dup = await exec(buildUploadCreateProgram({ uploadId: id }), { home });
  assert.notEqual(dup.code, 0);
  assert.match(dup.out, /ERROR=exists/);

  const data = Buffer.from("app bytes\n".repeat(20));
  let r = await put(home, id, "a.bin", data);
  assert.equal(r.code, 0, r.out);
  let v = kv(r.out);
  assert.equal(v.BYTES, String(data.length));
  assert.equal(v.SHA256, crypto.createHash("sha256").update(data).digest("hex"));
  r = await put(home, id, "sub/dir/b.txt", "hello");
  assert.equal(kv(r.out).BYTES, "5");
  assert.ok(!fs.existsSync(path.join(upDir(home, id), ".writing")), "marker removed when no writer is left");
  assert.ok(!fs.readdirSync(upDir(home, id)).some((n) => n.endsWith(".part")));

  // oversize: nothing is left behind
  r = await put(home, id, "big.bin", Buffer.alloc(500, 1), { maxBytes: 100 });
  assert.equal(r.code, 3);
  assert.match(r.out, /ERROR=toobig/);
  assert.ok(!fs.existsSync(path.join(upDir(home, id), "big.bin")));
  assert.ok(!fs.existsSync(path.join(upDir(home, id), "big.bin.part")));
  // exactly at the cap is fine
  r = await put(home, id, "edge.bin", Buffer.alloc(100, 1), { maxBytes: 100 });
  assert.equal(kv(r.out).BYTES, "100");

  r = await commit(home, id);
  assert.equal(r.code, 0, r.out);
  v = kv(r.out);
  assert.equal(v.ROOT, upDir(home, id));
  assert.equal(v.FILES, "3");
  assert.equal(v.EXTRACTED, "0");
  assert.equal(Number(v.BYTES), data.length + 5 + 100);
  assert.ok(fs.existsSync(path.join(upDir(home, id), ".committed")));
  const again = await commit(home, id);
  assert.equal(kv(again.out).ROOT, v.ROOT, "commit is idempotent");
  r = await put(home, id, "late.bin", "x");
  assert.equal(r.code, 2);
  assert.match(r.out, /ERROR=committed/);

  const del = await exec(buildUploadDeleteProgram({ uploadId: id }), { home });
  assert.equal(del.out.trim(), "ok");
  assert.ok(!fs.existsSync(upDir(home, id)));
});

test("upload: commit enforces file count and byte caps; an empty upload is refused", async () => {
  const home = newHome();
  const id = await newUpload(home);
  assert.match((await commit(home, id)).out, /ERROR=empty/);
  for (const n of ["a", "b", "c"]) await put(home, id, `${n}.txt`, "12345");
  let r = await commit(home, id, { maxFiles: 2 });
  assert.equal(r.code, 3);
  assert.match(r.out, /ERROR=toomany/);
  r = await commit(home, id, { maxBytes: 10 });
  assert.equal(r.code, 3);
  assert.match(r.out, /ERROR=toobig/);
  assert.ok(!fs.existsSync(path.join(upDir(home, id), ".committed")));
});

test("upload: a put cannot escape the upload directory through an existing link", async () => {
  const home = newHome();
  const id = await newUpload(home);
  const outside = tmp("rea-outside-");
  fs.symlinkSync(outside, path.join(upDir(home, id), "linkdir"));
  const r = await put(home, id, "linkdir/pwn.txt", "x");
  assert.notEqual(r.code, 0);
  assert.ok(!fs.existsSync(path.join(outside, "pwn.txt")));
});

test("upload: good archives (zip, tar, tar.gz) are verified and extracted into extracted/", async () => {
  const home = newHome();
  const work = tmp("rea-arch-");
  for (const [kind, name] of [["zip-good", "app.zip"], ["tar-good", "app.tar"], ["tgz-good", "app.tgz"]]) {
    const file = path.join(work, name);
    makeArchive(file, kind, PY_ARCHIVES);
    const id = await newUpload(home);
    const r1 = await put(home, id, name, fs.readFileSync(file), { archive: true, maxBytes: 1_000_000 });
    assert.equal(r1.code, 0, r1.out);
    const c = await commit(home, id);
    assert.equal(c.code, 0, `${kind}: ${c.out}`);
    const v = kv(c.out);
    assert.equal(v.EXTRACTED, "1");
    assert.equal(v.ROOT, path.join(upDir(home, id), "extracted"));
    assert.equal(v.FILES, "2");
    const first = kind === "zip-good" ? "app/index.js" : "src/a.js";
    assert.ok(fs.statSync(path.join(v.ROOT, first)).isFile());
    assert.equal(fs.statSync(path.join(v.ROOT, first)).mode & 0o077, 0);
  }
});

test("upload: bad archives are refused after listing and nothing is extracted", async () => {
  const home = newHome();
  const work = tmp("rea-arch-");
  const absEvil = "/tmp/rea-abs-evil.txt";
  fs.rmSync(absEvil, { force: true });
  const cases = [
    ["zip-slip", "a.zip", /leaves the folder/],
    ["zip-abs", "b.zip", /absolute/],
    ["zip-symlink", "c.zip", /link or special/],
    ["zip-bomb", "d.zip", /ratio/, { maxBytes: 50_000_000 }],
    ["zip-many", "e.zip", /too many entries/, { maxFiles: 10 }],
    ["tar-symlink", "f.tar", /link or special/],
    ["tar-hardlink", "g.tar", /link or special/],
    ["tar-abs", "h.tar", /absolute/],
    ["tar-dotdot", "i.tar", /leaves the folder/],
  ];
  for (const [kind, name, re, over] of cases) {
    const file = path.join(work, name);
    makeArchive(file, kind, PY_ARCHIVES);
    const id = await newUpload(home);
    const p = await put(home, id, name, fs.readFileSync(file), { archive: true, maxBytes: 5_000_000 });
    assert.equal(p.code, 0, p.out);
    const c = await commit(home, id, over);
    assert.notEqual(c.code, 0, `${kind} must be refused: ${c.out}`);
    assert.match(c.out, /ERROR=/);
    assert.match(c.out, re, `${kind}: ${c.out}`);
    assert.ok(!fs.existsSync(path.join(upDir(home, id), "extracted")), `${kind}: extracted/ is removed`);
    assert.ok(!fs.existsSync(path.join(upDir(home, id), ".committed")));
  }
  assert.ok(!fs.existsSync(absEvil));
  assert.ok(!fs.existsSync(path.join(home, "evil.txt")) && !fs.existsSync(path.join(home, ".cache", "evil.txt")) && !fs.existsSync(path.join(home, ".cache", "sparkdash", "evil.txt")));
  // a "zip" that is not one
  const id = await newUpload(home);
  await put(home, id, "junk.zip", "this is not a zip", { archive: true });
  const c = await commit(home, id);
  assert.notEqual(c.code, 0);
  assert.match(c.out, /not a supported archive/);
});

test("upload: sweep removes expired uploads and keeps those with a fresh writer marker", async () => {
  const home = newHome();
  const old = await newUpload(home);
  const fresh = await newUpload(home);
  const busy = await newUpload(home);
  const past = new Date(Date.now() - 48 * 3600_000);
  for (const id of [old, busy]) fs.utimesSync(path.join(upDir(home, id), ".meta"), past, past);
  fs.writeFileSync(path.join(upDir(home, busy), ".writing"), "");
  const r = await exec(buildUploadSweepProgram({ ttlHours: 24 }), { home });
  const v = kv(r.out);
  assert.equal(v.SWEPT, "1", r.out);
  assert.equal(v.KEPT, "2");
  assert.ok(!fs.existsSync(upDir(home, old)));
  assert.ok(fs.existsSync(upDir(home, fresh)) && fs.existsSync(upDir(home, busy)));
  // a stale marker does not protect
  fs.utimesSync(path.join(upDir(home, busy), ".writing"), past, past);
  const r2 = await exec(buildUploadSweepProgram({ ttlHours: 24 }), { home });
  assert.equal(kv(r2.out).SWEPT, "1");
  assert.ok(!fs.existsSync(upDir(home, busy)));
  assert.throws(() => buildUploadSweepProgram({ ttlHours: -1 }), /invalid ttl/);
});

// ── install (fake node and npm on PATH) ─────────────────────────────────────

const FAKE_REA_MJS = `
const a = process.argv.slice(2);
if (a[0] === "--version") { console.log(process.env.FAKE_REA_VERSION || "6.4.0"); }
else if (a[0] === "doctor") { console.log(process.env.FAKE_DOCTOR_GARBAGE ? "not json at all" : JSON.stringify({ healthy: true, scope_checks: [] })); }
else { console.log(JSON.stringify({ argv: a })); }
`;

function stubTools() {
  const dir = tmp("rea-stub-");
  const tree = path.join(dir, "tree");
  fs.mkdirSync(path.join(tree, "node_modules", REA_PKG, "scripts"), { recursive: true });
  fs.writeFileSync(path.join(tree, "node_modules", REA_PKG, "scripts", "rea.mjs"), FAKE_REA_MJS);
  const bin = path.join(dir, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(
    path.join(bin, "node"),
    `#!/bin/bash\nif [ "$1" = --version ] && [ -n "$FAKE_NODE_VERSION" ]; then echo "$FAKE_NODE_VERSION"; exit 0; fi\nexec "${process.execPath}" "$@"\n`,
    { mode: 0o755 }
  );
  fs.writeFileSync(
    path.join(bin, "npm"),
    `#!/bin/bash
echo "$*" > "$HOME/npm.args"; pwd > "$HOME/npm.cwd"
[ "$1" = ci ] || exit 9
[ -f package.json ] && [ -f package-lock.json ] || exit 8
cp package-lock.json "$HOME/npm.lock.seen"
if [ -n "$FAKE_NPM_FAIL" ]; then echo "npm ERR! network"; exit 1; fi
mkdir -p node_modules && cp -R "${tree}/node_modules/." node_modules/
echo "added 144 packages"
`,
    { mode: 0o755 }
  );
  return { bin, tree };
}

const installEnv = (stub, extra = {}) => ({ PATH: `${stub.bin}:/usr/bin:/bin`, ...extra });
const finalDir = (home) => path.join(home, ".local", "share", "sparkdash", "rea", REA_VERSION);

test("install: success lays down the pinned tree, launcher and record; npm gets the lockfile and no -g", async () => {
  const home = tmp("rea-home-");
  homes.push(home);
  const stub = stubTools();
  const payload = installPayload();
  const r = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: payload, env: installEnv(stub) });
  assert.equal(exitOf(r.out), 0, r.out);
  assert.match(r.out, /\[sparkdash\] installed/);
  assert.ok(fs.existsSync(path.join(finalDir(home), "node_modules", REA_PKG, "scripts", "rea.mjs")));
  assert.ok(!fs.existsSync(`${finalDir(home)}.staging`));
  assert.equal(fs.readFileSync(path.join(home, "npm.args"), "utf8").trim(), "ci --ignore-scripts --no-audit --no-fund");
  assert.ok(fs.readFileSync(path.join(home, "npm.cwd"), "utf8").trim().endsWith(`${REA_VERSION}.staging`));
  assert.equal(fs.readFileSync(path.join(home, "npm.lock.seen"), "utf8"), fs.readFileSync(new URL("../pinned/package-lock.json", import.meta.url), "utf8"), "lockfile arrived byte for byte");
  const launcher = path.join(home, ".local", "bin", "rea-sparkdash");
  assert.equal(fs.statSync(launcher).mode & 0o777, 0o755);
  assert.match(fs.readFileSync(launcher, "utf8"), /exec node .*node_modules\/rea-agents\/scripts\/rea\.mjs "\$@"/);
  const v = execFileSync(launcher, ["--version"], { env: { HOME: home, PATH: installEnv(stub).PATH } }).toString().trim();
  assert.equal(v, REA_VERSION);
  const rec = kv(fs.readFileSync(path.join(home, ".config", "sparkdash", "rea-install"), "utf8"));
  assert.equal(rec.VERSION, REA_VERSION);
  assert.ok(rec.DATE && rec.NODE);
  // reinstall over an existing install works and leaves no .old behind
  const again = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: payload, env: installEnv(stub) });
  assert.equal(exitOf(again.out), 0, again.out);
  assert.ok(!fs.existsSync(`${finalDir(home)}.old`));
});

test("install: a failed smoke test leaves the previous install untouched and removes staging", async () => {
  const home = tmp("rea-home-");
  homes.push(home);
  const stub = stubTools();
  const payload = installPayload();
  const ok = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: payload, env: installEnv(stub) });
  assert.equal(exitOf(ok.out), 0, ok.out);
  fs.writeFileSync(path.join(finalDir(home), "PREVIOUS-MARKER"), "keep");
  const launcher = path.join(home, ".local", "bin", "rea-sparkdash");
  const launcherBefore = fs.readFileSync(launcher, "utf8");

  let r = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: payload, env: installEnv(stub, { FAKE_REA_VERSION: "6.3.0" }) });
  assert.equal(exitOf(r.out), 4, r.out);
  assert.match(r.out, /expected 6\.4\.0/);
  assert.ok(fs.existsSync(path.join(finalDir(home), "PREVIOUS-MARKER")));
  assert.ok(!fs.existsSync(`${finalDir(home)}.staging`));
  assert.equal(fs.readFileSync(launcher, "utf8"), launcherBefore);

  r = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: payload, env: installEnv(stub, { FAKE_DOCTOR_GARBAGE: "1" }) });
  assert.equal(exitOf(r.out), 4, r.out);
  assert.match(r.out, /doctor --json did not print JSON/);
  assert.ok(fs.existsSync(path.join(finalDir(home), "PREVIOUS-MARKER")));
  assert.ok(!fs.existsSync(`${finalDir(home)}.staging`));

  r = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: payload, env: installEnv(stub, { FAKE_NPM_FAIL: "1" }) });
  assert.equal(exitOf(r.out), 3, r.out);
  assert.ok(fs.existsSync(path.join(finalDir(home), "PREVIOUS-MARKER")));
  assert.ok(!fs.existsSync(`${finalDir(home)}.staging`));
});

test("install: node too old or missing -> 127 before anything is written", async () => {
  const stub = stubTools();
  const payload = installPayload();
  for (const ver of ["v20.11.0", "v22.18.9", "v24.10.0", "v25.0.0"]) {
    const home = tmp("rea-home-");
    homes.push(home);
    const r = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: payload, env: installEnv(stub, { FAKE_NODE_VERSION: ver }) });
    assert.equal(exitOf(r.out), 127, `${ver}: ${r.out}`);
    assert.match(r.out, /too old/);
    assert.ok(!fs.existsSync(path.join(home, "npm.args")), "npm was not run");
    assert.ok(!fs.existsSync(path.join(home, ".local")));
  }
  for (const ver of ["v22.19.0", "v24.11.0", "v26.0.1"]) {
    const home = tmp("rea-home-");
    homes.push(home);
    const r = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: payload, env: installEnv(stub, { FAKE_NODE_VERSION: ver }) });
    assert.equal(exitOf(r.out), 0, `${ver}: ${r.out}`);
  }
  // no node at all
  const home = tmp("rea-home-");
  homes.push(home);
  const nobin = tmp("rea-nobin-");
  for (const t of ["base64", "bash"]) fs.symlinkSync(execFileSync("which", [t]).toString().trim(), path.join(nobin, t));
  const r = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: payload, env: { PATH: nobin } });
  assert.equal(exitOf(r.out), 127);
  assert.match(r.out, /node is not installed/);
});

test("install: a payload that does not pin the version is refused", async () => {
  const home = tmp("rea-home-");
  homes.push(home);
  const stub = stubTools();
  const bad = installPayload().replace('"rea-agents": "6.4.0"', '"rea-agents": "6.3.0"');
  const r = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: bad, env: installEnv(stub) });
  assert.equal(exitOf(r.out), 1, r.out);
  assert.ok(!fs.existsSync(path.join(home, "npm.args")));
  const truncated = installPayload().slice(0, 5000);
  const r2 = await exec(buildInstallProgram({ nonce: NONCE }), { home, stdin: truncated, env: installEnv(stub) });
  assert.equal(exitOf(r2.out), 1, r2.out);
});
