import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadHermes, mapHermesSession } from "./hermesAdapter.js";

test("missing Hermes state is unavailable, not an empty success", () => {
  assert.equal(loadHermes({}).coverage, "unavailable");
  assert.equal(loadHermes({ stateDir: path.join(os.tmpdir(), "sparkdash-hermes-missing") }).coverage, "unavailable");
});

test("a corrupt sessions file is unavailable and a real empty file is supported", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sparkdash-hermes-"));
  fs.writeFileSync(path.join(dir, "sessions.json"), "{");
  const corrupt = loadHermes({ stateDir: dir });
  assert.equal(corrupt.coverage, "unavailable");
  assert.match(corrupt.error, /corrupt/);
  assert.equal(corrupt.rows.length, 0);

  fs.writeFileSync(path.join(dir, "sessions.json"), "[]");
  const empty = loadHermes({ stateDir: dir });
  assert.equal(empty.coverage, "supported");
  assert.equal(empty.rows.length, 0);
  assert.equal(empty.error, null);
});

test("generating comes from running state, not from how old the timestamp is", () => {
  const idle = mapHermesSession({
    id: "old",
    title: "Old",
    status: "idle",
    updated_at: "2020-01-01T00:00:00Z",
  });
  assert.equal(idle.activity, "unknown");
  assert.equal(idle.activityProvenance, "none");

  const live = mapHermesSession(
    { id: "live", title: "Live", running: true, updated_at: "2020-01-01T00:00:00Z", billing_base_url: "http://10.0.0.8:8000/v1" },
    {}
  );
  assert.equal(live.activity, "generating");
  assert.equal(live.activityProvenance, "native");
  assert.deepEqual(live.origin, { host: "10.0.0.8", port: 8000 });
});

test("a state.db read failure is partial and does not pretend the list is empty-healthy", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sparkdash-hermes-db-"));
  fs.writeFileSync(path.join(dir, "state.db"), "");
  const failed = loadHermes({ stateDir: dir, readDb: () => { throw new Error("locked"); } });
  assert.equal(failed.coverage, "partial");
  assert.match(failed.error, /locked/);
  const none = loadHermes({ stateDir: dir, readDb: () => null });
  assert.equal(none.coverage, "partial");
  assert.match(none.error, /no readable sessions/);
});

test("the private database subprocess also excludes the helper bearer", async (t) => {
  const { readHermesDb } = await import("./hermesAdapter.js");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "sparkdash-hermes-env-"));
  const savedPath = process.env.PATH;
  const savedToken = process.env.OCCUPANCY_TOKEN;
  t.after(() => {
    process.env.PATH = savedPath;
    if (savedToken === undefined) delete process.env.OCCUPANCY_TOKEN;
    else process.env.OCCUPANCY_TOKEN = savedToken;
    fs.rmSync(dir, { recursive: true, force: true });
  });
  fs.writeFileSync(path.join(dir, "python3"), `#!${process.execPath}\nconsole.log(JSON.stringify({ rows: [{
    id: 'fixture', title: !Object.hasOwn(process.env, 'OCCUPANCY_TOKEN') && Boolean(process.env.HOME) ? 'isolated' : 'exposed'
  }] }));\n`, { mode: 0o700 });
  process.env.PATH = dir;
  process.env.OCCUPANCY_TOKEN = "disposable-fixture-only";
  assert.equal(readHermesDb(path.join(dir, "unused.db"))[0].title, "isolated");
});
