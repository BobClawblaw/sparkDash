process.env.BENCH_HISTORY_PATH = `${process.env.TMPDIR || "/tmp"}/sparkdash-sampling-test-history.json`;
process.env.BENCH_ACTIVE_PATH = `${process.env.TMPDIR || "/tmp"}/sparkdash-sampling-test-active.json`;
import { test } from "node:test";
import { strict as assert } from "node:assert";
const { decodeBenchManager, DECODE_BENCH_DEFAULTS } = await import("../DecodeBench.js");

const base = { sparkId: "sampling-test", lanIp: "127.0.0.1", port: 1, modelId: null, concurrencies: [1] };

function startAndCancel(extra) {
  const job = decodeBenchManager.start({ ...base, ...extra });
  const config = { ...job.config };
  decodeBenchManager.cancel(base.sparkId, job.benchId);
  return config;
}

test("decode bench defaults to temperature 0.7 with thinking on", () => {
  assert.equal(DECODE_BENCH_DEFAULTS.defaultTemperature, 0.7);
  assert.equal(DECODE_BENCH_DEFAULTS.defaultThinking, true);
  const c = startAndCancel({});
  assert.equal(c.temperature, 0.7);
  assert.equal(c.thinking, true);
});

test("temperature and thinking can be chosen per run", () => {
  const c = startAndCancel({ temperature: 0, thinking: false });
  assert.equal(c.temperature, 0);
  assert.equal(c.thinking, false);
});

test("an out-of-range temperature is refused", () => {
  assert.throws(() => decodeBenchManager.start({ ...base, temperature: 3 }), { status: 400 });
  assert.throws(() => decodeBenchManager.start({ ...base, temperature: "abc" }), { status: 400 });
});
