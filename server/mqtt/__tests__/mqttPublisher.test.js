/**
 * The MQTT bridge is driven entirely through injected dependencies, so these
 * tests exercise the real class against a stub client — no broker needed.
 */
import { test } from "node:test";
import { strict as assert } from "node:assert";
import { MqttPublisher } from "../MqttPublisher.js";

/** Stub mqtt.js client capturing the calls the publisher makes. */
function fakeClient(overrides = {}) {
  const calls = { publishes: [], ended: 0, endForce: null, handlers: {} };
  const client = {
    connected: true,
    publish(topic, payload, opts) {
      calls.publishes.push({ topic, payload: String(payload), opts: opts ?? {} });
    },
    end(force) {
      calls.ended += 1;
      calls.endForce = force;
    },
    on(event, fn) {
      calls.handlers[event] = fn;
    },
    ...overrides,
  };
  return { client, calls };
}

const ENABLED = { mqttEnabled: true, mqttUrl: "mqtt://broker.local:1883", mqttUsername: "", mqttTopicPrefix: "sparkdash" };

/** Build a publisher wired to a stub client; `connect` records every attempt. */
function harness({ settings = {}, client: clientOverrides = {} } = {}) {
  let current = { ...ENABLED, ...settings };
  const attempts = [];
  const { client, calls } = fakeClient(clientOverrides);
  const publisher = new MqttPublisher({
    getSettings: () => current,
    env: {},
    connect: (url, opts) => {
      attempts.push({ url, opts });
      return client;
    },
  });
  return {
    publisher,
    client,
    calls,
    attempts,
    set(patch) {
      current = { ...current, ...patch };
    },
    /** Fire a lifecycle event on the stub client, like mqtt.js would. */
    fire(event, arg) {
      calls.handlers[event]?.(arg);
    },
  };
}

test("disabled: no connection is attempted and nothing is published", () => {
  const h = harness({ settings: { mqttEnabled: false } });
  h.publisher.applySettings();
  h.publisher.publishEvent({ type: "spark.offline", message: "x" });
  h.publisher.publishFleet([{ id: "alpha", online: true }]);
  assert.equal(h.attempts.length, 0);
  assert.equal(h.calls.publishes.length, 0);
});

test("applySettings connects, sends credentials, and publishes dashboard availability on connect", () => {
  const h = harness();
  h.publisher.applySettings();
  assert.equal(h.attempts.length, 1);
  assert.equal(h.attempts[0].url, "mqtt://broker.local:1883");
  assert.match(h.attempts[0].opts.clientId, /^sparkdash-[0-9a-f]{8}$/);
  assert.equal(h.attempts[0].opts.reconnectPeriod, 5_000);
  // The will mirrors our own availability so a crashed dashboard reads 0 at the broker.
  assert.deepEqual(h.attempts[0].opts.will, {
    topic: "sparkdash/dashboard/status",
    payload: "0",
    qos: 0,
    retain: true,
  });
  h.fire("connect");
  assert.deepEqual(h.calls.publishes, [
    { topic: "sparkdash/dashboard/status", payload: "1", opts: { retain: true } },
  ]);
});

test("the broker password comes from the environment, the username from settings", () => {
  let current = { ...ENABLED, mqttUsername: "mia" };
  const attempts = [];
  const publisher = new MqttPublisher({
    getSettings: () => current,
    env: { SPARKDASH_MQTT_PASSWORD: "hunter2" },
    connect: (url, opts) => {
      attempts.push({ url, opts });
      return fakeClient().client;
    },
  });
  publisher.applySettings();
  assert.equal(attempts[0].opts.username, "mia");
  assert.equal(attempts[0].opts.password, "hunter2");
  // A settings PUT that changes nothing relevant must not reconnect…
  publisher.applySettings();
  assert.equal(attempts.length, 1);
  // …but a username change applies live, without touching the password.
  current = { ...current, mqttUsername: "" };
  publisher.applySettings();
  assert.equal(attempts.length, 2);
  assert.equal(attempts[1].opts.username, undefined);
  assert.equal(attempts[1].opts.password, "hunter2");
});

test("events stream to {prefix}/events with QoS 1 and the EventLog record verbatim", () => {
  const h = harness();
  h.publisher.applySettings();
  const event = { id: 7, ts: 1234, type: "spark.offline", severity: "warn", sparkId: "alpha", sparkName: "Alpha", message: "Alpha went offline" };
  h.publisher.publishEvent(event);
  assert.deepEqual(h.calls.publishes, [
    { topic: "sparkdash/events", payload: JSON.stringify(event), opts: { qos: 1 } },
  ]);
  // A custom prefix changes the topic, not the payload.
  h.set({ mqttTopicPrefix: "home/fleet" });
  h.publisher.publishEvent({ ...event, id: 8 });
  assert.equal(h.calls.publishes[1].topic, "home/fleet/events");
});

test("the fleet publishes retained availability plus a metrics payload per unit", () => {
  const h = harness();
  h.publisher.applySettings();
  h.publisher.publishFleet([
    { snapshot: { id: "alpha", online: true, uptime: 100 } }, // wrapped provenance form
    { id: "beta", online: false }, // bare snapshot
  ]);
  assert.equal(h.calls.publishes.length, 4);
  assert.deepEqual(
    h.calls.publishes.filter((p) => p.topic.startsWith("sparkdash/status/")),
    [
      { topic: "sparkdash/status/alpha", payload: "1", opts: { retain: true } },
      { topic: "sparkdash/status/beta", payload: "0", opts: { retain: true } },
    ]
  );
  // The metrics payload is the unit's Prometheus series as JSON: up + what was
  // measured. Retained, so a fresh subscriber sees the last state immediately.
  assert.equal(h.calls.publishes[1].topic, "sparkdash/metrics/alpha");
  assert.equal(h.calls.publishes[1].opts.qos, 0);
  assert.equal(h.calls.publishes[1].opts.retain, true);
  const alpha = JSON.parse(h.calls.publishes[1].payload);
  assert.equal(typeof alpha.ts, "number");
  assert.equal(alpha.up, 1);
  assert.equal(alpha.uptime_seconds, 100);
  // An offline unit says so on its metrics topic too ("sparkdash_up 0 and nothing else").
  assert.equal(h.calls.publishes[3].topic, "sparkdash/metrics/beta");
  assert.equal(h.calls.publishes[3].opts.retain, true);
  const beta = JSON.parse(h.calls.publishes[3].payload);
  assert.deepEqual(beta, { ts: beta.ts, up: 0 });
});

test("a Spark id is percent-encoded into its topics", () => {
  const h = harness();
  h.publisher.applySettings();
  h.publisher.publishFleet([{ id: "spark one", online: true, uptime: 5 }]);
  assert.deepEqual(
    h.calls.publishes.map((p) => p.topic),
    ["sparkdash/status/spark%20one", "sparkdash/metrics/spark%20one"]
  );
});

test("publishes are skipped while the broker is disconnected — never thrown, never queued", () => {
  const h = harness({ client: { connected: false } });
  h.publisher.applySettings();
  h.publisher.publishEvent({ type: "x", message: "y" });
  h.publisher.publishFleet([{ id: "alpha", online: true }]);
  h.fire("connect");
  assert.equal(h.calls.publishes.length, 0);
});

test("garbage entries are ignored", () => {
  const h = harness();
  h.publisher.applySettings();
  h.publisher.publishFleet(null);
  h.publisher.publishFleet([null, {}, { snapshot: {} }, { online: true }]);
  assert.equal(h.calls.publishes.length, 0);
});

test("a changed broker URL or prefix reopens the connection", () => {
  const h = harness();
  h.publisher.applySettings();
  h.set({ mqttUrl: "mqtts://broker.local:8883" });
  h.publisher.applySettings();
  assert.equal(h.calls.ended, 1);
  assert.equal(h.calls.endForce, true);
  assert.equal(h.attempts.length, 2);
  assert.equal(h.attempts[1].url, "mqtts://broker.local:8883");
  h.set({ mqttTopicPrefix: "home" });
  h.publisher.applySettings();
  assert.equal(h.calls.ended, 2);
  assert.equal(h.attempts.length, 3);
  assert.equal(h.attempts[2].opts.will.topic, "home/dashboard/status");
});

test("disabling tears the connection down", () => {
  const h = harness();
  h.publisher.applySettings();
  h.set({ mqttEnabled: false });
  h.publisher.applySettings();
  assert.equal(h.calls.ended, 1);
  // Late publishes after teardown are silent no-ops.
  h.publisher.publishEvent({ type: "x", message: "y" });
  assert.equal(h.calls.publishes.length, 0);
});

test("stop() marks the dashboard offline and force-closes", () => {
  const h = harness();
  h.publisher.applySettings();
  h.publisher.stop();
  assert.deepEqual(h.calls.publishes, [
    { topic: "sparkdash/dashboard/status", payload: "0", opts: { retain: true } },
  ]);
  assert.equal(h.calls.ended, 1);
  assert.equal(h.calls.endForce, true);
});

test("nothing throws when a connect attempt fails outright", () => {
  const publisher = new MqttPublisher({
    getSettings: () => ENABLED,
    env: {},
    connect: () => {
      throw new Error("bad url");
    },
  });
  publisher.applySettings();
  publisher.publishEvent({ type: "x", message: "y" });
  publisher.publishFleet([{ id: "alpha", online: true }]);
  publisher.stop();
});

test("each publisher gets its own client id (PID is 1 in every container)", () => {
  const a = harness();
  const b = harness();
  a.publisher.applySettings();
  b.publisher.applySettings();
  assert.notEqual(a.attempts[0].opts.clientId, b.attempts[0].opts.clientId);
});

test("status and metrics are resent only when they change, and retried after a skipped publish", () => {
  const h = harness();
  h.publisher.applySettings();
  const at = (uptime) => [{ snapshot: { id: "alpha", online: true, uptime } }];
  const topics = (from) => h.calls.publishes.slice(from).map((p) => p.topic);
  h.publisher.publishFleet(at(1));
  let mark = h.calls.publishes.length;
  h.publisher.publishFleet(at(2)); // metrics changed, status did not
  assert.deepEqual(topics(mark), ["sparkdash/metrics/alpha"]);
  h.client.connected = false;
  h.publisher.publishFleet([{ id: "alpha", online: false }]); // skipped: broker down
  h.client.connected = true;
  mark = h.calls.publishes.length;
  h.publisher.publishFleet([{ id: "alpha", online: false }]);
  assert.deepEqual(topics(mark), ["sparkdash/status/alpha", "sparkdash/metrics/alpha"]);
});

test("a Spark with id \"dashboard\" does not touch the dashboard's availability topic", () => {
  const h = harness();
  h.publisher.applySettings();
  h.fire("connect");
  const mark = h.calls.publishes.length;
  h.publisher.publishFleet([{ id: "dashboard", online: false }]);
  const topics = h.calls.publishes.slice(mark).map((p) => p.topic);
  assert.deepEqual(topics, ["sparkdash/status/dashboard", "sparkdash/metrics/dashboard"]);
  assert.ok(!topics.includes("sparkdash/dashboard/status"));
});

test("a reconnect resends the retained status and metrics on the next tick", () => {
  const h = harness();
  h.publisher.applySettings();
  const fleet = [{ snapshot: { id: "alpha", online: true, uptime: 1 } }];
  h.publisher.publishFleet(fleet);
  let mark = h.calls.publishes.length;
  h.publisher.publishFleet(fleet); // unchanged: nothing resent
  assert.equal(h.calls.publishes.length, mark);
  h.fire("connect"); // like a restarted broker handing the session back
  mark = h.calls.publishes.length;
  h.publisher.publishFleet(fleet);
  assert.deepEqual(
    h.calls.publishes.slice(mark).map((p) => p.topic),
    ["sparkdash/status/alpha", "sparkdash/metrics/alpha"]
  );
});
