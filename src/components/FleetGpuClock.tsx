import { useCallback, useEffect, useRef, useState } from "react";
import { fetchGpuClock, fetchSparks, resetFleetGpuClock, setFleetGpuClock } from "../api/client";
import type { FleetGpuClockResult } from "../api/types";

/** Fleet-wide GPU clock options: stock first, then 1800–2400 MHz in 100 MHz steps. */
const CAP_PRESETS = [1800, 1900, 2000, 2100, 2200, 2300, 2400] as const;

/**
 * How long a unit's status read may take before the row gives up on it. A Spark
 * behind a dead SSH connection can hang past any patience, and a row stuck on
 * "Reading the fleet…" would never mark the cap or offer a way out.
 */
const READ_TIMEOUT_MS = 6000;

/** Resolves to null after `ms`, so a stalled read can be raced and counted. */
const afterNull = (ms: number) => new Promise<null>((resolve) => window.setTimeout(() => resolve(null), ms));

/** What the Sparks report right now: one shared cap, a mix, or nothing readable. */
type FleetNow =
  | { kind: "same"; capMHz: number | null; units: number; unreadable: number }
  | { kind: "mixed"; caps: (number | null)[]; unreadable: number }
  | { kind: "unknown" };

/**
 * Fleet-wide GPU clock cap in Settings. One row of states — Full capacity, then
 * 1800–2400 MHz — with the one every Spark is on marked current; picking one
 * applies it to every unit in turn. Same manager and sudo rules as the per-unit
 * GPU clock cap in Edit unit.
 */
export function FleetGpuClock() {
  const [now, setNow] = useState<FleetNow | null>(null);
  const [persist, setPersist] = useState(true);
  const [busy, setBusy] = useState<number | "full" | null>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean; detail?: string } | null>(null);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);

  const read = useCallback(async () => {
    try {
      const res = await Promise.race([fetchSparks(), afterNull(READ_TIMEOUT_MS)]);
      if (!res) {
        setNow({ kind: "unknown" });
        return;
      }
      const { sparks } = res;
      const ids = sparks.filter((spark) => spark.kind !== "host").map((spark) => spark.id);
      // Each unit gets its own deadline: one unreachable Spark must not hide what
      // the others report, and must not hold the row on "Reading the fleet…".
      const statuses = await Promise.all(
        ids.map((id) => Promise.race([fetchGpuClock(id).catch(() => null), afterNull(READ_TIMEOUT_MS)])),
      );
      const caps = statuses.flatMap((status) => (status && status.supported ? [status.capMHz] : []));
      const unreadable = ids.length - caps.length;
      if (caps.length === 0) {
        setNow({ kind: "unknown" });
        return;
      }
      const [first] = caps;
      setNow(
        caps.every((cap) => cap === first)
          ? { kind: "same", capMHz: first, units: caps.length, unreadable }
          : { kind: "mixed", caps, unreadable },
      );
    } catch {
      setNow({ kind: "unknown" });
    }
  }, []);

  useEffect(() => {
    void read();
  }, [read]);

  async function apply(capMHz: number | null) {
    setBusy(capMHz ?? "full");
    setMsg(null);
    try {
      const res = capMHz === null ? await resetFleetGpuClock() : await setFleetGpuClock(capMHz, persist);
      const capped = res.results.filter((r) => r.ok && !("supported" in r)).length;
      const skipped = res.results.filter(
        (r): r is Extract<FleetGpuClockResult, { supported: false }> =>
          "supported" in r && r.supported === false,
      );
      const failed = res.results.filter((r): r is Extract<FleetGpuClockResult, { ok: false }> => !r.ok);
      // One line per distinct reason, not per unit: a fleet-wide refusal is three
      // copies of the same sentence, and repeating it hides the first one.
      const byReason: Record<string, string[]> = {};
      for (const r of failed) byReason[r.error] = [...(byReason[r.error] ?? []), r.id];
      const reasons = Object.keys(byReason);
      const detail = [
        ...reasons.map((reason) => `${byReason[reason].join(", ")}: ${reason}`),
        ...skipped.map((r) => `${r.id}: skipped — ${r.reason}`),
        // The common fleet-wide refusal is a permission the boot service needs and
        // the cap itself does not, so name the way out instead of only the wall.
        ...(reasons.length > 0 && reasons.every((reason) => reason.includes("keeping the cap after reboot"))
          ? ["Untick “Keep after reboot” to cap until the next reboot instead."]
          : []),
      ].join("; ");
      setMsg({
        // A skipped unit is not a failure: it never had a clock to cap.
        ok: failed.length === 0,
        text:
          capped === 0 && failed.length > 0
            ? `Nothing changed — 0 of ${res.results.length} units ${
                capMHz === null ? "unlocked" : "capped"
              }`
            : `${capMHz === null ? "Full capacity" : `Capped at ${capMHz} MHz`} — ${capped} of ${res.results.length} units${
                skipped.length ? `, ${skipped.length} skipped` : ""
              }`,
        detail: detail || undefined,
      });
      void read();
    } catch (err: unknown) {
      setMsg({
        ok: false,
        text: err instanceof Error ? err.message : "GPU clock request failed",
      });
    } finally {
      setBusy(null);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setMsg(null), 12_000);
    }
  }

  const shared = now?.kind === "same" ? now.capMHz : undefined;

  return (
    <div className="set-fleetcap">
      <p className="gpu-clock__now" data-testid="fleet-now">
        {now === null ? (
          "Reading the fleet…"
        ) : now.kind === "unknown" ? (
          "No unit reports its clock right now — reopen Settings to try again."
        ) : now.kind === "mixed" ? (
          `Now: mixed — ${now.caps.map((cap) => (cap === null ? "full capacity" : `${cap} MHz`)).join(", ")}${
            now.unreadable ? `, ${now.unreadable} unreadable` : ""
          }`
        ) : now.capMHz === null ? (
          `Now: full capacity on ${now.units} unit${now.units === 1 ? "" : "s"}${
            now.unreadable ? `, ${now.unreadable} unreadable` : ""
          }`
        ) : (
          `Now: capped at ${now.capMHz} MHz on ${now.units} unit${now.units === 1 ? "" : "s"}${
            now.unreadable ? `, ${now.unreadable} unreadable` : ""
          }`
        )}
      </p>
      <div className="set-fleetcap__presets" role="group" aria-label="GPU clock cap options">
        <button
          type="button"
          className={`btn btn--sm${shared === null ? " is-current" : ""}`}
          onClick={() => void apply(null)}
          disabled={busy !== null}
        >
          {busy === "full" ? "Applying…" : "Full capacity"}
        </button>
        {CAP_PRESETS.map((mhz) => (
          <button
            key={mhz}
            type="button"
            className={`btn btn--sm${shared === mhz ? " is-current" : ""}`}
            onClick={() => void apply(mhz)}
            disabled={busy !== null}
          >
            {busy === mhz ? "Applying…" : `${mhz} MHz`}
          </button>
        ))}
      </div>
      <label className="gpu-clock__check">
        <input
          type="checkbox"
          checked={persist}
          onChange={(e) => setPersist(e.target.checked)}
          disabled={busy !== null}
        />
        Keep after reboot — the option you pick also installs a boot service on each unit
      </label>
      {msg ? (
        <p className={`set-fleetcap__msg${msg.ok ? "" : " is-err"}`} role="status" aria-live="polite">
          {msg.text}
          {msg.detail ? <span className="set-fleetcap__detail">{msg.detail}</span> : null}
        </p>
      ) : null}
    </div>
  );
}
