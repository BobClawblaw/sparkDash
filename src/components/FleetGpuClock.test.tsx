import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchGpuClock, fetchSparks, resetFleetGpuClock, setFleetGpuClock } from "../api/client";
import type { FleetGpuClockResult, GpuClockStatus, SparkConfig } from "../api/types";
import { FleetGpuClock } from "./FleetGpuClock";
import { cleanupRenders, flush, render } from "../testing/render";

vi.mock("../api/client", () => ({
  fetchSparks: vi.fn(),
  fetchGpuClock: vi.fn(),
  setFleetGpuClock: vi.fn(),
  resetFleetGpuClock: vi.fn(),
}));

const listApi = vi.mocked(fetchSparks);
const statusApi = vi.mocked(fetchGpuClock);
const setApi = vi.mocked(setFleetGpuClock);
const resetApi = vi.mocked(resetFleetGpuClock);

const FLEET = {
  sparks: [
    { id: "spark1", kind: "spark" },
    { id: "spark2", kind: "spark" },
    { id: "desk", kind: "host" },
  ] as SparkConfig[],
};

const ready = (capMHz: number | null): GpuClockStatus => ({
  supported: true,
  hwMaxMHz: 3003,
  capMHz,
  sudo: "yes",
  service: { installed: false, clocks: null, enabled: null, active: null },
});

const done = (results: FleetGpuClockResult[]) => ({ success: true, results });

const byText = (c: HTMLElement, text: string) => {
  const button = [...c.querySelectorAll("button")].find((el) => el.textContent?.includes(text));
  if (!button) throw new Error(`no button matching ${text}`);
  return button;
};

const status = (c: HTMLElement) => c.querySelector('[role="status"]');

const settle = async () => {
  for (let i = 0; i < 6; i += 1) await flush();
};

const click = async (el: HTMLElement) => {
  el.click();
  await settle();
};

describe("FleetGpuClock", () => {
  beforeEach(() => {
    listApi.mockReset().mockResolvedValue(FLEET);
    statusApi.mockReset().mockResolvedValue(ready(2100));
    setApi.mockReset();
    resetApi.mockReset();
  });
  afterEach(() => cleanupRenders());

  it("marks the cap every Spark shares and applies a picked one in one click", async () => {
    setApi.mockResolvedValue(done([
      { id: "spark1", ok: true, capMHz: 1800 },
      { id: "spark2", ok: true, capMHz: 1800 },
    ]));
    const { container } = render(<FleetGpuClock />);
    await settle();

    expect(container.querySelector('[data-testid="fleet-now"]')!.textContent).toContain("Now: capped at 2100 MHz on 2 units");
    expect(byText(container, "2100 MHz").className).toContain("is-current");
    // No Apply step: the row is the choice, and the hosts are not asked at all.
    expect([...container.querySelectorAll("button")].map((b) => b.textContent)).not.toContain("Apply");
    expect(statusApi).toHaveBeenCalledWith("spark1");
    expect(statusApi).toHaveBeenCalledWith("spark2");
    expect(statusApi).not.toHaveBeenCalledWith("desk");

    await click(byText(container, "1800 MHz"));

    expect(setApi).toHaveBeenCalledWith(1800, true);
    const msg = status(container)!;
    expect(msg.textContent).toContain("Capped at 1800 MHz — 2 of 2 units");
    expect(msg.className).not.toContain("is-err");
  });

  it("marks nothing when the fleet is on different caps", async () => {
    statusApi.mockImplementation(async (id) => ready(id === "spark1" ? 1800 : null));
    const { container } = render(<FleetGpuClock />);
    await settle();

    expect(container.querySelector('[data-testid="fleet-now"]')!.textContent).toContain("Now: mixed — 1800 MHz, full capacity");
    expect(container.querySelectorAll(".is-current")).toHaveLength(0);
  });

  it("marks Full capacity when no cap is applied, and clears the caps on click", async () => {
    statusApi.mockResolvedValue(ready(null));
    resetApi.mockResolvedValue(done([
      { id: "spark1", ok: true, capMHz: null },
      { id: "spark2", ok: true, capMHz: null },
    ]));
    const { container } = render(<FleetGpuClock />);
    await settle();

    expect(byText(container, "Full capacity").className).toContain("is-current");

    await click(byText(container, "Full capacity"));

    expect(resetApi).toHaveBeenCalled();
    expect(setApi).not.toHaveBeenCalled();
    expect(status(container)!.textContent).toContain("Full capacity — 2 of 2 units");
  });

  it("reports a unit that cannot take a cap as skipped, not as an error", async () => {
    setApi.mockResolvedValue(done([
      { id: "spark1", ok: true, capMHz: 1800 },
      { id: "spark2", ok: true, supported: false, reason: "nvidia-smi was not found on this unit" },
    ]));
    const { container } = render(<FleetGpuClock />);
    await settle();

    await click(byText(container, "1800 MHz"));

    const msg = status(container)!;
    expect(msg.textContent).toContain("1 of 2 units, 1 skipped");
    expect(msg.className).not.toContain("is-err");
  });

  it("keeps the cap after reboot unless the box is unticked", async () => {
    setApi.mockResolvedValue(done([{ id: "spark1", ok: true, capMHz: 1800 }]));
    const { container } = render(<FleetGpuClock />);
    await settle();

    const box = container.querySelector('input[type="checkbox"]') as HTMLInputElement;
    expect(box.checked).toBe(true);

    await click(box);
    await click(byText(container, "1800 MHz"));

    expect(setApi).toHaveBeenCalledWith(1800, false);
  });

  it("says nothing changed when every unit refuses, names the reason once and the way out", async () => {
    const refusal = "keeping the cap after reboot installs a system service, which needs passwordless sudo";
    setApi.mockResolvedValue(done([
      { id: "spark1", ok: false, error: refusal },
      { id: "spark2", ok: false, error: refusal },
    ]));
    const { container } = render(<FleetGpuClock />);
    await settle();

    await click(byText(container, "1800 MHz"));

    const msg = status(container)!;
    expect(msg.textContent).toContain("Nothing changed — 0 of 2 units capped");
    expect(msg.textContent).not.toContain("Capped at 1800 MHz");
    // Grouped by reason: named once with both units, not twice.
    expect(msg.textContent?.match(/needs passwordless sudo/g)).toHaveLength(1);
    expect(msg.textContent).toContain("spark1, spark2:");
    expect(msg.textContent).toContain("Untick “Keep after reboot”");
    expect(msg.className).toContain("is-err");
  });

  it("surfaces a refused request", async () => {
    setApi.mockRejectedValue(new Error("Too many GPU clock changes, try again in a minute"));
    const { container } = render(<FleetGpuClock />);
    await settle();

    await click(byText(container, "2300 MHz"));

    const msg = status(container)!;
    expect(msg.textContent).toContain("Too many GPU clock changes");
    expect(msg.className).toContain("is-err");
  });

  it("marks what the units that answered report when one read hangs, and counts the other", async () => {
    vi.useFakeTimers();
    try {
      // A Spark behind a dead SSH connection answers nothing, ever.
      statusApi.mockImplementation((id: string) =>
        id === "spark2" ? new Promise<GpuClockStatus>(() => {}) : Promise.resolve(ready(2100)),
      );
      const { container } = render(<FleetGpuClock />);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(6000);
      });

      const line = container.querySelector('[data-testid="fleet-now"]')!.textContent;
      expect(line).toContain("capped at 2100 MHz on 1 unit");
      expect(line).toContain("1 unreadable");
      expect(byText(container, "2100 MHz").className).toContain("is-current");
    } finally {
      vi.useRealTimers();
    }
  });

  it("leaves the states usable, not 'Reading the fleet…', when every read hangs", async () => {
    vi.useFakeTimers();
    try {
      statusApi.mockImplementation(() => new Promise<GpuClockStatus>(() => {}));
      const { container } = render(<FleetGpuClock />);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(6000);
      });

      const line = container.querySelector('[data-testid="fleet-now"]')!.textContent;
      expect(line).toContain("No unit reports its clock right now");
      expect(byText(container, "Full capacity")).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });
});
