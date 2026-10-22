import { act } from "react";
import { describe, expect, it, vi } from "vitest";
import type { ReaJob, ReaLine } from "../../api/types";
import { render } from "../../testing/render";
import { setupData, statusData } from "./fixtures";
import type { InstallState } from "./hooks";
import { SetupCard } from "./SetupCard";

const job = (over: Partial<ReaJob> = {}): ReaJob => ({
  id: "j1",
  sparkId: "s1",
  status: "running",
  exitCode: null,
  startedAt: 1,
  finishedAt: null,
  error: null,
  ...over,
});

const install = (over: Partial<InstallState> = {}): InstallState => ({
  job: null,
  lines: [],
  partial: "",
  error: null,
  starting: false,
  running: false,
  start: vi.fn().mockResolvedValue(true),
  ...over,
});

const mount = (p: Partial<React.ComponentProps<typeof SetupCard>> = {}) =>
  render(
    <SetupCard
      unitName="spark-1"
      setup={setupData()}
      setupError={null}
      status={statusData({ installed: false, version: null, upToDate: false })}
      statusError={null}
      loading={false}
      install={install()}
      onRecheck={vi.fn()}
      {...p}
    />
  );

const button = (c: HTMLElement, text: RegExp) => Array.from(c.querySelectorAll("button")).find((b) => text.test(b.textContent ?? ""));

describe("SetupCard", () => {
  it("offers the one-click install of the pinned version and starts it", () => {
    const i = install();
    const { container } = mount({ install: i });
    const b = button(container, /Install REA 6\.4\.0/)!;
    expect(b.disabled).toBe(false);
    act(() => b.click());
    expect(i.start).toHaveBeenCalledTimes(1);
  });

  it("blocks the install while the opt-in is off, with the reason", () => {
    const { container } = mount({ setup: setupData({ enabled: false, startAllowed: false }) });
    expect(button(container, /Install REA/)!.disabled).toBe(true);
    expect(container.textContent).toContain("REA is turned off");
  });

  it("blocks the install when node is too old and says why", () => {
    const { container } = mount({ status: statusData({ node: { path: "/usr/bin/node", version: "20.1.0", ok: false }, installed: false }) });
    expect(button(container, /Install REA/)!.disabled).toBe(true);
    expect(container.textContent).toContain("Node.js 20.1.0 is older than 22.19");
  });

  it.each([
    [127, /Node\.js or npm is missing/],
    [3, /npm could not install/],
    [4, /smoke test failed/],
  ])("explains install exit code %i", (code, re) => {
    const lines: ReaLine[] = [{ seq: 1, text: "npm ERR! something" }];
    const { container } = mount({ install: install({ job: job({ status: "failed", exitCode: code }), lines }) });
    expect(container.textContent).toMatch(re);
    expect(container.textContent).toContain(`exit code ${code}`);
    expect(container.textContent).toContain("npm ERR! something");
  });

  it("streams output while running and shows doctor remediation, providers and engines", () => {
    const lines: ReaLine[] = [{ seq: 1, text: "added 144 packages" }];
    const status = statusData({
      doctor: { healthy: false, checks: [{ name: "node-pty", ok: false, classification: "environment", detail: "no prebuilt", remediation: "Reinstall REA." }] },
    });
    const { container } = mount({ status, install: install({ job: job(), lines, running: true }) });
    expect(container.textContent).toContain("added 144 packages");
    expect(container.textContent).toContain("Installing…");
    expect(container.textContent).toContain("Fix: Reinstall REA.");
    expect(container.textContent).toContain("Ghidra");
    expect(container.textContent).toContain("Android resource decoding.");
    expect(container.textContent).toContain("not sandboxed");
  });

  it("shows ready and Re-check calls back", () => {
    const onRecheck = vi.fn();
    const { container } = mount({ status: statusData(), onRecheck });
    expect(container.textContent).toContain("Ready");
    expect(button(container, /Install REA/)).toBeUndefined();
    act(() => button(container, /Re-check/)!.click());
    expect(onRecheck).toHaveBeenCalled();
  });
});
