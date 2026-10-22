import { act } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { VulnHuntSetup } from "../../api/types";
import { makeSpark } from "../../testing/fixtures";
import { flush, render } from "../../testing/render";

const setup = (enabled: boolean): VulnHuntSetup => ({
  repository: "https://github.com/example/VulnHunter",
  pinnedRev: "0".repeat(40),
  hostCommandFile: "~/.config/sparkdash/vulnhunt-host-cmd",
  steps: [],
  limits: { defaultTimeoutMinutes: 240, minTimeoutMinutes: 5, maxTimeoutMinutes: 720 },
  enabled,
  startAllowed: enabled,
  startBlockedReason: enabled ? null : "VulnHunter is turned off.",
  allowedHosts: [],
});

const api = vi.hoisted(() => ({
  fetchVulnHuntSetup: vi.fn(),
  fetchVulnHuntStatus: vi.fn(),
  listVulnHuntRuns: vi.fn(),
  readVulnHuntInstallStream: vi.fn(),
  updateSettings: vi.fn(),
}));
vi.mock("../../api/client", async (orig) => ({ ...(await orig<typeof import("../../api/client")>()), ...api }));

import { VulnHuntBenchPage } from "./SecurityPage";

describe("VulnHunter opt-in", () => {
  beforeEach(() => {
    api.fetchVulnHuntStatus.mockResolvedValue({
      reachable: true, installed: false, path: null, git: true, setsid: true, ready: false, runRoot: null, error: null,
      hostCommand: { source: "none", program: null, found: false, file: null, configured: false },
      install: { pinnedRev: "0".repeat(40), installedRev: null, upToDate: false, skillsDir: null, agentsDir: null, python311: "3.12", skillsDirCandidates: [] },
    });
    api.listVulnHuntRuns.mockResolvedValue({ runs: [], active: null });
    api.readVulnHuntInstallStream.mockResolvedValue(null);
  });

  it("offers a button when it is off, turns the setting on and asks the server again", async () => {
    api.fetchVulnHuntSetup.mockResolvedValueOnce(setup(false)).mockResolvedValue(setup(true));
    api.updateSettings.mockResolvedValue({ vulnhuntEnabled: true });
    const { container } = render(<VulnHuntBenchPage spark={makeSpark("s1")} />);
    await flush();
    expect(container.textContent).toContain("VulnHunter is turned off");
    const button = [...container.querySelectorAll("button")].find((b) => b.textContent === "Turn on VulnHunter")!;
    expect(button).toBeTruthy();
    await act(async () => button.click());
    await flush();
    expect(api.updateSettings).toHaveBeenCalledWith({ vulnhuntEnabled: true });
    expect(api.fetchVulnHuntSetup).toHaveBeenCalledTimes(2);
    expect(container.textContent).not.toContain("VulnHunter is turned off");
  });

  it("shows nothing about the opt-in when it is already on", async () => {
    api.fetchVulnHuntSetup.mockResolvedValue(setup(true));
    const { container } = render(<VulnHuntBenchPage spark={makeSpark("s1")} />);
    await flush();
    expect(container.textContent).not.toContain("Turn on VulnHunter");
    expect(api.updateSettings).not.toHaveBeenCalled();
  });
});
