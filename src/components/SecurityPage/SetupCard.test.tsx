import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VulnHuntApiError, type VulnHuntInstallInfo, type VulnHuntInstallJob, type VulnHuntSetup, type VulnHuntStatus } from "../../api/types";
import { flush, render } from "../../testing/render";

const api = vi.hoisted(() => ({
  installVulnHunt: vi.fn(),
  readVulnHuntInstallStream: vi.fn(),
  saveVulnHuntHostCommand: vi.fn(),
  clearVulnHuntHostCommand: vi.fn(),
}));
vi.mock("../../api/client", async (orig) => ({ ...(await orig<typeof import("../../api/client")>()), ...api }));

import { SetupCard } from "./SetupCard";

const setupData = (over: Partial<VulnHuntSetup> = {}): VulnHuntSetup => ({
  repository: "https://github.com/example/VulnHunter",
  pinnedRev: "0123456789abcdef0123456789abcdef01234567",
  hostCommandFile: "~/.config/sparkdash/vulnhunt-host-cmd",
  steps: ["git clone x"],
  limits: { defaultTimeoutMinutes: 240, minTimeoutMinutes: 5, maxTimeoutMinutes: 1440 },
  enabled: true,
  startAllowed: true,
  startBlockedReason: null,
  allowedHosts: [],
  ...over,
});

const statusData = (over: Partial<VulnHuntStatus> = {}, install: Partial<VulnHuntInstallInfo> = {}): VulnHuntStatus => ({
  reachable: true,
  installed: false,
  path: null,
  git: true,
  setsid: true,
  hostCommand: { source: "none", program: null, found: false, file: null, configured: false },
  ready: false,
  runRoot: null,
  error: null,
  install: {
    pinnedRev: "0123456789abcdef0123456789abcdef01234567",
    installedRev: null,
    upToDate: false,
    skillsDir: null,
    agentsDir: null,
    python311: "3.12",
    skillsDirCandidates: [],
    ...install,
  },
  ...over,
});

const job = (over: Partial<VulnHuntInstallJob> = {}): VulnHuntInstallJob => ({
  id: "j1",
  sparkId: "s1",
  kind: "install",
  status: "running",
  exitCode: null,
  error: null,
  startedAt: 1,
  finishedAt: null,
  ...over,
});

function mount(props: { setup?: VulnHuntSetup | null; status?: VulnHuntStatus; onRecheck?: () => void } = {}) {
  const onRecheck = props.onRecheck ?? vi.fn();
  const view = render(
    <SetupCard
      sparkId="s1"
      unitName="spark-1"
      setup={props.setup === undefined ? setupData() : props.setup}
      setupError={null}
      status={props.status ?? statusData()}
      loading={false}
      error={null}
      onRecheck={onRecheck}
    />
  );
  const q = <T extends Element>(sel: string) => view.container.querySelector<T>(sel);
  const btn = (text: RegExp) => Array.from(view.container.querySelectorAll("button")).find((b) => text.test(b.textContent ?? "")) as HTMLButtonElement | undefined;
  return { ...view, q, btn, onRecheck };
}

function setValue(el: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!;
  act(() => {
    setter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
const click = (el: Element) => act(() => (el as HTMLElement).click());
const submit = async (form: HTMLFormElement) => {
  await act(async () => {
    form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
};

beforeEach(() => {
  api.readVulnHuntInstallStream.mockResolvedValue(null);
});
afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("install form gating", () => {
  const installBtn = (m: ReturnType<typeof mount>) => m.btn(/^(Install|Update) on/)!;

  it("offers Install with the default skills directory when the unit has no candidates", async () => {
    const m = mount();
    await flush();
    expect(installBtn(m).disabled).toBe(false);
    expect(m.q<HTMLInputElement>('input[aria-label="Skills directory path"]')!.value).toBe("~/.claude/skills");
  });

  it("disables Install with the server's reason when starting is not allowed", async () => {
    const m = mount({ setup: setupData({ startAllowed: false, startBlockedReason: "Set SPARKDASH_TOKEN first." }) });
    await flush();
    expect(installBtn(m).disabled).toBe(true);
    expect(m.container.textContent).toContain("Set SPARKDASH_TOKEN first.");
  });

  it("disables Install when Python 3.11 is missing", async () => {
    const m = mount({ status: statusData({}, { python311: null }) });
    await flush();
    expect(installBtn(m).disabled).toBe(true);
    expect(m.container.textContent).toContain("Python 3.11 or newer is needed on this unit");
  });

  it("disables Install when git is missing", async () => {
    const m = mount({ status: statusData({ git: false }) });
    await flush();
    expect(installBtn(m).disabled).toBe(true);
    expect(m.container.textContent).toContain("git is not installed on this unit.");
  });

  it("disables Install for an empty skills directory", async () => {
    const m = mount();
    await flush();
    setValue(m.q<HTMLInputElement>('input[aria-label="Skills directory path"]')!, "   ");
    expect(installBtn(m).disabled).toBe(true);
    expect(m.container.textContent).toContain("Choose a skills directory.");
    setValue(m.q<HTMLInputElement>('input[aria-label="Skills directory path"]')!, "/tmp/a b");
    expect(installBtn(m).disabled).toBe(true);
  });

  it("shows Update when an older revision is installed", async () => {
    const m = mount({ status: statusData({ installed: true, path: "/home/u/.local/bin/vh" }, { installedRev: "aaaaaaaaaaaa", skillsDir: "/home/u/.claude/skills", skillsDirCandidates: ["/home/u/.claude/skills"] }) });
    await flush();
    expect(installBtn(m).textContent).toContain("Update");
    expect(m.container.textContent).toContain("Update available");
  });
});

describe("install request", () => {
  it("sends the chosen candidate and the optional agents directory", async () => {
    api.installVulnHunt.mockResolvedValue({ job: job(), revision: "r", repository: "x" });
    const m = mount({ status: statusData({}, { skillsDirCandidates: ["/home/u/.claude/skills", "/home/u/.codex/skills"] }) });
    await flush();
    const radios = m.container.querySelectorAll<HTMLInputElement>('input[type="radio"]');
    expect(radios[0].checked).toBe(true);
    click(radios[1]);
    const agents = m.q<HTMLInputElement>('input[placeholder^="optional, e.g."]')!;
    setValue(agents, " ~/.claude/agents ");
    await submit(m.q<HTMLFormElement>("form")!);
    expect(api.installVulnHunt).toHaveBeenCalledWith("s1", { skillsDir: "/home/u/.codex/skills", agentsDir: "~/.claude/agents" });
  });

  it("omits an empty agents directory", async () => {
    api.installVulnHunt.mockResolvedValue({ job: job(), revision: "r", repository: "x" });
    const m = mount();
    await flush();
    await submit(m.q<HTMLFormElement>("form")!);
    expect(api.installVulnHunt).toHaveBeenCalledWith("s1", { skillsDir: "~/.claude/skills" });
  });

  it.each([
    [400, "skills dir must be inside your home", "The unit's installer rejected the request"],
    [403, "Open dashboard: set a token", "The dashboard does not allow this"],
    [409, "A scan is running", "Another job is running on this unit"],
  ])("shows a %i refusal inline", async (status, message, title) => {
    api.installVulnHunt.mockRejectedValue(new VulnHuntApiError(message, status));
    const m = mount();
    await flush();
    await submit(m.q<HTMLFormElement>("form")!);
    const alert = m.q('[role="alert"]')!;
    expect(alert.textContent).toContain(message);
    expect(alert.textContent).toContain(title);
    expect(installBtnText(m)).toContain("Install");
  });
});

const installBtnText = (m: ReturnType<typeof mount>) => m.btn(/^(Install|Update) on/)?.textContent ?? "";

describe("install progress", () => {
  it("polls once a second while running, stops at completion and re-checks the unit once", async () => {
    vi.useFakeTimers();
    api.installVulnHunt.mockResolvedValue({ job: job(), revision: "r", repository: "x" });
    api.readVulnHuntInstallStream
      .mockResolvedValueOnce(null) // pick-up check on mount
      .mockResolvedValueOnce({ job: job(), lines: [{ seq: 1, text: "cloning", stream: "out" }], partial: "", nextLine: 1 })
      .mockResolvedValueOnce({ job: job({ status: "completed", exitCode: 0, finishedAt: 5 }), lines: [{ seq: 2, text: "done", stream: "out" }], partial: "", nextLine: 2 });
    const m = mount();
    await flush();
    await submit(m.q<HTMLFormElement>("form")!);
    expect(m.container.textContent).toContain("Installing…");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(api.readVulnHuntInstallStream).toHaveBeenLastCalledWith("s1", 0);
    expect(m.container.textContent).toContain("cloning");
    expect(m.onRecheck).not.toHaveBeenCalled();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(api.readVulnHuntInstallStream).toHaveBeenLastCalledWith("s1", 1);
    expect(m.container.textContent).toContain("done");
    expect(m.onRecheck).toHaveBeenCalledTimes(1);
    const calls = api.readVulnHuntInstallStream.mock.calls.length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5000);
    });
    expect(api.readVulnHuntInstallStream.mock.calls.length).toBe(calls);
    expect(m.onRecheck).toHaveBeenCalledTimes(1);
  });

  it("follows an install that is already running when the page opens", async () => {
    vi.useFakeTimers();
    api.readVulnHuntInstallStream.mockResolvedValueOnce({
      job: job(),
      lines: [{ seq: 1, text: "fetching", stream: "out" }],
      partial: "",
      nextLine: 1,
    });
    api.readVulnHuntInstallStream.mockResolvedValue({ job: job({ status: "failed", exitCode: 3, error: "pip failed" }), lines: [], partial: "", nextLine: 1 });
    const m = mount();
    await flush();
    expect(m.container.textContent).toContain("fetching");
    expect(m.container.textContent).toContain("Installing…");
    expect(m.q("form[aria-label^='Install VulnHunter']")).toBeNull();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1000);
    });
    expect(m.container.textContent).toContain("exit code 3");
    expect(m.container.textContent).toContain("pip failed");
    expect(m.btn(/^Retry$/)).toBeDefined();
    expect(m.onRecheck).toHaveBeenCalledTimes(1);
  });

  it("renders streamed output as text, never as markup", async () => {
    vi.useFakeTimers();
    const evil = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>';
    api.readVulnHuntInstallStream.mockResolvedValueOnce({
      job: job(),
      lines: [{ seq: 1, text: evil, stream: "out" }],
      partial: "<b>partial</b>",
      nextLine: 1,
    });
    api.readVulnHuntInstallStream.mockResolvedValue({ job: job(), lines: [], partial: "", nextLine: 1 });
    const m = mount();
    await flush();
    const term = m.q("pre.live-term")!;
    expect(term.textContent).toContain(evil);
    expect(term.textContent).toContain("<b>partial</b>");
    expect(m.container.querySelector("pre.live-term img, pre.live-term script, pre.live-term b")).toBeNull();
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});

describe("harness command", () => {
  const readyStatus = () =>
    statusData(
      { installed: true, ready: true, path: "/p", hostCommand: { source: "file", program: "my-harness", found: true, file: "~/x", configured: true } },
      { installedRev: "0123456789abcdef", upToDate: true, skillsDir: "/home/u/.claude/skills" }
    );

  it("never prefills the input, shows only the program, and clears it after a save", async () => {
    api.saveVulnHuntHostCommand.mockResolvedValue({ success: true });
    const m = mount({ status: readyStatus() });
    await flush();
    const input = m.q<HTMLInputElement>('input[placeholder^="one line"]')!;
    expect(input.value).toBe("");
    expect(input.type).toBe("text");
    expect(input.autocomplete).toBe("off");
    expect(m.container.textContent).toContain("my-harness");
    expect(m.btn(/^Remove$/)).toBeDefined();
    const save = m.btn(/^Save command$/)!;
    expect(save.disabled).toBe(true);
    setValue(input, "my-harness --headless -p");
    expect(save.disabled).toBe(false);
    await submit(input.closest("form") as HTMLFormElement);
    expect(api.saveVulnHuntHostCommand).toHaveBeenCalledWith("s1", "my-harness --headless -p");
    expect(input.value).toBe("");
    expect(m.onRecheck).toHaveBeenCalledTimes(1);
    expect(m.container.textContent).not.toContain("--headless");
  });

  it("keeps the input and shows the server's message when the save is refused", async () => {
    api.saveVulnHuntHostCommand.mockRejectedValue(new VulnHuntApiError("my-harnes is not on the PATH", 400));
    const m = mount({ status: readyStatus() });
    await flush();
    const input = m.q<HTMLInputElement>('input[placeholder^="one line"]')!;
    setValue(input, "my-harnes -p");
    await submit(input.closest("form") as HTMLFormElement);
    expect(m.q('[role="alert"]')!.textContent).toContain("not on the PATH");
    expect(input.value).toBe("my-harnes -p");
    expect(m.onRecheck).not.toHaveBeenCalled();
  });

  it("shows a 403 refusal and disables saving when starting is not allowed", async () => {
    api.saveVulnHuntHostCommand.mockRejectedValue(new VulnHuntApiError("token required", 403));
    const m = mount({ status: readyStatus() });
    await flush();
    const input = m.q<HTMLInputElement>('input[placeholder^="one line"]')!;
    setValue(input, "h -p");
    await submit(input.closest("form") as HTMLFormElement);
    expect(m.q('[role="alert"]')!.textContent).toContain("token required");

    const blocked = mount({ status: readyStatus(), setup: setupData({ startAllowed: false, startBlockedReason: "No token set." }) });
    await flush();
    const b = blocked.container.querySelector<HTMLInputElement>('input[placeholder^="one line"]')!;
    setValue(b, "h -p");
    expect(Array.from(blocked.container.querySelectorAll("button")).find((x) => /^Save command$/.test(x.textContent ?? ""))!.disabled).toBe(true);
    expect(blocked.container.textContent).toContain("No token set.");
  });

  it("removes the saved command", async () => {
    api.clearVulnHuntHostCommand.mockResolvedValue({ success: true });
    const m = mount({ status: readyStatus() });
    await flush();
    await act(async () => m.btn(/^Remove$/)!.click());
    expect(api.clearVulnHuntHostCommand).toHaveBeenCalledWith("s1");
    expect(m.onRecheck).toHaveBeenCalledTimes(1);
  });
});

describe("source hygiene", () => {
  it("does not use dangerouslySetInnerHTML in the Security page", async () => {
    const files = import.meta.glob("./*.tsx", { query: "?raw", import: "default", eager: true }) as Record<string, string>;
    const offenders = Object.entries(files)
      .filter(([name, src]) => !name.endsWith(".test.tsx") && /dangerouslySetInnerHTML/.test(src))
      .map(([name]) => name);
    expect(offenders).toEqual([]);
  });
});
