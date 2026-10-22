import type { ReaRun, ReaSetup, ReaStatus, ReaWorkflowSpec } from "../../api/types";

const noEffects = { launchesProcess: false, network: false, writesFs: false, mutatesDevice: false, usesProvider: false };

export const WF_STATIC: ReaWorkflowSpec = {
  id: "analyze-javascript-application",
  label: "Analyze a JavaScript/Electron application",
  group: "javascript",
  blurb: "Statically reconstructs modules.",
  command: "analyze-javascript-application",
  execClass: "static",
  effects: noEffects,
  targetKinds: ["path", "upload"],
  targets: 1,
  targetLabel: "ASAR file or extracted application folder",
  target2Label: null,
  needsProvider: false,
  prerequisites: [],
  args: [
    { name: "max-heap-mb", flag: "--max-heap-mb", kind: "int", help: "Heap in MiB.", min: 128, max: 16384, default: 1024 },
    { name: "artifact-format", flag: "--artifact-format", kind: "choice", help: "Format.", choices: ["auto", "asar", "directory"], default: "auto" },
    { name: "include-maps", flag: "--include-maps", kind: "bool", help: "Also read source maps." },
  ],
  positionals: ["$target"],
  requireOneOf: null,
  resultShape: "javascript-app",
  defaultTimeoutMinutes: 30,
  viewable: true,
};

export const WF_TWO: ReaWorkflowSpec = {
  ...WF_STATIC,
  id: "compare-managed-members",
  label: "Compare .NET builds",
  group: "managed",
  blurb: "Compares member inventories.",
  command: "compare-managed-members",
  targets: 2,
  targetLabel: "Baseline assembly",
  target2Label: "Candidate assembly",
  args: [],
  positionals: ["$target", "$target2"],
  resultShape: "generic",
  viewable: false,
  defaultTimeoutMinutes: 10,
};

export const WF_ZERO: ReaWorkflowSpec = {
  ...WF_STATIC,
  id: "inspect-apktool-client",
  label: "Check the apktool launcher",
  group: "android",
  blurb: "Inspects the selected apktool launcher.",
  command: "inspect-apktool-client",
  execClass: "native-provider",
  effects: { ...noEffects, launchesProcess: true },
  targetKinds: [],
  targets: 0,
  targetLabel: null,
  args: [],
  positionals: [],
  prerequisites: ["apktool"],
  resultShape: "generic",
  viewable: false,
};

export const WF_NATIVE: ReaWorkflowSpec = {
  ...WF_STATIC,
  id: "annotate-native-function",
  label: "Annotate a function",
  group: "native",
  blurb: "Edits a function's name or comments.",
  command: "annotate-native-function",
  execClass: "native-provider",
  effects: { ...noEffects, launchesProcess: true, usesProvider: true, writesFs: true },
  needsProvider: true,
  args: [
    { name: "procedure", flag: null, kind: "string", help: "Function address or name.", positional: true, required: true, maxLength: 300 },
    { name: "name", flag: "--name", kind: "string", help: "Analyst name.", maxLength: 300 },
    { name: "comment", flag: "--comment", kind: "string", help: "Comment.", maxLength: 300 },
  ],
  positionals: ["$target", "procedure"],
  requireOneOf: ["name", "comment"],
  resultShape: "native-function",
  viewable: false,
};

export const WF_EXEC: ReaWorkflowSpec = {
  ...WF_STATIC,
  id: "observe-native-ui",
  label: "Observe a native app",
  group: "native-runtime",
  blurb: "Launches the application and observes its UI.",
  command: "observe-native-ui",
  execClass: "executes-target",
  effects: { ...noEffects, launchesProcess: true },
  args: [{ name: "wait-ms", flag: "--wait-ms", kind: "int", help: "Wait.", min: 0, max: 60000 }],
  resultShape: "generic",
  viewable: false,
};

export const WF_DEVICE: ReaWorkflowSpec = {
  ...WF_EXEC,
  id: "uninstall-adb-package",
  label: "Uninstall a package",
  group: "adb-write",
  execClass: "device",
  effects: { ...noEffects, launchesProcess: true, mutatesDevice: true },
  targets: 0,
  targetKinds: [],
  targetLabel: null,
  args: [],
  positionals: [],
};

export const setupData = (over: Partial<ReaSetup> = {}): ReaSetup => ({
  repository: "https://github.com/morluto/rea",
  pinnedVersion: "6.4.0",
  node: { min: "22.19" },
  limits: { defaultTimeoutMinutes: 30, maxTimeoutMinutes: 240, uploadMaxBytes: 1000, uploadMaxFiles: 3 },
  enabled: true,
  startAllowed: true,
  startBlockedReason: null,
  deviceWritesEnabled: false,
  ...over,
});

export const statusData = (over: Partial<ReaStatus> = {}): ReaStatus => ({
  reachable: true,
  node: { path: "/usr/bin/node", version: "22.20.0", ok: true },
  npm: true,
  installed: true,
  version: "6.4.0",
  pinnedVersion: "6.4.0",
  upToDate: true,
  launcher: "~/.local/bin/rea-sparkdash",
  doctor: { healthy: true, checks: [{ name: "node", ok: true, classification: "environment" }] },
  providers: [
    { id: "auto", label: "Auto", available: true },
    { id: "ghidra", label: "Ghidra", available: false, reason: "not installed" },
  ],
  engines: [
    { id: "ghidra", label: "Ghidra", found: false, unlocks: "Deep native analysis." },
    { id: "apktool", label: "Apktool", found: true, path: "/usr/bin/apktool", unlocks: "Android resource decoding." },
  ],
  error: null,
  ...over,
});

export const runData = (over: Partial<ReaRun> = {}): ReaRun => ({
  id: "rea-20261012-000000-abcd",
  sparkId: "s1",
  status: "completed",
  startedAt: 1_000_000,
  finishedAt: 1_060_000,
  exitCode: 0,
  note: null,
  label: "",
  workflowId: WF_STATIC.id,
  workflowLabel: WF_STATIC.label,
  command: "rea analyze-javascript-application /home/u/app.asar",
  target: { kind: "path", display: "/home/u/app.asar" },
  provider: null,
  execClass: "static",
  effects: noEffects,
  confirmedExecute: false,
  timeoutMinutes: 30,
  resultBytes: 100,
  resultCached: true,
  summary: null,
  ...over,
});
