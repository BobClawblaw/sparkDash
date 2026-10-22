import { describe, expect, it } from "vitest";
import {
  buildOptions,
  checkRunForm,
  defaultOptionValues,
  findRows,
  installExitExplanation,
  optionProblem,
  uploadRelProblem,
  isArchiveName,
  planUpload,
  plain,
  sanitizeUploadPath,
  targetFromDisplay,
  unitPathProblem,
  viewSources,
  workflowAvailability,
  type RunFormState,
} from "./reaLogic";
import { WF_DEVICE, WF_EXEC, WF_NATIVE, WF_STATIC, WF_TWO, WF_ZERO, setupData, statusData } from "./fixtures";

const file = (name: string, size = 10) => new File([new Uint8Array(size)], name);
const limits = { maxBytes: 100, maxFiles: 3 };

describe("planUpload", () => {
  it("accepts small selections, flags archives by extension and keeps folder paths", () => {
    const plan = planUpload(
      [
        { path: "app/a.js", file: file("a.js", 5) },
        { path: "pack.tar.gz", file: file("pack.tar.gz", 5) },
      ],
      limits
    );
    expect(plan.problems).toEqual([]);
    expect(plan.entries.map((e) => [e.relPath, e.archive])).toEqual([
      ["app/a.js", false],
      ["pack.tar.gz", true],
    ]);
    expect(plan.totalBytes).toBe(10);
  });

  it("refuses more files than the limit and more bytes than the limit", () => {
    const many = planUpload([1, 2, 3, 4].map((i) => ({ path: `f${i}`, file: file(`f${i}`, 1) })), limits);
    expect(many.problems.join(" ")).toMatch(/4 files; at most 3/);
    const big = planUpload([{ path: "big.bin", file: file("big.bin", 101) }], limits);
    expect(big.problems.join(" ")).toMatch(/at most 100 B/);
  });

  it("replaces unsupported characters and reports collisions and over-deep paths", () => {
    expect(sanitizeUploadPath("My File (1).dll")).toEqual({ path: "My_File__1_.dll", changed: true });
    expect(sanitizeUploadPath(Array(17).fill("d").join("/"))).toBeNull();
    const plan = planUpload([{ path: "a b", file: file("x") }, { path: "a_b", file: file("y") }], limits);
    expect(plan.adjusted).toBe(1);
    expect(plan.problems.join(" ")).toMatch(/Two files would be stored as "a_b"/);
  });

  it("detects archives", () => {
    for (const n of ["x.zip", "x.TAR", "x.tar.gz", "x.tgz"]) expect(isArchiveName(n)).toBe(true);
    expect(isArchiveName("x.gz")).toBe(false);
  });
});

describe("unitPathProblem", () => {
  it("accepts absolute and home paths and explains refusals", () => {
    expect(unitPathProblem("/opt/app/bin")).toBeNull();
    expect(unitPathProblem("~/samples/a.asar")).toBeNull();
    expect(unitPathProblem("relative/x")).toMatch(/absolute/);
    expect(unitPathProblem("/a/../b")).toMatch(/\.\./);
    expect(unitPathProblem("/a;rm -rf")).toMatch(/Only letters/);
    expect(unitPathProblem("/")).toMatch(/Name a file/);
  });
});

describe("buildOptions", () => {
  it("generates typed values for int, choice and bool and omits unset ones", () => {
    const v = { ...defaultOptionValues(WF_STATIC), "max-heap-mb": "2048", "artifact-format": "asar", "include-maps": true };
    expect(buildOptions(WF_STATIC, v)).toMatchObject({ options: { "max-heap-mb": 2048, "artifact-format": "asar", "include-maps": true }, errors: {}, blockers: [] });
    expect(buildOptions(WF_STATIC, defaultOptionValues(WF_STATIC)).options).toEqual({});
  });

  it("checks ranges, required options and requireOneOf", () => {
    const bad = buildOptions(WF_STATIC, { ...defaultOptionValues(WF_STATIC), "max-heap-mb": "10" });
    expect(bad.errors["max-heap-mb"]).toMatch(/At least 128/);
    const empty = buildOptions(WF_NATIVE, defaultOptionValues(WF_NATIVE));
    expect(empty.errors.procedure).toBe("Required.");
    expect(empty.blockers.join(" ")).toMatch(/at least one of: name, comment/);
    const ok = buildOptions(WF_NATIVE, { ...defaultOptionValues(WF_NATIVE), procedure: "main", name: "entry" });
    expect(ok).toMatchObject({ options: { procedure: "main", name: "entry" }, errors: {}, blockers: [] });
  });

  it("handles list, intlist, json and path kinds", () => {
    const wf = {
      ...WF_STATIC,
      args: [
        { name: "l", flag: "--l", kind: "list" as const, help: "", maxItems: 2 },
        { name: "n", flag: "--n", kind: "intlist" as const, help: "", min: 0, max: 9 },
        { name: "j", flag: "--j", kind: "json" as const, help: "", jsonType: "object" as const },
        { name: "p", flag: "--p", kind: "path" as const, help: "" },
      ],
    };
    const r = buildOptions(wf, { l: "a\nb", n: "1, 2 3", j: '{"rules":[]}', p: "/opt/x" });
    expect(r.options).toEqual({ l: ["a", "b"], n: [1, 2, 3], j: '{"rules":[]}', p: "/opt/x" });
    const bad = buildOptions(wf, { l: "a\nb\nc", n: "20", j: "[1]", p: "rel" });
    expect(Object.keys(bad.errors).sort()).toEqual(["j", "l", "n", "p"]);
  });
});

describe("checkRunForm", () => {
  const base = (w = WF_STATIC): RunFormState => ({
    workflow: w,
    targets: [{ kind: "path", value: "/opt/a" }, null],
    provider: "auto",
    values: defaultOptionValues(w),
    timeoutMinutes: "30",
    label: "",
    authorized: false,
    confirmed: false,
  });

  it("needs authorization, and builds the request body", () => {
    const f = base();
    expect(checkRunForm(f, setupData()).ok).toBe(false);
    const ok = checkRunForm({ ...f, authorized: true, label: " pre-release ", values: { ...f.values, "max-heap-mb": "512" } }, setupData());
    expect(ok.request).toEqual({
      workflowId: WF_STATIC.id,
      authorized: true,
      target: { kind: "path", value: "/opt/a" },
      options: { "max-heap-mb": 512 },
      timeoutMinutes: 30,
      label: "pre-release",
    });
  });

  it("sends no target for zero-target workflows and both targets for compare-class", () => {
    const zero = checkRunForm({ ...base(WF_ZERO), targets: [null, null], authorized: true }, setupData());
    expect(zero.request).toEqual({ workflowId: WF_ZERO.id, authorized: true, timeoutMinutes: 30 });
    const two = base(WF_TWO);
    expect(checkRunForm({ ...two, authorized: true }, setupData()).blockers.join(" ")).toMatch(/second target/);
    const t2 = checkRunForm({ ...two, authorized: true, targets: [{ kind: "path", value: "/a" }, { kind: "upload", uploadId: "up-20261012-000000-abcdef" }] }, setupData());
    expect(t2.request).toMatchObject({ target: { kind: "path", value: "/a" }, target2: { kind: "upload", uploadId: "up-20261012-000000-abcdef" } });
  });

  it("gates executes-target workflows on the separate confirmation and sends confirmExecute", () => {
    const f = { ...base(WF_EXEC), authorized: true };
    expect(checkRunForm(f, setupData()).ok).toBe(false);
    const ok = checkRunForm({ ...f, confirmed: true }, setupData());
    expect(ok.request?.confirmExecute).toBe(true);
  });

  it("blocks device-mutating workflows while device writes are off", () => {
    const f = { ...base(WF_DEVICE), targets: [null, null] as RunFormState["targets"], authorized: true, confirmed: true };
    expect(checkRunForm(f, setupData({ deviceWritesEnabled: false })).blockers.join(" ")).toMatch(/REA_ENABLE_DEVICE_WRITES/);
    expect(checkRunForm(f, setupData({ deviceWritesEnabled: true })).ok).toBe(true);
  });

  it("sends the provider only for workflows that use one", () => {
    const f = { ...base(WF_NATIVE), authorized: true, provider: "ghidra", values: { ...defaultOptionValues(WF_NATIVE), procedure: "main", name: "x" } };
    expect(checkRunForm(f, setupData()).request?.provider).toBe("ghidra");
    expect(checkRunForm({ ...base(), authorized: true, provider: "ghidra" }, setupData()).request?.provider).toBeUndefined();
  });

  it("limits the time to the server maximum", () => {
    const f = { ...base(), authorized: true, timeoutMinutes: "999" };
    expect(checkRunForm(f, setupData()).timeoutError).toMatch(/1 and 240/);
  });
});

describe("workflowAvailability", () => {
  it("names missing engines and providers", () => {
    const st = statusData({ engines: [{ id: "ghidra", label: "Ghidra", found: false, unlocks: "" }, { id: "apktool", label: "Apktool", found: false, unlocks: "" }] });
    expect(workflowAvailability(WF_ZERO, st)).toEqual({ ok: false, reason: "needs Apktool" });
    expect(workflowAvailability(WF_NATIVE, st)).toEqual({ ok: false, reason: "needs Ghidra, Hopper or IDA" });
    expect(workflowAvailability(WF_STATIC, st).ok).toBe(true);
    expect(workflowAvailability(WF_NATIVE, null).ok).toBe(true);
  });
});

describe("result helpers", () => {
  it("lists view sources from the summary tables and the shape", () => {
    const s = viewSources("javascript-app", [{ id: "modules", label: "Modules" }]);
    expect(s).toEqual([{ id: "modules", label: "Modules", param: "collection" }]);
    expect(viewSources("layout", undefined).map((x) => `${x.param}:${x.id}`)).toEqual(["collection:sections", "collection:symbols", "facet:mitigations", "facet:linkage"]);
    expect(viewSources("generic", undefined)).toEqual([]);
  });

  it("offers only sources the server accepts, never a table id with dots or an unknown collection", () => {
    const tables = [
      { id: "modules", label: "Modules and assets" },
      { id: "nested.items", label: "nested items" },
      { id: "findings", label: "findings" },
    ];
    expect(viewSources("javascript-app", tables)).toEqual([{ id: "modules", label: "Modules and assets", param: "collection" }]);
    expect(viewSources("generic", tables)).toEqual([]);
    const native = viewSources("native-function", [{ id: "procedure", label: "Procedure" }, { id: "procedure", label: "dup" }]);
    expect(native[0]).toMatchObject({ id: "procedure", param: "facet" });
    expect(native.every((x) => x.param === "facet")).toBe(true);
    expect(native.filter((x) => x.id === "procedure")).toHaveLength(1);
    expect(native.some((x) => x.id.includes("."))).toBe(false);
  });

  it("finds the page of rows in a view", () => {
    expect(findRows({ view: { items: [{ a: 1 }, { a: 2 }], other: [{ b: 1 }] } })?.length).toBe(2);
    expect(findRows({ nothing: 1 })).toBeNull();
  });

  it("stringifies hostile values as plain text and rebuilds targets from a display string", () => {
    expect(plain("<img src=x onerror=alert(1)>")).toBe("<img src=x onerror=alert(1)>");
    expect(targetFromDisplay({ kind: "upload", display: "upload up-20261012-000000-abcdef/app/a.js" })).toEqual({
      kind: "upload",
      uploadId: "up-20261012-000000-abcdef",
      relPath: "app/a.js",
    });
    expect(targetFromDisplay({ kind: "path", display: "/opt/x" })).toEqual({ kind: "path", value: "/opt/x" });
    expect(targetFromDisplay({ kind: "path", display: "bad" })).toBeNull();
  });

  it("explains installer exit codes", () => {
    expect(installExitExplanation(127)).toMatch(/Node\.js or npm is missing/);
    expect(installExitExplanation(3)).toMatch(/npm could not install/);
    expect(installExitExplanation(4)).toMatch(/smoke test/);
    expect(installExitExplanation(1)).toBeNull();
  });
});

describe("option validation mirrors the server", () => {
  const base = { kind: "string" as const };
  it("checks each list entry (pattern, length, leading dash, dot segments)", () => {
    const list = { kind: "list" as const, pattern: "^[a-z/]+$", maxLength: 5, noDotDot: true };
    expect(optionProblem(list, "ab\ncd")).toBeNull();
    expect(optionProblem(list, "ab\nABC")).toMatch(/shape/);
    expect(optionProblem(list, "abcdefg")).toMatch(/At most 5/);
    expect(optionProblem({ kind: "list", noDotDot: true }, "x/../y")).toMatch(/\.\./);
  });
  it("refuses a leading - on positional strings, dot segments, and long json", () => {
    expect(optionProblem({ ...base, positional: true }, "-rf")).toMatch(/start with/);
    expect(optionProblem({ ...base }, "-rf")).toBeNull();
    expect(optionProblem({ ...base, noDotDot: true }, "a/./b")).toMatch(/segments/);
    expect(optionProblem({ ...base, maxLength: 300 }, "x".repeat(301))).toMatch(/At most 300/);
    expect(optionProblem({ kind: "json", jsonType: "object", maxLength: 10 }, JSON.stringify({ a: "0123456789" }))).toMatch(/At most 10/);
    expect(optionProblem({ kind: "json", jsonType: "object" }, "{}")).toBeNull();
  });
  it("validates a path inside an upload like the server", () => {
    expect(uploadRelProblem("")).toBeNull();
    expect(uploadRelProblem("extracted/app.asar")).toBeNull();
    expect(uploadRelProblem("a b")).not.toBeNull();
    expect(uploadRelProblem("a/../b")).not.toBeNull();
    expect(uploadRelProblem("a/./b")).not.toBeNull();
    expect(uploadRelProblem(Array(17).fill("a").join("/"))).not.toBeNull();
  });
  it("disables mutatesDevice workflows with the reason when device writes are off", () => {
    expect(workflowAvailability(WF_DEVICE, statusData(), setupData({ deviceWritesEnabled: false }))).toMatchObject({ ok: false });
    expect(workflowAvailability(WF_DEVICE, statusData(), setupData({ deviceWritesEnabled: false })).reason).toMatch(/REA_ENABLE_DEVICE_WRITES/);
    expect(workflowAvailability(WF_DEVICE, statusData(), setupData({ deviceWritesEnabled: true })).ok).toBe(true);
  });
});
