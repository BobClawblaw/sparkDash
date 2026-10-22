import { useCallback, useEffect, useRef, useState } from "react";
import {
  attachReaRun,
  cancelReaWatch,
  commitReaUpload,
  createReaUpload,
  deleteReaRun,
  deleteReaUpload,
  fetchReaResult,
  fetchReaSetup,
  fetchReaSpec,
  fetchReaStatus,
  installRea,
  onReaForbidden,
  listReaRuns,
  putReaUploadFile,
  readReaInstallStream,
  readReaStream,
  refreshReaRun,
  startReaRun,
  stopReaRun,
} from "../../api/client";
import {
  ReaApiError,
  type ReaJob,
  type ReaLine,
  type ReaResultSummary,
  type ReaRun,
  type ReaRunRequest,
  type ReaSetup,
  type ReaSpec,
  type ReaStatus,
  type ReaTarget,
} from "../../api/types";
import { isLive, type PlannedUpload } from "./reaLogic";

export const POLL_MS = 1500;
const MAX_LINES = 5000;
const SETTLE_TRIES = 20;

const msg = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Merge newly read lines (by sequence number) into the buffer. */
export function mergeLines(prev: ReaLine[], next: ReaLine[], max = MAX_LINES): ReaLine[] {
  if (!next.length) return prev;
  const last = prev.length ? prev[prev.length - 1].seq : 0;
  const fresh = next.filter((l) => l.seq > last);
  if (!fresh.length) return prev;
  const merged = prev.concat(fresh);
  return merged.length > max ? merged.slice(merged.length - max) : merged;
}

// ── static data ──

export function useReaSetup() {
  const [setup, setSetup] = useState<ReaSetup | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  useEffect(() => {
    let off = false;
    fetchReaSetup()
      .then((s) => !off && (setSetup(s), setError(null)))
      .catch((e) => !off && setError(msg(e)));
    return () => {
      off = true;
    };
  }, [version]);
  const reload = useCallback(() => setVersion((v) => v + 1), []);
  // The opt-in can be switched off elsewhere while this page is open: look again when the window regains focus
  // and whenever a gated call answers 403.
  useEffect(() => {
    const onFocus = () => reload();
    window.addEventListener("focus", onFocus);
    const off = onReaForbidden(reload);
    return () => {
      window.removeEventListener("focus", onFocus);
      off();
    };
  }, [reload]);
  return { setup, error, reload };
}

export function useReaSpec() {
  const [spec, setSpec] = useState<ReaSpec | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    let off = false;
    fetchReaSpec()
      .then((s) => !off && (setSpec(s), setError(null)))
      .catch((e) => !off && setError(msg(e)));
    return () => {
      off = true;
    };
  }, []);
  return { spec, error };
}

/** The unit's readiness. Nothing is fetched while `active` is false (the opt-in is off: the routes answer 403). */
export function useReaStatus(sparkId: string, active: boolean) {
  const [status, setStatus] = useState<ReaStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const reqRef = useRef(0);
  const reload = useCallback(async () => {
    const id = ++reqRef.current;
    setLoading(true);
    try {
      const s = await fetchReaStatus(sparkId);
      if (id === reqRef.current) {
        setStatus(s);
        setError(null);
      }
    } catch (e) {
      if (id === reqRef.current) setError(msg(e));
    } finally {
      if (id === reqRef.current) setLoading(false);
    }
  }, [sparkId]);
  useEffect(() => {
    if (!active) return;
    void reload();
    return () => {
      reqRef.current += 1;
    };
  }, [reload, active]);
  return { status, error, loading, reload };
}

// ── install ──

export interface InstallError {
  message: string;
  status: number | null;
}
const toInstallError = (e: unknown): InstallError => ({ message: msg(e), status: e instanceof ReaApiError ? e.status : null });

export function useReaInstall(sparkId: string, active: boolean, onDone: () => void) {
  const [job, setJob] = useState<ReaJob | null>(null);
  const [lines, setLines] = useState<ReaLine[]>([]);
  const [partial, setPartial] = useState("");
  const [error, setError] = useState<InstallError | null>(null);
  const [starting, setStarting] = useState(false);
  const sinceRef = useRef(0);
  const followedRef = useRef(false);
  const doneRef = useRef(onDone);
  doneRef.current = onDone;
  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);
  const running = job?.status === "running";
  const jobId = job?.id ?? null;

  const follow = useCallback((j: ReaJob, initial: ReaLine[] = [], next = 0) => {
    followedRef.current = true;
    sinceRef.current = next;
    setLines(initial);
    setPartial("");
    setError(null);
    setJob(j);
  }, []);

  // Pick up an install that is already running on the unit.
  useEffect(() => {
    if (!active) return;
    let off = false;
    readReaInstallStream(sparkId, 0)
      .then((r) => {
        if (off || followedRef.current || !r || r.job.status !== "running") return;
        follow(r.job, r.lines, r.nextLine);
        setPartial(r.partial ?? "");
      })
      .catch(() => {
        /* nothing to pick up */
      });
    return () => {
      off = true;
    };
  }, [sparkId, active, follow]);

  useEffect(() => {
    if (!running || !jobId) return;
    let off = false;
    let timer: number | undefined;
    const tick = async () => {
      try {
        const r = await readReaInstallStream(sparkId, sinceRef.current);
        if (off) return;
        if (!r) {
          setJob((p) => (p ? { ...p, status: "detached", error: "The dashboard no longer has this install job (it may have restarted). Check the unit again." } : p));
          doneRef.current();
          return;
        }
        sinceRef.current = Math.max(sinceRef.current, r.nextLine);
        setLines((p) => mergeLines(p, r.lines));
        setPartial(r.partial ?? "");
        setJob(r.job);
        setError(null);
        if (r.job.status !== "running") {
          doneRef.current();
          return;
        }
      } catch (e) {
        if (off) return;
        setError(toInstallError(e));
      }
      timer = window.setTimeout(tick, 1000);
    };
    timer = window.setTimeout(tick, 1000);
    return () => {
      off = true;
      window.clearTimeout(timer);
    };
  }, [sparkId, running, jobId]);

  const start = useCallback(async (): Promise<boolean> => {
    setError(null);
    setStarting(true);
    try {
      const r = await installRea(sparkId);
      if (!mountedRef.current) return true;
      follow(r.job);
      return true;
    } catch (e) {
      if (mountedRef.current) setError(toInstallError(e));
      return false;
    } finally {
      if (mountedRef.current) setStarting(false);
    }
  }, [sparkId, follow]);

  return { job, lines, partial, error, starting, running, start };
}

export type InstallState = ReturnType<typeof useReaInstall>;

// ── runs ──

export interface Followed {
  run: ReaRun;
  job: ReaJob | null;
  lines: ReaLine[];
  partial: string;
  stage: string | null;
  noLive: boolean;
}

export function useReaRunner(sparkId: string, active: boolean, onSettled: (run: ReaRun) => void) {
  const [runs, setRuns] = useState<ReaRun[] | null>(null);
  const [listError, setListError] = useState<string | null>(null);
  const [followed, setFollowed] = useState<Followed | null>(null);
  const [polling, setPolling] = useState(false);
  const [pollError, setPollError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [startError, setStartError] = useState<string | null>(null);
  const lineRef = useRef(0);
  const settledRef = useRef(onSettled);
  settledRef.current = onSettled;
  const followId = followed?.run.id ?? null;

  const reloadRuns = useCallback(async () => {
    try {
      const r = await listReaRuns(sparkId);
      setRuns(r.runs);
      setListError(null);
      return r;
    } catch (e) {
      setListError(msg(e));
      return null;
    }
  }, [sparkId]);

  const follow = useCallback((run: ReaRun) => {
    lineRef.current = 0;
    setPollError(null);
    setFollowed({ run, job: null, lines: [], partial: "", stage: null, noLive: false });
    setPolling(true);
  }, []);

  // First load: history, and pick up whatever is running on this unit.
  useEffect(() => {
    if (!active) return;
    let off = false;
    void (async () => {
      const r = await reloadRuns();
      if (off || !r) return;
      if (r.active) {
        const run = r.runs.find((x) => x.id === r.active?.id);
        if (run) follow(run);
        return;
      }
      const stale = r.runs.find(isLive);
      if (!stale) return;
      try {
        const fresh = await refreshReaRun(sparkId, stale.id);
        if (off) return;
        if (fresh.state.state === "running") {
          await attachReaRun(sparkId, stale.id);
          if (!off) follow(fresh.run ?? stale);
        } else {
          await reloadRuns();
        }
      } catch {
        /* the run stays listed with Check status / Watch actions */
      }
    })();
    return () => {
      off = true;
    };
  }, [sparkId, active, reloadRuns, follow]);

  useEffect(() => {
    if (!followId || !polling) return;
    let off = false;
    let timer: number | undefined;
    let settleTries = 0;
    let fails = 0;
    const finish = (run: ReaRun | null) => {
      setPolling(false);
      void reloadRuns();
      if (run) settledRef.current(run);
    };
    const tick = async () => {
      let next = POLL_MS;
      try {
        const read = await readReaStream(sparkId, followId, lineRef.current);
        if (off) return;
        fails = 0;
        setPollError(null);
        const live = read.live;
        if (live) lineRef.current = Math.max(lineRef.current, live.nextLine);
        setFollowed((p) =>
          p && p.run.id === followId
            ? {
                run: read.run ?? p.run,
                job: live?.job ?? p.job,
                lines: live ? mergeLines(p.lines, live.lines) : p.lines,
                partial: live?.partial ?? "",
                stage: live?.progress?.stage ?? live?.job.stage ?? p.stage,
                noLive: !live,
              }
            : p
        );
        if (!live) {
          if (read.run && isLive(read.run)) setPolling(false);
          else finish(read.run);
          return;
        }
        if (live.job.status !== "running") {
          settleTries += 1;
          const settled = read.run && !isLive(read.run) && (read.run.status !== "completed" || read.run.resultCached || settleTries > 6);
          if (settled || live.job.status === "cancelled" || live.job.status === "detached" || settleTries > SETTLE_TRIES) {
            return finish(read.run);
          }
        }
      } catch (e) {
        if (off) return;
        fails += 1;
        setPollError(msg(e));
        if (e instanceof ReaApiError && e.status === 404) return setPolling(false);
        next = Math.min(6000, POLL_MS * (fails + 1));
      }
      timer = window.setTimeout(tick, next);
    };
    timer = window.setTimeout(tick, 150);
    return () => {
      off = true;
      window.clearTimeout(timer);
    };
  }, [sparkId, followId, polling, reloadRuns]);

  const attempt = useCallback(async (fn: () => Promise<unknown>) => {
    setActionError(null);
    try {
      await fn();
      return true;
    } catch (e) {
      setActionError(msg(e));
      return false;
    }
  }, []);

  const start = useCallback(
    async (req: ReaRunRequest): Promise<boolean> => {
      setActionError(null);
      setStartError(null);
      try {
        const r = await startReaRun(sparkId, req);
        follow(r.run);
        void reloadRuns();
        return true;
      } catch (e) {
        setStartError(msg(e));
        if (e instanceof ReaApiError && e.status === 409) void reloadRuns();
        return false;
      }
    },
    [sparkId, follow, reloadRuns]
  );

  const stop = useCallback((r: ReaRun) => attempt(() => stopReaRun(sparkId, r.id)), [sparkId, attempt]);

  const stopWatching = useCallback(async () => {
    const ok = await attempt(() => cancelReaWatch(sparkId));
    if (ok) {
      setPolling(false);
      await reloadRuns();
    }
  }, [sparkId, attempt, reloadRuns]);

  const attach = useCallback(
    async (r: ReaRun) => {
      const ok = await attempt(() => attachReaRun(sparkId, r.id));
      if (ok) follow(r);
      return ok;
    },
    [sparkId, attempt, follow]
  );

  const refresh = useCallback(
    async (r: ReaRun): Promise<ReaRun | null> => {
      let fresh: ReaRun | null = null;
      const ok = await attempt(async () => {
        fresh = (await refreshReaRun(sparkId, r.id)).run;
      });
      await reloadRuns();
      if (ok && fresh) {
        const next: ReaRun = fresh;
        setFollowed((p) => (p?.run.id === r.id ? { ...p, run: next } : p));
      }
      return ok ? fresh : null;
    },
    [sparkId, attempt, reloadRuns]
  );

  const remove = useCallback(
    async (r: ReaRun, force = false): Promise<{ ok: boolean; canForce: boolean }> => {
      setActionError(null);
      try {
        await deleteReaRun(sparkId, r.id, force);
        setFollowed((p) => (p?.run.id === r.id ? null : p));
        await reloadRuns();
        return { ok: true, canForce: false };
      } catch (e) {
        setActionError(msg(e));
        return { ok: false, canForce: e instanceof ReaApiError && e.canForce };
      }
    },
    [sparkId, reloadRuns]
  );

  return {
    runs,
    listError,
    followed,
    polling,
    pollError,
    actionError,
    startError,
    reloadRuns,
    follow,
    unfollow: () => setFollowed(null),
    start,
    stop,
    stopWatching,
    attach,
    refresh,
    remove,
    clearStartError: () => setStartError(null),
    clearActionError: () => setActionError(null),
  };
}

// ── one run's result ──

export interface ResultState {
  loading: boolean;
  error: string | null;
  run: ReaRun | null;
  summary: ReaResultSummary | null;
}

export function useReaResult(sparkId: string, runId: string | null, version = 0): ResultState {
  const [state, setState] = useState<ResultState & { forId: string | null }>({ loading: false, error: null, run: null, summary: null, forId: null });
  useEffect(() => {
    if (!runId) {
      setState({ loading: false, error: null, run: null, summary: null, forId: null });
      return;
    }
    let off = false;
    setState({ loading: true, error: null, run: null, summary: null, forId: runId });
    fetchReaResult(sparkId, runId)
      .then((r) => !off && setState({ loading: false, error: null, run: r.run, summary: r.summary, forId: runId }))
      .catch((e) => !off && setState({ loading: false, error: msg(e), run: null, summary: null, forId: runId }));
    return () => {
      off = true;
    };
  }, [sparkId, runId, version]);
  if (!runId || state.forId === runId) return state;
  return { loading: true, error: null, run: null, summary: null };
}

// ── uploads ──

export type UploadPhase = "idle" | "uploading" | "committing" | "done" | "error";

export interface UploadFileState {
  relPath: string;
  size: number;
  loaded: number;
  status: "queued" | "uploading" | "done" | "error";
  error?: string;
}

export interface UploadResult {
  uploadId: string;
  root: string;
  files: number;
  bytes: number;
  extracted: boolean;
  /** Set when exactly one plain file went up: the run should target that file inside the upload. */
  relPath: string | null;
}

const CONCURRENCY = 2;
/** Waits between the retries of one file's PUT (so up to 4 attempts). */
export const UPLOAD_RETRY_MS = [1000, 2000, 4000];

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    const t = setTimeout(done, ms);
    function done() {
      clearTimeout(t);
      signal.removeEventListener("abort", done);
      resolve();
    }
    signal.addEventListener("abort", done, { once: true });
  });

/** Rate limited (429) or no answer (status 0, not cancelled): worth another try. Everything else is fatal. */
export function isRetryableUploadError(e: unknown, signal?: AbortSignal): boolean {
  if (signal?.aborted) return false;
  return e instanceof ReaApiError && (e.status === 429 || e.status === 0);
}

/** Run one PUT with backoff on 429 / network failures. */
export async function withUploadRetry<T>(fn: (attempt: number) => Promise<T>, signal: AbortSignal, waits: readonly number[] = UPLOAD_RETRY_MS): Promise<T> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await fn(attempt);
    } catch (e) {
      if (attempt >= waits.length || !isRetryableUploadError(e, signal)) throw e;
      await sleep(waits[attempt], signal);
      if (signal.aborted) throw e;
    }
  }
}

/** Upload a planned selection: create, PUT each file (2 at a time), commit. Cancel aborts and deletes the upload. */
export function useReaUpload(sparkId: string) {
  const [phase, setPhase] = useState<UploadPhase>("idle");
  const [files, setFiles] = useState<UploadFileState[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<UploadResult | null>(null);
  const abortRef = useRef<AbortController | null>(null);
  const uploadIdRef = useRef<string | null>(null);
  const mountedRef = useRef(true);

  const cleanup = useCallback(
    (id: string | null) => {
      if (id) void deleteReaUpload(sparkId, id).catch(() => undefined);
    },
    [sparkId]
  );

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      // Leaving mid-upload: stop the transfers and drop the half-written upload.
      if (abortRef.current) {
        abortRef.current.abort();
        cleanup(uploadIdRef.current);
      }
    };
  }, [cleanup]);

  const reset = useCallback(() => {
    setPhase("idle");
    setFiles([]);
    setError(null);
    setResult(null);
    abortRef.current = null;
    uploadIdRef.current = null;
  }, []);

  const start = useCallback(
    async (entries: readonly PlannedUpload[]): Promise<UploadResult | null> => {
      if (abortRef.current) return null;
      const ctl = new AbortController();
      abortRef.current = ctl;
      uploadIdRef.current = null;
      setError(null);
      setResult(null);
      setPhase("uploading");
      setFiles(entries.map((e) => ({ relPath: e.relPath, size: e.size, loaded: 0, status: "queued" })));
      const patch = (i: number, p: Partial<UploadFileState>) => {
        if (mountedRef.current) setFiles((prev) => prev.map((f, j) => (j === i ? { ...f, ...p } : f)));
      };
      let failure: string | null = null;
      try {
        const created = await createReaUpload(sparkId);
        uploadIdRef.current = created.uploadId;
        let next = 0;
        const worker = async () => {
          while (!ctl.signal.aborted && failure === null) {
            const i = next++;
            if (i >= entries.length) return;
            const e = entries[i];
            patch(i, { status: "uploading" });
            try {
              await withUploadRetry((attempt) => {
                if (attempt > 0) patch(i, { loaded: 0 });
                return putReaUploadFile(sparkId, created.uploadId, e.relPath, e.file, {
                  archive: e.archive,
                  signal: ctl.signal,
                  onProgress: (loaded) => patch(i, { loaded }),
                });
              }, ctl.signal);
              patch(i, { status: "done", loaded: e.size });
            } catch (err) {
              if (ctl.signal.aborted && failure === null) return; // the user cancelled
              const m = msg(err);
              patch(i, { status: "error", error: m });
              if (failure === null) failure = `${e.relPath}: ${m}`;
              ctl.abort();
              return;
            }
          }
        };
        await Promise.all(Array.from({ length: Math.min(CONCURRENCY, entries.length) }, worker));
        if (ctl.signal.aborted && failure === null) throw new Error("Upload cancelled");
        if (failure !== null) throw new Error(failure);
        if (mountedRef.current) setPhase("committing");
        const c = await commitReaUpload(sparkId, created.uploadId);
        const single = entries.length === 1 && !entries[0].archive ? entries[0].relPath : null;
        const res: UploadResult = { uploadId: c.uploadId, root: c.root, files: c.files, bytes: c.bytes, extracted: c.extracted, relPath: single };
        abortRef.current = null;
        if (mountedRef.current) {
          setResult(res);
          setPhase("done");
        }
        return res;
      } catch (e) {
        const wasCancel = ctl.signal.aborted && failure === null;
        cleanup(uploadIdRef.current);
        abortRef.current = null;
        uploadIdRef.current = null;
        if (mountedRef.current) {
          if (wasCancel) reset();
          else {
            setError(msg(e));
            setPhase("error");
          }
        }
        return null;
      }
    },
    [sparkId, cleanup, reset]
  );

  const cancel = useCallback(() => {
    abortRef.current?.abort();
  }, []);

  return { phase, files, error, result, start, cancel, reset };
}

export function uploadTargetOf(r: UploadResult, extraRel: string): ReaTarget {
  const rel = extraRel.trim() || r.relPath || "";
  return rel ? { kind: "upload", uploadId: r.uploadId, relPath: rel } : { kind: "upload", uploadId: r.uploadId };
}
