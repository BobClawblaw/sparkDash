import { useCallback, useEffect, useRef, useState } from "react";
import { updateSettings } from "../../api/client";
import type { ReaRun, ReaWorkflowSpec, Settings, SparkSnapshot } from "../../api/types";
import { History } from "./History";
import { useReaInstall, useReaResult, useReaRunner, useReaSetup, useReaSpec, useReaStatus } from "./hooks";
import { LiveRun } from "./LiveRun";
import { Notice, ReaCredits } from "./parts";
import { isLive, reaReady, targetFromDisplay } from "./reaLogic";
import { ResultPanel } from "./ResultView";
import { RunForm, type RunPrefill } from "./RunForm";
import { SetupCard } from "./SetupCard";
import { WorkflowPicker } from "./WorkflowPicker";
import "../../styles/rea.css";

export const REA_CONSENT =
  "REA parses untrusted files and can run targets on this unit as its SSH user. Once it is on, anyone who can reach this dashboard can use it, so set SPARKDASH_TOKEN if others can. It is off by default and you can turn it off again in Settings.";

/** Everything for one unit. Keyed by unit id, so switching units starts from a clean slate. */
function Workspace({ spark, spec: specState }: { spark: SparkSnapshot; spec: ReturnType<typeof useReaSpec> }) {
  const { setup, error: setupError, reload: reloadSetup } = useReaSetup();
  const active = setup?.enabled === true;
  const [enabling, setEnabling] = useState(false);
  const [enableError, setEnableError] = useState<string | null>(null);
  const enable = useCallback(async () => {
    setEnabling(true);
    setEnableError(null);
    try {
      await updateSettings({ reaEnabled: true });
      reloadSetup();
    } catch (e) {
      setEnableError(e instanceof Error ? e.message : String(e));
    } finally {
      setEnabling(false);
    }
  }, [reloadSetup]);

  const status = useReaStatus(spark.id, active);
  const install = useReaInstall(spark.id, active, status.reload);
  const [workflow, setWorkflow] = useState<ReaWorkflowSpec | null>(null);
  const [viewedId, setViewedId] = useState<string | null>(null);
  const [resultVersion, setResultVersion] = useState(0);
  const [prefill, setPrefill] = useState<RunPrefill | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const formRef = useRef<HTMLDivElement>(null);

  const onSettled = useCallback((run: ReaRun) => {
    if (run.status === "completed") {
      setViewedId(run.id);
      setResultVersion((v) => v + 1);
    }
  }, []);
  const runner = useReaRunner(spark.id, active, onSettled);
  const result = useReaResult(spark.id, viewedId, resultVersion);
  const spec = specState.spec;
  const viewedRun = runner.runs?.find((r) => r.id === viewedId) ?? result.run ?? null;
  const viewedWorkflow = viewedRun && spec ? (spec.workflows.find((w) => w.id === viewedRun.workflowId) ?? null) : null;

  useEffect(() => {
    if (viewedId) resultRef.current?.scrollIntoView?.({ block: "start", behavior: "smooth" });
  }, [viewedId]);

  const anyLive = (runner.followed ? isLive(runner.followed.run) : false) || (runner.runs?.some(isLive) ?? false);
  const disabledReason =
    setup && !setup.enabled
      ? "REA is turned off. Turn it on above first."
      : setup && !setup.startAllowed
        ? (setup.startBlockedReason ?? "Starting runs is not allowed on this dashboard.")
        : !setup
          ? "Checking whether this dashboard allows runs…"
          : status.loading && !status.status
            ? "Checking the unit…"
            : !reaReady(status.status)
              ? "Finish the setup above before starting a run."
              : anyLive
                ? "A run is already going on this unit. Wait for it to finish, or stop it."
                : null;

  const runAgain = (run: ReaRun) => {
    const w = spec?.workflows.find((x) => x.id === run.workflowId);
    if (!w) return;
    setWorkflow(w);
    setPrefill((p) => ({
      nonce: (p?.nonce ?? 0) + 1,
      workflowId: w.id,
      label: run.label,
      provider: run.provider,
      timeoutMinutes: run.timeoutMinutes,
      targets: [targetFromDisplay(run.target), targetFromDisplay(run.target2)],
    }));
    window.setTimeout(() => formRef.current?.scrollIntoView?.({ block: "start", behavior: "smooth" }), 0);
  };

  return (
    <>
      {setup && !setup.enabled ? (
        <Notice
          tone="warn"
          title="REA is turned off"
          actions={
            <button type="button" className="btn btn--sm btn--primary" onClick={() => void enable()} disabled={enabling}>
              {enabling ? "Turning on…" : "Turn on REA"}
            </button>
          }
        >
          {REA_CONSENT}
          {enableError ? ` ${enableError}` : ""}
        </Notice>
      ) : null}

      <SetupCard
        unitName={spark.name}
        setup={setup}
        setupError={setupError}
        status={status.status}
        statusError={active ? status.error : null}
        loading={status.loading}
        install={install}
        onRecheck={() => void status.reload()}
      />

      <WorkflowPicker spec={spec} specError={specState.error} status={status.status}
        setup={setup}
        selectedId={workflow?.id ?? null}
        onSelect={(w) => {
          // A manual pick starts clean: "Run again" values are applied only for the run that asked for them.
          setPrefill(null);
          setWorkflow(w);
        }}
      />

      {workflow ? (
        <div ref={formRef}>
          <RunForm
            key={workflow.id}
            sparkId={spark.id}
            unitName={spark.name}
            workflow={workflow}
            setup={setup}
            status={status.status}
            disabledReason={disabledReason}
            error={runner.startError}
            onStart={runner.start}
            onDismissError={runner.clearStartError}
            prefill={prefill}
          />
        </div>
      ) : null}

      {runner.actionError ? (
        <Notice
          tone="bad"
          actions={
            <button type="button" className="btn btn--sm" onClick={runner.clearActionError}>
              Dismiss
            </button>
          }
        >
          {runner.actionError}
        </Notice>
      ) : null}

      {runner.followed ? (
        <LiveRun
          followed={runner.followed}
          polling={runner.polling}
          pollError={runner.pollError}
          onStop={() => runner.stop(runner.followed!.run)}
          onStopWatching={() => void runner.stopWatching()}
          onWatch={() => void runner.attach(runner.followed!.run)}
          onRefresh={() => void runner.refresh(runner.followed!.run)}
          onDismiss={runner.unfollow}
          onViewResult={(r) => {
            setViewedId(r.id);
            setResultVersion((v) => v + 1);
          }}
        />
      ) : null}

      {viewedId ? (
        <div ref={resultRef}>
          <ResultPanel sparkId={spark.id} state={result} run={viewedRun} workflow={viewedWorkflow} onClose={() => setViewedId(null)} />
        </div>
      ) : null}

      <History
        sparkId={spark.id}
        runs={runner.runs}
        error={runner.listError}
        followedId={runner.followed?.run.id ?? null}
        viewedId={viewedId}
        onReload={() => void runner.reloadRuns()}
        onOpen={(r) => setViewedId(r.id)}
        onRunAgain={runAgain}
        onWatch={(r) => void runner.attach(r)}
        onRefresh={(r) => void runner.refresh(r)}
        onDelete={async (r, force) => {
          const res = await runner.remove(r, force);
          if (res.ok && viewedId === r.id) setViewedId(null);
          return res;
        }}
      />
    </>
  );
}

/** The REA tool page body for one unit: setup, workflow picker, run form, live output, result and history. */
export function ReaToolPage({ spark }: { spark: SparkSnapshot | null; sparks: readonly SparkSnapshot[] }) {
  const specState = useReaSpec();
  const unsupported = spark != null && (spark.platform === "windows" || spark.platform === "darwin");
  return (
    <div className="rea">
      {!spark ? (
        <Notice tone="info" title="No unit to run on">
          REA runs on a Linux unit (a DGX Spark or a GPU host). Add one first.
        </Notice>
      ) : unsupported ? (
        <Notice tone="info" title={`${spark.name} cannot run REA`}>
          REA runs on Linux units. Pick another unit above.
        </Notice>
      ) : (
        <Workspace key={spark.id} spark={spark} spec={specState} />
      )}
      <ReaCredits />
    </div>
  );
}
