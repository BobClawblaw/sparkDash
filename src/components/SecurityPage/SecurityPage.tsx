import { useCallback, useEffect, useRef, useState } from "react";
import type { SparkSnapshot, VulnHuntRun } from "../../api/types";
import { History } from "./History";
import { LiveScan } from "./LiveScan";
import { Notice } from "./parts";
import { ReportPanel } from "./ReportView";
import { ScanForm } from "./ScanForm";
import { SetupCard } from "./SetupCard";
import { updateSettings } from "../../api/client";
import { useVulnHuntReport, useVulnHuntRunner, useVulnHuntSetup, useVulnHuntStatus } from "./hooks";
import { FALLBACK_LIMITS, isLive } from "./securityLogic";
import "../../styles/security.css";

/** Everything for one unit. Keyed by unit id, so switching units starts from a clean slate. */
function Workspace({ spark }: { spark: SparkSnapshot }) {
  const { setup, error: setupError, reload: reloadSetup } = useVulnHuntSetup();
  const [enabling, setEnabling] = useState(false);
  const [enableError, setEnableError] = useState<string | null>(null);
  const enable = useCallback(async () => {
    setEnabling(true);
    setEnableError(null);
    try {
      await updateSettings({ vulnhuntEnabled: true });
      reloadSetup();
    } catch (e) {
      setEnableError(e instanceof Error ? e.message : String(e));
    } finally {
      setEnabling(false);
    }
  }, [reloadSetup]);
  const status = useVulnHuntStatus(spark.id);
  const [viewedId, setViewedId] = useState<string | null>(null);
  const [reportVersion, setReportVersion] = useState(0);
  const reportRef = useRef<HTMLDivElement>(null);

  const onSettled = useCallback((run: VulnHuntRun) => {
    // A finished scan opens its report straight away (the server captures it on demand).
    if (run.status === "completed") {
      setViewedId(run.id);
      setReportVersion((v) => v + 1);
    }
  }, []);
  const runner = useVulnHuntRunner(spark.id, onSettled);
  const report = useVulnHuntReport(spark.id, viewedId, reportVersion);
  const viewedRun = runner.runs?.find((r) => r.id === viewedId) ?? report.run ?? null;

  // Bring a report that was just opened into view.
  useEffect(() => {
    if (viewedId) reportRef.current?.scrollIntoView?.({ block: "start", behavior: "smooth" });
  }, [viewedId]);

  const followedLive = runner.followed ? isLive(runner.followed.run) : false;
  const anyLive = followedLive || (runner.runs?.some(isLive) ?? false);
  const notReady = !status.status || !status.status.ready;
  const disabledReason = setup && !setup.startAllowed
    ? (setup.startBlockedReason ?? "Starting scans is not allowed on this dashboard.")
    : status.loading && !status.status
    ? "Checking the unit…"
    : notReady
      ? "Finish the setup above before starting a scan."
      : anyLive
        ? "A scan is already running on this unit. Wait for it to finish, or stop it."
        : null;

  const openReport = (run: VulnHuntRun) => {
    setViewedId(run.id);
  };

  return (
    <>
      {setup && !setup.enabled ? (
        <Notice
          tone="warn"
          title="VulnHunter is turned off"
          actions={
            <button type="button" className="btn btn--sm btn--primary" onClick={() => void enable()} disabled={enabling}>
              {enabling ? "Turning on…" : "Turn on VulnHunter"}
            </button>
          }
        >
          VulnHunter runs an AI agent on your units, as their SSH user, against code you point it at, and the install step and the harness command put
          things on the unit. It is opt-in and off by default. Once it is on, anyone who can reach this dashboard can use it, so set
          SPARKDASH_TOKEN if others can. You can turn it off again in Settings.
          {enableError ? ` ${enableError}` : ""}
        </Notice>
      ) : null}

      <SetupCard
        sparkId={spark.id}
        unitName={spark.name}
        setup={setup}
        setupError={setupError}
        status={status.status}
        loading={status.loading}
        error={status.error}
        onRecheck={() => void status.reload()}
      />

      <ScanForm
        unitName={spark.name}
        limits={setup?.limits ?? FALLBACK_LIMITS}
        disabledReason={disabledReason}
        error={runner.startError}
        onStart={runner.start}
        onDismissError={runner.clearStartError}
      />

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
        <LiveScan
          followed={runner.followed}
          polling={runner.polling}
          pollError={runner.pollError}
          onStop={() => runner.stop(runner.followed!.run)}
          onStopWatching={() => void runner.stopWatching()}
          onWatch={() => void runner.attach(runner.followed!.run)}
          onRefresh={() => void runner.refresh(runner.followed!.run)}
          onDismiss={runner.unfollow}
          onViewReport={openReport}
        />
      ) : null}

      {viewedId ? (
        <div ref={reportRef}>
          <ReportPanel state={report} run={viewedRun} onClose={() => setViewedId(null)} />
        </div>
      ) : null}

      <History
        runs={runner.runs}
        error={runner.listError}
        followedId={runner.followed?.run.id ?? null}
        viewedId={viewedId}
        onReload={() => void runner.reloadRuns()}
        onOpen={openReport}
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

/** The VulnHunter benchmark page body: setup, scan form, live output, history and parsed reports for one unit. */
export function VulnHuntBenchPage({ spark }: { spark: SparkSnapshot | null }) {
  if (!spark) {
    return (
      <Notice tone="info" title="No unit to scan on">
        Scans run on a Linux unit (a DGX Spark or a GPU host). Add one first.
      </Notice>
    );
  }
  if (spark.platform === "windows" || spark.platform === "darwin") {
    return (
      <Notice tone="info" title={`${spark.name} cannot run scans`}>
        VulnHunter scans run on Linux units. Pick another unit above.
      </Notice>
    );
  }
  return (
    <div className="sec">
      <Workspace key={spark.id} spark={spark} />
    </div>
  );
}
