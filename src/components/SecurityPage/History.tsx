import { useState } from "react";
import type { VulnHuntRun } from "../../api/types";
import { formatDuration } from "../../shared/formatDuration";
import { ListIcon, RotateIcon } from "../ui/icons";
import { Panel } from "../ui/Panel";
import { Tag } from "../ui/Tag";
import { Notice, fmtWhen } from "./parts";
import { SEVERITY_ORDER, isLive, runTitle, severityTone, statusLabel, statusTone } from "./securityLogic";

interface HistoryProps {
  runs: VulnHuntRun[] | null;
  error: string | null;
  followedId: string | null;
  viewedId: string | null;
  onReload: () => void;
  onOpen: (run: VulnHuntRun) => void;
  onWatch: (run: VulnHuntRun) => void;
  onRefresh: (run: VulnHuntRun) => void;
  /** Resolves with `canForce` when the server could not confirm the scan had ended. */
  onDelete: (run: VulnHuntRun, force: boolean) => Promise<{ ok: boolean; canForce: boolean }>;
}

const COUNT_KEYS = SEVERITY_ORDER.filter((s) => s !== "Informational");

/** Scans of this unit, newest first, with their severity counts and the row actions. */
export function History({ runs, error, followedId, viewedId, onReload, onOpen, onWatch, onRefresh, onDelete }: HistoryProps) {
  const [confirm, setConfirm] = useState<{ id: string; force: boolean } | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const remove = async (run: VulnHuntRun, force: boolean) => {
    setBusyId(run.id);
    const r = await onDelete(run, force);
    setBusyId(null);
    // A 409 that offers `canForce` turns the same confirmation into a forced delete.
    setConfirm(r.ok ? null : r.canForce ? { id: run.id, force: true } : null);
  };

  return (
    <Panel
      title="Scan history"
      icon={<ListIcon className="h-4 w-4" />}
      actions={
        <button type="button" className="btn btn--sm btn--ghost" onClick={onReload}>
          <RotateIcon className="h-3.5 w-3.5" /> Reload
        </button>
      }
    >
      {error ? <Notice tone="bad">{error}</Notice> : null}
      {runs == null ? (
        error ? null : <p className="sec-muted">Loading…</p>
      ) : runs.length === 0 ? (
        <p className="sec-muted">No scans on this unit yet.</p>
      ) : (
        <ul className="sec-runs">
          {runs.map((run) => {
            const counts = run.summary?.counts;
            const hasReport = run.resultCached && run.summary?.hasReport !== false;
            const live = isLive(run);
            const confirming = confirm?.id === run.id;
            return (
              <li key={run.id} className={`sec-run${viewedId === run.id ? " is-viewed" : ""}${followedId === run.id ? " is-followed" : ""}`}>
                <div className="sec-run__main">
                  <div className="sec-run__head">
                    <Tag tone={statusTone(run.status)}>{statusLabel(run.status)}</Tag>
                    <b className="sec-run__title" title={run.source.value}>
                      {runTitle(run)}
                    </b>
                  </div>
                  <div className="sec-run__sub">
                    <span>{run.source.type === "url" ? "Git URL" : "Path"}</span>
                    {run.label ? <span className="sec-mono sec-run__src">{run.source.value}</span> : null}
                    <span>{run.readOnly ? "read-only requested" : "may execute code"}</span>
                    <span>{fmtWhen(run.startedAt)}</span>
                    {run.finishedAt ? <span>{formatDuration(run.finishedAt - run.startedAt)}</span> : null}
                  </div>
                  {counts ? (
                    <div className="sec-run__counts" aria-label="Findings by severity">
                      {COUNT_KEYS.map((s) => (
                        <Tag key={s} tone={counts[s] > 0 ? severityTone(s) : "neutral"} className={counts[s] > 0 ? "" : "sec-zero"}>
                          {counts[s]} {s}
                        </Tag>
                      ))}
                    </div>
                  ) : run.status === "failed" && run.note ? (
                    <p className="sec-run__note">{run.note}</p>
                  ) : null}
                </div>
                <div className="sec-run__actions">
                  {confirming ? (
                    <>
                      <span className="sec-confirm">{confirm.force ? "Could not confirm the scan ended. Delete anyway?" : "Delete this scan?"}</span>
                      <button type="button" className="btn btn--sm btn--danger" disabled={busyId === run.id} onClick={() => void remove(run, confirm.force)}>
                        {confirm.force ? "Delete anyway" : "Delete"}
                      </button>
                      <button type="button" className="btn btn--sm" onClick={() => setConfirm(null)}>
                        Cancel
                      </button>
                    </>
                  ) : (
                    <>
                      {hasReport ? (
                        <button type="button" className="btn btn--sm" onClick={() => onOpen(run)} aria-pressed={viewedId === run.id}>
                          Report
                        </button>
                      ) : null}
                      {live && followedId !== run.id ? (
                        <button type="button" className="btn btn--sm" onClick={() => onWatch(run)}>
                          Watch
                        </button>
                      ) : null}
                      {live ? (
                        <button type="button" className="btn btn--sm btn--ghost" onClick={() => onRefresh(run)}>
                          Check status
                        </button>
                      ) : null}
                      <button type="button" className="btn btn--sm btn--ghost" onClick={() => setConfirm({ id: run.id, force: false })}>
                        Delete
                      </button>
                    </>
                  )}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </Panel>
  );
}
