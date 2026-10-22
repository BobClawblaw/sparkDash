import { useId } from "react";
import type { ReaSetup, ReaStatus } from "../../api/types";
import { CheckIcon, RotateIcon, XIcon } from "../ui/icons";
import { LiveTerminal, terminalText } from "../ui/LiveTerminal";
import { Panel } from "../ui/Panel";
import { Tag } from "../ui/Tag";
import type { InstallState } from "./hooks";
import { CopyButton, Notice } from "./parts";
import { installExitExplanation, nodeWillBeInstalled, readinessProblems, reaReady } from "./reaLogic";

interface SetupCardProps {
  unitName: string;
  setup: ReaSetup | null;
  setupError: string | null;
  status: ReaStatus | null;
  statusError: string | null;
  loading: boolean;
  install: InstallState;
  onRecheck: () => void;
}

function Check({ ok, label, detail }: { ok: boolean; label: string; detail?: string | null }) {
  return (
    <li className={`rea-check ${ok ? "is-ok" : "is-bad"}`}>
      {ok ? <CheckIcon className="rea-check__icon" /> : <XIcon className="rea-check__icon" />}
      <span>
        <b>{label}</b>
        <span className="sr-only">{ok ? " ready" : " not ready"}</span>
      </span>
      {detail ? <span className="rea-check__detail">{detail}</span> : null}
    </li>
  );
}

function InstallOutput({ install }: { install: InstallState }) {
  const job = install.job;
  if (!job) return null;
  const failed = job.status !== "running" && job.status !== "completed";
  const why = failed ? installExitExplanation(job.exitCode) : null;
  const tail = failed ? install.lines.slice(-6) : [];
  return (
    <div className="rea-install-out">
      {install.running && install.error ? (
        <Notice tone="warn" title="Lost contact with the install output (still trying)">
          {install.error.message}
        </Notice>
      ) : null}
      <div className="rea-install-out__head">
        <Tag tone={job.status === "running" ? "acc" : job.status === "completed" ? "good" : "bad"}>
          {job.status === "running" ? "Installing…" : job.status === "completed" ? "Installed" : job.status === "cancelled" ? "Install cancelled" : "Install failed"}
        </Tag>
        <CopyButton text={() => terminalText(install.lines, install.partial)} label="Copy output" />
      </div>
      <LiveTerminal lines={install.lines} partial={install.partial} running={job.status === "running"} />
      {job.status === "completed" ? (
        <p className="rea-ok" role="status">
          <CheckIcon className="h-3.5 w-3.5" /> Done. Checking the unit again…
        </p>
      ) : null}
      {failed ? (
        <Notice tone="bad" title={job.exitCode != null ? `The install did not finish (exit code ${job.exitCode})` : "The install did not finish"}>
          {why ? <p>{why}</p> : null}
          {job.error ? <p>{job.error}</p> : null}
          {tail.length ? <pre className="rea-install-out__tail">{tail.map((l) => l.text).join("\n")}</pre> : null}
        </Notice>
      ) : null}
    </div>
  );
}

/** Readiness of the unit, the one-click install, the doctor checks, providers and engines. */
export function SetupCard({ unitName, setup, setupError, status, statusError, loading, install, onRecheck }: SetupCardProps) {
  const uid = useId();
  const pinned = setup?.pinnedVersion ?? status?.pinnedVersion ?? "";
  const minNode = setup?.node.min ?? "22.19";
  const ready = reaReady(status);
  const outdated = Boolean(status?.installed && !status.upToDate);
  const problems = status ? readinessProblems(status, minNode) : [];
  const gate =
    setup && !setup.enabled
      ? "REA is turned off. Turn it on above first."
      : setup && !setup.startAllowed
        ? (setup.startBlockedReason ?? "Changing a unit is not allowed on this dashboard.")
        : !setup && !setupError
          ? "Checking whether this dashboard allows changes…"
          : null;
  const reason = problems[0] ?? gate ?? (install.running ? "An install is already running on this unit." : null) ?? (!status ? "Checking the unit…" : null);
  const willInstallNode = nodeWillBeInstalled(status);
  const nodeVersion = status?.node.installVersion ?? "22";
  const verb = status?.installed ? (outdated ? "Update to" : "Reinstall") : "Install";
  const showInstall = !status || !ready || outdated;
  const canInstall = !reason && !install.starting && !install.running;

  return (
    <Panel
      title={`REA on ${unitName}`}
      actions={
        <button type="button" className="btn btn--sm btn--ghost" onClick={onRecheck} disabled={loading || install.running}>
          <RotateIcon className={`h-3.5 w-3.5${loading ? " rea-spin" : ""}`} /> Re-check
        </button>
      }
    >
      <div className="rea-stack">
        {setupError ? <Notice tone="bad" title="Could not read the REA setup">{setupError}</Notice> : null}
        {statusError ? <Notice tone="bad" title="Could not check the unit">{statusError}</Notice> : null}

        {status ? (
          <ul className="rea-checks" aria-label={`Readiness of ${unitName}`}>
            <Check ok={status.reachable} label="Unit reachable" />
            <Check
              ok={status.node.ok}
              label="Node.js"
              detail={
                status.node.ok
                  ? `${status.node.version ?? ""}${status.node.path ? ` at ${status.node.path}` : ""}`
                  : willInstallNode
                    ? `${status.node.version ? `${status.node.version} is too old; ` : "not found; "}the install will add ${nodeVersion}`
                    : status.node.version
                      ? `${status.node.version} (needs ${minNode} or newer)`
                      : `needs ${minNode} or newer`
              }
            />
            <Check ok={status.npm || willInstallNode} label="npm" detail={!status.npm && willInstallNode ? "comes with Node.js" : null} />
            <Check
              ok={status.installed && status.upToDate}
              label="REA"
              detail={status.installed ? `${status.version ?? "unknown version"}${outdated ? ` (this dashboard installs ${pinned})` : ""}` : "not installed"}
            />
          </ul>
        ) : loading ? (
          <p className="rea-muted">Checking the unit…</p>
        ) : null}

        {ready && !outdated ? (
          <p className="rea-ok" role="status">
            <CheckIcon className="h-3.5 w-3.5" /> <span><b>Ready</b> — REA {status?.version} is installed on {unitName}.</span>
          </p>
        ) : null}

        {problems.length ? (
          <ul className="rea-problems" aria-label="Problems on this unit">
            {problems.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>
        ) : null}

        {willInstallNode && showInstall ? (
          <Notice tone="info" title={`The install will also set up Node.js ${nodeVersion}`}>
            {unitName} has no Node.js {minNode}+ that sparkDash could find (it looked on the PATH, nvm, volta, fnm, asdf and <code>~/.local</code>). The install
            downloads the official Node.js {nodeVersion} build from nodejs.org, checks its SHA-256 against the value pinned in this dashboard, and unpacks it
            under <code>~/.local/share/sparkdash/node</code>. No root, no package manager, and nothing else on the unit is touched.
          </Notice>
        ) : null}

        {showInstall ? (
          <div className="rea-actions">
            <button type="button" className="btn btn--primary" disabled={!canInstall} onClick={() => void install.start()}>
              {install.starting || install.running ? "Installing…" : `${verb} REA ${pinned}`}
            </button>
            {reason && !install.running ? (
              <span className="rea-hint" role="status">
                {reason}
              </span>
            ) : null}
          </div>
        ) : null}
        <p className="rea-hint">
          One click installs the pinned REA {pinned || "release"} on {unitName} with <code>npm ci --ignore-scripts</code>, as the user the dashboard
          connects with, under <code>~/.local/share/sparkdash/rea</code>. Nothing is installed on the machine running the dashboard, and REA&apos;s own
          agent-client setup is never run.
          {status && status.python3 === false ? " python3 is not installed there, so uploading archives (zip/tar) will not work until it is." : ""}
        </p>

        {install.error && !install.running ? (
          <Notice tone="bad" title={install.error.status === 409 ? "Another job is running on this unit" : install.error.status === 403 ? "The dashboard does not allow this" : "The install was not started"}>
            {install.error.message}
          </Notice>
        ) : null}
        <InstallOutput install={install} />

        {status?.doctor ? (
          <section aria-labelledby={`${uid}-doctor`}>
            <h4 className="rea-subtitle" id={`${uid}-doctor`}>
              Doctor checks <Tag tone={status.doctor.healthy ? "good" : "warn"}>{status.doctor.healthy ? "healthy" : "needs attention"}</Tag>
            </h4>
            <ul className="rea-doctor">
              {status.doctor.checks.map((c) => (
                <li key={c.name} className={`rea-doctor__item ${c.ok ? "is-ok" : "is-bad"}`}>
                  <span className="rea-doctor__head">
                    {c.ok ? <CheckIcon className="rea-check__icon" /> : <XIcon className="rea-check__icon" />}
                    <b>{c.name}</b>
                    {c.classification ? <Tag>{c.classification}</Tag> : null}
                  </span>
                  {c.detail ? <span className="rea-check__detail">{c.detail}</span> : null}
                  {!c.ok && c.remediation ? <span className="rea-doctor__fix">Fix: {c.remediation}</span> : null}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        {status && status.providers.length ? (
          <section aria-labelledby={`${uid}-prov`}>
            <h4 className="rea-subtitle" id={`${uid}-prov`}>
              Analysis providers
            </h4>
            <ul className="rea-chips">
              {status.providers.map((p) => (
                <li key={p.id} className="rea-chip" title={p.reason ?? undefined}>
                  <Tag tone={p.available ? "good" : "neutral"}>{p.available ? "available" : "not available"}</Tag> {p.label}
                  {!p.available && p.reason ? <small className="rea-faint"> {p.reason}</small> : null}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        {status && status.engines.length ? (
          <section aria-labelledby={`${uid}-eng`}>
            <h4 className="rea-subtitle" id={`${uid}-eng`}>
              Engines and helpers found on {unitName}
            </h4>
            <ul className="rea-engines">
              {status.engines.map((e) => (
                <li key={e.id} className={`rea-engine${e.found ? " is-found" : ""}`}>
                  <span className="rea-engine__head">
                    <b>{e.label}</b>
                    <Tag tone={e.found ? "good" : "neutral"}>{e.found ? "found" : "not found"}</Tag>
                  </span>
                  <small className="rea-faint">{e.unlocks}</small>
                  {e.found && e.path ? <code className="rea-engine__path">{e.path}</code> : null}
                </li>
              ))}
            </ul>
          </section>
        ) : null}

        <Notice tone="warn" title="Not sandboxed">
          REA&apos;s native providers and file extractors are not sandboxed. They parse untrusted bytes as the unit&apos;s SSH user, and some
          workflows start analysis engines or helper programs. Use a unit you are willing to expose to the files you analyze.
        </Notice>
      </div>
    </Panel>
  );
}
