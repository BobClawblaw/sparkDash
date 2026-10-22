import { useId, useState } from "react";
import type { VulnHuntSetup, VulnHuntStatus } from "../../api/types";
import { CheckIcon } from "../ui/icons";
import { LiveTerminal, terminalText } from "../ui/LiveTerminal";
import { Tag } from "../ui/Tag";
import type { InstallError, useVulnHuntInstall } from "./hooks";
import { CopyButton, Notice } from "./parts";
import { installBlockedReason, shortRev } from "./securityLogic";

export type InstallState = ReturnType<typeof useVulnHuntInstall>;

interface InstallStepProps {
  unitName: string;
  setup: VulnHuntSetup | null;
  setupError: string | null;
  status: VulnHuntStatus;
  install: InstallState;
}

const DEFAULT_SKILLS_DIR = "~/.claude/skills";
const LAST_LINES = 6;

function errorTitle(e: InstallError): string {
  if (e.status === 403) return "The dashboard does not allow this";
  if (e.status === 409) return "Another job is running on this unit";
  if (e.status === 400) return "The unit's installer rejected the request";
  return "The install was not started";
}

/** Step 1: what VulnHunter state the unit is in, and the install / update form with its live output. */
export function InstallStep({ unitName, setup, setupError, status, install }: InstallStepProps) {
  const uid = useId();
  const info = status.install;
  const candidates = info.skillsDirCandidates;
  const installed = status.installed;
  const outdated = installed && !info.upToDate;
  const needs = !installed || outdated;
  const pinned = setup?.pinnedRev || info.pinnedRev;

  // null = the "other path" text input is the choice.
  const [choice, setChoice] = useState<string | null>(() =>
    info.skillsDir && candidates.includes(info.skillsDir) ? info.skillsDir : (candidates[0] ?? null)
  );
  const [custom, setCustom] = useState(() => (candidates.length ? "" : (info.skillsDir ?? DEFAULT_SKILLS_DIR)));
  const [agents, setAgents] = useState("");

  const pick = choice !== null && candidates.includes(choice) ? choice : null;
  const skillsDir = (pick ?? custom).trim();
  const agentsDir = agents.trim();
  const reason = installBlockedReason({
    setup,
    setupError,
    git: status.git,
    python311: info.python311,
    skillsDir,
    agentsDir,
    running: install.running,
  });
  const verb = installed ? "Update" : "Install";
  const job = install.job;
  const lastLines = job?.status === "failed" || job?.status === "detached" || job?.status === "cancelled" ? install.lines.slice(-LAST_LINES) : [];

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (reason) return;
    void install.start(agentsDir ? { skillsDir, agentsDir } : { skillsDir });
  };

  return (
    <section className="sec-step" aria-labelledby={`${uid}-h`}>
      <h3 className="sec-step__title" id={`${uid}-h`}>
        <span className="sec-step__num">1</span> VulnHunter
      </h3>

      <p className="sec-step__status" role="status">
        {installed ? (
          <>
            <Tag tone={outdated ? "warn" : "good"}>{outdated ? "Update available" : "Installed"}</Tag>{" "}
            {info.installedRev ? (
              <>
                revision <code>{shortRev(info.installedRev)}</code>
              </>
            ) : (
              "revision unknown"
            )}
            {info.skillsDir ? (
              <>
                {" "}
                · skills in <code>{info.skillsDir}</code>
              </>
            ) : null}
            {outdated && pinned ? (
              <>
                {" "}
                · this dashboard installs <code>{shortRev(pinned)}</code>
              </>
            ) : null}
          </>
        ) : (
          <>
            <Tag tone="warn">Not installed</Tag> VulnHunter is not on {unitName} yet.
          </>
        )}
      </p>

      {needs && !install.running ? (
        <form className="sec-form" onSubmit={submit} aria-label={`${verb} VulnHunter on ${unitName}`}>
          <fieldset className="sec-fieldset" disabled={install.starting}>
            <legend className="sec-label">Skills directory (where the harness finds the vulnhunt skill)</legend>
            <div className="sec-chips">
              {candidates.map((c) => (
                <label key={c} className={`sec-chip${pick === c ? " is-on" : ""}`}>
                  <input type="radio" name={`${uid}-dir`} checked={pick === c} onChange={() => setChoice(c)} />
                  <code>{c}</code>
                </label>
              ))}
              {candidates.length ? (
                <label className={`sec-chip${pick === null ? " is-on" : ""}`}>
                  <input type="radio" name={`${uid}-dir`} checked={pick === null} onChange={() => setChoice(null)} />
                  <span>Another path</span>
                </label>
              ) : null}
            </div>
            {pick === null ? (
              <input
                type="text"
                className="sec-mono"
                value={custom}
                placeholder={DEFAULT_SKILLS_DIR}
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                aria-label="Skills directory path"
                onChange={(e) => setCustom(e.target.value)}
              />
            ) : null}

            <label className="sec-label" htmlFor={`${uid}-agents`}>
              Agents directory <span className="sec-faint">(optional)</span>
            </label>
            <input
              id={`${uid}-agents`}
              type="text"
              className="sec-mono"
              value={agents}
              placeholder="optional, e.g. ~/.claude/agents"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              onChange={(e) => setAgents(e.target.value)}
            />
          </fieldset>

          <p className="sec-hint">
            This {installed ? "replaces" : "installs"}, on {unitName} and as the user the dashboard connects with: VulnHunter revision{" "}
            <code>{shortRev(pinned) || "pinned by the dashboard"}</code> in <code>~/.local/share/sparkdash/VulnHunter</code>, the{" "}
            <code>vulnhunt</code> skill in the skills directory above, and the <code>vh</code> command in <code>~/.local/bin</code>. Nothing is
            installed on the machine running the dashboard.
          </p>

          {install.error ? (
            <Notice tone="bad" title={errorTitle(install.error)}>
              {install.error.message}
            </Notice>
          ) : null}

          <div className="sec-actions">
            <button type="submit" className="btn btn--primary" disabled={Boolean(reason) || install.starting}>
              {install.starting ? "Starting…" : `${verb} on ${unitName}`}
            </button>
            {reason ? (
              <span className="sec-hint" role="status">
                {reason}
              </span>
            ) : null}
          </div>
        </form>
      ) : null}

      {install.running && install.error ? (
        <Notice tone="warn" title="Lost contact with the install output (still trying)">
          {install.error.message}
        </Notice>
      ) : null}

      {job ? (
        <div className="sec-install-out">
          <div className="sec-install-out__head">
            <Tag tone={job.status === "running" ? "acc" : job.status === "completed" ? "good" : "bad"}>
              {job.status === "running"
                ? "Installing…"
                : job.status === "completed"
                  ? "Installed"
                  : job.status === "cancelled"
                    ? "Install cancelled"
                    : "Install failed"}
            </Tag>
            <CopyButton text={() => terminalText(install.lines, install.partial)} label="Copy output" />
          </div>
          <LiveTerminal lines={install.lines} partial={install.partial} running={job.status === "running"} emptyText="Waiting for output…" />
          {job.status === "completed" ? (
            <p className="sec-ok" role="status">
              <CheckIcon className="h-3.5 w-3.5" /> Done. Checking the unit again…
            </p>
          ) : null}
          {job.status !== "running" && job.status !== "completed" ? (
            <Notice
              tone="bad"
              title={job.exitCode != null ? `The install did not finish (exit code ${job.exitCode})` : "The install did not finish"}
              actions={
                <button
                  type="button"
                  className="btn btn--sm"
                  onClick={() => void install.start(agentsDir ? { skillsDir, agentsDir } : { skillsDir })}
                  disabled={Boolean(reason) || install.starting}
                >
                  Retry
                </button>
              }
            >
              {job.error ? <p>{job.error}</p> : null}
              {lastLines.length ? <pre className="sec-install-out__tail">{lastLines.map((l) => l.text).join("\n")}</pre> : null}
            </Notice>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
