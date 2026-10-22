import { useId, useMemo, useState, type FormEvent } from "react";
import type { VulnHuntScanRequest } from "../../api/types";
import { Panel } from "../ui/Panel";
import { ShieldIcon } from "../ui/icons";
import { Notice } from "./parts";
import { FALLBACK_LIMITS, SOURCE_PLACEHOLDER, checkScanForm, initialForm, type ScanFormState, type ScanLimits } from "./securityLogic";

interface ScanFormProps {
  unitName: string;
  limits?: ScanLimits;
  /** Why the form cannot be used right now (setup missing, a scan running…); null when it can. */
  disabledReason?: string | null;
  /** Message from the server for the last attempt (400 / 409). */
  error?: string | null;
  /** Resolves true when the scan was accepted. */
  onStart: (request: VulnHuntScanRequest) => Promise<boolean>;
  onDismissError?: () => void;
}

/** Start a scan: what to scan, the two explicit confirmations, and a few options. */
export function ScanForm({ unitName, limits = FALLBACK_LIMITS, disabledReason = null, error = null, onStart, onDismissError }: ScanFormProps) {
  const [form, setForm] = useState<ScanFormState>(() => initialForm(limits));
  const [starting, setStarting] = useState(false);
  const uid = useId();
  const check = useMemo(() => checkScanForm(form, limits), [form, limits]);
  const locked = disabledReason != null || starting;
  const patch = (p: Partial<ScanFormState>) => {
    onDismissError?.();
    setForm((f) => ({ ...f, ...p }));
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!check.request || locked) return;
    setStarting(true);
    let ok = false;
    try {
      ok = await onStart(check.request);
    } finally {
      setStarting(false);
    }
    // Every scan is attested anew.
    if (ok) setForm((f) => ({ ...f, authorized: false, confirmExecute: false }));
  };

  const sourceId = `${uid}-source`;
  const hintId = `${uid}-hint`;
  const showHint = form.value.trim() !== "" && check.sourceHint != null;

  return (
    <Panel title="New scan" icon={<ShieldIcon className="h-4 w-4" />}>
      <form className="sec-form" onSubmit={submit} aria-label="New security scan">
        {disabledReason ? <Notice tone="info">{disabledReason}</Notice> : null}
        <fieldset className="sec-fieldset" disabled={locked}>
          <div className="sec-field">
            <span className="sec-label" id={`${uid}-src-label`}>
              What to scan
            </span>
            <div className="seg sec-seg" role="group" aria-labelledby={`${uid}-src-label`}>
              <button type="button" aria-pressed={form.sourceType === "url"} onClick={() => patch({ sourceType: "url" })}>
                Git URL
              </button>
              <button type="button" aria-pressed={form.sourceType === "path"} onClick={() => patch({ sourceType: "path" })}>
                Path on the unit
              </button>
            </div>
            <input
              id={sourceId}
              type="text"
              className="sec-mono"
              value={form.value}
              placeholder={SOURCE_PLACEHOLDER[form.sourceType]}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              aria-label={form.sourceType === "url" ? "Repository URL" : `Path on ${unitName}`}
              aria-describedby={showHint ? hintId : undefined}
              aria-invalid={showHint || undefined}
              onChange={(e) => patch({ value: e.target.value })}
            />
            {showHint ? (
              <p className="sec-hint is-warn" id={hintId}>
                {check.sourceHint}
              </p>
            ) : (
              <p className="sec-hint">
                {form.sourceType === "url"
                  ? `The unit clones it over https, then scans the checkout.`
                  : `A checkout that already exists on ${unitName}, under the user's home directory.`}
              </p>
            )}
          </div>

          <div className="sec-row">
            <div className="sec-field">
              <label className="sec-label" htmlFor={`${uid}-label`}>
                Label <span className="sec-faint">(optional)</span>
              </label>
              <input
                id={`${uid}-label`}
                type="text"
                value={form.label}
                maxLength={120}
                placeholder="e.g. pre-release audit"
                onChange={(e) => patch({ label: e.target.value })}
              />
            </div>
            <div className="sec-field sec-field--narrow">
              <label className="sec-label" htmlFor={`${uid}-timeout`}>
                Time limit (minutes, whole scan)
              </label>
              <input
                id={`${uid}-timeout`}
                type="number"
                inputMode="numeric"
                min={limits.minTimeoutMinutes}
                max={limits.maxTimeoutMinutes}
                step={1}
                value={form.timeoutMinutes}
                aria-invalid={check.timeoutError ? true : undefined}
                onChange={(e) => patch({ timeoutMinutes: e.target.value })}
              />
              {check.timeoutError ? <p className="sec-hint is-warn">{check.timeoutError}</p> : null}
            </div>
          </div>

          <label className="sec-check-field">
            <input
              type="checkbox"
              checked={form.readOnly}
              onChange={(e) => patch({ readOnly: e.target.checked, confirmExecute: e.target.checked ? false : form.confirmExecute })}
            />
            <span>
              <b>Read-only scan (asks the harness not to run code)</b>
              <small>
                The prompt tells the agent to read the source and report, and not to install dependencies or execute anything. It is an
                instruction to your harness, not a sandbox: use a harness or container that confines the agent if you need a guarantee.
              </small>
            </span>
          </label>

          {!form.readOnly ? (
            <div className="sec-danger" role="group" aria-label="Code execution">
              <label className="sec-check-field">
                <input type="checkbox" checked={form.confirmExecute} onChange={(e) => patch({ confirmExecute: e.target.checked })} />
                <span>
                  <b>Allow the scan to execute code on this unit (dependencies, exploit tests)</b>
                  <small>
                    The scanned project&apos;s dependencies may be installed and its code run as the user the dashboard connects with on{" "}
                    {unitName}. Only do this for code you trust enough to run there.
                  </small>
                </span>
              </label>
            </div>
          ) : null}

          <label className="sec-check-field">
            <input type="checkbox" checked={form.authorized} onChange={(e) => patch({ authorized: e.target.checked })} />
            <span>
              <b>I am authorized to scan this code</b>
              <small>VulnHunter performs dual-use security work. Scan only code you own or are authorized to audit.</small>
            </span>
          </label>
        </fieldset>

        {error ? (
          <Notice tone="bad" title="The scan was not started">
            {error}
          </Notice>
        ) : null}

        <div className="sec-actions">
          <button type="submit" className="btn btn--primary" disabled={!check.ok || locked}>
            {starting ? "Starting…" : `Start scan on ${unitName}`}
          </button>
          {!check.ok && !disabledReason ? (
            <span className="sec-hint" role="status">
              {check.blockers[0]}
            </span>
          ) : null}
        </div>
      </form>
    </Panel>
  );
}
