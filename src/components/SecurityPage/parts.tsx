import type { ReactNode } from "react";
import { AlertTriangleIcon, InfoIcon } from "../ui/icons";
import { CopyButton } from "../bench/tooleval/parts";

export { CopyButton };

/** Inline notice. `bad` is announced as an alert, the rest as a status. */
export function Notice({
  tone = "info",
  title,
  children,
  actions,
}: {
  tone?: "info" | "warn" | "bad";
  title?: string;
  children?: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className={`sec-notice sec-notice--${tone}`} role={tone === "bad" ? "alert" : "status"}>
      {tone === "info" ? <InfoIcon className="sec-notice__icon" /> : <AlertTriangleIcon className="sec-notice__icon" />}
      <div className="sec-notice__body">
        {title ? <b>{title}</b> : null}
        {children ? <div>{children}</div> : null}
      </div>
      {actions ? <div className="sec-notice__actions">{actions}</div> : null}
    </div>
  );
}

/** A shell command to copy: monospace block with a Copy button. */
export function CommandBlock({ label, command }: { label?: string; command: string }) {
  return (
    <div className="sec-cmd">
      <div className="sec-cmd__head">
        <span className="eyebrow">{label ?? "Command"}</span>
        <CopyButton text={command} />
      </div>
      <pre className="sec-cmd__body">{command}</pre>
    </div>
  );
}

export function fmtWhen(ms: number | null | undefined): string {
  if (!ms) return "–";
  return new Date(ms).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
