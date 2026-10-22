/**
 * Programs sparkDash runs on a unit to drive REA (rea-agents, github.com/morluto/rea).
 * Same approach as VulnHunt (vulnhunt/commands.js) and Tool Eval: each program is shipped
 * base64-encoded so no quoting layer can mangle it, and a run is DETACHED (setsid) with its
 * output in files under ~/.cache/sparkdash/rea/runs/<runId>/, so closing the browser or
 * restarting sparkDash never kills a long analysis and its output can be re-attached later.
 *
 * What sparkDash installs: a pinned `rea-agents` (npm ci --ignore-scripts from the checked-in
 * lockfile, never `-g`, never `rea setup`) under ~/.local/share/sparkdash/rea/<version>/ and a
 * launcher ~/.local/bin/rea-sparkdash. Nothing else on the unit is touched.
 *
 * Exit codes written to <run>/exit by the run wrapper (the tool's own code never stands in):
 *   0   rea finished and printed a result          2    target not usable / bad request on the unit
 *   10  rea exited non-zero or printed an error    11   result exceeded the size cap (result.json truncated)
 *   124 time limit                                 126  provider / engine / prerequisite missing
 *   127 REA, node or setsid not installed          143  stopped on request
 * Install program codes: 0 ok, 1 filesystem / payload problem, 3 npm failed, 4 smoke test failed,
 * 127 node (22.19+/24.11+/26+) or npm missing or too old.
 *
 * Output conventions of the short programs (read / view / export / compare / upload): a "section"
 * is a line consisting of the per-call sentinel immediately followed by a name (for example
 * `<S>SIZE`), and its value is on the following line(s). A BODY section is the last thing printed
 * and its bytes begin right after the newline that ends the marker line.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { exitToken } from "../tooleval/commands.js";

export { exitToken };

export const REA_PKG = "rea-agents";
export const REA_VERSION = "6.4.0";
export const INSTALL_ROOT = "$HOME/.local/share/sparkdash/rea";
export const RUN_ROOT = "$HOME/.cache/sparkdash/rea/runs";
export const UPLOAD_ROOT = "$HOME/.cache/sparkdash/rea/uploads";
export const LAUNCHER = "$HOME/.local/bin/rea-sparkdash";
export const INSTALL_RECORD = "$HOME/.config/sparkdash/rea-install";
const PATH_LINE = 'export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:$PATH"';

/**
 * Seconds the wrapper gives rea to wind down after TERM before it is killed. Overridable through
 * SPARKDASH_REA_GRACE in the environment of the program (tests use a small value), like
 * SPARKDASH_REA_LOGMAX (bytes, default 64 MiB: output.log is trimmed to a quarter of it) and
 * SPARKDASH_REA_TICK (seconds between janitor checks, default 15).
 */
export const GRACE_SECONDS = 20;

export const RUN_ID_RE = /^rea-[0-9]{8}-[0-9]{6}-[a-z0-9]{4}$/;
export const UPLOAD_ID_RE = /^up-[0-9]{8}-[0-9]{6}-[a-z0-9]{6}$/;
export const REL_PATH_RE = /^[A-Za-z0-9._-]{1,128}(\/[A-Za-z0-9._-]{1,128}){0,15}$/;
const ARCHIVE_RE = /\.(zip|tar|tar\.gz|tgz)$/i;
const RESERVED_FIRST = new Set([".committed", ".meta", ".writing", ".archive", "extracted"]);

const DEFAULT_RESULT_CAP = 256 * 1024 * 1024;
const VIEW_CAP = 4 * 1024 * 1024;

export function runDirRef(runId) {
  return `~/.cache/sparkdash/rea/runs/${runId}`;
}
export function uploadDirRef(id) {
  return `~/.cache/sparkdash/rea/uploads/${id}`;
}

function runId(v) {
  if (typeof v !== "string" || !RUN_ID_RE.test(v)) throw new Error("invalid run id");
  return v;
}
function uploadId(v) {
  if (typeof v !== "string" || !UPLOAD_ID_RE.test(v)) throw new Error("invalid upload id");
  return v;
}
function posInt(v, name, max = Number.MAX_SAFE_INTEGER) {
  if (!Number.isInteger(v) || v < 1 || v > max) throw new Error(`invalid ${name}`);
  return v;
}
function sentinelOf(s) {
  if (typeof s !== "string" || !/^[A-Za-z0-9_:.-]{8,128}$/.test(s)) throw new Error("invalid sentinel");
  return s;
}
const b64 = (v) => Buffer.from(String(v), "utf8").toString("base64");

function wrap(program) {
  return `bash -c "$(printf %s '${b64(program)}' | base64 -d)"`;
}

/** The pinned package.json + package-lock.json framed for the install program's stdin. */
export function installPayload() {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "pinned");
  const pkg = fs.readFileSync(path.join(dir, "package.json"), "utf8");
  const lock = fs.readFileSync(path.join(dir, "package-lock.json"), "utf8");
  return `PKG ${Buffer.byteLength(pkg)}\n${pkg}LOCK ${Buffer.byteLength(lock)}\n${lock}`;
}

// ── shared shell ────────────────────────────────────────────────────────────

const HELPERS = `
# A pid only counts while the run has not written its exit file and the process still looks like our
# wrapper: the run directory is in its arguments (guards against a recycled pid being mistaken for,
# or signalled as, the run). The command line is empty for an instant while setsid execs (and for good
# once the process is a zombie), and between fork and exec it is still this shell's own, so retry
# briefly and accept both. Errors from a vanished /proc entry are silenced.
ours() {
  local c i
  [ -r "/proc/$PID/cmdline" ] || return 0
  for i in 1 2 3 4 5 6; do
    c=$(tr '\\0' ' ' 2>/dev/null < "/proc/$PID/cmdline")
    [ -n "$c" ] && break
    sleep 0.1
  done
  case "$c" in *"$RD"*) return 0;; esac
  [ "$c" = "$(tr '\\0' ' ' 2>/dev/null < "/proc/$$/cmdline")" ] && return 0
  return 1
}
# A leader that is gone is gone, even if a member of its group (the watchdog) is still around: a wrapper
# that was SIGKILLed or OOM-killed must not read as running until the time limit.
alive() { [ "$PID" != 0 ] || return 1; [ -f "$X" ] && return 1; if [ -d /proc/self ]; then [ -d "/proc/$PID" ] || return 1; fi; { kill -0 "$PID" 2>/dev/null || kill -0 -- "-$PID" 2>/dev/null; } || return 1; ours; }
follow() {
  tail -n "$1" -F "$L" 2>/dev/null &
  T=$!
  while alive; do sleep 1; done
  sleep 1
  kill "$T" 2>/dev/null
  wait "$T" 2>/dev/null
}
`;

function dirs(id, create = false) {
  return `
umask 077
RD="${RUN_ROOT}/${runId(id)}"
${create ? 'mkdir -p "$RD" || exit 1' : ""}
L="$RD/output.log"; X="$RD/exit"; P="$RD/pid"
PID=$(cat "$P" 2>/dev/null || echo 0)
`;
}

/** Node 22.19+, 24.11+ or 26+ (rea-agents' engines range). `node_ok v22.19.0`. */
const NODE_OK = `
node_ok() {
  local v="\${1#v}" maj min
  maj="\${v%%.*}"; v="\${v#*.}"; min="\${v%%.*}"
  case "$maj$min" in ''|*[!0-9]*) return 1;; esac
  case "$maj" in
    22) [ "$min" -ge 19 ];;
    24) [ "$min" -ge 11 ];;
    *) [ "$maj" -ge 26 ];;
  esac
}
`;

// ── run ─────────────────────────────────────────────────────────────────────

/**
 * The detached part. Arguments: run dir, time limit (seconds, whole run), result cap (bytes), then
 * rea's own argv. It always writes <run>/exit, whatever happens, and never lets rea's exit code stand in.
 */
const INNER = `
umask 077
RD="$1"; TMO="$2"; CAP="$3"; shift 3
X="$RD/exit"; P="$RD/pid"; R="$RD/result.json"; RC=1; TERMED=""
GRACE="\${SPARKDASH_REA_GRACE:-${GRACE_SECONDS}}"
LOGMAX="\${SPARKDASH_REA_LOGMAX:-67108864}"; TICK="\${SPARKDASH_REA_TICK:-15}"
trap 'echo "$RC" > "$X"; rm -f "$P"' EXIT
# Every process of this session except this shell (rea and anything it started).
kill_rest() { local p; for p in $(ps -o pid= --sid "$$" 2>/dev/null); do [ "$p" = "$$" ] || kill -"$1" "$p" 2>/dev/null; done; }
trap 'TERMED=1; trap "" TERM INT; kill -TERM -- "-$$" 2>/dev/null' TERM INT
cd "$RD" || exit 1
rm -f "$R" "$RD/timeout" "$RD/rea.rc" "$RD/rea.pid" "$RD/output.trim" "$RD/view-req.json" "$RD/export.json"
: > "$R"

# One time limit for the whole run plus a janitor that keeps output.log bounded. GNU timeout is
# avoided on purpose: it moves its child into a new process group, which a stop request (TERM to
# this session's group) cannot reach.
INNER=$$
wrapper_alive() { kill -0 "$INNER" 2>/dev/null && tr '\\0' ' ' 2>/dev/null < "/proc/$INNER/cmdline" | grep -qF -- "$RD"; }
(
  end=$(( $(date +%s) + TMO ))
  while [ "$(date +%s)" -lt "$end" ]; do
    wrapper_alive || exit 0
    left=$(( end - $(date +%s) )); [ "$left" -gt "$TICK" ] && left="$TICK"; [ "$left" -lt 1 ] && left=1
    sleep "$left"
    SZ=$(stat -c %s "$RD/output.log" 2>/dev/null || echo 0)
    if [ "$SZ" -gt "$LOGMAX" ]; then
      if tail -c $(( LOGMAX / 4 )) "$RD/output.log" > "$RD/output.trim" 2>/dev/null; then cat "$RD/output.trim" > "$RD/output.log"; fi
      rm -f "$RD/output.trim"
      echo "[sparkdash] output trimmed to the most recent part"
    fi
  done
  wrapper_alive || exit 0
  : > "$RD/timeout"
  echo "[sparkdash] the run hit its time limit"
  kill -TERM -- "-$INNER" 2>/dev/null
) &

export NO_COLOR=1
echo "[sparkdash] stage: rea $1"
# rea runs in the background of THIS session so that a stop request and the time limit both reach it
# and everything it started. Its stdout goes through a size cap into result.json; its stderr is the log.
( "${LAUNCHER}" "$@" < /dev/null & RP=$!; echo "$RP" > "$RD/rea.pid"; wait "$RP"; echo $? > "$RD/rea.rc" ) | head -c $(( CAP + 1 )) > "$R" &
HP=$!
while :; do
  wait "$HP"
  [ -n "$TERMED" ] && break
  kill -0 "$HP" 2>/dev/null || break
done
if [ -n "$TERMED" ]; then
  # Give rea its grace period, then end whatever is left; this shell survives to settle the run.
  # The pipe's reader and its subshell end with TERM at once, so rea.rc is not written: watch rea's own pid.
  RP=$(cat "$RD/rea.pid" 2>/dev/null)
  for i in $(seq 1 "$GRACE"); do { [ -z "$RP" ] || ! kill -0 "$RP" 2>/dev/null; } && break; sleep 1; done
  kill_rest KILL
  wait "$HP" 2>/dev/null
fi

REARC=$(cat "$RD/rea.rc" 2>/dev/null)
SZ=$(stat -c %s "$R" 2>/dev/null || echo 0)
HEADTXT=$(head -c 512 "$R" 2>/dev/null | tr -d ' \\n\\r\\t')
ERRCODE=""
case "$HEADTXT" in
  '{"code":'*|'{"error":'*) ERRCODE=$(head -c 1024 "$R" | tr -d '\\n\\r' | grep -o '"code": *"[A-Za-z0-9_.-]*"' | head -n 1 | sed 's/.*: *"\\(.*\\)"/\\1/'); [ -n "$ERRCODE" ] || ERRCODE=error;;
esac
if [ -f "$RD/timeout" ]; then RC=124
elif [ -n "$TERMED" ]; then RC=143
elif [ "$SZ" -gt "$CAP" ]; then
  truncate -s "$CAP" "$R" 2>/dev/null
  echo "[sparkdash] the result exceeded the size limit ($CAP bytes) and was cut off"
  RC=11
elif [ -z "$REARC" ]; then
  echo "[sparkdash] rea did not report an exit status"; RC=10
elif [ "$REARC" = 127 ] || [ "$REARC" = 126 ]; then
  echo "[sparkdash] the rea launcher could not start (is node installed on this unit?)"; RC=127
elif [ "$REARC" != 0 ] || [ -n "$ERRCODE" ]; then
  [ "$REARC" = 0 ] || echo "[sparkdash] rea exited with code $REARC"
  [ -z "$ERRCODE" ] || echo "[sparkdash] rea reported: $ERRCODE"
  case "$ERRCODE" in
    provider_unavailable|provider_missing|capability_unavailable|missing_analysis_engine|missing_dependency|missing_browser_executable|environment_unavailable) RC=126;;
    target_unavailable|file_unavailable) RC=2;;
    *) RC=10;;
  esac
elif [ "$SZ" -eq 0 ]; then
  echo "[sparkdash] rea printed no result"; RC=10
else
  RC=0
fi
[ "$RC" = 124 ] && echo "[sparkdash] the run was ended at its time limit"
echo "[sparkdash] stage: done"
# Whatever rea left in this session (the watchdog and its sleep, orphaned helpers) ends now.
trap "" TERM INT
kill -TERM -- "-$$" 2>/dev/null
wait 2>/dev/null
exit "$RC"
`;

/**
 * Start a run (detached) and follow it. `argvB64` is the NUL-joined argv for the launcher (e.g.
 * `inspect-artifact /abs/path --json`), `pathsB64` the NUL-joined list of absolute paths that must
 * resolve inside the unit user's home. Every path is replaced in argv by its resolved form.
 */
export function buildRunProgram({ runId: id, argvB64, pathsB64 = "", displayLine, timeoutSeconds, resultCapBytes = DEFAULT_RESULT_CAP, nonce = "" }) {
  const TX = exitToken(nonce);
  const tmo = posInt(timeoutSeconds, "time limit", 7 * 86400);
  const cap = posInt(resultCapBytes, "result cap", 2 ** 40);
  if (typeof argvB64 !== "string" || !/^[A-Za-z0-9+/=]*$/.test(argvB64)) throw new Error("invalid argv");
  if (typeof pathsB64 !== "string" || !/^[A-Za-z0-9+/=]*$/.test(pathsB64)) throw new Error("invalid paths");
  const innerB64 = b64(INNER);
  return wrap(`
${PATH_LINE}
${dirs(id, true)}
${HELPERS}
if [ "$PID" != 0 ] && alive; then echo "[sparkdash] this run is already running"; echo "${TX}-1"; exit 0; fi
# A refusal before anything started is recorded like any other end of a run.
fail() { echo "[sparkdash] $1"; : > "$L"; echo "[sparkdash] $1" >> "$L"; echo "$2" > "$X"; echo "${TX}$2"; exit 0; }
LCH="${LAUNCHER}"
[ -f "$LCH" ] && [ -x "$LCH" ] || fail "REA is not installed on this unit. Use Install on the REA page." 127
command -v node >/dev/null 2>&1 || fail "node is not installed on this unit." 127
command -v setsid >/dev/null 2>&1 || fail "setsid (util-linux) is not installed on this unit." 127
mapfile -d '' -t ARGS < <(printf %s '${argvB64}' | base64 -d)
mapfile -d '' -t PATHS < <(printf %s '${pathsB64}' | base64 -d)
[ "\${#ARGS[@]}" -gt 0 ] || fail "no command was given" 2

# Run-owned output paths (the caller never passes a user output path) and "~/" are resolved here. The
# parent <run>/out is created; the leaf is never pre-created (some commands need it absent).
USEOUT=0
for j in "\${!ARGS[@]}"; do
  a="\${ARGS[$j]}"
  case "$a" in
    "@@REA_RUN_OUT@@/"*)
      case "$a" in */../*|*/..) fail "An output path is not valid." 2;; esac
      ARGS[$j]="$RD/out/\${a#@@REA_RUN_OUT@@/}"; USEOUT=1;;
    "~/"*) ARGS[$j]="$HOME/\${a#\\~/}";;
  esac
done
for j in "\${!PATHS[@]}"; do
  case "\${PATHS[$j]}" in "~/"*) PATHS[$j]="$HOME/\${PATHS[$j]#\\~/}";; esac
done

# Both sides resolved: a symlinked home or cache location is common and must not read as "outside".
REALHOME=$(realpath -e -- "$HOME" 2>/dev/null) || REALHOME="$HOME"
for i in "\${!PATHS[@]}"; do
  p="\${PATHS[$i]}"
  [ -n "$p" ] || continue
  case "$p" in /*) ;; *) fail "A target path must be absolute." 2;; esac
  real=$(realpath -e -- "$p" 2>/dev/null) || fail "A target path does not exist on this unit." 2
  case "$real" in "$REALHOME"/*) ;; *) fail "A target path must be inside this unit user's home directory." 2;; esac
  # rea is handed the resolved path, so a link swapped in afterwards is not followed.
  for j in "\${!ARGS[@]}"; do [ "\${ARGS[$j]}" = "$p" ] && ARGS[$j]="$real"; done
done

rm -f "$X"; : > "$L"
rm -rf "$RD/out"
[ "$USEOUT" = 0 ] || mkdir -p "$RD/out" || fail "Could not create the output directory." 1
printf '[sparkdash] %s\\n' "$(printf %s '${b64(displayLine)}' | base64 -d)" >> "$L"
setsid bash -c "$(printf %s '${innerB64}' | base64 -d)" _ "$RD" "${tmo}" "${cap}" "\${ARGS[@]}" >> "$L" 2>&1 < /dev/null &
PID=$!
echo "$PID" > "$P"
follow "+1"
echo "${TX}$(cat "$X" 2>/dev/null || echo -1)"
`);
}

/** Re-open the output of a run that is running (or finished). */
export function buildAttachProgram({ runId: id, nonce = "" }) {
  const TX = exitToken(nonce);
  return wrap(`
${dirs(id)}
${HELPERS}
[ -f "$L" ] || { echo "[sparkdash] no output was recorded for this run on the unit"; echo "${TX}-1"; exit 0; }
if [ "$PID" != 0 ] && alive; then follow "+1"; else tail -n +1 "$L" 2>/dev/null; fi
echo "${TX}$(cat "$X" 2>/dev/null || echo -1)"
`);
}

/**
 * Ask a running run to stop: TERM its process group, then wait longer than the wrapper's own grace
 * period (it winds rea down and settles) before ending the group outright.
 */
export function buildStopProgram({ runId: id }) {
  return wrap(`
${dirs(id)}
${HELPERS}
GRACE="\${SPARKDASH_REA_GRACE:-${GRACE_SECONDS}}"
for i in 1 2 3 4 5 6 7 8 9 10; do [ -f "$P" ] || [ -f "$X" ] && break; sleep 0.5; done
PID=$(cat "$P" 2>/dev/null || echo 0)
if [ "$PID" = 0 ] || ! alive; then echo "not running"; exit 0; fi
kill -TERM -- "-$PID" 2>/dev/null || kill -TERM "$PID" 2>/dev/null
for i in $(seq 1 $(( GRACE + 15 ))); do alive || break; sleep 1; done
if alive; then
  # Last resort: end everything in the session except the wrapper, give it a moment to settle the run, then the wrapper.
  for p in $(ps -o pid= --sid "$PID" 2>/dev/null); do [ "$p" = "$PID" ] || kill -KILL "$p" 2>/dev/null; done
  for i in 1 2 3 4 5 6 7 8; do alive || break; sleep 1; done
  if alive; then kill -KILL -- "-$PID" 2>/dev/null || kill -KILL "$PID" 2>/dev/null; fi
  echo "killed"
else echo "stopped"; fi
`);
}

/** Is a run still alive, and how did it end? Prints ALIVE or EXIT=<code> (or GONE). */
export function buildCheckProgram({ runId: id }) {
  return wrap(`
${dirs(id)}
${HELPERS}
[ -d "$RD" ] || { echo GONE; exit 0; }
if [ "$PID" != 0 ] && alive; then echo ALIVE
# Just created and the pid is not written yet (the wrapper is between mkdir and launch): not "ended".
elif [ "$PID" = 0 ] && [ ! -f "$X" ] && [ -n "$(find "$RD" -maxdepth 0 -mmin -1 2>/dev/null)" ]; then echo ALIVE
else echo "EXIT=$(cat "$X" 2>/dev/null || echo -1)"; fi
`);
}

export function buildDeleteRunProgram({ runId: id }) {
  return wrap(`rm -rf "${RUN_ROOT}/${runId(id)}"; echo ok`);
}

// ── reading results ─────────────────────────────────────────────────────────

/** Locate <run>/result.json as a resolved path that is inside the run directory and not a link, or print NORESULT. */
function resultLocator(id, S, varName = "RES") {
  return `
RD="${RUN_ROOT}/${runId(id)}"
REALRD=$(realpath -e -- "$RD" 2>/dev/null) || { echo "${S}NORESULT"; exit 0; }
${varName}=$(realpath -e -- "$RD/result.json" 2>/dev/null)
[ ! -L "$RD" ] && [ "$${varName}" = "$REALRD/result.json" ] && [ -f "$${varName}" ] && [ ! -L "$RD/result.json" ] || { echo "${S}NORESULT"; exit 0; }
`;
}

/**
 * Sections: SIZE (bytes), SHA256, then BODY (the bytes of result.json) only when size <= maxBytes,
 * else TOOBIG. Both sides of the location check are resolved paths and a symlink reads as NORESULT.
 * The result is JSON the unit produced from untrusted input: it is the LAST thing printed.
 */
export function buildReadResultProgram({ runId: id, sentinel, maxBytes }) {
  const S = sentinelOf(sentinel);
  const max = posInt(maxBytes, "maxBytes");
  return wrap(`
${resultLocator(id, S)}
SZ=$(stat -c %s "$RES" 2>/dev/null || echo 0)
echo "${S}SIZE"; echo "$SZ"
echo "${S}SHA256"; sha256sum -- "$RES" 2>/dev/null | cut -d' ' -f1
if [ "$SZ" -le ${max} ]; then echo "${S}BODY"; cat -- "$RES"; else echo "${S}TOOBIG"; fi
`);
}

/** The shared tail of view / compare: run rea with a 120 s limit, cap the output, print STATUS then BODY or TOOBIG. */
function cappedRea(S, cap, argsShell) {
  return `
OUT="$RD/rea-out.$$"
trap 'rm -f "$OUT"' EXIT
LCH="${LAUNCHER}"
[ -f "$LCH" ] && [ -x "$LCH" ] || { echo "${S}STATUS"; echo 127; exit 0; }
command -v timeout >/dev/null 2>&1 || { echo "${S}STATUS"; echo 127; exit 0; }
export NO_COLOR=1
( timeout -k 5 120 "$LCH" ${argsShell} 2>/dev/null < /dev/null; echo $? > "$OUT.rc" ) | head -c ${cap + 1} > "$OUT"
REARC=$(cat "$OUT.rc" 2>/dev/null || echo 1); rm -f "$OUT.rc"
SZ=$(stat -c %s "$OUT" 2>/dev/null || echo 0)
if [ "$SZ" -gt ${cap} ]; then
  echo "${S}STATUS"; echo 11; echo "${S}TOOBIG"
else
  echo "${S}STATUS"; echo "$REARC"
  echo "${S}SIZE"; echo "$SZ"
  echo "${S}BODY"; cat -- "$OUT"
fi
`;
}

const VIEW_CHECK = `
const fs = require("fs");
const os = require("os");
const expand = (p) => (typeof p === "string" && p.startsWith("~/") ? os.homedir() + p.slice(1) : p);
let v;
try { v = JSON.parse(Buffer.from(process.env.VIEW_B64, "base64").toString("utf8")); } catch (e) { process.exit(2); }
const want = fs.realpathSync(process.env.RESULT);
const src = v && v.source;
if (!src || src.kind !== "file" || typeof src.path !== "string") process.exit(3);
let got;
try { got = fs.realpathSync(expand(src.path)); } catch (e) { process.exit(3); }
if (got !== want) process.exit(3);
// REA 6.4.0 accepts only {kind:"inline", evidence} (or retained-evidence): stream result.json into the
// request without parsing it (it can be hundreds of MB), in 1 MiB chunks.
const out = fs.openSync(process.env.OUTFILE, "w", 0o600);
fs.writeSync(out, '{"source":{"kind":"inline","evidence":');
const inp = fs.openSync(want, "r");
const buf = Buffer.allocUnsafe(1 << 20);
let n;
while ((n = fs.readSync(inp, buf, 0, buf.length, null)) > 0) fs.writeSync(out, buf, 0, n);
fs.writeSync(out, '},"view":' + JSON.stringify(v.view === undefined ? null : v.view) + "}");
fs.closeSync(inp);
fs.closeSync(out);
`;

/**
 * Project a result through \`rea inspect-analysis-view\`. \`viewB64\` is the base64 of the view JSON built
 * by the caller; its source must be {kind:"file", path} naming exactly this run's result.json (a leading
 * "~/" is accepted). The program turns it into the {kind:"inline", evidence} form REA 6.4.0 requires. Sections: STATUS (rea's code, 127 launcher/node missing, 124 timeout, 11 over the
 * cap, 2 bad view, 3 source is not this run's result), then SIZE + BODY, or TOOBIG.
 */
export function buildViewProgram({ runId: id, viewB64, sentinel, nonce = "", maxBytes = VIEW_CAP }) {
  void nonce;
  const S = sentinelOf(sentinel);
  if (typeof viewB64 !== "string" || !/^[A-Za-z0-9+/=]{1,1048576}$/.test(viewB64)) throw new Error("invalid view");
  const cap = posInt(maxBytes, "maxBytes", 64 * 1024 * 1024);
  return wrap(`
umask 077
${PATH_LINE}
${resultLocator(id, S)}
command -v node >/dev/null 2>&1 || { echo "${S}STATUS"; echo 127; exit 0; }
VR="$REALRD/view-req.json"
JS=$(printf %s '${b64(VIEW_CHECK)}' | base64 -d)
VIEW_B64='${viewB64}' RESULT="$RES" OUTFILE="$VR" node -e "$JS" 2>/dev/null
VC=$?
if [ "$VC" != 0 ]; then rm -f "$VR"; echo "${S}STATUS"; echo "$VC"; exit 0; fi
RD="$REALRD"
${cappedRea(S, cap, 'inspect-analysis-view "$VR" --json')}
`);
}

/** Stream result.json for download: SIZE, then BODY, or TOOBIG when it is larger than maxBytes. */
export function buildExportProgram({ runId: id, sentinel, maxBytes }) {
  const S = sentinelOf(sentinel);
  const max = posInt(maxBytes, "maxBytes");
  return wrap(`
${resultLocator(id, S)}
SZ=$(stat -c %s "$RES" 2>/dev/null || echo 0)
echo "${S}SIZE"; echo "$SZ"
if [ "$SZ" -le ${max} ]; then echo "${S}BODY"; head -c ${max} -- "$RES"; else echo "${S}TOOBIG"; fi
`);
}

/** Run \`rea compare <left> <right> --json\` on two runs of this unit. Sections as for the view program. */
export function buildCompareProgram({ leftRunId, rightRunId, sentinel, maxBytes = VIEW_CAP }) {
  const S = sentinelOf(sentinel);
  const cap = posInt(maxBytes, "maxBytes", 256 * 1024 * 1024);
  runId(leftRunId);
  runId(rightRunId);
  return wrap(`
umask 077
${PATH_LINE}
${resultLocator(leftRunId, S, "LEFT")}
LREALRD="$REALRD"
${resultLocator(rightRunId, S, "RIGHT")}
RD="$REALRD"
# \`rea compare\` takes Evidence BUNDLES; a run's result.json is one Evidence record. Wrap each record with REA's
# own bundle builder (pinned version), into files owned by the right-hand run's directory.
LB="$RD/compare-left.bundle.json"; RB="$RD/compare-right.bundle.json"
BUNDLER="$HOME/.local/share/sparkdash/rea/${REA_VERSION}/node_modules/rea-agents/dist/domain/evidenceBundle.js"
JS=$(printf %s '${Buffer.from(BUNDLE_JS, "utf8").toString("base64")}' | base64 -d)
for pair in "$LEFT|$LB" "$RIGHT|$RB"; do
  if ! IN="\${pair%%|*}" OUT="\${pair##*|}" BUNDLER="$BUNDLER" node --input-type=module -e "$JS" 2>/dev/null; then
    rm -f "$LB" "$RB"; echo "${S}STATUS"; echo 2; exit 0
  fi
done
${cappedRea(S, cap, 'compare "$LB" "$RB" --json')}
rm -f "$LB" "$RB"
`);
}

/** Node (ESM) program: read one Evidence record, write the canonical single-record bundle REA's compare accepts. */
const BUNDLE_JS = `
import fs from "node:fs";
import { pathToFileURL } from "node:url";
const m = await import(pathToFileURL(process.env.BUNDLER).href);
const rec = JSON.parse(fs.readFileSync(process.env.IN, "utf8"));
// A result that is already a bundle (records + manifests) is passed through unchanged.
const text = Array.isArray(rec && rec.records) ? JSON.stringify(rec) : m.serializeEvidenceBundle(m.createEvidenceBundle([rec]));
fs.writeFileSync(process.env.OUT, text, { mode: 0o600 });
`;

// ── status ──────────────────────────────────────────────────────────────────

/**
 * What the unit can do today: key=value lines. DOCTOR_B64 / PROVIDERS_B64 carry the (bounded: 60 s,
 * 256 KiB) JSON reports base64-encoded on one line so report text can never be mistaken for a key.
 * ENGINE_<id>=<path or empty> for the engines rea can use. Only paths and versions are printed.
 */
export function buildStatusProgram({ deep = true } = {}) {
  return wrap(`
${PATH_LINE}
${NODE_OK}
clean() { tr -d '\\n\\r' | tr -cd '[:print:]' | head -c 400; }
NODEP=$(command -v node 2>/dev/null || true)
echo "NODE=$(printf %s "$NODEP" | clean)"
NV=""
if [ -n "$NODEP" ]; then NV=$(timeout 10 node --version 2>/dev/null | head -n 1 | tr -cd '0-9A-Za-z.+v-' | head -c 40); fi
echo "NODE_VERSION=$NV"
if [ -n "$NV" ] && node_ok "$NV"; then echo "NODE_OK=1"; else echo "NODE_OK=0"; fi
echo "NPM=$(command -v npm 2>/dev/null | clean)"
LCH="${LAUNCHER}"
IV=""
if [ -f "$LCH" ] && [ -x "$LCH" ]; then
  echo "LAUNCHER=$LCH"
  if [ -n "$NODEP" ]; then IV=$(timeout -k 3 20 "$LCH" --version 2>/dev/null < /dev/null | head -n 1 | tr -cd '0-9A-Za-z.+-' | head -c 40); fi
else
  echo "LAUNCHER="
fi
echo "INSTALLED_VERSION=$IV"
${
  deep
    ? `if [ -n "$IV" ]; then
  cap_b64() { ( timeout -k 3 60 "$LCH" "$@" 2>/dev/null < /dev/null | head -c 262144 | base64 -w0 ) 2>/dev/null; }
  echo "DOCTOR_B64=$(cap_b64 doctor --json)"
  echo "PROVIDERS_B64=$(cap_b64 providers --json)"
fi`
    : ""
}
engine() {
  local id="$1" p="$2"
  echo "ENGINE_$id=$(printf %s "$p" | clean)"
}
P=""
if [ -n "\${GHIDRA_INSTALL_DIR:-}" ] && [ -x "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" ]; then P="$GHIDRA_INSTALL_DIR/support/analyzeHeadless"; else P=$(command -v analyzeHeadless 2>/dev/null || true); fi
engine ghidra "$P"
P=""
if [ -n "\${HOPPER_LAUNCHER_PATH:-}" ] && [ -x "$HOPPER_LAUNCHER_PATH" ]; then P="$HOPPER_LAUNCHER_PATH"; else P=$(command -v Hopper 2>/dev/null || true); fi
engine hopper "$P"
P=$(command -v idat 2>/dev/null || command -v idat64 2>/dev/null || true)
engine ida "$P"
for e in jadx apktool binwalk unblob adb jeb; do
  engine "$e" "$(command -v "$e" 2>/dev/null || true)"
done
# Wakaru is configured by command (REA_WAKARU_COMMAND) in the unit user's environment; only whether it resolves is reported.
P=""
if [ -n "\${REA_WAKARU_COMMAND:-}" ]; then W1=\${REA_WAKARU_COMMAND%% *}; P=$(command -v "$W1" 2>/dev/null || true); fi
engine wakaru "$P"
`);
}

// ── install ─────────────────────────────────────────────────────────────────

/**
 * Install the pinned rea-agents. The payload (installPayload()) arrives on STDIN. It is unpacked
 * into <version>.staging, \`npm ci --ignore-scripts\` runs there, the result is smoke tested, and only
 * then is it moved into place. A failure removes staging and leaves a previous install untouched.
 */
export function buildInstallProgram({ nonce = "" } = {}) {
  const TX = exitToken(nonce);
  const VER = REA_VERSION;
  const PIN_CHECK = `
const fs = require("fs");
const pin = process.argv[1];
const p = JSON.parse(fs.readFileSync("package.json", "utf8"));
const l = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
const e = l.packages && l.packages["node_modules/${REA_PKG}"];
process.exit(p.dependencies && p.dependencies["${REA_PKG}"] === pin && e && e.version === pin && e.integrity ? 0 : 1);
`;
  return wrap(`
umask 022
${PATH_LINE}
${NODE_OK}
fail() { echo "[sparkdash] $1"; echo "${TX}$2"; exit 0; }
step() { echo "[sparkdash] $1"; }
STG=""
cleanup() { [ -z "$STG" ] || rm -rf -- "$STG"; }
trap cleanup EXIT
trap 'exit 1' TERM INT

command -v node >/dev/null 2>&1 || fail "node is not installed on this unit (REA needs node 22.19+, 24.11+ or 26+)." 127
command -v npm >/dev/null 2>&1 || fail "npm is not installed on this unit." 127
NV=$(node --version 2>/dev/null | head -n 1)
node_ok "$NV" || fail "node $NV is too old: REA needs node 22.19+, 24.11+ or 26+." 127
step "using node $NV at $(command -v node)"

ROOT="${INSTALL_ROOT}"
VER="${VER}"
mkdir -p "$ROOT" || fail "Could not create $ROOT." 1
STG="$ROOT/$VER.staging"
rm -rf -- "$STG"
mkdir -p "$STG" || fail "Could not create the staging directory." 1

read_part() {
  local line label len
  IFS= read -r line || return 1
  label="\${line%% *}"; len="\${line#* }"
  [ "$label" = "$1" ] || return 1
  case "$len" in ''|*[!0-9]*) return 1;; esac
  [ "\${#len}" -le 7 ] && [ "$len" -le 4194304 ] || return 1
  head -c "$len" > "$2" || return 1
  [ "$(wc -c < "$2")" -eq "$len" ]
}
read_part PKG "$STG/package.json" || fail "The install payload (package.json) did not arrive intact." 1
read_part LOCK "$STG/package-lock.json" || fail "The install payload (package-lock.json) did not arrive intact." 1
cd "$STG" || fail "Could not enter the staging directory." 1
node -e '${PIN_CHECK.replace(/'/g, "'\\''")}' "$VER" 2>/dev/null || fail "The install payload does not pin ${REA_PKG} $VER; refusing to install." 1

step "installing ${REA_PKG} $VER (npm ci --ignore-scripts, from the pinned lockfile)"
export npm_config_update_notifier=false npm_config_audit=false npm_config_fund=false
timeout -k 10 1500 npm ci --ignore-scripts --no-audit --no-fund 2>&1 || fail "npm ci failed (is the npm registry reachable from this unit?)." 3

REA="$STG/node_modules/${REA_PKG}/scripts/rea.mjs"
[ -f "$REA" ] || fail "The installed package has no rea.mjs; refusing to use it." 4
step "checking the install"
GOT=$(timeout -k 5 60 node "$REA" --version 2>/dev/null < /dev/null | head -n 1 | tr -d '\\r')
[ "$GOT" = "$VER" ] || fail "rea --version printed '$(printf %s "$GOT" | tr -cd '[:print:]' | head -c 40)', expected $VER; the previous install was left as it was." 4
timeout -k 5 120 node "$REA" doctor --json 2>/dev/null < /dev/null | head -c 1048576 | node -e 'JSON.parse(require("fs").readFileSync(0, "utf8"))' 2>/dev/null \\
  || fail "rea doctor --json did not print JSON; the previous install was left as it was." 4

FINAL="$ROOT/$VER"
OLD=""
if [ -e "$FINAL" ]; then
  OLD="$FINAL.old"
  rm -rf -- "$OLD"
  mv -- "$FINAL" "$OLD" || fail "Could not move the previous install aside." 1
fi
if ! mv -- "$STG" "$FINAL"; then
  [ -z "$OLD" ] || mv -- "$OLD" "$FINAL"
  fail "Could not move the new install into place." 1
fi
STG=""
[ -z "$OLD" ] || rm -rf -- "$OLD"

BIN="$HOME/.local/bin"
mkdir -p "$BIN" || fail "Could not create $BIN." 1
LTMP="$BIN/.rea-sparkdash.$$"
{
  printf '#!/bin/bash\\n# sparkdash-managed launcher for rea-agents ${VER}\\n'
  printf 'exec node %q "$@"\\n' "$FINAL/node_modules/${REA_PKG}/scripts/rea.mjs"
} > "$LTMP" && chmod 755 "$LTMP" && mv -f -- "$LTMP" "${LAUNCHER}" || { rm -f "$LTMP"; fail "Could not write the launcher." 1; }
REC="${INSTALL_RECORD}"
mkdir -p "$(dirname "$REC")" || fail "Could not create the config directory." 1
{ printf 'VERSION=%s\\n' "$VER"; printf 'NODE=%s\\n' "$NV"; printf 'DATE=%s\\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; } > "$REC.$$" && chmod 600 "$REC.$$" && mv -f -- "$REC.$$" "$REC"
step "installed: ${LAUNCHER} -> $FINAL"
echo "${TX}0"
`);
}

// ── uploads ─────────────────────────────────────────────────────────────────

const UPLOAD_LOCATE = (id) => `
umask 077
UR="${UPLOAD_ROOT}"
UD="$UR/${uploadId(id)}"
REALUR=$(realpath -e -- "$UR" 2>/dev/null) || REALUR=""
REALUD=$(realpath -e -- "$UD" 2>/dev/null) || REALUD=""
err() { echo "ERROR=$1"; [ -z "$2" ] || echo "DETAIL=$2"; exit "$3"; }
[ -n "$REALUR" ] && [ -d "$UD" ] && [ ! -L "$UD" ] && [ "$REALUD" = "$REALUR/${id}" ] || err nouploaddir "" 2
`;

/** Allocate <uploads>/<id>/ (fails when it exists). Prints UPLOAD=<id> and DIR=<resolved dir>. */
export function buildUploadCreateProgram({ uploadId: id }) {
  uploadId(id);
  return wrap(`
umask 077
UR="${UPLOAD_ROOT}"
mkdir -p "$UR" || { echo "ERROR=mkdir"; exit 1; }
UD="$UR/${id}"
mkdir -- "$UD" 2>/dev/null || { echo "ERROR=exists"; exit 2; }
printf 'CREATED=%s\\n' "$(date +%s)" > "$UD/.meta"
echo "UPLOAD=${id}"
echo "DIR=$(realpath -e -- "$UD")"
`);
}

/**
 * One file from STDIN into <upload>/<relPath>: written to <name>.part with a hard byte cap, hashed,
 * then renamed into place. Prints BYTES= and SHA256=; on failure ERROR=<reason> and a non-zero exit
 * (2 not usable, 3 over the cap, 1 i/o). archive=true flags the file for extraction on commit.
 */
export function buildUploadPutProgram({ uploadId: id, relPath, maxBytes, archive = false }) {
  uploadId(id);
  const max = posInt(maxBytes, "maxBytes", 2 ** 40);
  if (typeof relPath !== "string" || !REL_PATH_RE.test(relPath)) throw new Error("invalid path");
  const segs = relPath.split("/");
  if (segs.some((s) => s === "." || s === ".." || s.endsWith(".part"))) throw new Error("invalid path");
  if (RESERVED_FIRST.has(segs[0])) throw new Error("reserved path");
  if (archive && !ARCHIVE_RE.test(relPath)) throw new Error("unsupported archive type");
  return wrap(`
${UPLOAD_LOCATE(id)}
[ ! -e "$UD/.committed" ] || err committed "" 2
REL=$(printf %s '${b64(relPath)}' | base64 -d)
DEST="$UD/$REL"
DIR=$(dirname -- "$DEST")
mkdir -p -- "$DIR" || err mkdir "" 1
REALDIR=$(realpath -e -- "$DIR" 2>/dev/null)
case "$REALDIR" in "$REALUD"|"$REALUD"/*) ;; *) err outside "" 2;; esac
[ ! -d "$DEST" ] || err isdir "" 2
PART="$DEST.part"
touch "$UD/.writing"
done_writing() {
  rm -f -- "$PART"
  # The marker stays while another file of this upload is still being written.
  find "$UD" -type f -name '*.part' 2>/dev/null | grep -q . || rm -f "$UD/.writing"
}
trap done_writing EXIT
rm -f -- "$PART"
head -c ${max + 1} > "$PART" || err write "" 1
SZ=$(stat -c %s "$PART" 2>/dev/null || echo 0)
[ "$SZ" -le ${max} ] || err toobig "" 3
SUM=$(sha256sum -- "$PART" | cut -d' ' -f1)
mv -f -- "$PART" "$DEST" || err rename "" 1
${archive ? `grep -qxF -- "$REL" "$UD/.archive" 2>/dev/null || printf '%s\\n' "$REL" >> "$UD/.archive"` : `:`}
echo "BYTES=$SZ"
echo "SHA256=$SUM"
`);
}

const EXTRACT_PY = `
import os, re, stat, sys, tarfile, zipfile

BS = chr(92)
arc, dest = sys.argv[1], sys.argv[2]
max_entries, max_bytes, ratio = int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
dest_real = os.path.realpath(dest)

def refuse(msg):
    print("REASON=" + msg)
    sys.exit(4)

def clean(n):
    return re.sub(r"[^A-Za-z0-9._/-]", "?", n)[:80]

def check_name(name):
    if not name or chr(0) in name:
        refuse("an entry has an empty or invalid name")
    n = name.replace(BS, "/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        refuse("absolute path entry: " + clean(name))
    segs = [s for s in n.split("/") if s not in ("", ".")]
    if any(s == ".." for s in segs):
        refuse("entry leaves the folder: " + clean(name))
    return segs

def check_totals(total, count):
    if count > max_entries:
        refuse("too many entries (%d)" % count)
    if total > max_bytes:
        refuse("unpacked size over the limit")
    size = max(os.path.getsize(arc), 1)
    if total > ratio * size:
        refuse("compression ratio over %d:1" % ratio)

def dest_path(segs):
    p = os.path.join(dest, *segs)
    if not os.path.realpath(p).startswith(dest_real + os.sep):
        refuse("entry leaves the folder")
    return p

def write_file(src, segs, budget):
    p = dest_path(segs)
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    n = 0
    with os.fdopen(fd, "wb") as out:
        while True:
            b = src.read(65536)
            if not b:
                break
            n += len(b)
            if n > budget:
                refuse("an entry is larger than its header says")
            out.write(b)
    return n

def do_zip():
    z = zipfile.ZipFile(arc)
    plan = []
    total = 0
    for i in z.infolist():
        segs = check_name(i.filename)
        fmt = stat.S_IFMT((i.external_attr >> 16) & 0xFFFF)
        if fmt and fmt not in (stat.S_IFREG, stat.S_IFDIR):
            refuse("link or special entry: " + clean(i.filename))
        if i.flag_bits & 1:
            refuse("encrypted entry: " + clean(i.filename))
        d = i.is_dir()
        if not d:
            total += i.file_size
        plan.append((i, segs, d))
        if len(plan) > max_entries:
            refuse("too many entries")
    check_totals(total, len(plan))
    os.makedirs(dest, mode=0o700, exist_ok=True)
    used = 0
    for i, segs, d in plan:
        if not segs:
            continue
        if d:
            os.makedirs(dest_path(segs), mode=0o700, exist_ok=True)
        else:
            with z.open(i) as src:
                used += write_file(src, segs, max_bytes - used)

def do_tar():
    plan = []
    total = 0
    with tarfile.open(arc, "r:*") as t:
        for m in t:
            segs = check_name(m.name)
            if m.isdir():
                pass
            elif m.isreg():
                total += m.size
            else:
                refuse("link or special entry: " + clean(m.name))
            plan.append((segs, m.isdir()))
            if len(plan) > max_entries:
                refuse("too many entries")
    check_totals(total, len(plan))
    os.makedirs(dest, mode=0o700, exist_ok=True)
    used = 0
    with tarfile.open(arc, "r:*") as t:
        for k, m in enumerate(t):
            segs, d = plan[k]
            if not segs:
                continue
            if d:
                os.makedirs(dest_path(segs), mode=0o700, exist_ok=True)
            else:
                src = t.extractfile(m)
                if src is None:
                    refuse("unreadable entry: " + clean(m.name))
                used += write_file(src, segs, max_bytes - used)

try:
    if zipfile.is_zipfile(arc):
        do_zip()
    elif tarfile.is_tarfile(arc):
        do_tar()
    else:
        refuse("not a supported archive (zip, tar, tar.gz)")
except SystemExit:
    raise
except Exception:
    refuse("the archive could not be read or unpacked")
`;

/**
 * Close an upload: verify it, extract flagged archives (listed first; refused on absolute, \`..\`,
 * link, device or encrypted entries, entry count over maxFiles, unpacked size over maxBytes or a
 * ratio over 100:1; python3 is required for archives and a unit without it refuses them), write
 * .committed. Prints ROOT=<absolute dir to analyse>, FILES=, BYTES=, EXTRACTED=0|1. A committed
 * upload prints the same again. Failures: ERROR=<reason> [DETAIL=...] and exit 2 (not usable),
 * 3 (over a cap), 4 (archive refused), 5 (a writer is active), 1 (i/o).
 */
export function buildUploadCommitProgram({ uploadId: id, maxFiles, maxBytes }) {
  uploadId(id);
  const files = posInt(maxFiles, "maxFiles", 10_000_000);
  const max = posInt(maxBytes, "maxBytes", 2 ** 50);
  return wrap(`
${UPLOAD_LOCATE(id)}
export PATH="/usr/local/bin:/usr/bin:/bin:$PATH"
if [ -f "$UD/.committed" ]; then cat -- "$UD/.committed"; exit 0; fi
if [ -f "$UD/.writing" ]; then
  W=$(stat -c %Y "$UD/.writing" 2>/dev/null || echo 0)
  [ $(( $(date +%s) - W )) -ge 60 ] || err writing "a file of this upload is still being written" 5
fi
find "$UD" -type f -name '*.part' -delete 2>/dev/null
rm -rf -- "$UD/extracted"
BAD=$(find "$UD" -mindepth 1 \\( -type l -o ! \\( -type f -o -type d \\) \\) -print -quit 2>/dev/null)
[ -z "$BAD" ] || err badentry "the upload contains a link or special file" 4
count() { find "$1" -type f ! -name .meta ! -name .writing ! -name .archive ! -name .committed 2>/dev/null | wc -l; }
bytes() { find "$1" -type f ! -name .meta ! -name .writing ! -name .archive ! -name .committed -printf '%s\\n' 2>/dev/null | awk '{s+=$1} END{print s+0}'; }
N=$(count "$UD"); B=$(bytes "$UD")
[ "$N" -gt 0 ] || err empty "nothing was uploaded" 2
[ "$N" -le ${files} ] || err toomany "more than ${files} files" 3
[ "$B" -le ${max} ] || err toobig "more than ${max} bytes" 3
ROOT="$REALUD"; EXTRACTED=0
if [ -s "$UD/.archive" ]; then
  command -v python3 >/dev/null 2>&1 || err nopython "python3 is required on this unit to verify archives" 2
  PY=$(printf %s '${b64(EXTRACT_PY)}' | base64 -d)
  while IFS= read -r a; do
    [ -n "$a" ] || continue
    AP=$(realpath -e -- "$UD/$a" 2>/dev/null)
    case "$AP" in "$REALUD"/*) ;; *) rm -rf -- "$UD/extracted"; err badentry "archive is missing" 4;; esac
    [ -f "$AP" ] && [ ! -L "$UD/$a" ] || { rm -rf -- "$UD/extracted"; err badentry "archive is not a regular file" 4; }
    OUT=$(python3 -I -c "$PY" "$AP" "$REALUD/extracted" ${files} ${max} 100 2>/dev/null)
    RCP=$?
    if [ "$RCP" != 0 ]; then
      rm -rf -- "$UD/extracted"
      REASON=$(printf '%s\\n' "$OUT" | sed -n 's/^REASON=//p' | head -n 1 | tr -cd '[:print:]' | head -c 160)
      err archive "\${REASON:-the archive was refused}" 4
    fi
  done < "$UD/.archive"
  EXTRACTED=1
  ROOT="$REALUD/extracted"
  [ -d "$ROOT" ] || err archive "the archive was empty" 4
fi
N=$(count "$ROOT"); B=$(bytes "$ROOT")
[ "$N" -le ${files} ] || { rm -rf -- "$UD/extracted"; err toomany "more than ${files} files" 3; }
[ "$B" -le ${max} ] || { rm -rf -- "$UD/extracted"; err toobig "more than ${max} bytes" 3; }
{ echo "ROOT=$ROOT"; echo "FILES=$N"; echo "BYTES=$B"; echo "EXTRACTED=$EXTRACTED"; } > "$UD/.committed" || err write "" 1
touch "$UD/.meta"
rm -f "$UD/.writing"
cat -- "$UD/.committed"
`);
}

export function buildUploadDeleteProgram({ uploadId: id }) {
  uploadId(id);
  return wrap(`rm -rf -- "${UPLOAD_ROOT}/${id}"; echo ok`);
}

/**
 * Remove uploads older than the TTL (age = time since the upload was created or last committed). An
 * upload whose .writing marker is younger than the TTL has an open writer and is kept. Prints
 * SWEPT=<n> and KEPT=<n>.
 */
export function buildUploadSweepProgram({ ttlHours }) {
  if (typeof ttlHours !== "number" || !Number.isFinite(ttlHours) || ttlHours < 0 || ttlHours > 24 * 365) throw new Error("invalid ttl");
  const ttl = Math.round(ttlHours * 3600);
  return wrap(`
UR="${UPLOAD_ROOT}"
TTL=${ttl}
NOW=$(date +%s)
SW=0; KP=0
[ -d "$UR" ] || { echo "SWEPT=0"; echo "KEPT=0"; exit 0; }
for d in "$UR"/up-*; do
  [ -d "$d" ] && [ ! -L "$d" ] || continue
  n=$(basename -- "$d")
  [[ "$n" =~ ^up-[0-9]{8}-[0-9]{6}-[a-z0-9]{6}$ ]] || continue
  W=$(stat -c %Y "$d/.writing" 2>/dev/null || echo 0)
  if [ "$W" -gt 0 ] && [ $(( NOW - W )) -lt "$TTL" ]; then KP=$(( KP + 1 )); continue; fi
  M=$(stat -c %Y "$d/.meta" 2>/dev/null || stat -c %Y "$d" 2>/dev/null || echo "$NOW")
  if [ $(( NOW - M )) -ge "$TTL" ]; then rm -rf -- "$d"; SW=$(( SW + 1 )); else KP=$(( KP + 1 )); fi
done
echo "SWEPT=$SW"
echo "KEPT=$KP"
`);
}
