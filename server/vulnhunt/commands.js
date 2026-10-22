/**
 * Programs sparkDash runs on a unit to drive VulnHunter (github.com/nealbridges/VulnHunter).
 * Same approach as Tool Eval (tooleval/commands.js) and the model launchers: each program is
 * shipped base64-encoded so no quoting layer can mangle it, and a scan is DETACHED (setsid)
 * with its output in files under ~/.cache/sparkdash/vulnhunt/<runId>/, so closing the browser
 * or restarting sparkDash never kills a long hunt and the output can be re-attached later.
 *
 * What the unit must provide (sparkDash installs nothing):
 *   - `vh`, the VulnHunter operator CLI (its install.sh puts it in ~/.local/bin)
 *   - the harness's headless one-shot as VULNHUNT_HOST_CMD, taken from the environment or from
 *     the first line of ~/.config/sparkdash/vulnhunt-host-cmd (a file the unit's user owns and
 *     nobody else can write). The dashboard can write that file (PUT .../host-command, same gate as starting
 *     a scan) but never reads it back: only the program's name is ever reported.
 *
 * The scan sequence is the one VulnHunter's own operator skill and benchmark harness use:
 * `vh clone` -> `vh host <prompt>` (prompt = "/vulnhunt <checkout>") -> `vh find-results`
 * -> `vh write-manifest` -> `vh validate-manifest`. The clone is deleted afterwards; only the
 * results folder is kept (under <run>/results).
 *
 * Exit codes written to <run>/exit by the wrapper (the harness's own code is never passed through):
 *   0 hunt finished with a results folder      2 source not usable on the unit
 *   3 clone failed                             4 hunt finished but produced no new results folder
 *   10 the harness command exited non-zero     124 the scan hit its time limit
 *   126 harness command not configured safely  127 VulnHunter / git / setsid not set up
 *   143 stopped on request
 */

import { exitToken } from "../tooleval/commands.js";

export { exitToken };

export const RUN_ROOT = "$HOME/.cache/sparkdash/vulnhunt";
export const HOST_CMD_FILE = "$HOME/.config/sparkdash/vulnhunt-host-cmd";
const PATH_LINE = 'export PATH="$HOME/.local/bin:$HOME/.cargo/bin:/usr/local/bin:$PATH"';

/**
 * Seconds the wrapper gives the harness to wind down after TERM before it is killed. Overridable
 * through SPARKDASH_VULNHUNT_GRACE in the environment of the program (tests use a small value), like
 * SPARKDASH_VULNHUNT_LOGMAX (bytes, default 64 MiB: output.log is trimmed to a quarter of it) and
 * SPARKDASH_VULNHUNT_TICK (seconds between janitor checks, default 15).
 */
export const GRACE_SECONDS = 20;

/** The VulnHunter revision sparkDash installs (pinned: bump it deliberately after reading the diff). */
export const VULNHUNTER_REPO = "https://github.com/nealbridges/VulnHunter.git";
export const VULNHUNTER_REV = "b91b81e696a756e8a3d9ea69248b469b834a2f92";
export const INSTALL_DIR = "$HOME/.local/share/sparkdash/VulnHunter";
export const INSTALL_RECORD = "$HOME/.config/sparkdash/vulnhunt-install";

export function runDirRef(runId) {
  return `~/.cache/sparkdash/vulnhunt/${runId}`;
}

function wrap(program) {
  const b64 = Buffer.from(program, "utf8").toString("base64");
  return `bash -c "$(printf %s '${b64}' | base64 -d)"`;
}

/** The first token of a (shlex-quoted) command line, as `vh host` will split it. */
const FIRST_TOKEN = `
first_token() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import shlex, sys
try:
    t = shlex.split(sys.argv[1])
    print(t[0] if t else "")
except Exception:
    print("")' "$1"
  else
    local f=\${1%% *}; printf '%s\\n' "\${f//\\"/}"
  fi
}
`;

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

function dirs(runId) {
  return `
umask 077
RD="${RUN_ROOT}/${runId}"
mkdir -p "$RD" || exit 1
L="$RD/output.log"; X="$RD/exit"; P="$RD/pid"
PID=$(cat "$P" 2>/dev/null || echo 0)
`;
}

/**
 * The detached part: clone, hunt, collect. Arguments: run dir, kind, source, read-only flag
 * ("1"/"0"), time limit in seconds (for the whole scan, clone included). It always writes
 * <run>/exit, whatever happens, and it never lets the harness's exit code stand in for its own.
 */
const INNER = `
umask 077
RD="$1"; KIND="$2"; VAL="$3"; RO="$4"; TMO="$5"
X="$RD/exit"; P="$RD/pid"; RC=1; TERMED=""
GRACE="\${SPARKDASH_VULNHUNT_GRACE:-${GRACE_SECONDS}}"
LOGMAX="\${SPARKDASH_VULNHUNT_LOGMAX:-67108864}"; TICK="\${SPARKDASH_VULNHUNT_TICK:-15}"
trap 'echo "$RC" > "$X"; rm -f "$P"' EXIT
stage() { echo "[sparkdash] stage: $1"; }
# Every process of this session except this shell (the harness and anything it started).
kill_rest() { local p; for p in $(ps -o pid= --sid "$$" 2>/dev/null); do [ "$p" = "$$" ] || kill -"$1" "$p" 2>/dev/null; done; }
# A stop request or the time limit: stop at the next stage boundary with the right code.
terminated() {
  if [ -n "$TERMED" ]; then
    if [ -f "$RD/timeout" ]; then RC=124; else RC=143; fi
    exit "$RC"
  fi
}
trap 'TERMED=1; trap "" TERM INT; kill -TERM -- "-$$" 2>/dev/null' TERM INT
cd "$RD" || exit 1
rm -rf "$RD/src" "$RD/results" "$RD/results-dir" "$RD/before.txt" "$RD/timeout" "$RD/output.trim"

# One time limit for the whole scan, clone included, plus a janitor that keeps output.log bounded.
# GNU timeout is avoided on purpose: it moves its child into a new process group, which a stop
# request (TERM to this session's group) cannot reach.
INNER=$$
# The wrapper is still this shell (not a recycled pid): its command line carries the run directory.
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
  echo "[sparkdash] the scan hit its time limit"
  kill -TERM -- "-$INNER" 2>/dev/null
) &
WD=$!

stage clone
# The clone ignores the user's global git config (credential helpers, insteadOf), follows no redirect,
# runs no hooks and fetches no LFS objects; only the one protocol the source type needs is allowed.
GITENV=(env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_COUNT=2
  GIT_CONFIG_KEY_0=http.followRedirects GIT_CONFIG_VALUE_0=false
  GIT_CONFIG_KEY_1=core.hooksPath GIT_CONFIG_VALUE_1=/dev/null
  GIT_LFS_SKIP_SMUDGE=1 GIT_TERMINAL_PROMPT=0)
if [ "$KIND" = url ]; then
  "\${GITENV[@]}" GIT_ALLOW_PROTOCOL=https vh clone "$VAL" --dest "$RD/src"
else
  "\${GITENV[@]}" GIT_ALLOW_PROTOCOL=file git clone --depth 1 -- "file://$VAL" "$RD/src"
fi
CRC=$?
terminated
if [ "$CRC" -ne 0 ]; then
  if [ "$KIND" = url ]; then echo "[sparkdash] clone failed"; else echo "[sparkdash] could not clone the local checkout (is it a git repository with a commit?)"; fi
  RC=3; exit 3
fi
echo "[sparkdash] checked out $(git -C "$RD/src" rev-parse --short HEAD 2>/dev/null || echo unknown)"

# A repository can ship a directory that looks like a results folder: only folders created by THIS hunt count.
vh find-results "$RD/src" > "$RD/before.txt" 2>/dev/null

PF="$RD/prompt.txt"
{
  printf '/vulnhunt %s\\n\\nIMPORTANT: This is running in non-interactive headless mode. Do NOT ask for approval or confirmation. Execute immediately.' "$RD/src"
  if [ "$RO" = 1 ]; then
    printf '  Perform a read-only scan, skip instructions related to getting dependencies and executing code'
  else
    printf '  --no-read-only (bash is allowed: run the exploit tests and fetch dependencies where the methodology needs them)'
  fi
  printf '\\n'
} > "$PF"

terminated
stage hunt
cd "$RD/src" || { RC=3; exit 3; }
# The hunt runs in the background of THIS session so that a stop request and the time limit both
# reach the harness and everything it started.
vh host "$PF" &
HP=$!
wait "$HP"; HRC=$?
if [ -n "$TERMED" ]; then
  # Give the harness its grace period, then end whatever is left; this shell survives to collect.
  for i in $(seq 1 "$GRACE"); do kill -0 "$HP" 2>/dev/null || break; sleep 1; done
  kill -0 "$HP" 2>/dev/null && kill_rest KILL
  wait "$HP" 2>/dev/null
fi
rm -f "$PF"
if [ -f "$RD/timeout" ]; then HRC=124
elif [ -n "$TERMED" ]; then HRC=143
fi
case "$HRC" in
  0|124|143) ;;
  *) echo "[sparkdash] the harness command exited with code $HRC"; HRC=10;;
esac
[ "$HRC" = 124 ] && echo "[sparkdash] the hunt was ended at its time limit"

stage collect
mkdir -p "$RD/results"
R=""
while IFS= read -r d; do
  [ -n "$d" ] || continue
  [ -L "$d" ] && continue
  grep -qxF -- "$d" "$RD/before.txt" 2>/dev/null && continue
  R="$d"; break
done < <(vh find-results "$RD/src" 2>/dev/null)
if [ -n "$R" ]; then
  EC=0; [ "$HRC" -eq 0 ] || EC=1
  # A stop request during collect must not cut the manifest short: these children ignore TERM.
  ( trap "" TERM INT; vh write-manifest "$R" --exit-code "$EC" && vh validate-manifest "$R" )
  NAME=$(basename -- "$R")
  if mv -- "$R" "$RD/results/$NAME"; then
    printf '%s\\n' "$RD/results/$NAME" > "$RD/results-dir"
  else
    echo "[sparkdash] could not keep the results folder"; R=""
  fi
else
  echo "[sparkdash] the hunt produced no new *_VULNHUNT_RESULTS_* directory"
fi
# The clone is not needed any more (the results folder was moved out of it).
rm -rf "$RD/src"
# Stopped on request, even if the stop arrived after the hunt itself had finished.
if [ -n "$TERMED" ] && [ "$HRC" -eq 0 ]; then HRC=143; fi
RC=$HRC
if [ "$HRC" -eq 0 ] && [ -z "$R" ]; then RC=4; fi
stage done
# Whatever the hunt left in this session (the watchdog and its sleep, orphaned helpers) ends now.
trap "" TERM INT
kill -TERM -- "-$$" 2>/dev/null
wait 2>/dev/null
exit "$RC"
`;

/** Start a scan (detached) and follow it. `argvB64` is NUL-joined [kind, source, ro, timeoutSeconds], base64. */
export function buildRunProgram({ runId, argvB64, displayLine, nonce = "" }) {
  const TX = exitToken(nonce);
  const displayB64 = Buffer.from(displayLine, "utf8").toString("base64");
  const innerB64 = Buffer.from(INNER, "utf8").toString("base64");
  return wrap(`
${PATH_LINE}
${dirs(runId)}
${HELPERS}
${FIRST_TOKEN}
fail() { echo "[sparkdash] $1"; echo "${TX}$2"; exit 0; }
command -v vh >/dev/null 2>&1 || fail "vh (the VulnHunter operator CLI) is not installed on this unit. Open the setup steps on the Security page." 127
command -v git >/dev/null 2>&1 || fail "git is not installed on this unit." 127
command -v setsid >/dev/null 2>&1 || fail "setsid (util-linux) is not installed on this unit." 127
if [ "$PID" != 0 ] && alive; then echo "[sparkdash] this scan is already running"; echo "${TX}-1"; exit 0; fi
mapfile -d '' -t ARGS < <(printf %s '${argvB64}' | base64 -d)
KIND="\${ARGS[0]}"; VAL="\${ARGS[1]}"; RO="\${ARGS[2]}"; TMO="\${ARGS[3]}"
case "$KIND" in url|path) ;; *) fail "unknown source type" 2;; esac
case "$TMO" in ''|*[!0-9]*) fail "invalid time limit" 2;; esac

# The harness command lives on the unit, never in the request.
HOSTCMD="\${VULNHUNT_HOST_CMD:-}"
CF="${HOST_CMD_FILE}"
if [ -z "$HOSTCMD" ] && [ -e "$CF" ]; then
  [ -f "$CF" ] && [ ! -L "$CF" ] || fail "$CF must be a regular file, not a link." 126
  [ "$(stat -c %u "$CF")" = "$(id -u)" ] || fail "$CF must be owned by the unit's user." 126
  MODE=$(stat -c %a "$CF"); [ $(( 0$MODE & 022 )) -eq 0 ] || fail "$CF must not be writable by group or others (chmod 600)." 126
  HOSTCMD=$(head -n 1 "$CF")
fi
[ -n "$HOSTCMD" ] || fail "No harness command is configured. Put your harness's headless one-shot on one line in $CF (see the setup steps on the Security page)." 126
FIRST=$(first_token "$HOSTCMD")
[ -n "$FIRST" ] && command -v "$FIRST" >/dev/null 2>&1 || fail "The configured harness command was not found on PATH: $FIRST" 126
export VULNHUNT_HOST_CMD="$HOSTCMD"

if [ "$KIND" = path ]; then
  case "$VAL" in "~/"*) VAL="$HOME/\${VAL#\\~/}";; esac
  REAL=$(realpath -e -- "$VAL" 2>/dev/null) || fail "That path does not exist on this unit." 2
  # Both sides resolved: a symlinked home or checkout location is common and must not read as "outside".
  REALHOME=$(realpath -e -- "$HOME" 2>/dev/null) || REALHOME="$HOME"
  case "$REAL" in "$REALHOME"/*) ;; *) fail "The path must be inside this unit user's home directory." 2;; esac
  [ -d "$REAL/.git" ] || [ -f "$REAL/.git" ] || fail "That path is not a git checkout." 2
  VAL="$REAL"
fi

rm -f "$X"; : > "$L"
printf '[sparkdash] %s\\n' "$(printf %s '${displayB64}' | base64 -d)" >> "$L"
setsid bash -c "$(printf %s '${innerB64}' | base64 -d)" _ "$RD" "$KIND" "$VAL" "$RO" "$TMO" >> "$L" 2>&1 < /dev/null &
PID=$!
echo "$PID" > "$P"
follow "+1"
echo "${TX}$(cat "$X" 2>/dev/null || echo -1)"
`);
}

/** Re-open the output of a scan that is running (or finished). */
export function buildAttachProgram({ runId, nonce = "" }) {
  const TX = exitToken(nonce);
  return wrap(`
${dirs(runId)}
${HELPERS}
[ -f "$L" ] || { echo "[sparkdash] no output was recorded for this scan on the unit"; echo "${TX}-1"; exit 0; }
if [ "$PID" != 0 ] && alive; then follow "+1"; else tail -n +1 "$L" 2>/dev/null; fi
echo "${TX}$(cat "$X" 2>/dev/null || echo -1)"
`);
}

/**
 * Ask a running scan to stop: TERM its process group, then wait longer than the wrapper's own grace
 * period (it winds the harness down and collects what exists) before ending the group outright.
 */
export function buildStopProgram({ runId }) {
  return wrap(`
${dirs(runId)}
${HELPERS}
GRACE="\${SPARKDASH_VULNHUNT_GRACE:-${GRACE_SECONDS}}"
for i in 1 2 3 4 5 6 7 8 9 10; do [ -f "$P" ] || [ -f "$X" ] && break; sleep 0.5; done
PID=$(cat "$P" 2>/dev/null || echo 0)
if [ "$PID" = 0 ] || ! alive; then echo "not running"; exit 0; fi
kill -TERM -- "-$PID" 2>/dev/null || kill -TERM "$PID" 2>/dev/null
for i in $(seq 1 $(( GRACE + 15 ))); do alive || break; sleep 1; done
if alive; then kill -KILL -- "-$PID" 2>/dev/null || kill -KILL "$PID" 2>/dev/null; echo "killed"; else echo "stopped"; fi
`);
}

/** Is a scan still alive, and how did it end? Prints ALIVE or EXIT=<code> (or GONE). */
export function buildCheckProgram({ runId }) {
  return wrap(`
${dirs(runId)}
${HELPERS}
[ -d "$RD" ] || { echo GONE; exit 0; }
if [ "$PID" != 0 ] && alive; then echo ALIVE; else echo "EXIT=$(cat "$X" 2>/dev/null || echo -1)"; fi
`);
}

/** What the unit can do today: key=value lines (no secrets; only the harness program's name). */
export function buildStatusProgram() {
  return wrap(`
${PATH_LINE}
${FIRST_TOKEN}
echo "VH=$(command -v vh || true)"
echo "GIT=$(command -v git || true)"
echo "SETSID=$(command -v setsid || true)"
HOSTCMD="\${VULNHUNT_HOST_CMD:-}"; SRC=""
CF="${HOST_CMD_FILE}"
if [ -n "$HOSTCMD" ]; then SRC=env
elif [ -e "$CF" ]; then
  if [ -f "$CF" ] && [ ! -L "$CF" ] && [ "$(stat -c %u "$CF")" = "$(id -u)" ] && [ $(( 0$(stat -c %a "$CF") & 022 )) -eq 0 ]; then
    HOSTCMD=$(head -n 1 "$CF"); SRC=file
  else
    SRC=unsafe
  fi
fi
echo "HOSTCMD_SOURCE=\${SRC:-none}"
if [ -n "$HOSTCMD" ]; then
  FIRST=$(first_token "$HOSTCMD")
  echo "HOSTCMD_PROGRAM=$(basename -- "$FIRST")"
  [ -n "$FIRST" ] && command -v "$FIRST" >/dev/null 2>&1 && echo "HOSTCMD_FOUND=1" || echo "HOSTCMD_FOUND=0"
fi
echo "HOSTCMD_FILE=${HOST_CMD_FILE}"
echo "RUNROOT=${RUN_ROOT}"
if [ -d "${INSTALL_DIR}/.git" ]; then echo "INSTALLED_REV=$(git -C "${INSTALL_DIR}" rev-parse HEAD 2>/dev/null)"; fi
if [ -f "${INSTALL_RECORD}" ]; then sed -n 's/^SKILLS_DIR=\\(.*\\)$/INSTALLED_SKILLS_DIR=\\1/p;s/^AGENTS_DIR=\\(.*\\)$/INSTALLED_AGENTS_DIR=\\1/p' "${INSTALL_RECORD}" | head -n 2; fi
# Skills directories of harnesses that are installed here (offered as choices in the UI).
for d in "$HOME/.claude/skills" "$HOME/.codex/skills" "$HOME/.config/opencode/skills" "$HOME/.grok/skills" "$HOME/.hermes/skills" "$HOME/.agents/skills"; do
  [ -d "$d" ] && echo "SKILLSDIR=$d"
done
PYV=""; for c in python3.13 python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)' 2>/dev/null; then PYV=$("$c" -c 'import sys; print("%d.%d" % sys.version_info[:2])'); break; fi
done
echo "PYTHON311=$PYV"
`);
}

/**
 * Print what a finished scan produced, sectioned by per-call sentinels (the report body is
 * agent-written text, so the sentinels carry a nonce it cannot know and the report comes LAST).
 * Both sides of the location check are resolved paths, and symlinks are never followed: a results
 * folder or report that points outside <run>/results reads as empty.
 */
export function buildReadReportProgram({ runId, sentinel, maxReportBytes = 2 * 1024 * 1024 }) {
  const S = sentinel;
  return wrap(`
RD="${RUN_ROOT}/${runId}"
REALRD=$(realpath -e -- "$RD" 2>/dev/null) || { echo "${S}NORESULT"; exit 0; }
RES=$(head -n 1 "$RD/results-dir" 2>/dev/null)
REALRES=$(realpath -e -- "$RES" 2>/dev/null)
case "$REALRES" in "$REALRD/results/"*) ;; *) echo "${S}NORESULT"; exit 0;; esac
[ -d "$REALRES" ] && [ ! -L "$RES" ] || { echo "${S}NORESULT"; exit 0; }
cd "$REALRES" || { echo "${S}NORESULT"; exit 0; }
echo "${S}DIR"; basename -- "$REALRES"
echo "${S}MANIFEST"
if [ -f scan_manifest.json ] && [ ! -L scan_manifest.json ] && [ "$(wc -c < scan_manifest.json)" -le 65536 ]; then tr -d '\\n' < scan_manifest.json; echo; fi
echo "${S}FILES"
find . -type f -not -path './.git/*' 2>/dev/null | head -n 600 | sed 's|^\\./||' | grep -E '^[A-Za-z0-9._/@+=,-]{1,200}$'
echo "${S}REPORT"
if [ -f README.md ] && [ ! -L README.md ]; then
  SZ=$(wc -c < README.md)
  if [ "$SZ" -le ${maxReportBytes} ]; then cat README.md; else echo "__TOOBIG__$SZ"; fi
fi
`);
}

export function buildDeleteRunProgram({ runId }) {
  return wrap(`rm -rf "${RUN_ROOT}/${runId}"; echo ok`);
}

/** The `vh` launcher (same shape as upstream's): @REPO@ and @PY@ are filled in on the unit. */
const LAUNCHER_B64 = Buffer.from(
  '#!/bin/sh\n# sparkdash-managed launcher for VulnHunter\'s operator CLI\nPYTHONPATH="@REPO@${PYTHONPATH:+:$PYTHONPATH}" exec "@PY@" -m vh "$@"\n',
  "utf8"
).toString("base64");

/**
 * Install VulnHunter on the unit: the pinned revision is fetched by hash into ~/.local/share/sparkdash/VulnHunter,
 * the `vulnhunt` skill is copied into the harness's skills directory (and the agent definition into its agents
 * directory when given), and a `vh` launcher is written to ~/.local/bin. Upstream's install.sh is not used on
 * purpose: besides the same copying it builds a virtualenv from PyPI for the fix skill, which a scan does not need.
 * Output streams like any job; the exit marker carries the result.
 */
export function buildInstallProgram({ skillsDir, agentsDir = "", nonce = "", repo = VULNHUNTER_REPO, rev = VULNHUNTER_REV, protocol = "https" }) {
  const TX = exitToken(nonce);
  // These are interpolated into the program text: constants of this module, or a local test fixture.
  if (!/^[0-9a-f]{40}$/.test(rev)) throw new Error("invalid revision");
  if (!/^(https:\/\/|file:\/\/\/)[A-Za-z0-9._~/:@+=,-]{1,300}$/.test(repo)) throw new Error("invalid repository");
  if (protocol !== "https" && protocol !== "file") throw new Error("invalid protocol");
  const b64 = (v) => Buffer.from(String(v), "utf8").toString("base64");
  return wrap(`
umask 022
${PATH_LINE}
fail() { echo "[sparkdash] $1"; echo "${TX}$2"; exit 0; }
step() { echo "[sparkdash] $1"; }
SK_RAW=$(printf %s '${b64(skillsDir)}' | base64 -d)
AG_RAW=$(printf %s '${b64(agentsDir)}' | base64 -d)
expand() { case "$1" in "~/"*) printf '%s' "$HOME/\${1#\\~/}";; *) printf '%s' "$1";; esac; }
SK=$(expand "$SK_RAW"); AG=""; [ -n "$AG_RAW" ] && AG=$(expand "$AG_RAW")
REALHOME=$(realpath -e -- "$HOME" 2>/dev/null) || REALHOME="$HOME"
# Destinations must be inside the unit user's home (created if missing), never the home itself.
inside_home() {
  local d="$1" parent real
  mkdir -p -- "$d" 2>/dev/null || return 1
  real=$(realpath -e -- "$d" 2>/dev/null) || return 1
  case "$real" in "$REALHOME"/*) return 0;; esac
  return 1
}
command -v git >/dev/null 2>&1 || fail "git is not installed on this unit." 127
PY=""
for c in python3.13 python3.12 python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 11) else 1)' 2>/dev/null; then PY=$(command -v "$c"); break; fi
done
[ -n "$PY" ] || fail "Python 3.11 or newer is required on this unit (VulnHunter's requirement)." 127
step "using $PY"
inside_home "$SK" || fail "The skills directory must be inside this unit user's home directory." 2
[ -z "$AG" ] || inside_home "$AG" || fail "The agents directory must be inside this unit user's home directory." 2
SK=$(realpath -e -- "$SK"); [ -z "$AG" ] || AG=$(realpath -e -- "$AG")

REPO="${INSTALL_DIR}"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=${protocol}
export GIT_CONFIG_COUNT=2 GIT_CONFIG_KEY_0=http.followRedirects GIT_CONFIG_VALUE_0=false GIT_CONFIG_KEY_1=core.hooksPath GIT_CONFIG_VALUE_1=/dev/null
mkdir -p "$(dirname "$REPO")" || fail "Could not create the install directory." 1
if [ ! -d "$REPO/.git" ]; then
  rm -rf "$REPO"; git init -q "$REPO" || fail "git init failed." 1
  git -C "$REPO" remote add origin "${repo}"
fi
step "fetching VulnHunter ${rev.slice(0, 12)} from ${repo}"
git -C "$REPO" fetch --depth 1 origin "${rev}" || fail "Could not fetch VulnHunter (is github.com reachable from this unit?)." 3
git -C "$REPO" checkout -q --detach -f FETCH_HEAD || fail "Could not check out the fetched revision." 3
[ "$(git -C "$REPO" rev-parse HEAD)" = "${rev}" ] || fail "The fetched revision does not match the pinned one; refusing to install." 3
[ -f "$REPO/vulnhunt/SKILL.md" ] && [ -f "$REPO/vh/cli.py" ] || fail "The fetched revision does not look like VulnHunter." 3

step "installing the vulnhunt skill into $SK"
rm -rf -- "$SK/vulnhunt"
cp -R "$REPO/vulnhunt" "$SK/vulnhunt" || fail "Could not copy the skill." 1
printf '%s\n' "${rev}" > "$SK/vulnhunt/.installed-from"
if [ -n "$AG" ] && [ -f "$REPO/agents/vulnhunter.md" ]; then
  step "installing the agent definition into $AG"
  cp "$REPO/agents/vulnhunter.md" "$AG/vulnhunter.md" || fail "Could not copy the agent definition." 1
fi

BIN="$HOME/.local/bin"
mkdir -p "$BIN"
printf %s '${LAUNCHER_B64}' | base64 -d | sed -e "s|@REPO@|$REPO|" -e "s|@PY@|$PY|" > "$BIN/vh"
chmod +x "$BIN/vh"
"$BIN/vh" --help >/dev/null 2>&1 || fail "The vh launcher does not run (python modules missing?)." 1

mkdir -p "$(dirname "${INSTALL_RECORD}")"
{ printf 'REV=%s\n' "${rev}"; printf 'SKILLS_DIR=%s\n' "$SK"; [ -z "$AG" ] || printf 'AGENTS_DIR=%s\n' "$AG"; } > "${INSTALL_RECORD}"
step "installed: vh at $BIN/vh, skill at $SK/vulnhunt"
echo "${TX}0"
`);
}

/**
 * Save the harness's headless command for the unit (the first line of ~/.config/sparkdash/vulnhunt-host-cmd,
 * mode 600). The command travels base64-encoded and is only ever written, never printed back.
 */
export function buildSetHostCommandProgram({ command, nonce = "" }) {
  const TX = exitToken(nonce);
  const b64 = Buffer.from(String(command), "utf8").toString("base64");
  return wrap(`
umask 077
${PATH_LINE}
${FIRST_TOKEN}
fail() { echo "$1"; echo "${TX}$2"; exit 0; }
CMD=$(printf %s '${b64}' | base64 -d)
FIRST=$(first_token "$CMD")
[ -n "$FIRST" ] || fail "The command could not be read (check the quoting)." 2
command -v "$FIRST" >/dev/null 2>&1 || fail "$FIRST was not found on PATH on this unit." 2
CF="${HOST_CMD_FILE}"
mkdir -p "$(dirname "$CF")" || fail "Could not create the config directory." 1
[ ! -L "$CF" ] || rm -f "$CF"
TMP="$CF.$$"
printf '%s\n' "$CMD" > "$TMP" && chmod 600 "$TMP" && mv -f "$TMP" "$CF" || { rm -f "$TMP"; fail "Could not write the command file." 1; }
echo "saved"
echo "${TX}0"
`);
}

export function buildClearHostCommandProgram({ nonce = "" }) {
  const TX = exitToken(nonce);
  return wrap(`rm -f "${HOST_CMD_FILE}"; echo "${TX}0"`);
}
