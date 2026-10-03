#!/bin/sh
# Step 0 guard: run a hook script with a REAL Python 3, or do nothing at all.
#
#   sh python.sh <plugin> <say|quiet> <script.py> [args...]
#
# Hooks pass the script's full path. Skills pass it relative to the plugin root (scripts/x.py):
# a skill runs this file through Claude Code's Bash tool, and its PowerShell twin through the
# PowerShell tool, so a skill never calls `python3` itself (on Windows that name is often missing or
# the Microsoft Store stub, and on a Mac without the Command Line Tools it is Apple's stub).
#
# Windows without Git Bash runs hooks in PowerShell instead; there hooks/python.ps1 does the same
# job (see the note at its top on why each hooks.json command is two lines).
#
# Why (02.10.2026). A Mac without Apple's Command Line Tools still has /usr/bin/python3 - a stub
# that, when run, pops the "install developer tools?" window. A hook that simply ran `python3`
# threw that window at a beginner in the middle of a lesson, on every session start and on every
# file write. On Windows the same trap is the Microsoft Store stub, and python.org's Python there is
# called `python` or `py`, never `python3`. Linux may have no Python at all.
#
# So: on macOS, /usr/bin/python3 counts only when `xcode-select -p` names a developer folder that
# really holds python3 (that check never opens a window). Everywhere, a candidate counts only after
# `-c` proves it is Python 3.8+ (the Windows stub answers `-c` with an error, not with the Store).
# Nothing found: `say` prints one line for Claude (SessionStart puts stdout into Claude's context),
# `quiet` prints nothing; both exit 0, so the session goes on without this plugin - never an error,
# never a window. Stdin is untouched until the real script gets it through `exec`.
plugin=$1 mode=$2 script=$3
shift 3
case "$script" in
  /*|[A-Za-z]:[/\\]*) ;;
  *) script="$(cd "$(dirname "$0")/.." && pwd)/$script" ;;
esac

real() {   # real <command...>: is this a working Python 3.8+?
  "$@" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' </dev/null >/dev/null 2>&1
}

# The two overrides exist for the tests only (tests/test_step0.py): a fake Apple stub and a fake OS.
stub=${STEP0_APPLE_STUB:-/usr/bin/python3}
os=${STEP0_OS:-$(uname -s 2>/dev/null)}

# UTF-8 both ways for the real script: on Windows (Git Bash) Python would read the hook's JSON
# in the ANSI code page and garble every non-English file name.
PYTHONUTF8=1 PYTHONIOENCODING=utf-8
export PYTHONUTF8 PYTHONIOENCODING

PY=
case "$os" in
  Darwin)
    p=$(command -v python3 2>/dev/null)
    if [ -n "$p" ] && [ "$p" != "$stub" ]; then
      real "$p" && PY=$p
    elif [ -n "$p" ]; then
      dev=$(xcode-select -p 2>/dev/null)
      [ -n "$dev" ] && [ -x "$dev/usr/bin/python3" ] && real "$p" && PY=$p
    fi
    ;;
  MINGW*|MSYS*|CYGWIN*)
    # Windows (Git Bash): python.org's `python`, then the launcher `py -3`, then `python3` - the order
    # of hooks/python.ps1. `python` and `python3` may be the Store stub; `real` rules it out.
    p=$(command -v python 2>/dev/null) && real "$p" && PY=$p
    if [ -z "$PY" ] && command -v py >/dev/null 2>&1 && real py -3; then
      exec py -3 "$script" "$@"
    fi
    if [ -z "$PY" ]; then
      p=$(command -v python3 2>/dev/null) && real "$p" && PY=$p
    fi
    # A Python installed after Claude Code started: its PATH (and Git Bash's) is the one from before the
    # install until Claude Code restarts. Look where python.org's installer puts it, newest first - the
    # launcher, the per-user folders, the install paths in the registry - as hooks/python.ps1 does.
    if [ -z "$PY" ]; then
      la=$(cygpath -u "${LOCALAPPDATA:-}" 2>/dev/null)
      sr=$(cygpath -u "${SYSTEMROOT:-}" 2>/dev/null)
      for p in "${la:+$la/Programs/Python/Launcher/py.exe}" "${sr:+$sr/py.exe}"; do
        [ -n "$p" ] && [ -f "$p" ] && real "$p" -3 && exec "$p" -3 "$script" "$@"
      done
      pf=$(cygpath -u "${PROGRAMFILES:-}" 2>/dev/null)
      found=$(
        for d in "${la:-/nonexistent}"/Programs/Python/Python3* "${pf:-/nonexistent}"/Python3*; do
          [ -f "$d/python.exe" ] && printf '%s\t%s\n' "$(basename "$d" | tr -cd 0-9)" "$d/python.exe"
        done | sort -rn | cut -f2-
        for k in 'HKCU\Software\Python\PythonCore' 'HKLM\Software\Python\PythonCore' \
                 'HKLM\Software\WOW6432Node\Python\PythonCore'; do
          MSYS2_ARG_CONV_EXCL='*' reg.exe query "$k" /s /v ExecutablePath 2>/dev/null |
            sed -n 's/^ *ExecutablePath *REG_SZ *//p' | tr -d '\r' | sort -r |
            while IFS= read -r w; do cygpath -u "$w" 2>/dev/null; done
        done
      )
      while IFS= read -r p; do
        [ -n "$p" ] && [ -f "$p" ] && real "$p" && { PY=$p; break; }
      done <<EOF2
$found
EOF2
    fi
    ;;
  *)
    for c in python3 python; do
      p=$(command -v "$c" 2>/dev/null) || continue
      real "$p" && { PY=$p; break; }
    done
    if [ -z "$PY" ] && command -v py >/dev/null 2>&1 && real py -3; then
      exec py -3 "$script" "$@"
    fi
    ;;
esac

if [ -n "$PY" ]; then
  exec "$PY" "$script" "$@"
fi

if [ "$mode" = say ]; then
  echo "$plugin is paused: this computer has no working Python 3 yet, so $plugin does nothing for now. Tell the person in one line and do step 0 first (in the Poly A1 folder it is the first step of START-HERE): Mac - xcode-select --install, then press Install in Apple's window and wait 5-10 minutes; Windows - winget install -e --id Python.Python.3.12 --scope user; Linux - sudo apt-get install -y python3. No restart of Claude Code is needed after that."
fi
exit 0
