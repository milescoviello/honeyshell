#!/bin/bash
# Run every suite. Exit non-zero if any UNEXPECTED one fails.
#
# One suite is expected to fail on Debian 13, and says so out loud rather
# than being skipped: scripttest.py, where 3 of its 423 cases differ from
# Python 3.13.5 in how an uncaught exception's traceback is formatted under
# `python3 -c`. See "Known failures" in docs/testing.md. Listing it here
# keeps CI green without hiding it; any other failure still turns the build
# red, and skipping the suite instead would hide the 420 cases that pass.
#
# awktest.py used to be the listed one. It is fixed -- 97/97 against the
# reference awk, 47/47 against mawk 1.3.4 -- and is no longer tolerated.
#
# KNOWN_FAILURES can be overridden to run with nothing tolerated:
#   KNOWN_FAILURES= ./run-suites.sh
: "${KNOWN_FAILURES=scripttest.py}"

# Refuse to run twice at once: the first thing this does is delete
# __pycache__ out from under anything already importing, and the differential
# suites each build a temp tree that a concurrent run will race.
LOCK=/tmp/honeyshell-suites.lock
if command -v flock >/dev/null 2>&1; then
  exec 9>"$LOCK" || exit 1
  if ! flock -n 9; then
    echo "refusing: another suite run already holds $LOCK" >&2
    exit 2
  fi
fi

cd "$(dirname "$0")" || exit 1
rm -rf __pycache__
# Concurrent interpreters writing the same .pyc is a race nobody needs, and a
# suite that dies on a signal should say where rather than just "rc=139".
export PYTHONDONTWRITEBYTECODE=1 PYTHONFAULTHANDLER=1

# One suite at a time took over an hour in CI. Most suites share nothing but
# the emulator module, so they run in a pool; the ones below run first and
# alone, because their assertions are about timing, load or scheduling, and a
# loaded machine is exactly what makes those flaky. The list is copied from
# the private gate at publish time rather than maintained twice.
#
#   JOBS=1 ./run-suites.sh     everything serially, as it used to run
SERIAL="accttest.py chantest.py ciphertest.py corescattertest.py crosstest.py capturetest.py deploytest.py detect.py doortest.py ifaceleaktest.py libdeptest.py maxauthtest.py probesuite.py replaytest.py rotwindowtest.py selfstatetest.py sftpexttest.py sftplstest.py sftptest.py stamptest.py tunneltest.py uploadmemtest.py concurtest.py fsbudgettest.py"
: "${JOBS:=$(nproc 2>/dev/null || echo 2)}"

WORK=$(mktemp -d) || exit 1
trap 'rm -rf "$WORK"' EXIT
export WORK
# Straight to a file, never through $(...): some suites print NUL bytes, and
# bash drops those from a command substitution with a warning per suite.
run_one() {
  timeout 900 python3 -W ignore "$1" > "$WORK/$1.out" 2>&1
  echo $? > "$WORK/$1.rc"
}
export -f run_one

LIST=$(ls *test*.py detect.py probesuite.py 2>/dev/null | sort -u)
ser=""; par=""
for f in $LIST; do
  case " $(echo $SERIAL) " in
    *" $f "*) ser="$ser $f" ;;
    *)        par="$par $f" ;;
  esac
done
for f in $ser; do run_one "$f"; done
printf '%s\n' $par | xargs -r -P "$JOBS" -I{} bash -c 'run_one "$1"' _ {}

# Reported in name order, not finishing order, so two runs diff cleanly.
n=0; bad=0; known=0
for f in $LIST; do
  n=$((n+1))
  rc=$(cat "$WORK/$f.rc" 2>/dev/null || echo 255)
  [ "$rc" -eq 0 ] && continue
  last=$(tr -d '\000' < "$WORK/$f.out" | tail -1)
  case " $KNOWN_FAILURES " in
    *" $f "*)
      known=$((known+1))
      echo "KNOWN  $f  rc=$rc  --  $last"
      continue ;;
  esac
  bad=$((bad+1))
  echo "FAIL   $f  rc=$rc"
  tr -d '\000' < "$WORK/$f.out" | grep -aiE '^\s*(FAIL|differ)|Traceback|Error' | head -6
  echo "       $last"
done
echo
echo "suites: $n   unexpected failures: $bad   known: $known   (pool width $JOBS)"
[ "$bad" -eq 0 ]
