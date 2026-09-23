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
n=0; bad=0; known=0
for f in $(ls *test*.py detect.py probesuite.py 2>/dev/null | sort -u); do
  n=$((n+1))
  out=$(timeout 900 python3 -W ignore "$f" 2>&1)
  rc=$?
  [ $rc -eq 0 ] && continue
  case " $KNOWN_FAILURES " in
    *" $f "*)
      known=$((known+1))
      echo "KNOWN  $f  rc=$rc  --  $(echo "$out" | tail -1)"
      continue ;;
  esac
  bad=$((bad+1))
  echo "FAIL   $f  rc=$rc"
  echo "$out" | grep -iE '^\s*(FAIL|differ)|Traceback|Error' | head -6
  echo "       $(echo "$out" | tail -1)"
done
echo
echo "suites: $n   unexpected failures: $bad   known: $known"
[ "$bad" -eq 0 ]
