#!/bin/bash
# Run every suite. Exit non-zero if any UNEXPECTED one fails.
#
# One suite is expected to fail and says so out loud rather than being
# skipped: awktest.py differs from GNU awk on `gsub(/a/, "\\&")` -- see
# "The one known failure" in docs/testing.md. Listing it here keeps CI green
# without hiding it, and an unexpected failure still turns the build red.
# Silencing a known failure by skipping the suite would also hide the other
# 89 cases it checks.
#
# KNOWN_FAILURES can be overridden to run with nothing tolerated:
#   KNOWN_FAILURES= ./run-suites.sh
: "${KNOWN_FAILURES=awktest.py}"

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
