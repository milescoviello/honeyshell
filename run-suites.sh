#!/bin/bash
# Run every suite. Exit non-zero if any of them does.
#
# A suite prints its own summary line last; this only reports the ones that
# failed, because 139 passing summaries scroll the failures off the screen.
cd "$(dirname "$0")" || exit 1
rm -rf __pycache__
n=0; bad=0
for f in $(ls *test*.py detect.py probesuite.py 2>/dev/null | sort -u); do
  n=$((n+1))
  out=$(timeout 900 python3 -W ignore "$f" 2>&1)
  rc=$?
  if [ $rc -ne 0 ]; then
    bad=$((bad+1))
    echo "== $f  rc=$rc"
    echo "$out" | grep -iE '^\s*(FAIL|differ)|Traceback|Error' | head -6
    echo "   $(echo "$out" | tail -1)"
  fi
done
echo "SUITES: $n  FAILED: $bad"
[ "$bad" -eq 0 ]
