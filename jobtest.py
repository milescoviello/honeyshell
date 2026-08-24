#!/usr/bin/env python3
"""Does the shell know about the jobs it just started?

Tenth coherence sweep. Loaders background things constantly -- `./payload &`,
`nohup ./x >/dev/null 2>&1 &`, `do_dl & wait` -- so the question is whether a
shell that has just forked a job can name it, and whether the rest of the
line still runs.

Found in one pass:

  * `&` was only handled when it ended the whole line. `sleep 3 & jobs`
    passed "&" to sleep as an argument -- "sleep: invalid time interval '&'"
    -- and `./payload & echo ok` is the standard loader shape. It is a list
    separator now, like `;`, with the segment before it backgrounded.
  * Making it a separator meant splitting on `&`, which split `2>&1` in half
    and turned `cmd >/dev/null 2>&1 &` into three segments. A `&` is a
    control operator only when the character before it is not < or > and the
    one after it is not >.
  * `jobs` printed nothing, on a shell that had just forked a job.
  * `kill %1` answered "arguments must be process or job IDs" immediately
    after creating job 1.
  * A later `cmd_jobs` stub returning ("", 0) shadowed the real one -- two
    definitions of the same method in one class, and Python takes the last.

The reference is the real bash on this host, with pids masked.
"""

import re
import subprocess
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

# Short sleeps: real bash waits for its background jobs before the pipe
# closes, so a long one hangs the reference rather than the emulator.
CASES = [
    "sleep 3 & jobs; kill %1 2>/dev/null",
    "sleep 3 & jobs %1; kill %1 2>/dev/null",
    "sleep 3 & jobs -p | grep -cE '^[0-9]+$'; kill %1 2>/dev/null",
    "sleep 3 & kill %1; echo rc=$?",
    "sleep 3 & kill %+; echo rc=$?",
    "sleep 3 & sleep 4 & jobs; kill %1 %2 2>/dev/null",
    "kill %9 2>&1; echo rc=$?",
    "sleep 3 & disown; jobs; echo after",
    "sleep 3 & echo pid-set=$([ -n \"$!\" ] && echo yes); kill %1 2>/dev/null",
    "sleep 0.1 & wait; echo done",
    "nohup sleep 3 >/dev/null 2>&1 & echo started; kill %1 2>/dev/null",
    "echo first & echo second",
    "true & echo after-true",
    # the redirection forms that must not be mistaken for a control operator
    "echo x 2>&1 | cat",
    "echo x >/dev/null 2>&1; echo rc=$?",
    "sleep 3 >/dev/null 2>&1 & echo bg; kill %1 2>/dev/null",
    "echo y &> /dev/null; echo rc=$?",
    "echo z 1>&2 2>/dev/null; echo rc=$?",
    "echo \"a & b\"",
    "echo 'x&y'",
]


def norm(text):
    """Mask pids: they differ by construction."""
    return re.sub(r"\b\d{3,7}\b", "PID", text)


def main():
    verbose = "-v" in sys.argv
    ok = bad = skip = 0
    for snip in CASES:
        try:
            r = subprocess.run(["bash", "--noprofile", "--norc", "-c", snip],
                               capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            skip += 1
            continue
        sh = fs.Shell(fs.VFS())
        sh.exec_mode = True
        got = sh.run(snip)
        sh._err.clear()
        if norm(got) == norm(r.stdout):
            ok += 1
            if verbose:
                print("  ok   %-48s %r" % (snip[:48], got[:32]))
        else:
            bad += 1
            print("  DIFF %-48s" % snip[:48])
            print("       real %r" % norm(r.stdout)[:64])
            print("       ours %r" % norm(got)[:64])

    # ---- and the job the shell reports has to be in its own process table
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.run("sleep 300 &")
    checks = [
        ("the job table has one entry", len(sh.jobs) == 1),
        ("$! matches the job's pid",
         sh.jobs and sh.vars.get("!") == str(sh.jobs[0]["pid"])),
        ("ps shows a process with that pid",
         sh.jobs and sh.run("ps -o pid= -p %d" % sh.jobs[0]["pid"]).strip()
         == str(sh.jobs[0]["pid"])),
        ("ps shows it as sleep",
         "sleep" in sh.run("ps -o comm= -p %d"
                           % sh.jobs[0]["pid"]) if sh.jobs else False),
        ("jobs names it Running", "Running" in sh.run("jobs")),
        ("kill %1 succeeds", sh.run("kill %1; echo rc=$?").strip() == "rc=0"),
        ("after the kill jobs is empty", sh.run("jobs").strip() == ""),
    ]
    for name, cond in checks:
        if cond:
            ok += 1
            if verbose:
                print("  ok   %s" % name)
        else:
            bad += 1
            print("  DIFF %s" % name)

    print()
    print("=" * 60)
    print("%d/%d match  (%d differ, %d skipped)"
          % (ok, ok + bad, bad, skip))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
