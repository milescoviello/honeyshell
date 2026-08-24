#!/usr/bin/env python3
"""Naming a background job: do %+, %-, %N and %prefix all resolve?

Thirty-eighth coherence sweep. The axis is job control -- how a shell
names the things it has put in the background -- picked because
daemonising without systemd is the other half of persistence, and
`./miner &` followed by `disown` is how it is done when there is no unit
file to write.

_job_by_spec already understood %+, %-, %N and a command prefix. cmd_jobs
did not use it: it matched the literal string "%N" and nothing else, so

    jobs %+      printed nothing
    jobs %-      printed nothing
    jobs %sle    printed nothing
    jobs %9      printed nothing, and exited 0

and the one spec it did handle came back mislabelled. With two jobs
running, `jobs` prints "[1]-" for the first, but `jobs %1` printed
"[1]+" -- the marker was recomputed over the filtered list rather than
the whole table, so the shell contradicted itself about which job was
current depending on how you asked.

Two more:

  * `jobs -l` omitted the pid. That is the only column that flag exists
    to add.
  * bare `disown` emptied the whole job table. It drops the *current*
    job; -a is the one that means all. Clearing everything meant a single
    disown orphaned every background job the session had -- jobs went
    empty while the processes were still in ps -- and made disown and
    disown -a indistinguishable.

Measured but deliberately not changed: `kill %1` and `setsid`. Both
behave differently under a non-interactive shell, which is what an ssh
exec channel is, and the reference runs did not separate that cleanly
from the emulator's behaviour. Guessing at them would be worse than
leaving them measured and alone.

Reference measured on the guest, as root, one bash -c per case so job
numbering starts fresh:

    sleep 30 & jobs -l                  [1]+ 34501 Running sleep 30 &
    sleep 30 & sleep 31 & jobs          [1]- ... / [2]+ ...
    sleep 30 & sleep 31 & jobs %+       [2]+  Running sleep 31 &
    sleep 30 & sleep 31 & jobs %-       [1]-  Running sleep 30 &
    sleep 30 & sleep 31 & jobs %1       [1]-  Running sleep 30 &
    sleep 30 & jobs %sle                [1]+  Running sleep 30 &
    jobs %9                             bash: jobs: %9: no such job
    sleep 30 & sleep 31 & disown; jobs  [1]+  Running sleep 30 &
    sleep 30 & sleep 31 & disown -a     (nothing)

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def run(script):
    """One shell per case: jobs accumulate, and sharing a shell is how a
    first pass at this misread its own leftovers."""
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    out = s.run(script)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def line(out, n=0):
    ls = [l for l in out.strip().split("\n") if l.strip()]
    return ls[n] if len(ls) > n else ""


# -- listing -------------------------------------------------------------

def t_one_job():
    out, rc = run("sleep 30 & jobs")
    eq("rc 0", rc, 0)
    check("marked current", line(out).startswith("[1]+"), out)
    check("shows the command", "sleep 30 &" in out, out)
    check("running", "Running" in out, out)


def t_two_jobs_are_marked_minus_and_plus():
    out, _ = run("sleep 30 & sleep 31 & jobs")
    check("first is previous", line(out, 0).startswith("[1]-"), out)
    check("second is current", line(out, 1).startswith("[2]+"), out)


def t_jobs_l_carries_the_pid():
    out, _ = run("sleep 30 & jobs -l")
    m = re.match(r"^\[1\]\+ (\d+) +Running", line(out))
    check("pid column present", m is not None, out)
    if m:
        pid_only, _ = run("sleep 30 & jobs -p")
        eq("and matches jobs -p", m.group(1), pid_only.strip())


def t_jobs_p_is_just_pids():
    out, _ = run("sleep 30 & jobs -p")
    check("a bare number", out.strip().isdigit(), out)


# -- naming --------------------------------------------------------------

def t_percent_plus_is_the_current_job():
    out, rc = run("sleep 30 & sleep 31 & jobs %+")
    eq("rc 0", rc, 0)
    check("names job 2", line(out).startswith("[2]+"), out)
    check("with its command", "sleep 31 &" in out, out)


def t_percent_minus_is_the_previous_job():
    out, rc = run("sleep 30 & sleep 31 & jobs %-")
    eq("rc 0", rc, 0)
    check("names job 1", line(out).startswith("[1]-"), out)
    check("with its command", "sleep 30 &" in out, out)


def t_percent_number():
    out, _ = run("sleep 30 & sleep 31 & jobs %1")
    check("job 1 is still marked previous",
          line(out).startswith("[1]-"), out)
    out, _ = run("sleep 30 & sleep 31 & jobs %2")
    check("job 2 is still marked current",
          line(out).startswith("[2]+"), out)


def t_the_marker_does_not_depend_on_how_you_ask():
    """`jobs` and `jobs %1` must agree about job 1."""
    both, _ = run("sleep 30 & sleep 31 & jobs")
    one, _ = run("sleep 30 & sleep 31 & jobs %1")
    eq("same line either way", line(one), line(both, 0))


def t_percent_prefix():
    out, rc = run("sleep 30 & jobs %sle")
    eq("rc 0", rc, 0)
    check("prefix names the job", line(out).startswith("[1]+"), out)


def t_unknown_jobspec_says_so():
    out, rc = run("jobs %9")
    check("bash's wording", "jobs: %9: no such job" in out, out)
    eq("rc 1", rc, 1)
    out, rc = run("sleep 30 & jobs %nosuch")
    check("prefix that matches nothing", "no such job" in out, out)
    eq("rc 1 there too", rc, 1)


# -- disown --------------------------------------------------------------

def t_bare_disown_drops_only_the_current_job():
    out, rc = run("sleep 30 & sleep 31 & disown; jobs")
    eq("rc 0", rc, 0)
    check("job 1 survives", line(out).startswith("[1]"), out)
    check("and it is sleep 30", "sleep 30 &" in out, out)
    check("job 2 is gone", "sleep 31" not in out, out)


def t_disown_a_drops_everything():
    out, rc = run("sleep 30 & sleep 31 & disown -a; jobs")
    eq("rc 0", rc, 0)
    eq("nothing left", out.strip(), "")


def t_disown_by_spec():
    out, _ = run("sleep 30 & sleep 31 & disown %1; jobs")
    check("job 1 removed", "sleep 30" not in out, out)
    check("job 2 remains", "sleep 31" in out, out)


def t_disown_then_jobs_is_empty_only_once():
    """One disown must not orphan the whole table."""
    out, _ = run("sleep 30 & sleep 31 & sleep 32 & disown; jobs")
    lines = [l for l in out.strip().split("\n") if l.strip()]
    eq("two of three survive", len(lines), 2)


# -- the shape a loader uses ---------------------------------------------

def t_background_then_disown_leaves_it_running():
    """`./miner & disown` is daemonising without a unit file."""
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    s.run("mkdir -p /tmp/m; printf '#!/bin/sh\\nsleep 999\\n' > /tmp/m/miner; "
          "chmod 755 /tmp/m/miner")
    s._err.clear()
    s.run("/tmp/m/miner & disown")
    s._err.clear()
    jobs = s.run("jobs")
    s._err.clear()
    eq("the job is disowned", jobs.strip(), "")
    ps = s.run("ps aux")
    s._err.clear()
    check("but the process is still there", "/tmp/m/miner" in ps,
          ps[-200:])


def t_wait_returns():
    out, rc = run("sleep 1 & wait; echo waited=$?")
    check("wait completes", "waited=0" in out, out)
    eq("rc 0", rc, 0)


TESTS = [t_one_job, t_two_jobs_are_marked_minus_and_plus,
         t_jobs_l_carries_the_pid, t_jobs_p_is_just_pids,
         t_percent_plus_is_the_current_job,
         t_percent_minus_is_the_previous_job, t_percent_number,
         t_the_marker_does_not_depend_on_how_you_ask, t_percent_prefix,
         t_unknown_jobspec_says_so,
         t_bare_disown_drops_only_the_current_job,
         t_disown_a_drops_everything, t_disown_by_spec,
         t_disown_then_jobs_is_empty_only_once,
         t_background_then_disown_leaves_it_running, t_wait_returns]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
