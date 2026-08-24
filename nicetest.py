r"""Process priority: set it and nothing moved.

Sixty-sixth coherence sweep. A miner renices itself -- to 19 to stay out
of the way of whoever owns the box, or negative to take more of it -- and
anyone hunting one looks at top's NI column. So: do the commands that set
and report priority agree?

  1. renice was `return "", 0`. No output, no effect. Real renice prints
     a line per target and the new value appears in ps, in top and in
     /proc/<pid>/stat. Nothing moved, and nothing said so.

  2. `ps -o pri` was the literal 20. On Linux pri is 19 - nice, so it was
     wrong even at nice 0, and it could not follow a renice that was not
     happening anyway.

  3. /proc/<pid>/stat carried the literals 20 and 0 for priority and
     nice. Priority there is 20 + nice, so once renice worked these two
     views of one number would still have disagreed.

  4. top's PR and NI columns were the literals 20 and 0 -- and top is
     where anyone watching a miner's CPU looks first.

  5. `taskset -p 701` answered "pid 1's current affinity mask" whatever
     pid it was given, so it reported on init. The mask was the literal
     f, right for a 4-CPU box by coincidence.

  6. chrt fell through to the unimplemented-binary handler, so
     `chrt -p PID` -- its ordinary use -- said "chrt: missing operand".

And one found while checking top: it printed 20 rows while its own header
said "Tasks: 28 total". A command contradicting itself in its own output,
with nginx and mariadb among the eight it left out. Batch top prints
every task, sorted by %CPU descending.

Reference measured on the dev host: renice -n 7 gives
"PID (process ID) old priority 0, new priority 7", after which
/proc/<pid>/stat reads "27 7" for fields 18 and 19 and `ps -o pri,ni`
reads "12 7".

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def shell(user="root"):
    s = fs.Shell(fs.VFS(), user=user, peer="203.0.113.77")
    s.exec_mode = True
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def out(s, cmd):
    o = s.run(cmd)
    o += "".join(s._err)
    s._err.clear()
    return o.strip()


def views(s, pid):
    """(ps ni, ps pri, stat priority, stat nice, top PR, top NI)."""
    ni, pri = out(s, "ps -o ni=,pri= -p %d" % pid).split()
    f18, f19 = out(s, "cut -d' ' -f18,19 /proc/%d/stat" % pid).split()
    top = out(s, "top -bn1 | grep -E '^ *%d ' | awk '{print $3, $4}'" % pid)
    tpr, tni = top.split() if top else ("", "")
    return ni, pri, f18, f19, tpr, tni


# -- at rest --------------------------------------------------------------

def t_a_normal_process_reads_nice_zero_everywhere():
    s = shell()
    ni, pri, f18, f19, tpr, tni = views(s, 701)
    eq("ps ni", ni, "0")
    eq("ps pri", pri, "19")
    eq("stat priority", f18, "20")
    eq("stat nice", f19, "0")
    eq("top PR", tpr, "20")
    eq("top NI", tni, "0")


def t_pri_is_nineteen_minus_nice():
    s = shell()
    for want in (0, 5, 10, 19, -5):
        out(s, "renice -n %d -p 701" % want)
        ni, pri, _a, _b, _c, _d = views(s, 701)
        eq("nice %d -> ni" % want, ni, str(want))
        eq("nice %d -> pri" % want, pri, str(19 - want))


# -- renice does something, and says so -----------------------------------

def t_renice_prints_the_transition():
    s = shell()
    eq("first", out(s, "renice -n 10 -p 701"),
       "701 (process ID) old priority 0, new priority 10")
    eq("second reports the old value", out(s, "renice -n 3 -p 701"),
       "701 (process ID) old priority 10, new priority 3")


def t_renice_reaches_all_four_views():
    s = shell()
    out(s, "renice -n 12 -p 701")
    ni, pri, f18, f19, tpr, tni = views(s, 701)
    eq("ps ni", ni, "12")
    eq("ps pri", pri, "7")
    eq("stat priority is 20+nice", f18, "32")
    eq("stat nice", f19, "12")
    eq("top PR", tpr, "32")
    eq("top NI", tni, "12")


def t_renice_only_touches_its_target():
    s = shell()
    out(s, "renice -n 15 -p 701")
    ni, pri, f18, f19, _c, _d = views(s, 884)
    eq("other ps ni", ni, "0")
    eq("other stat", "%s %s" % (f18, f19), "20 0")


def t_renice_clamps_to_the_legal_range():
    s = shell()
    out(s, "renice -n 99 -p 701")
    eq("clamped high", out(s, "ps -o ni= -p 701"), "19")
    out(s, "renice -n -99 -p 701")
    eq("clamped low", out(s, "ps -o ni= -p 701"), "-20")


def t_renice_on_a_pid_that_is_not_there():
    s = shell()
    o = out(s, "renice -n 5 -p 99999")
    check("reports it", "No such process" in o, o)


def t_renice_bad_usage():
    s = shell()
    o = out(s, "renice")
    check("usage", "usage" in o.lower(), o)


def t_only_root_may_lower_a_nice_value():
    s = shell()
    out(s, "renice -n 10 -p 701")
    d = shell(user="deploy")
    out(d, "renice -n 10 -p 701")
    o = out(d, "renice -n 2 -p 701")
    check("refused for deploy", "Permission denied" in o, o)
    o = out(s, "renice -n 2 -p 701")
    check("allowed for root", "new priority 2" in o, o)


# -- taskset reports the pid it was asked about ---------------------------

def t_taskset_names_the_right_pid():
    s = shell()
    for pid in (701, 884, 1):
        eq("taskset -p %d" % pid, out(s, "taskset -p %d" % pid),
           "pid %d's current affinity mask: f" % pid)


def t_the_mask_matches_the_cpu_count():
    s = shell()
    ncpu = int(out(s, "nproc"))
    mask = out(s, "taskset -p 701").rsplit(": ", 1)[1]
    eq("mask covers every cpu", mask, "%x" % ((1 << ncpu) - 1))


def t_taskset_on_a_pid_that_is_not_there():
    s = shell()
    o = out(s, "taskset -p 99999")
    check("reports it", "No such process" in o, o)


def t_taskset_still_runs_a_command():
    s = shell()
    eq("runs it", out(s, "taskset -c 0,1 echo pinned"), "pinned")


# -- chrt -----------------------------------------------------------------

def t_chrt_reports_the_policy():
    s = shell()
    o = out(s, "chrt -p 701")
    check("no missing operand", "missing operand" not in o, o)
    # Three, not two: the guest prints the runtime parameter as well, and
    # this had pinned the shorter shape. See schedtest.
    eq("three lines", len(o.splitlines()), 3)
    check("policy", "current scheduling policy: SCHED_OTHER" in o, o)
    check("priority", "current scheduling priority: 0" in o, o)
    check("runtime parameter", "current runtime parameter: 1400000" in o, o)
    check("names the pid", "pid 701's" in o, o)


def t_chrt_on_a_pid_that_is_not_there():
    s = shell()
    o = out(s, "chrt -p 99999")
    check("reports it", "No such process" in o, o)


# -- ionice and nice were already right -----------------------------------

def t_ionice_and_nice_unchanged():
    s = shell()
    eq("ionice -p", out(s, "ionice -p 701"), "none: prio 0")
    eq("bare nice", out(s, "nice"), "0")
    eq("nice runs a command", out(s, "nice -n 19 echo ran"), "ran")


# -- top's header and body agree ------------------------------------------

def t_top_lists_every_task_it_counts():
    s = shell()
    body = out(s, "top -bn1")
    m = re.search(r"Tasks:\s+(\d+) total", body)
    check("header parses", m is not None, body[:80])
    rows = len([l for l in body.splitlines() if re.match(r"^ *\d+ ", l)])
    eq("body matches the header", rows, int(m.group(1)))


def t_top_includes_the_daemons():
    s = shell()
    body = out(s, "top -bn1")
    for pid in (1, 701, 884):
        check("top lists pid %d" % pid,
              re.search(r"^ *%d " % pid, body, re.M) is not None,
              "pid %d missing" % pid)


def t_top_is_sorted_by_cpu():
    s = shell()
    body = out(s, "top -bn1")
    cpus = [float(l.split()[8]) for l in body.splitlines()
            if re.match(r"^ *\d+ ", l)]
    eq("descending", cpus, sorted(cpus, reverse=True))


TESTS = [t_a_normal_process_reads_nice_zero_everywhere,
         t_pri_is_nineteen_minus_nice, t_renice_prints_the_transition,
         t_renice_reaches_all_four_views, t_renice_only_touches_its_target,
         t_renice_clamps_to_the_legal_range,
         t_renice_on_a_pid_that_is_not_there, t_renice_bad_usage,
         t_only_root_may_lower_a_nice_value, t_taskset_names_the_right_pid,
         t_the_mask_matches_the_cpu_count,
         t_taskset_on_a_pid_that_is_not_there, t_taskset_still_runs_a_command,
         t_chrt_reports_the_policy, t_chrt_on_a_pid_that_is_not_there,
         t_ionice_and_nice_unchanged, t_top_lists_every_task_it_counts,
         t_top_includes_the_daemons, t_top_is_sorted_by_cpu]


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
