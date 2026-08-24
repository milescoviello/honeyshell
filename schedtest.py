#!/usr/bin/env python3
"""What priority is this process, and does changing it change anything?

Six commands read one scheduler state -- nice, renice, ionice, chrt,
taskset, ps -- and /proc/<pid>/stat holds the numbers all of them are
quoting. Some of them were reading it, some were reporting a constant, and
one was reporting success for a change nothing else could see.

    renice -n 7 -p $$     7 (process ID) old priority 0, new priority 7
    ps -o ni= -p $$       7
    top                   PR 27  NI 7
    nice                  0

`nice` with no arguments is the one command whose entire job is to print
the current nice, and it printed the literal 0 while the other three
agreed on 7.

The rest of the axis:

  * `nice -n N cmd` parsed N and threw it away, so a miner running
    `nice -n 19 ./miner` to stay out of the way, and then checking, saw
    nothing had happened.
  * `ionice -c3 -p N` and `ionice -p N` are the same command, and the read
    did not know about the write: both printed the constant
    "none: prio 0". Dropping a process to the idle class and confirming it
    is two lines of any install script.
  * `taskset -cp 1` printed "pid 4100's current affinity mask: f" -- the
    wrong format and the wrong pid. -c asks for the CPU list, and the
    clustered -cp left the pid looking like a command.
  * `chrt -p` printed two of the three lines the guest prints, and
    `chrt -m` -- how anything checks whether a real-time policy is even
    available -- answered "bad usage".
  * `ps -o cls` fell through to "-" on a box whose chrt reports
    SCHED_OTHER, which ps spells TS.
  * /proc/<pid>/stat was 50 fields where proc(5) defines 52 and the guest
    prints 52: nswap and cnswap were missing, so everything after them read
    two positions early and field 40, rt_priority, gave back the policy.

Reference output measured on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-58s %s" % (name, detail))


def sh():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    return s


S = sh()


def R(cmd, s=None):
    t = s or S
    t._err = []
    out = t.run(cmd)
    return out or "", "".join(t._err), t.last_rc


def statf(pid, field, s=None):
    line = R("cat /proc/%d/stat" % pid, s)[0].split()
    return line[field - 1] if len(line) >= field else None


# ---------------------------------------------------------------------------
# /proc/<pid>/stat is the shape everything else indexes into
# ---------------------------------------------------------------------------
def t_stat_has_the_fields_proc5_defines():
    for pid in (1, S.shell_pid):
        f = R("cat /proc/%d/stat" % pid)[0].split()
        check("pid %d's stat line has 52 fields" % pid, len(f) == 52,
              str(len(f)))
        check("pid %d: field 1 is the pid" % pid, f[0] == str(pid), f[0])
        check("pid %d: field 2 is the comm in brackets" % pid,
              f[1].startswith("(") and f[1].endswith(")"), f[1])
        check("pid %d: field 3 is a state letter" % pid,
              len(f[2]) == 1 and f[2].isalpha(), f[2])
        check("pid %d: rt_priority and policy are both 0" % pid,
              f[39] == "0" and f[40] == "0", "%s %s" % (f[39], f[40]))
        check("pid %d: exit_signal is SIGCHLD" % pid, f[37] == "17", f[37])
        check("pid %d: processor is a cpu this box has" % pid,
              f[38].isdigit() and int(f[38]) < 4, f[38])


def t_priority_and_nice_are_one_number():
    s = sh()
    pid = s.shell_pid
    check("nice starts at 0", R("nice", s)[0].strip() == "0",
          R("nice", s)[0].strip())
    check("stat's nice starts at 0", statf(pid, 19, s) == "0",
          statf(pid, 19, s))
    check("stat's priority is 20 plus nice", statf(pid, 18, s) == "20",
          statf(pid, 18, s))
    out, _e, rc = R("renice -n 7 -p %d" % pid, s)
    check("renice reports the change", rc == 0
          and "new priority 7" in out, out[:60])
    for name, got in (("nice", R("nice", s)[0].strip()),
                      ("ps -o ni", R("ps -o ni= -p %d" % pid, s)[0].strip()),
                      ("stat field 19", statf(pid, 19, s))):
        check("%s sees the new nice" % name, got == "7", got)
    check("stat's priority moved with it", statf(pid, 18, s) == "27",
          statf(pid, 18, s))
    check("ps's PRI is 19 minus nice",
          R("ps -o pri= -p %d" % pid, s)[0].strip() == "12",
          R("ps -o pri= -p %d" % pid, s)[0].strip())
    top = [l for l in R("top -bn1", s)[0].splitlines()
           if l.split()[:1] == [str(pid)]]
    check("top's PR and NI agree", top and top[0].split()[2:4] == ["27", "7"],
          (top or [""])[0][:40])


def t_nice_applies_its_increment():
    s = sh()
    pid = s.shell_pid
    got = R("nice -n 5 awk '{print $19}' /proc/%d/stat" % pid, s)[0].strip()
    check("nice -n 5 makes the child nice 5", got == "5", got)
    got = R("nice -n 19 awk '{print $18}' /proc/%d/stat" % pid, s)[0].strip()
    check("and priority follows it", got == "39", got)
    check("the increment does not stick after the command",
          R("nice", s)[0].strip() == "0", R("nice", s)[0].strip())
    # It is an increment, not an assignment: on top of a renice.
    R("renice -n 4 -p %d" % pid, s)
    got = R("nice -n 5 awk '{print $19}' /proc/%d/stat" % pid, s)[0].strip()
    check("nice -n adds to the current nice", got == "9", got)
    check("and is clamped at 19",
          R("nice -n 30 awk '{print $19}' /proc/%d/stat" % pid,
            s)[0].strip() == "19",
          R("nice -n 30 awk '{print $19}' /proc/%d/stat" % pid, s)[0].strip())
    # Bare `nice cmd` is an increment of 10.
    s2 = sh()
    got = R("nice awk '{print $19}' /proc/%d/stat" % s2.shell_pid,
            s2)[0].strip()
    check("bare nice uses the default increment of 10", got == "10", got)


def t_root_may_lower_a_nice_and_a_user_may_not():
    s = sh()
    R("renice -n 9 -p %d" % s.shell_pid, s)
    out, _e, rc = R("renice -n 2 -p %d" % s.shell_pid, s)
    check("root can lower a nice", rc == 0 and "new priority 2" in out,
          out[:50])
    check("and the readers followed",
          R("nice", s)[0].strip() == "2", R("nice", s)[0].strip())


# ---------------------------------------------------------------------------
# ionice: setting it and reading it are the same command
# ---------------------------------------------------------------------------
def t_ionice_remembers():
    s = sh()
    pid = s.shell_pid
    check("an unset process is none: prio 0",
          R("ionice -p %d" % pid, s)[0].strip() == "none: prio 0",
          R("ionice -p %d" % pid, s)[0].strip())
    out, _e, rc = R("ionice -c3 -p %d" % pid, s)
    check("setting the class says nothing and exits 0",
          (out, rc) == ("", 0), "%r rc=%s" % (out, rc))
    check("reading it back says idle",
          R("ionice -p %d" % pid, s)[0].strip() == "idle",
          R("ionice -p %d" % pid, s)[0].strip())
    R("ionice -c2 -n 7 -p %d" % pid, s)
    check("best-effort reports its class and priority",
          R("ionice -p %d" % pid, s)[0].strip() == "best-effort: prio 7",
          R("ionice -p %d" % pid, s)[0].strip())
    check("another process is unaffected",
          R("ionice -p 1", s)[0].strip() == "none: prio 0",
          R("ionice -p 1", s)[0].strip())
    out, err, rc = R("ionice -c9 -p %d" % pid, s)
    check("an unknown class is refused", rc == 1
          and "unknown scheduling class" in err, err[:50])


# ---------------------------------------------------------------------------
# taskset and chrt
# ---------------------------------------------------------------------------
def t_taskset_answers_about_the_pid_it_was_given():
    out = R("taskset -p 1")[0].strip()
    check("taskset -p names pid 1", out.startswith("pid 1's"), out[:40])
    check("and gives a mask", out.endswith("affinity mask: f"), out[-30:])
    out = R("taskset -cp 1")[0].strip()
    check("taskset -cp still names pid 1", out.startswith("pid 1's"),
          out[:40])
    check("and gives a list, not a mask",
          out.endswith("affinity list: 0-3"), out[-30:])
    check("-c -p spelled apart is the same",
          R("taskset -c -p 1")[0] == R("taskset -cp 1")[0], "differs")
    # The list has to be the CPUs the box says it has.
    ncpu = int(R("nproc")[0].strip())
    check("the list covers every CPU nproc counts",
          out.endswith("0-%d" % (ncpu - 1)), "%s vs nproc %d" % (out[-6:],
                                                                 ncpu))
    allowed = R("grep Cpus_allowed_list /proc/self/status")[0].split(":")[-1]
    check("and matches Cpus_allowed_list in /proc",
          allowed.strip() == "0-%d" % (ncpu - 1), allowed.strip())
    out, err, rc = R("taskset -p 999999")
    check("a pid that is not there is refused", rc == 1
          and "No such process" in err, err[:50])


def t_chrt_reports_the_policy():
    out, _e, rc = R("chrt -p 1")
    lines = out.splitlines()
    check("chrt -p exits 0", rc == 0, "rc=%s" % rc)
    check("it prints the guest's three lines", len(lines) == 3, str(lines))
    check("policy first", lines[0]
          == "pid 1's current scheduling policy: SCHED_OTHER", lines[:1])
    check("then priority", lines[1]
          == "pid 1's current scheduling priority: 0", lines[1:2])
    check("then the runtime parameter", lines[2]
          == "pid 1's current runtime parameter: 1400000", lines[2:3])
    # ...and it agrees with what /proc and ps say about the same process.
    check("the policy matches stat's policy field", statf(1, 41) == "0",
          statf(1, 41))
    check("the priority matches stat's rt_priority", statf(1, 40) == "0",
          statf(1, 40))
    check("and ps calls the class TS",
          R("ps -o cls= -p 1")[0].strip() == "TS",
          R("ps -o cls= -p 1")[0].strip())
    check("with no rtprio to show",
          R("ps -o rtprio= -p 1")[0].strip() == "-",
          R("ps -o rtprio= -p 1")[0].strip())
    out, _e, rc = R("chrt -m")
    check("chrt -m exits 0", rc == 0, "rc=%s" % rc)
    check("and lists the policies with their ranges",
          "SCHED_FIFO min/max priority\t: 1/99" in out
          and "SCHED_OTHER min/max priority\t: 0/0" in out, out[:60])
    check("SCHED_OTHER's range agrees with the priority chrt -p reported",
          out.startswith("SCHED_OTHER min/max priority\t: 0/0"), out[:40])


TESTS = [t_stat_has_the_fields_proc5_defines,
         t_priority_and_nice_are_one_number,
         t_nice_applies_its_increment,
         t_root_may_lower_a_nice_and_a_user_may_not,
         t_ionice_remembers,
         t_taskset_answers_about_the_pid_it_was_given,
         t_chrt_reports_the_policy]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
