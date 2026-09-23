#!/usr/bin/env python3
"""When did this process start, and do all the readers agree?

203.0.113.63 uploaded a 30MB implant on 2026-08-25 and ran

    chmod +x ./.4248086081489418656/sshd;nohup ./.4248086081489418656/sshd &

The first thing anybody does after that is look at their own process. This
box gave two different answers about when anything started.

Five readers, and they came from two tables:

  * `ps -o etime` / `-o start`  read proc_meta[pid]["start"]
  * `ps -o lstart`              was a hardcoded BOOT_TS for every process
  * `stat /proc/<pid>`          BOOT_TS
  * `stat /proc/<pid>/exe`      BOOT_TS
  * /proc/<pid>/stat field 22   (pid % 97) * 100 + 250

The last one is worth staring at: the process's start time in clock ticks
was computed *from its pid*. And self.fs.proc_started already held the right
answer for the session's own processes -- it was populated on every resync
and read by nothing except the fd-link timestamps.

What that produced:

  * `w` said the login was at 08:30 and `ps -p $$ -o etime` said 41 days,
    for the same shell. One command each, and the obvious pair to run.
  * `ps -eo lstart,etime` printed a start 41 days ago beside an elapsed time
    of 00:00 -- which cannot happen, and those are the two columns anyone
    puts side by side precisely to catch it.
  * `stat /proc/<pid>/exe` dated a just-launched implant to six weeks ago.
  * the standard hand calculation, `uptime - $22/100`, gave ~29 seconds for
    a shell ps said had been up 41 days.

So the checks here are mostly *cross-reader*: they do not assert a
particular start time, they assert that the answers cannot disagree. A
persona with a different boot time or uptime still has to satisfy them.

Usage:  python3 procstarttest.py
"""

import re
import sys
import time

import fakeshell as F

CHECKS, FAILS = [], []
TOL = 4          # seconds; these are wall-clock reads a few calls apart


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def near(name, a, b, tol=TOL):
    ok = a is not None and b is not None and abs(a - b) <= tol
    CHECKS.append(name)
    if not ok:
        FAILS.append((name, a, b))


def sh():
    return F.Shell()


def lstart_epoch(text):
    """ps -o lstart= is 'Www Mmm _d HH:MM:SS YYYY', printed in UTC here."""
    try:
        return time.mktime(time.strptime(" ".join(text.split()),
                                         "%a %b %d %H:%M:%S %Y"))
    except ValueError:
        return None


def num(text):
    try:
        return float(str(text).strip())
    except (TypeError, ValueError):
        return None


def etime_secs(text):
    """[[DD-]HH:]MM:SS -> seconds."""
    text = (text or "").strip()
    m = re.match(r"^(?:(\d+)-)?(?:(\d+):)?(\d+):(\d+)$", text)
    if not m:
        return None
    d, h, mi, s = (int(x) if x else 0 for x in m.groups())
    return d * 86400 + h * 3600 + mi * 60 + s


def launch_implant(s):
    """The shape from the capture: chmod +x, then nohup ... &."""
    s.run("mkdir -p /root/.stage; echo payload > /root/.stage/sshd; "
          "chmod +x /root/.stage/sshd")
    s.run("cd /root/.stage && nohup ./sshd &")
    for line in s.run("pgrep -a sshd").splitlines():
        if "./sshd" in line:
            return line.split()[0]
    return None


def readers(s, pid):
    """Every answer the box gives for one process's start."""
    return {
        "etime": etime_secs(s.run("ps -p %s -o etime=" % pid)),
        "lstart": lstart_epoch(s.run("ps -p %s -o lstart=" % pid)),
        "procdir": num(s.run("stat -c %%Y /proc/%s" % pid)),
        "exe": num(s.run("stat -c %%Y /proc/%s/exe" % pid)),
        "ticks": num(s.run("cut -d' ' -f22 /proc/%s/stat" % pid)),
        "uptime": num(s.run("cut -d' ' -f1 /proc/uptime")),
    }


def agree(label, s, pid):
    """The invariant: every reader has to describe the same instant."""
    r = readers(s, pid)
    now = time.time()
    for k in ("etime", "lstart", "procdir", "ticks", "uptime"):
        check("%s: %s is readable" % (label, k), r[k] is not None, True)
    if None in (r["etime"], r["lstart"]):
        return r
    # lstart and etime are the pair a human compares.
    near("%s: lstart + etime == now" % label, r["lstart"] + r["etime"], now,
         TOL + 2)
    if r["procdir"] is not None:
        near("%s: /proc/<pid> mtime is the start" % label,
             r["procdir"], r["lstart"])
    if r["exe"] is not None:
        near("%s: /proc/<pid>/exe mtime is the start" % label,
             r["exe"], r["lstart"])
    if None not in (r["ticks"], r["uptime"]):
        # The standard hand calculation.
        near("%s: uptime - ticks/100 == etime" % label,
             r["uptime"] - r["ticks"] / 100.0, r["etime"], TOL + 2)
    return r


def t_the_session_shell():
    """`w` and `ps` on your own shell must not disagree by six weeks."""
    s = sh()
    r = agree("session shell", s, s.run("echo $$").strip())
    check("the shell has not been running for weeks",
          r["etime"] is not None and r["etime"] < 600, True)

    # And against w's LOGIN@ column, which was right all along.
    rows = [l.split() for l in s.run("w").splitlines()[2:] if l.split()]
    if rows and r["lstart"]:
        hhmm = time.strftime("%H:%M", time.localtime(r["lstart"]))
        check("w's LOGIN@ matches the shell's start",
              any(hhmm in c for c in rows[0]), True)


def t_a_boot_time_daemon():
    """The other end: something that really did start at boot."""
    s = sh()
    r = agree("boot daemon", s, "412")
    check("a boot daemon is old", r["etime"] is not None
          and r["etime"] > 3600, True)
    if r["lstart"] is not None:
        near("its start is the boot", r["lstart"], F.BOOT_TS, 90)


def t_a_process_the_attacker_launched():
    """nohup ./sshd & -- the shape from the capture."""
    s = sh()
    pid = launch_implant(s)
    check("the launched process is visible to pgrep", pid is not None, True)
    if not pid:
        return
    r = agree("implant", s, pid)
    check("it started just now",
          r["etime"] is not None and r["etime"] < 60, True)
    # ps and /proc have to agree it exists at all, not just when it began.
    check("ps -p finds it", pid in s.run("ps -p %s" % pid), True)
    check("/proc has it", s.run("ls -d /proc/%s" % pid).strip(),
          "/proc/%s" % pid)
    check("kill -0 succeeds",
          s.run("kill -0 %s >/dev/null 2>&1; echo $?" % pid).strip(), "0")


def t_no_process_contradicts_itself():
    """Across the whole table: lstart + etime == now, for everything.

    This is the check that would have caught it without knowing which
    process to look at.
    """
    s = sh()
    launch_implant(s)
    now = time.time()
    bad = []
    out = s.run("ps -eo pid=,lstart=,etime=")
    for line in out.splitlines():
        f = line.split()
        if len(f) < 7:
            continue
        pid = f[0]
        ls = lstart_epoch(" ".join(f[1:6]))
        et = etime_secs(f[6])
        if ls is None or et is None:
            continue
        if abs((ls + et) - now) > 90:
            bad.append((pid, f[6], time.strftime("%b %d %H:%M",
                                                 time.localtime(ls))))
    check("no process has a start that contradicts its elapsed time",
          bad[:6], [])


def t_starttime_is_not_derived_from_the_pid():
    """field 22 was (pid % 97) * 100 + 250. Two pids, one ordering."""
    s = sh()
    pid = launch_implant(s)
    if not pid:
        return
    young = num(s.run("cut -d' ' -f22 /proc/%s/stat" % pid))
    old = num(s.run("cut -d' ' -f22 /proc/412/stat"))
    check("a newly started process has a later starttime than a boot daemon",
          young is not None and old is not None and young > old, True)
    # And the pid-derived formula must not reproduce it.
    if young is not None:
        check("starttime is not the old pid formula",
              int(young) != int((int(pid) % 97) * 100 + 250), True)


def t_nothing_starts_at_tick_zero():
    """No process on a real box has starttime 0, and they are staggered.

    /proc/<pid>/stat field 22 is ticks-since-boot, and every process that
    was not in the start table defaulted to the boot instant itself -- 481
    of this box's 493 processes reporting the identical tick 0, a value no
    real /proc ever shows. On the guest pid 1 is 8, pid 2 is 8, pid 3
    through 27 sit at 19 while the early kernel threads come up, pid 213 is
    111 and pid 588 is 434. The ordering is information: later pid, later
    start.
    """
    s = sh()
    zero, total, ticks = 0, 0, {}
    for line in s.run("ls /proc").split():
        if not line.isdigit():
            continue
        st = s.run("awk '{print $22}' /proc/%s/stat" % line).strip()
        if not st.isdigit():
            continue
        total += 1
        ticks[int(line)] = int(st)
        if st == "0":
            zero += 1
    check("there are processes to check", total > 100, True)
    check("no process starts at tick 0", zero, 0)
    # The three the guest pins exactly.
    for pid, want in ((1, 8), (2, 8), (213, 111)):
        if pid in ticks:
            check("pid %d starts at tick %d, as on the guest" % (pid, want),
                  ticks[pid], want)
    # Monotonic in pid, across every process. Without a pid wrap -- pid_max
    # is 4194304 against a highest pid of 21435 -- a process created later
    # cannot have started earlier, and the guest gives 0 out-of-order over
    # all 104 of its own. This covered only the boot-time range while the
    # workload table was ordered wrongly: the services held 21421/21428/
    # 21435 while being the oldest things on the box, which `ps -eo
    # pid,lstart --sort=pid` showed in one screen.
    #
    # Processes that predate this session only. The session's own pids are
    # a separate, older question: this shell is 4100 while the workload
    # sits at 21400+, so the newest process on the box holds a lower pid
    # than things started days ago. That one is entangled with the fork
    # counter in /proc/stat and is queued on its own.
    up_ticks = int(float(s.run("cut -d. -f1 /proc/uptime").strip() or 0)) * 100
    order = sorted(p for p, t in ticks.items() if up_ticks - t > 60000)
    bad = [p for a, p in zip(order, order[1:]) if ticks[p] < ticks[a]]
    check("starttime never decreases as pid increases", bad, [])
    # The workload range has to be in the comparison, but not every pid in
    # it: the hourly job is minutes old by design and drops out of the
    # "predates this session" filter for part of each hour.
    check("the comparison covered the workload pids",
          max(order) > 21000, True)
    # And the boot-time ones must not all share a value, which is what
    # made the old behaviour visible in one glance.
    boot = [t for p, t in ticks.items() if t < 100000]
    check("boot-time processes are staggered, not identical",
          len(set(boot)) > 5, True)


def t_proc_and_ps_agree_on_age():
    """`uptime - starttime/100` is how you age a process by hand.

    It has to land on what ps says. Introducing the stagger above broke
    this first: ps read its default from _proc_start and /proc/<pid>/stat
    computed its own, so the two drifted apart by up to six seconds on
    every boot-time process. One default, consulted by both.
    """
    # One shell pass, not a Python loop calling out per process: reading
    # uptime once and then spending seconds in subprocess calls makes the
    # baseline stale and every late comparison looks two seconds off. That
    # is a measurement artifact, and it cost a false failure here first.
    s = sh()
    out = s.run(
        '''up=$(cut -d. -f1 /proc/uptime); bad=0; n=0
for d in /proc/[0-9]*; do p=${d#/proc/}
  st=$(awk '{print $22}' $d/stat 2>/dev/null); [ -z "$st" ] && continue
  et=$(ps -o etimes= -p $p 2>/dev/null | tr -d " "); [ -z "$et" ] && continue
  n=$((n+1)); c=$((up - st/100)); df=$((c - et)); a=${df#-}
  [ "$a" -gt 1 ] && bad=$((bad+1))
done; echo "$n $bad"''')
    parts = out.split()
    checked = int(parts[0]) if parts and parts[0].isdigit() else 0
    bad = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else -1
    check("enough processes compared", checked > 50, True)
    check("/proc and ps agree on every process's age", bad, 0)


def t_pid_order_holds_as_the_box_ages():
    """The ordering has to survive uptime, not just today's uptime.

    This tree sits at exactly REF_UPTIME, where an age-anchored job's start
    is still fresh; the deployed box had 15.7 days more, where the same
    anchor has receded that far into the past. So the local check passed
    while `ps -eo pid,lstart --sort=pid` on the live box showed pid 21435
    starting two weeks before pid 21428 -- a check that is green here and
    wrong there is worse than no check.

    Asserted against the job table directly at several simulated uptimes,
    because a Shell cannot be built at an arbitrary boot time without
    disagreeing with itself about everything else.
    """
    import workload as wl
    import fakeshell as F2
    orig = F2.BOOT_TS
    try:
        for extra_days in (0, 1, 15.7, 60, 365):
            F2.BOOT_TS = orig - int(extra_days * 86400)
            rows = sorted(wl.active(), key=lambda j: j["pid"])
            check("uptime REF+%gd: the table has jobs" % extra_days,
                  len(rows) > 3, True)
            bad, prev = [], None
            for j in rows:
                if prev is not None and j["started"] < prev - 1:
                    bad.append(j["pid"])
                prev = j["started"]
            check("uptime REF+%gd: pid order tracks start order" % extra_days,
                  bad, [])
            # ...and a recurring job stays recurring-sized. An hourly
            # builder reported 15.7 days of ELAPSED on the live box.
            for j in rows:
                if j.get("name") == "prep":
                    age = time.time() - j["started"]
                    check("uptime REF+%gd: the hourly job is under an hour "
                          "old" % extra_days, age < 3700, True)
    finally:
        F2.BOOT_TS = orig


def main():
    for fn in (t_nothing_starts_at_tick_zero,
               t_pid_order_holds_as_the_box_ages,
               t_proc_and_ps_agree_on_age,
               t_the_session_shell,
               t_a_boot_time_daemon,
               t_a_process_the_attacker_launched,
               t_no_process_contradicts_itself,
               t_starttime_is_not_derived_from_the_pid):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-54s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("procstarttest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
