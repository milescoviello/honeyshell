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


def main():
    for fn in (t_the_session_shell,
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
