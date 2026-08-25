#!/usr/bin/env python3
"""A process that uses CPU has to use it everywhere.

Seven readers answer "how much CPU is this box doing", and a payload the
attacker started got a different answer from every one of them. An hour
after launching a miner:

    ps -o time,pcpu      00:56:24   94.3      <- TIME says 94.0%, ps says 94.3
    /proc/<pid>/stat     utime 0, stime 0     <- no CPU at all
    /proc/<pid>/schedstat 0 0 193             <- zero nanoseconds on cpu
    /proc/loadavg        0.03                 <- an idle box
    uptime               load average: 0.03
    top %Cpu(s)          98.9 id              <- above its own row saying 94.3
    /proc/stat           user jiffies unmoved

The first thing anyone does after starting a miner is run `top`. Seeing a
task at 94.3% on a box that reports 98.9% idle, at load 0.03, with zero
ticks in /proc, is not a subtle tell. Two of the crews that landed here this
week install SRBMiner and check `systemctl is-active xmrig` first -- these
are people who look at CPU numbers for a living.

Two separate faults produced it:

  * %CPU was the literal 94.3 while TIME was `elapsed * 0.94`. Real ps
    computes the first from the second, so the two numbers in one row could
    not both be right.
  * /proc/<pid>/stat read the TIME string out of `proc_rows`, which is a
    snapshot taken when the process table last changed -- at launch. ps went
    on counting and /proc stayed at zero. The docstring above `_proc_dynamic`
    already says a frozen /proc/<pid>/stat is as good as a confession.

Everything now derives from one rate per process. Reference values measured
on debian:trixie with a real busy loop and procps-ng:

    ps -o etimes,times,pcpu,stat   8  8  100  R
    /proc/<pid>/stat               utime 800, stime 0
    /proc/<pid>/schedstat          6001138096 ns after 6.00s of utime

so %CPU is times/etimes*100, times is (utime+stime)/100, schedstat's first
field is that same total in nanoseconds, and a busy process is R, not S.

Backdating a process's start rather than waiting an hour is the only way to
measure the steady state; `proc_meta[pid]["start"]` is what every reader
already derives elapsed time from, so moving it moves all of them together.

Usage:  python3 cpuloadtest.py
"""

import re
import sys
import time

import fakeshell

CHECKS, FAILS = [], []
HZ = 100


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def near(name, got, want, tol):
    CHECKS.append(name)
    try:
        ok = abs(float(got) - float(want)) <= tol
    except (TypeError, ValueError):
        ok = False
    if not ok:
        FAILS.append((name, got, "%s +/- %s" % (want, tol)))


def box():
    fs = fakeshell.VFS()
    return fs, fakeshell.Shell(vfs=fs)


def launch(sh, fs, cmd="/root/.x/miner", age=None):
    """Start a payload; optionally pretend it has been running for `age`."""
    sh.run("mkdir -p /root/.x; echo x > %s; chmod 755 %s" % (cmd, cmd))
    sh.run("nohup %s &" % cmd)
    out = sh.run("ps -eo pid,args --no-headers")
    pid = None
    for line in out.splitlines():
        if cmd in line:
            pid = int(line.split()[0])
    if pid is None:
        return None
    sh.run("ps -p %d" % pid)            # settle the rate
    if age:
        meta = getattr(fs, "proc_meta", {}).get(pid)
        if meta:
            meta["start"] = time.time() - age
    setattr(fs, "_load_cache", None)
    return pid


def col(sh, pid, spec):
    out = sh.run("ps -o %s= -p %d" % (spec, pid)).strip()
    return out.split()[-1] if out else ""


def hms(text):
    """00:56:24 -> 3384."""
    n = 0
    for part in str(text or "0").split(":"):
        try:
            n = n * 60 + int(part)
        except ValueError:
            return None
    return n


def stat_fields(sh, pid):
    raw = sh.run("cat /proc/%d/stat" % pid).strip()
    if not raw:
        return None
    return raw.split()


def loads(sh):
    m = re.match(r"^([\d.]+) ([\d.]+) ([\d.]+) (\d+)/(\d+)",
                 sh.run("cat /proc/loadavg").strip())
    if not m:
        return None
    return (float(m.group(1)), float(m.group(2)), float(m.group(3)),
            int(m.group(4)), int(m.group(5)))


def cpu_line(sh):
    for line in sh.run("head -1 /proc/stat").splitlines():
        if line.startswith("cpu "):
            return [int(x) for x in line.split()[1:]]
    return None


def main():
    # -- an idle box stays idle ---------------------------------------------
    fs, sh = box()
    la = loads(sh)
    check("idle: loadavg parses", la is not None, True)
    if la:
        check("idle: one-minute load is near zero", la[0] < 0.20, True)
    top = sh.run("top -bn1")
    m = re.search(r"([\d.]+) id,", top)
    check("idle: top reports an idle cpu", bool(m) and float(m.group(1)) > 95,
          True)
    busiest = 0.0
    for line in sh.run("ps -eo pcpu --no-headers").splitlines():
        try:
            busiest = max(busiest, float(line.strip()))
        except ValueError:
            pass
    check("idle: nothing is burning cpu", busiest < 1.0, True)
    idle_cpu = cpu_line(sh)
    check("idle: /proc/stat has a cpu line", idle_cpu is not None, True)

    # -- one payload, one hour ----------------------------------------------
    fs, sh = box()
    pid = launch(sh, fs, age=3600)
    check("the payload is in ps", pid is not None, True)
    if pid is None:
        for name, got, want in FAILS:
            print("  FAIL %-56s got %r want %r" % (name, got, want))
        return len(FAILS)

    etime = hms(col(sh, pid, "etime"))
    cpu = hms(col(sh, pid, "time"))
    pcpu = col(sh, pid, "pcpu")
    state = col(sh, pid, "stat")
    near("etime is the hour we backdated", etime, 3600, 5)
    check("it used some cpu", bool(cpu) and cpu > 0, True)
    # The invariant real ps holds: %CPU is TIME/ETIME.
    # Tight on purpose. The bug was %CPU 94.3 beside a TIME of 94.0% -- a
    # third of a point, and invisible to any tolerance loose enough to be
    # comfortable. The two numbers come from one division on a real box, so
    # the only honest tolerance is rounding.
    near("ps: %CPU is TIME over ETIME", float(pcpu or -1),
         round(cpu * 100.0 / max(1, etime), 1), 0.15)
    check("ps: a process using a core is R, not S",
          state.startswith("R"), True)

    st = stat_fields(sh, pid)
    check("/proc/<pid>/stat is readable", st is not None and len(st) > 21,
          True)
    if st:
        ticks = int(st[13]) + int(st[14])
        near("/proc/<pid>/stat ticks match ps TIME", ticks / float(HZ), cpu,
             1.5)
        check("/proc/<pid>/stat state matches ps", st[2], "R")

    sched = sh.run("cat /proc/%d/schedstat" % pid).split()
    check("schedstat has three fields", len(sched) == 3, True)
    if len(sched) == 3:
        near("schedstat nanoseconds match ps TIME",
             int(sched[0]) / 1e9, cpu, 1.5)

    la = loads(sh)
    check("load average moved", la is not None and la[0] > 0.80, True)
    if la:
        check("load is one core's worth, not more", la[0] < 1.30, True)
        check("the 15-minute average lags the 1-minute one", la[2] <= la[0],
              True)
        check("loadavg counts it as runnable", la[3] >= 1, True)

    up = sh.run("uptime")
    m = re.search(r"load average: ([\d.]+), ([\d.]+), ([\d.]+)", up)
    check("uptime prints a load", bool(m), True)
    if m and la:
        check("uptime and /proc/loadavg agree",
              (float(m.group(1)), float(m.group(2)), float(m.group(3))),
              (la[0], la[1], la[2]))

    top = sh.run("top -bn1")
    m = re.search(r"%Cpu\(s\):\s*([\d.]+) us,\s*([\d.]+) sy,\s*([\d.]+) ni,"
                  r"\s*([\d.]+) id,\s*([\d.]+) wa,\s*([\d.]+) hi,"
                  r"\s*([\d.]+) si,\s*([\d.]+) st", top)
    check("top's cpu line parses", bool(m), True)
    if m:
        vals = [float(x) for x in m.groups()]
        near("top's cpu percentages total 100", sum(vals), 100.0, 0.6)
        check("top does not call a busy box idle", vals[3] < 98.0, True)
    row = [l for l in top.splitlines() if str(pid) in l and "miner" in l]
    check("top lists the payload", len(row) == 1, True)
    if row:
        f = row[0].split()
        check("top's %CPU matches ps", f[8], pcpu)
        check("top's TIME+ matches ps TIME", hms(f[10]), cpu)
        check("top's state matches ps", f[7], "R")

    busy_cpu = cpu_line(sh)
    if busy_cpu and idle_cpu:
        check("/proc/stat user jiffies moved", busy_cpu[0] > idle_cpu[0], True)
        near("...by the cpu the process used",
             (busy_cpu[0] + busy_cpu[2]) - (idle_cpu[0] + idle_cpu[2]),
             cpu * HZ, cpu * HZ * 0.05 + 200)

    # -- reading twice never goes backwards ---------------------------------
    a = hms(col(sh, pid, "time"))
    b = hms(col(sh, pid, "time"))
    check("cpu time never decreases between reads", b >= a, True)
    s1 = stat_fields(sh, pid)
    s2 = stat_fields(sh, pid)
    if s1 and s2:
        check("...and neither does /proc's copy",
              int(s2[13]) + int(s2[14]) >= int(s1[13]) + int(s1[14]), True)

    # -- something that sleeps is not something that spins ------------------
    fs, sh = box()
    spid = launch(sh, fs, cmd="/root/.x/waiter")
    sh.run("nohup sleep 900 &")
    slp = None
    for line in sh.run("ps -eo pid,args --no-headers").splitlines():
        if "sleep 900" in line:
            slp = int(line.split()[0])
    check("the sleeper is in ps", slp is not None, True)
    if slp:
        sh.run("ps -p %d" % slp)
        meta = getattr(fs, "proc_meta", {}).get(slp)
        if meta:
            meta["start"] = time.time() - 3600
        setattr(fs, "_load_cache", None)
        check("a sleeping process used no cpu", hms(col(sh, slp, "time")), 0)
        check("...and reports 0.0%", float(col(sh, slp, "pcpu") or -1), 0.0)
        check("...and is S, not R", col(sh, slp, "stat").startswith("S"), True)
        sst = stat_fields(sh, slp)
        if sst:
            check("...with no ticks in /proc",
                  int(sst[13]) + int(sst[14]), 0)

    # -- two payloads are twice the load ------------------------------------
    fs, sh = box()
    launch(sh, fs, cmd="/root/.x/m1", age=3600)
    launch(sh, fs, cmd="/root/.x/m2", age=3600)
    setattr(fs, "_load_cache", None)
    la2 = loads(sh)
    check("two payloads, two cores of load",
          la2 is not None and 1.6 < la2[0] < 2.4, True)
    top = sh.run("top -bn1")
    m = re.search(r"([\d.]+) id,", top)
    check("top's idle drops further with two", bool(m) and float(m.group(1))
          < 60.0, True)

    # -- killing it gives the cpu back --------------------------------------
    fs, sh = box()
    kpid = launch(sh, fs, cmd="/root/.x/k1", age=3600)
    before = loads(sh)
    sh.run("kill -9 %d" % kpid)
    setattr(fs, "_load_cache", None)
    after = loads(sh)
    check("the load was there to begin with",
          before is not None and before[0] > 0.80, True)
    check("killing it drops the load",
          after is not None and after[0] < 0.20, True)
    check("...and it is gone from ps",
          str(kpid) not in sh.run("ps -eo pid --no-headers"), True)

    for name, got, want in FAILS:
        print("  FAIL %-56s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("cpuloadtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
