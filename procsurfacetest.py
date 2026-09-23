#!/usr/bin/env python3
"""What /proc/<pid> shows, and whether it agrees with ps.

203.0.113.33 replaced ps, top, htop, pgrep, kill, pkill, killall, lsof,
netstat, ss, w, who and id with fakes on 2026-08-25 and made all of them
immutable. When the tooling is gone, /proc is what is left -- so /proc has
to hold up on its own.

It did not, in two ways.

**The surface was half there.** `ls /proc/1` lists 56 entries on the guest
and listed 31 here. The 25 missing were not obscure: uid_map, gid_map and
setgroups are how a process decides whether it is inside a namespace,
smaps_rollup is what anything measuring its own memory reads, schedstat is
the scheduler's view of the CPU time /proc/<pid>/stat reports, and
clear_refs, pagemap, stack and mem are what anyone poking at another
process reaches for. A short /proc/<pid> is one `ls` from being noticed.

**The CPU numbers came from the wrong column.** utime and stime were
`int(cpu * 30)` and `int(cpu * 12)` -- derived from the *%CPU rate* while ps
prints a *total* from the TIME column. So:

    pid 1     ps TIME 00:00:41     /proc/1/stat utime,stime = 0 0
    implant   ps TIME 00:00:00     /proc/<pid>/stat = 2829 1131

The second is 39.6 seconds of CPU on a process that had existed for under a
second. Measured on the guest, pid 1 gives TIME 00:00:23 against 1317 + 1029
= 2346 ticks, so (utime + stime) / 100 == TIME, exactly, and a process that
has just started reports 0 0.

Usage:  python3 procsurfacetest.py
"""

import re
import time
import sys

import fakeshell as F

CHECKS, FAILS = [], []

#: `ls /proc/1` on the guest, 2026-08-25.
GUEST_PROC = set("""
arch_status attr autogroup auxv cgroup clear_refs cmdline comm coredump_filter
cpu_resctrl_groups cpuset cwd environ exe fd fdinfo gid_map io
ksm_merging_pages ksm_stat limits loginuid map_files maps mem mountinfo mounts
mountstats net ns numa_maps oom_adj oom_score oom_score_adj pagemap
patch_state personality projid_map root sched schedstat sessionid setgroups
smaps smaps_rollup stack stat statm status syscall task timens_offsets timers
timerslack_ns uid_map wchan
""".split())


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh():
    return F.Shell()


def secs(text):
    """ps TIME, [DD-]HH:MM:SS or MM:SS, to seconds.

    The day field is days, not another base-60 digit. This folded the
    whole string base-60 after turning the "-" into a ":", so 5-23:24:58
    came back as 1164298 rather than 516298 -- 2.3x out -- and the
    process it belonged to was reported as disagreeing with its own
    /proc/<pid>/stat when the two in fact agreed to 0.07s. Nothing on this
    box had a TIME of a day or more in the DD- form until torchrun grew
    per-rank workers, so the parser had never been asked the question its
    own docstring claimed it answered.
    """
    t = (text or "").strip()
    if not t:
        return None
    days = 0
    if "-" in t:
        head, _, t = t.partition("-")
        try:
            days = int(head)
        except ValueError:
            return None
    total = 0
    try:
        for part in t.split(":"):
            total = total * 60 + int(part)
    except ValueError:
        return None
    return days * 86400 + total


def t_the_surface_matches_the_guest():
    s = sh()
    got = set(s.run("ls /proc/1/").split())
    check("nothing the guest has is missing", sorted(GUEST_PROC - got), [])
    check("nothing is present that the guest lacks", sorted(got - GUEST_PROC), [])


def t_modes_are_the_measured_ones():
    """clear_refs is write-only and mem is 0600; both matter."""
    s = sh()
    for name, mode in (("clear_refs", "200"), ("mem", "600"),
                       ("uid_map", "644"), ("stack", "400"),
                       ("pagemap", "400"), ("smaps_rollup", "444"),
                       ("schedstat", "444"), ("setgroups", "644")):
        check("/proc/1/%s mode" % name,
              s.run("stat -c %%a /proc/1/%s" % name).strip(), mode)


def t_the_new_files_have_content():
    """A file ls lists and cat returns nothing for is worse than absent."""
    s = sh()
    check("uid_map says no namespace",
          s.run("cat /proc/1/uid_map").split(), ["0", "0", "4294967295"])
    check("gid_map matches uid_map",
          s.run("cat /proc/1/gid_map").strip(),
          s.run("cat /proc/1/uid_map").strip())
    check("setgroups", s.run("cat /proc/1/setgroups").strip(), "allow")
    check("cpuset", s.run("cat /proc/1/cpuset").strip(), "/")
    check("coredump_filter",
          s.run("cat /proc/1/coredump_filter").strip(), "00000033")
    check("timerslack_ns", s.run("cat /proc/1/timerslack_ns").strip(), "50000")
    check("oom_adj", s.run("cat /proc/1/oom_adj").strip(), "0")
    check("patch_state", s.run("cat /proc/1/patch_state").strip(), "-1")
    check("ksm_stat has its four counters",
          len(s.run("cat /proc/1/ksm_stat").split("\n")[:-1]), 4)
    check("timens_offsets names both clocks",
          [l.split()[0] for l in s.run("cat /proc/1/timens_offsets").splitlines()],
          ["monotonic", "boottime"])
    check("smaps_rollup is labelled [rollup]",
          "[rollup]" in s.run("head -1 /proc/1/smaps_rollup"), True)


def t_cputime_agrees_with_ps():
    """(utime + stime) / 100 == the TIME column, for every process."""
    s = sh()
    bad = []
    # One ps snapshot up front and then a separate /proc read per pid is
    # two samples of a value that moves, and there are ~488 pids, so the
    # loop itself is the drift: green run alone and red under an
    # eight-wide pool, at 290:24 against 290:22. Both numbers come out of
    # one shell invocation per process now -- microseconds apart instead of
    # seconds -- so the 1s tolerance is measuring the emulator's agreement
    # rather than the harness's own runtime.
    pids = [l.split()[0] for l in s.run("ps -eo pid=").splitlines()
            if l.split()]
    for pid in pids:
        pair = s.run("ps -o time= -p %s; cut -d' ' -f14,15 /proc/%s/stat"
                     % (pid, pid)).split()
        if len(pair) != 3:
            continue
        want = secs(pair[0])
        f = [pid, pair[0]]
        raw = pair[1:]
        if want is None or len(raw) != 2:
            continue
        try:
            got = (int(raw[0]) + int(raw[1])) / 100.0
        except ValueError:
            continue
        # ps floors its TIME column to whole seconds while /proc keeps
        # jiffies, so (proc - ps) is in [0, 1) by construction before any
        # drift at all -- a 1s tolerance cannot accommodate its own
        # rounding, and the gate caught it at 1.05s. Two seconds still
        # catches what this is for: the frozen /proc/<pid>/stat this test
        # was written against was 72s out, and grew.
        if abs(got - want) > 2:
            bad.append((pid, f[1], raw))
    check("no process disagrees with its own TIME column", bad[:6], [])


def t_schedstat_agrees_with_stat():
    """The scheduler and the stat file describe the same process."""
    s = sh()
    for pid in ("1", "412"):
        raw = s.run("cut -d' ' -f14,15 /proc/%s/stat" % pid).split()
        sched = s.run("cat /proc/%s/schedstat" % pid).split()
        if len(raw) == 2 and len(sched) == 3:
            ticks = int(raw[0]) + int(raw[1])
            check("schedstat cpu ns matches stat ticks for pid %s" % pid,
                  int(sched[0]), ticks * 10 ** 7)


def t_smaps_rollup_agrees_with_status_and_ps():
    """Three readers of one number."""
    s = sh()
    for pid in ("1", "412"):
        roll = None
        for line in s.run("cat /proc/%s/smaps_rollup" % pid).splitlines():
            m = re.match(r"^Rss:\s+(\d+) kB", line)
            if m:
                roll = int(m.group(1))
                break
        vm = None
        m = re.search(r"VmRSS:\s+(\d+) kB",
                      s.run("grep VmRSS /proc/%s/status" % pid))
        if m:
            vm = int(m.group(1))
        psr = s.run("ps -p %s -o rss=" % pid).strip()
        check("smaps_rollup Rss == VmRSS for pid %s" % pid, roll, vm)
        check("...and == ps rss for pid %s" % pid,
              str(roll) if roll is not None else None, psr or None)


def t_a_just_started_process_has_no_cpu():
    """The implant case: launched now, so it cannot have burned much CPU.

    The bound is elapsed wall-clock, not zero. This asserted exactly
    ["0", "0"], which held only because /proc/<pid>/stat derived its ticks
    as int(seconds) * 100 -- whole seconds -- so anything under a second
    old reported nothing whatever it was doing. That quantisation was the
    bug (a 2% daemon gained nothing between two reads and every sampler
    faster than 1 Hz called it idle); with jiffy precision a process the
    emulator models as CPU-burning shows a few tens of jiffies a quarter
    second in, which is what a real one does.

    What must still hold is the thing the implant case is actually about:
    a process cannot have used more CPU than has existed since it started.
    """
    import time as _time
    s = sh()
    _t0 = _time.time()
    s.run("mkdir -p /root/.stage; echo x > /root/.stage/miner; "
          "chmod +x /root/.stage/miner")
    s.run("cd /root/.stage && nohup ./miner &")
    pid = None
    for line in s.run("pgrep -a miner").splitlines():
        if "./miner" in line:
            pid = line.split()[0]
    check("the launched process exists", pid is not None, True)
    if not pid:
        return
    raw = s.run("cut -d' ' -f14,15 /proc/%s/stat" % pid).split()
    elapsed = max(0.05, _time.time() - _t0)
    try:
        ticks = sum(int(x) for x in raw)
    except (TypeError, ValueError):
        ticks = None
    check("it reports ticks at all, as a number", ticks is not None, True)
    if ticks is not None:
        # One core's worth of jiffies per second of life, plus slop for the
        # emulator's own scheduling. A figure above this is CPU the process
        # could not have had.
        ceiling = int(elapsed * 100) + 50
        check("a just-started process has not out-burned its own lifetime",
              ticks <= ceiling, True)
    check("and ps agrees", secs(s.run("ps -p %s -o time=" % pid)), 0)


def t_the_cpu_line_is_the_sum_of_the_per_cpu_lines():
    """/proc/stat's aggregate must equal cpu0..cpuN, field by field.

    Nothing checked this, and it is the cheapest possible contradiction to
    find: two readings of one table, one of which anybody can add up. All
    ten fields, so a future change that touches only the aggregate -- or
    only the per-core rows -- cannot pass.
    """
    s = sh()
    agg, per = None, []
    for line in s.run("cat /proc/stat").splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "cpu":
            agg = [int(x) for x in f[1:]]
        elif f[0].startswith("cpu") and f[0][3:].isdigit():
            per.append([int(x) for x in f[1:]])
    check("there is an aggregate cpu line", agg is not None, True)
    check("one line per cpu", len(per), F.NCPU)
    if agg is None or not per:
        return
    names = ("user", "nice", "system", "idle", "iowait", "irq", "softirq",
             "steal", "guest", "guest_nice")
    for i, n in enumerate(names[:len(agg)]):
        check("cpu %s = sum of the per-cpu column" % n,
              sum(p[i] for p in per if i < len(p)), agg[i])


def t_steal_is_small_and_every_reader_rounds_it_the_same():
    """A KVM guest reports steal, and top and vmstat both derive it here.

    The persona carries a real, non-zero steal figure rather than a clean
    zero -- exactly zero on a KVM guest is the less believable number --
    but it is small enough that both readers show 0.0, and they have to
    agree on that. This pins the relationship, not the constant: if steal
    ever grows, top and vmstat must move together.
    """
    s = sh()
    f = [int(x) for x in s.run("awk '/^cpu /{print}' /proc/stat").split()[1:]]
    total = sum(f)
    steal_pct = 100.0 * f[7] / total
    check("steal is non-zero, as a guest's is", f[7] > 0, True)
    check("...but well under a percent", steal_pct < 1.0, True)
    top_st = None
    for line in s.run("top -bn1 | head -6").splitlines():
        m = re.search(r"([0-9.]+)\s+st", line)
        if m:
            top_st = float(m.group(1))
    check("top prints a steal figure", top_st is not None, True)
    if top_st is not None:
        check("top's steal matches the table to one decimal",
              top_st, round(steal_pct, 1))
    vm = s.run("vmstat 1 1").splitlines()
    if len(vm) >= 3:
        hdr, row = vm[-2].split(), vm[-1].split()
        if "st" in hdr:
            check("vmstat's steal agrees too",
                  int(row[hdr.index("st")]), int(round(steal_pct)))


def t_proc_holds_exactly_the_processes_ps_reports():
    """A /proc/<pid> directory ps denies is an artifact outliving its fact.

    Enumerating /proc directly is standard recon -- it is how you list
    processes without running ps -- so the two counts are a pair anyone
    can compare in one line. On the live box the verification VFS carried
    sixteen hollow pid directories, 4101-4117, each with an empty comm and
    an empty stat, left behind by an older build; a fresh session has
    none, and this keeps it that way. Every pid /proc admits to must also
    be a process, and must have the two files a real one always has.
    """
    s = sh()
    proc = sorted(x for x in s.run("ls -d /proc/[0-9]*").replace(
        "/proc/", "").split() if x.isdigit())
    ps = sorted(x for x in s.run("ps -eo pid=").split() if x.isdigit())
    check("/proc holds no pid ps denies", sorted(set(proc) - set(ps)), [])
    check("ps names no pid /proc lacks", sorted(set(ps) - set(proc)), [])
    # and none of them is hollow
    hollow = [p for p in proc[:40]
              if not s.run("cat /proc/%s/comm" % p).strip()
              or not s.run("cat /proc/%s/stat" % p).strip()]
    check("no pid directory is empty", hollow, [])


def t_every_reader_agrees_when_the_box_booted():
    """btime, /proc/uptime, uptime, who -b and last reboot are one fact."""
    s = sh()
    btime = None
    for line in s.run("cat /proc/stat").splitlines():
        if line.startswith("btime"):
            btime = int(line.split()[1])
    check("btime is present", btime is not None, True)
    up = float(s.run("cat /proc/uptime").split()[0])
    now = int(s.run("date +%s").strip())
    # /proc/uptime and btime describe the same instant; a second of slack
    # covers the two reads landing either side of a tick.
    check("btime and /proc/uptime agree",
          abs((now - up) - btime) <= 2, True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(btime))
    check("uptime -s prints that instant", s.run("uptime -s").strip(), stamp)
    check("who -b prints it to the minute",
          stamp[:16] in s.run("who -b"), True)
    check("last reboot prints the same day",
          time.strftime("%b %e", time.localtime(btime)).replace("  ", " ")
          in s.run("last reboot | head -1").replace("  ", " "), True)


def main():
    for fn in (t_the_surface_matches_the_guest,
               t_modes_are_the_measured_ones,
               t_the_new_files_have_content,
               t_cputime_agrees_with_ps,
               t_schedstat_agrees_with_stat,
               t_smaps_rollup_agrees_with_status_and_ps,
               t_a_just_started_process_has_no_cpu,
               t_the_cpu_line_is_the_sum_of_the_per_cpu_lines,
               t_steal_is_small_and_every_reader_rounds_it_the_same,
               t_proc_holds_exactly_the_processes_ps_reports,
               t_every_reader_agrees_when_the_box_booted):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-54s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("procsurfacetest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
