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
    """ps TIME, [DD-]HH:MM:SS or MM:SS, to seconds."""
    t = (text or "").strip()
    if not t:
        return None
    total = 0
    try:
        for part in t.replace("-", ":").split(":"):
            total = total * 60 + int(part)
    except ValueError:
        return None
    return total


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
    for line in s.run("ps -eo pid=,time=").splitlines():
        f = line.split()
        if len(f) != 2:
            continue
        pid, want = f[0], secs(f[1])
        raw = s.run("cut -d' ' -f14,15 /proc/%s/stat" % pid).split()
        if want is None or len(raw) != 2:
            continue
        try:
            got = (int(raw[0]) + int(raw[1])) / 100.0
        except ValueError:
            continue
        if abs(got - want) > 1:
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
    """The implant case: launched now, so it cannot have burned CPU."""
    s = sh()
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
    check("it reports no CPU ticks", raw, ["0", "0"])
    check("and ps agrees", secs(s.run("ps -p %s -o time=" % pid)), 0)


def main():
    for fn in (t_the_surface_matches_the_guest,
               t_modes_are_the_measured_ones,
               t_the_new_files_have_content,
               t_cputime_agrees_with_ps,
               t_schedstat_agrees_with_stat,
               t_smaps_rollup_agrees_with_status_and_ps,
               t_a_just_started_process_has_no_cpu):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-54s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("procsurfacetest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
