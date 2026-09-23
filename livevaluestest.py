#!/usr/bin/env python3
"""What on this box moves, and do the things that move stay consistent?

A honeypot persona is usually checked one command at a time: does `free`
say a terabyte, does `lscpu` say 192. Nobody had asked the other
question -- read the same thing twice, a moment apart, and does it
change the way a running machine's would? Almost nothing did.

    cat /proc/meminfo ; sleep 1 ; cat /proc/meminfo    identical
    cat /proc/net/dev ; sleep 1 ; cat /proc/net/dev    identical
    grep MHz /proc/cpuinfo | sort -u                   one value, 192 cores
    ps -o time= -p <training job> twice                identical

The last one is the worst of them: `workload.active()` computed a job's
start as ``now - age``, so every job was *permanently* its stated age.
The training run had burned 34454:24 of CPU and would never gain another
jiffy, on a box whose load average claimed four busy cores.

Fixing that exposed the same shape one layer down. /proc/<pid>/stat
recovered its utime by parsing back the TIME column `ps` prints -- a
string with one-second resolution -- so anything sampling faster than
1 Hz saw no change at all. Real /proc keeps jiffies and ps rounds them
for display, not the reverse.

And two fields were simply wrong rather than frozen:

  * field 22, starttime, was 0 for every process except the session's
    own, because `proc_started` only ever held the shell and sshd. A
    training run ps calls six days old read as forty-one days old --
    the whole uptime -- to anything computing a lifetime from /proc.
  * field 20, num_threads, was the literal 1 while /proc/<pid>/status
    said 32 for the same process. htop and btop take the count from
    stat, so a 32-thread database drew as single-threaded.

Making memory move then broke three suites, which is the other half of
this: a value that moves has to keep every identity it had when it was
still. /proc/meminfo, /proc/vmstat and `free` are computed from one
table precisely so they cannot disagree, and a wander that ignored
"Active = Active(anon) + Active(file)" broke that in four places at
once. Worse, the walk produced figures that were not multiples of 4 kB,
so the kB -> pages -> kB round trip vmstat and sysconf make lost the
remainder: _AVPHYS_PAGES * PAGESIZE came out one byte short of MemFree.

Everything here asserts a relationship rather than a number, so it keeps
working the next time the persona is resized.
"""

import os
import re
import sys
import time

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


def shell():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    s.has_pty = True
    return s


S = shell()


def R(cmd, t=None):
    t = t or S
    t._err = []
    out = t.run(cmd)
    return out or "", "".join(t._err), t.last_rc


def dyn(path, t=None):
    """A generated file's live contents, or b'' if the emulator has no
    such generator -- a suite that dies on import reports nothing."""
    t = t or S
    try:
        return t.fs._dynamic(path) or b""
    except Exception:                                          # noqa: BLE001
        return b""


def meminfo(t=None):
    d = {}
    for line in dyn("/proc/meminfo", t).decode("latin-1").splitlines():
        k, _, v = line.partition(":")
        f = v.split()
        if f and f[0].isdigit():
            d[k] = int(f[0])
    return d


def busy_pid():
    """The pid of the heaviest job, or None."""
    try:
        rows = sorted(S._all_procs(), key=lambda r: -float(r[2] or 0))
        return rows[0][1] if rows and float(rows[0][2] or 0) > 50 else None
    except Exception:                                          # noqa: BLE001
        return None


# ------------------------------------------------- things that must move

def t_the_files_a_sampler_reads_twice_all_change():
    """Anything a monitor samples has to differ between two reads."""
    paths = ("/proc/stat", "/proc/uptime", "/proc/diskstats",
             "/proc/meminfo", "/proc/net/dev", "/proc/cpuinfo")
    before = {p: dyn(p) for p in paths}
    time.sleep(1.3)
    after = {p: dyn(p) for p in paths}
    for p in paths:
        if not before[p]:
            check("%s exists" % p, False, "empty")
            continue
        check("%s changes between reads" % p, before[p] != after[p],
              "identical after 1.3s")


def t_cpu_clocks_are_not_all_the_base_frequency():
    txt = dyn("/proc/cpuinfo").decode("latin-1")
    mhz = re.findall(r"cpu MHz\s+:\s+([\d.]+)", txt)
    check("cpuinfo reports a clock per cpu", len(mhz) > 1, "%d" % len(mhz))
    if len(mhz) < 2:
        return
    vals = sorted(set(float(x) for x in mhz))
    check("cores do not all share one frequency", len(vals) > 1,
          "every core at %s" % vals[0])
    check("clocks are in a plausible range",
          all(500.0 < v < 7000.0 for v in vals),
          "%.0f .. %.0f" % (vals[0], vals[-1]))


def t_a_busy_process_accumulates_cpu_faster_than_once_a_second():
    """The quantisation bug: utime moved in whole-second steps, so a
    sampler faster than 1 Hz read a 388% job as idle."""
    pid = busy_pid()
    if pid is None:
        check("there is a busy process to measure", False, "none over 50%")
        return

    def ticks():
        try:
            S._resync_proc()
        except Exception:                                      # noqa: BLE001
            pass
        f = dyn("/proc/%d/stat" % pid).decode("latin-1").split()
        return (int(f[13]) + int(f[14])) if len(f) > 14 else None

    a = ticks()
    time.sleep(0.30)
    b = ticks()
    check("the busy process has a stat line", a is not None and b is not None)
    if a is None or b is None:
        return
    check("its cpu time advances within 300ms", b > a,
          "%d -> %d, quantised to whole seconds" % (a, b))


def t_a_jobs_start_instant_does_not_move():
    """The cause behind the check above, pinned separately.

    A scheduled job's start was computed as `now` minus a whole number of
    elapsed seconds. `now` is fractional and the subtrahend is not, so
    `now - started` came back an exact integer: the job's CPU total sat
    still for most of every second and then jumped a whole one. The
    symptom is intermittent -- the 300ms probe above only catches it when
    the window happens to straddle a second boundary, which it did on one
    run in three -- so assert the cause, which is not intermittent at all.
    """
    import workload
    first = {j["pid"]: j["started"] for j in workload.active()}
    time.sleep(0.30)
    second = {j["pid"]: j["started"] for j in workload.active()}
    check("every job reports the same pids across two reads",
          sorted(first) == sorted(second), "the job table changed under us")
    moved = sorted(pid for pid in first
                   if pid in second and abs(second[pid] - first[pid]) > 0.001)
    check("no job's start instant moves between two reads", not moved,
          "pids %s drifted; a start derived from `now` is not a start"
          % (moved[:4],))


# --------------------------------------------- fields that were wrong

def t_start_time_matches_the_age_ps_reports():
    """field 22 was 0 -- boot -- for everything but the session."""
    pid = busy_pid()
    if pid is None:
        check("there is a job to check a start time on", False, "none")
        return
    try:
        S._resync_proc()
    except Exception:                                          # noqa: BLE001
        pass
    f = dyn("/proc/%d/stat" % pid).decode("latin-1").split()
    up = dyn("/proc/uptime").decode("latin-1").split()
    check("stat has 52 fields", len(f) >= 22, "%d" % len(f))
    if len(f) < 22 or not up:
        return
    start, uptime = int(f[21]), float(up[0])
    check("starttime is after boot", start > 0,
          "0 means the process started at boot")
    check("starttime is before now", start < uptime * 100,
          "start=%d uptime_ticks=%d" % (start, uptime * 100))
    # The job is younger than the box: it did not start at boot.
    age_days = (uptime - start / 100.0) / 86400.0
    check("the job is younger than the machine", age_days < uptime / 86400.0,
          "age %.2fd vs uptime %.2fd" % (age_days, uptime / 86400.0))


def t_thread_count_agrees_between_stat_and_status():
    """stat field 20 was the literal 1 while status said 32."""
    seen = 0
    for row in S._all_procs():
        pid = row[1]
        f = dyn("/proc/%d/stat" % pid).decode("latin-1").split()
        st = dyn("/proc/%d/status" % pid).decode("latin-1")
        thr = re.search(r"^Threads:\s+(\d+)", st, re.M)
        if len(f) < 20 or not thr:
            continue
        seen += 1
        check("pid %d: stat[20] == status Threads" % pid,
              f[19] == thr.group(1),
              "stat=%s status=%s" % (f[19], thr.group(1)))
    check("some process was checked", seen >= 5, "%d" % seen)
    check("at least one process is multi-threaded",
          any((dyn("/proc/%d/stat" % r[1]).decode("latin-1").split() or
               ["0"] * 20)[19] not in ("0", "1")
              for r in S._all_procs()), "every process claims one thread")


def t_percent_mem_is_derived_from_rss():
    """%MEM carried literals from when the box had 2 GB, so mariadbd
    showed 18.4% of a terabyte with an RES of 374 MB."""
    total = meminfo().get("MemTotal", 0)
    check("MemTotal is known", total > 0)
    if not total:
        return
    for row in S._all_procs():
        rss, mem = row[5], float(row[3])
        want = round(100.0 * rss / total, 1)
        check("pid %d %%MEM matches its RSS" % row[1], abs(mem - want) < 0.15,
              "shows %.1f, RSS implies %.2f" % (mem, want))


# ------------------------------------- moving without breaking identities

def t_memory_is_consistent_within_one_instant():
    """Two readers in the same breath must agree; the walk is quantised
    for exactly this reason."""
    a = dyn("/proc/meminfo")
    b = dyn("/proc/meminfo")
    check("two reads in the same tick are identical", a == b,
          "meminfo differs between back-to-back reads")


def t_memory_identities_hold_while_it_moves():
    for _ in range(3):
        d = meminfo()
        if not d:
            check("meminfo parses", False, "empty")
            return
        check("Active == anon + file",
              d.get("Active") == d.get("Active(anon)", 0)
              + d.get("Active(file)", 0),
              "%s vs %s+%s" % (d.get("Active"), d.get("Active(anon)"),
                               d.get("Active(file)")))
        check("Inactive == anon + file",
              d.get("Inactive") == d.get("Inactive(anon)", 0)
              + d.get("Inactive(file)", 0), "")
        check("anon LRU == AnonPages + Shmem",
              d.get("Active(anon)", 0) + d.get("Inactive(anon)", 0)
              == d.get("AnonPages", 0) + d.get("Shmem", 0), "")
        check("file LRU == Buffers + Cached - Shmem",
              d.get("Active(file)", 0) + d.get("Inactive(file)", 0)
              == d.get("Buffers", 0) + d.get("Cached", 0)
              - d.get("Shmem", 0), "")
        check("free memory is inside the machine",
              0 < d.get("MemFree", 0) < d.get("MemTotal", 1), "")
        time.sleep(0.4)


def t_memory_figures_are_page_aligned():
    """kB that is not a multiple of four cannot survive the round trip
    through pages that vmstat and sysconf make."""
    d = meminfo()
    for key in ("MemFree", "MemAvailable", "Cached", "Buffers",
                "Active", "Inactive", "Active(anon)", "Active(file)"):
        v = d.get(key)
        if v is None:
            continue
        check("%s is a whole number of pages" % key, v % 4 == 0,
              "%d kB" % v)


def t_vmstat_and_meminfo_still_agree():
    vm = {}
    for line in dyn("/proc/vmstat").decode("latin-1").splitlines():
        f = line.split()
        if len(f) == 2 and f[1].isdigit():
            vm[f[0]] = int(f[1])
    d = meminfo()
    if not vm or not d:
        check("vmstat and meminfo both readable", False, "")
        return
    check("nr_free_pages * 4 == MemFree",
          vm.get("nr_free_pages", 0) * 4 == d.get("MemFree"),
          "%s vs %s" % (vm.get("nr_free_pages", 0) * 4, d.get("MemFree")))
    check("nr_file_pages * 4 == Buffers + Cached",
          vm.get("nr_file_pages", 0) * 4
          == d.get("Buffers", 0) + d.get("Cached", 0),
          "%s vs %s" % (vm.get("nr_file_pages", 0) * 4,
                        d.get("Buffers", 0) + d.get("Cached", 0)))


def t_hugepages_survive_a_generated_meminfo():
    """`sysctl -w vm.nr_hugepages=N` used to edit the meminfo node, which
    a file generated on every read discards -- so the count moved in
    sysctl and /proc/sys and /sys/kernel/mm while meminfo said zero."""
    t = shell()
    R("sysctl -w vm.nr_hugepages=8", t)
    d = meminfo(t)
    check("meminfo HugePages_Total follows the sysctl",
          d.get("HugePages_Total") == 8, "%s" % d.get("HugePages_Total"))
    check("meminfo HugePages_Free follows too",
          d.get("HugePages_Free") == 8, "%s" % d.get("HugePages_Free"))
    check("Hugetlb is the count times the page size",
          d.get("Hugetlb") == 8 * getattr(fs, "HUGEPAGE_KB", 2048),
          "%s" % d.get("Hugetlb"))
    out = R("cat /proc/sys/vm/nr_hugepages", t)[0].strip()
    check("/proc/sys agrees with meminfo", out == "8", out)


# --------------------------------------------------- hardware in sysfs

def t_sysfs_block_stat_matches_diskstats():
    """Every block device has /sys/block/<dev>/stat and none of ours did,
    so anything reading per-device I/O out of sysfs found nothing."""
    ds = dyn("/proc/diskstats").decode("latin-1").splitlines()
    checked = 0
    for line in ds:
        f = line.split()
        if len(f) < 14:
            continue
        name = f[2]
        blob = dyn("/sys/block/%s/stat" % name)
        if not blob:
            # partitions live under their disk
            continue
        checked += 1
        # These are two views of ONE set of counters, and the counters
        # move. Read in separate commands they legitimately differ -- a
        # real busy disk advances between two reads too, which is why the
        # exact-match form here was green alone and red under the pool, at
        # one or two reads and ~60 sectors apart.
        #
        # The honest invariant for a monotonic counter sampled between two
        # other samples is that it lies between them. Bracket it: read
        # diskstats again after the sysfs read, and require sysfs to sit in
        # [before, after] field by field. That still fails a sysfs file
        # carrying different counters, a stale one, or one that runs
        # backwards -- it only tolerates the drift that time itself causes.
        after = {}
        for _l in dyn("/proc/diskstats").decode("latin-1").splitlines():
            _g = _l.split()
            if len(_g) >= 14:
                after[_g[2]] = _g[3:]
        _sys = blob.decode("latin-1").split()
        _lo, _hi = f[3:], after.get(name, f[3:])
        _ok = len(_sys) == len(_lo)
        if _ok:
            for _a, _b, _c in zip(_lo, _sys, _hi):
                try:
                    if not (int(_a) <= int(_b) <= int(_c)):
                        _ok = False
                        break
                except ValueError:
                    if not (_a == _b == _c):
                        _ok = False
                        break
        check("/sys/block/%s/stat matches diskstats" % name, _ok,
              "sysfs %r not bracketed by /proc %r..%r"
              % (_sys[:4], _lo[:4], _hi[:4]))
    check("some block device exposes a stat file", checked >= 1,
          "none of %d devices" % len(ds))


def t_every_pci_device_has_a_modalias():
    """modalias is how a GPU is identified -- fastfetch and btop parse
    the base class out of it rather than reading lspci."""
    names = R("ls /sys/bus/pci/devices")[0].split()
    check("sysfs lists pci devices", len(names) > 4, "%d" % len(names))
    display = 0
    for bdf in names:
        blob = R("cat /sys/bus/pci/devices/%s/modalias 2>/dev/null" % bdf)[0]
        m = re.match(r"pci:v([0-9A-F]{8})d([0-9A-F]{8})sv[0-9A-F]{8}"
                     r"sd[0-9A-F]{8}bc([0-9A-F]{2})sc([0-9A-F]{2})",
                     blob.strip())
        check("%s has a well-formed modalias" % bdf, bool(m),
              blob.strip()[:40] or "missing")
        if m and m.group(3) == "03":
            display += 1
    check("the display adapters are visible through sysfs", display >= 1,
          "%d devices with base class 03" % display)


def t_gpu_count_agrees_between_lspci_and_nvidia_smi():
    lspci = R("lspci")[0]
    n_lspci = len([l for l in lspci.splitlines()
                   if "VGA compatible controller" in l and "NVIDIA" in l])
    smi = R("nvidia-smi -L")[0]
    n_smi = len([l for l in smi.splitlines() if l.startswith("GPU ")])
    check("lspci and nvidia-smi count the same cards", n_lspci == n_smi,
          "lspci=%d nvidia-smi=%d" % (n_lspci, n_smi))
    drm = [d for d in R("ls /sys/class/drm")[0].split()
           if re.match(r"^card\d+$", d)]
    check("every nvidia card has a drm node", len(drm) >= n_smi,
          "drm cards=%d nvidia=%d" % (len(drm), n_smi))


# ------------------------------------------------------------ terminfo

def t_clear_is_terminfo_not_a_stub():
    """`clear` printed nothing at all -- the first command an interactive
    user types did visibly nothing."""
    cases = {"xterm": "\x1b[H\x1b[2J\x1b[3J",
             "xterm-256color": "\x1b[H\x1b[2J\x1b[3J",
             "screen": "\x1b[H\x1b[J",
             "vt100": "\x1b[H\x1b[J",
             "linux": "\x1b[H\x1b[J\x1b[3J"}
    for term, want in cases.items():
        t = shell()
        t.vars["TERM"] = term
        t.term = term
        got, err, rc = R("clear", t)
        check("clear on %s emits the terminfo sequence" % term, got == want,
              "%r" % got)
        check("clear on %s succeeds" % term, rc == 0, "rc=%s %s" % (rc, err))
        tput = R("tput clear", t)[0]
        check("tput clear agrees with clear on %s" % term, tput == got,
              "%r vs %r" % (tput, got))
    t = shell()
    t.vars["TERM"] = ""
    got, err, rc = R("clear", t)
    check("clear with no TERM fails the way it does on a real box",
          rc == 1 and "TERM environment variable not set" in err,
          "rc=%s err=%r" % (rc, err))


TESTS = [t_the_files_a_sampler_reads_twice_all_change,
         t_cpu_clocks_are_not_all_the_base_frequency,
         t_a_busy_process_accumulates_cpu_faster_than_once_a_second,
         t_a_jobs_start_instant_does_not_move,
         t_start_time_matches_the_age_ps_reports,
         t_thread_count_agrees_between_stat_and_status,
         t_percent_mem_is_derived_from_rss,
         t_memory_is_consistent_within_one_instant,
         t_memory_identities_hold_while_it_moves,
         t_memory_figures_are_page_aligned,
         t_vmstat_and_meminfo_still_agree,
         t_hugepages_survive_a_generated_meminfo,
         t_sysfs_block_stat_matches_diskstats,
         t_every_pci_device_has_a_modalias,
         t_gpu_count_agrees_between_lspci_and_nvidia_smi,
         t_clear_is_terminfo_not_a_stub]


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
