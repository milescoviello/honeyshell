#!/usr/bin/env python3
"""Sixty-four cores, or four numbers in a trenchcoat?

htop finally drew a per-core grid, and the grid was the tell. Every idle
core's trickle came from `0.004 + (c % 7) * 0.0015`, so the 64 bars carried
exactly seven distinct values in a pattern that repeated every seventh bar
straight down the screen -- and the busy cores were cpu0, cpu1, cpu2, cpu3,
cpu4, a contiguous prefix no scheduler produces. A five-thread job on a
64-thread box lands on five scattered cores, and it takes whole physical
cores before it doubles up on an SMT sibling.

Four more came out of measuring a real 24-thread Linux box instead of
reading our own output and deciding it looked plausible:

**Counters went backwards.** iowait was computed as the integer remainder
of the other fields, which is tidy and sums exactly, but when two of the
floors ticked over in the same jiffy the remainder dropped. Six of 64 cores
did it. A /proc/stat counter that decreases makes every sampler that
differences it -- top, htop, btop, vmstat -- print nonsense. Every field is
now floor() of its own monotonically rising second count.

**Booked time was given back.** The CPU seconds of the live process table
were charged to a core, so when a charged process exited, or the workload
shifted and its pid remapped, that core's user count fell. The kernel does
not unbill a dead process; a per-core high-water mark now says so.

**user:system was one ratio in 64 hats.** A flat 68/27 split gave every
core the same ratio to three decimals. The real box: 19.9 to 41.2, i.e.
userspace dominating by more than an order of magnitude. Ours was 1.3 to
5.9 -- a machine spending a third of its cycles in the kernel, which no
compute node does.

**Every row summed to the same total.** Ours agreed to within 3 jiffies
across all 64; the real box's per-core totals spread over 63462 jiffies,
ten and a half minutes, because cores come online late or park.

And the one that ties them together: /proc/stat and /proc/cpuinfo each had
their own idea of where the work was. /proc/stat marked a core busy from
*either* the workload module or the process table's booked CPU; cpuinfo
only knew about the first. So htop drew 0, 3, 16, 18 and 30 pinned while
cpuinfo called 3, 16, 18, 30 and 45 the fastest. Two commands, one
question, different answers -- which is the whole point of a sweep.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakeshell

CHECKS, FAILS = [], []
FIELDS = ["user", "nice", "system", "idle", "iowait", "irq", "softirq",
          "steal", "guest", "guest_nice"]


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                           peer_port=40333)


def rows(sh):
    out = {}
    for ln in sh.fs._dynamic("/proc/stat").decode().splitlines():
        if ln.startswith("cpu") and ln[3:4].isdigit():
            p = ln.split()
            out[int(p[0][3:])] = [int(x) for x in p[1:]]
    return out


def busy_pct(a, b):
    """The percentage htop would draw, from two samples."""
    pct = {}
    for c in a:
        d = [y - x for x, y in zip(a[c], b[c])]
        tot = sum(d)
        pct[c] = 100.0 * (tot - d[3] - d[4]) / tot if tot else 0.0
    return pct


def main():
    F = fakeshell
    ncpu, ncores = F.NCPU, F.CPU_CORES

    # -- the scatter -------------------------------------------------------
    check("CORE_ORDER is a permutation of the cores",
          sorted(F.CORE_ORDER), list(range(ncpu)))
    check("whole physical cores are used before SMT siblings",
          len({c % ncores for c in F.CORE_ORDER[:ncores]}), ncores,
          "a job takes a free core before it shares one")
    check("the fill order is not the identity",
          F.CORE_ORDER[:8] == list(range(8)), False,
          "cpu0, cpu1, cpu2... is not how anything schedules")

    # -- the trickle -------------------------------------------------------
    check("every idle core has its own baseline",
          len(set(F.CORE_TRICKLE)), ncpu)
    same7 = [c for c in range(ncpu - 7)
             if abs(F.CORE_TRICKLE[c] - F.CORE_TRICKLE[c + 7]) < 1e-12]
    check("no core repeats its c+7 neighbour", same7, [],
          "the (c %% 7) term drew a pattern repeating every seventh bar")
    check("idle baselines stay under 4%%",
          max(F.CORE_TRICKLE) < 0.04, True)

    # -- the rate bound: idle can never go negative ------------------------
    worst_rate = 0.0
    worst_back = 0.0
    for c in range(ncpu):
        for frac, amp in ((0.94, 0.10), (F.CORE_TRICKLE[c], None)):
            prev = F._core_busy_secs(c, 0.0, frac, amp)
            t = 0.0
            while t < 700.0:
                t += 0.5
                v = F._core_busy_secs(c, t, frac, amp)
                worst_rate = max(worst_rate, (v - prev) / 0.5)
                worst_back = min(worst_back, v - prev)
                prev = v
    check("a core never books more than one second per second",
          worst_rate < 1.0, True, "got %.4f" % worst_rate)
    check("booked seconds never decrease", worst_back >= 0.0, True,
          "got %.6f" % worst_back)

    # -- monotonicity of the emitted integers ------------------------------
    sh = shell()
    prev = rows(sh)
    drops = {}
    for _ in range(40):
        time.sleep(0.05)
        cur = rows(sh)
        for c in cur:
            for i, (x, y) in enumerate(zip(prev[c], cur[c])):
                if y < x:
                    drops[FIELDS[i]] = drops.get(FIELDS[i], 0) + 1
        prev = cur
    check("no /proc/stat field on any core ever decreases", drops, {},
          "iowait as an integer remainder dropped on 6 of 64 cores")
    check("no idle count is negative",
          [c for c in prev if prev[c][3] < 0], [])

    # -- the row totals ----------------------------------------------------
    sums = [sum(v) for v in prev.values()]
    check("per-core totals are not all the same",
          max(sums) - min(sums) > 1000, True,
          "the real box spread 63462 jiffies; got %d" % (max(sums) - min(sums)))

    # -- the split ---------------------------------------------------------
    ratios = [prev[c][0] / max(1, prev[c][2]) for c in prev]
    check("user:system differs per core",
          len({round(r, 2) for r in ratios}) >= ncpu - 2, True)
    check("userspace dominates, as on a real box",
          min(ratios) > 5.0 and max(ratios) < 60.0, True,
          "real 24-thread box measured 19.9 .. 41.2; got %.1f .. %.1f"
          % (min(ratios), max(ratios)))

    # -- the aggregate row is the sum of the per-core rows -----------------
    agg = None
    for ln in sh.fs._dynamic("/proc/stat").decode().splitlines():
        if ln.startswith("cpu  "):
            agg = [int(x) for x in ln.split()[1:]]
            break
    cur = rows(sh)
    colsum = [sum(cur[c][i] for c in cur) for i in range(10)]
    # Sampled a moment apart, so allow the drift of one read.
    check("the cpu line is the sum of the cpuN lines",
          all(abs(a - b) <= 200 for a, b in zip(agg, colsum)), True,
          "agg %r vs colsum %r" % (agg[:5], colsum[:5]))

    # -- booked time is never handed back ----------------------------------
    sh2 = shell()
    before = rows(sh2)
    sh2.fs._live_pids = lambda: []          # every charged process exits
    time.sleep(0.15)
    after = rows(sh2)
    lost = [c for c in before
            if after[c][0] < before[c][0] or after[c][2] < before[c][2]]
    check("a core keeps its booked time when the process exits", lost, [],
          "the kernel does not unbill a dead process")

    # -- one question, one answer -----------------------------------------
    sh3 = shell()
    a = rows(sh3)
    time.sleep(1.2)
    b = rows(sh3)
    pct = busy_pct(a, b)
    hot = sorted(c for c in pct if pct[c] > 40.0)
    check("the workload is not on a contiguous block of cores",
          hot == list(range(len(hot))), False, "got %r" % (hot,))
    check("something is actually running", len(hot) > 0, True)

    # The count has to follow the workload, not a constant. This suite was
    # written when the box ran one training job at 4.9 cores; the nightly
    # batch job starts at 02:00 and takes it to 6.97, and the mapping has
    # to hold across that without being retuned. Measured at 03:10 with
    # the night job live: workload 6.97 cores, loadavg 7.08, six full
    # cores plus an edge core at 97%, and /proc/cpuinfo's seven fastest
    # were the same seven /proc/stat had above 40%.
    try:
        import workload as _wl
        _cores = sum(j["cpu"] for j in _wl.active()) / 100.0
    except Exception:                                          # noqa: BLE001
        _cores = None
    if _cores:
        check("the busy-core count follows the workload",
              abs(len(hot) - _cores) <= 1.05, True,
              "%d cores above 40%% against a workload of %.2f"
              % (len(hot), _cores))
        _la = sh3.fs.loadavg()
        check("...and so does the load average",
              abs(_la[0] - _cores) < 0.8, True,
              "load %.2f against %.2f cores" % (_la[0], _cores))
        _full, _edge, _part, _sp, _ch = sh3.fs._hot_cores()
        check("the cores are taken from the fill order, in order",
              sorted(_full), sorted(F.CORE_ORDER[:len(_full)]))
        if _edge is not None:
            check("the part-loaded core is the next one in that order",
                  _edge, F.CORE_ORDER[len(_full)])

    ci = sh3.fs._dynamic("/proc/cpuinfo").decode()
    mhz = [float(l.split(":")[1]) for l in ci.splitlines()
           if l.startswith("cpu MHz")]
    check("/proc/cpuinfo reports one clock per core", len(mhz), ncpu)
    fastest = sorted(sorted(range(ncpu), key=lambda i: -mhz[i])[:len(hot)])
    check("the cores htop draws pinned are the cores cpuinfo clocks highest",
          fastest, hot,
          "stat and cpuinfo each had their own idea of where the work was")
    if hot:
        idle_mhz = [mhz[c] for c in range(ncpu) if c not in hot]
        check("no idle core outruns a busy one",
              min(mhz[c] for c in hot) > max(idle_mhz), True)

    # -- the clock tiers cannot cross, at any instant ----------------------
    crossed = []
    for k in range(12):
        ci = sh3.fs._dynamic("/proc/cpuinfo").decode()
        m = [float(l.split(":")[1]) for l in ci.splitlines()
             if l.startswith("cpu MHz")]
        full, edge, _part, _sp, charged = sh3.fs._hot_cores()
        up = max(1.0, time.time() - F.BOOT_TS)
        pinned = set(full) | {c for c, v in charged.items() if v / up > 0.25}
        low = [m[c] for c in range(ncpu) if c not in pinned and c != edge]
        if pinned and low and min(m[c] for c in pinned) <= max(low):
            crossed.append(k)
        if edge is not None and low and m[edge] <= max(low):
            crossed.append(k)
        time.sleep(0.08)
    check("pinned > part-loaded > idle holds at every instant", crossed, [],
          "a +/-480 walk let an idle core reach 2980 while a part-loaded "
          "core sat at 2640")

    print("%d/%d assertions pass" % (sum(CHECKS), len(CHECKS)))
    for f in FAILS:
        print(f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
