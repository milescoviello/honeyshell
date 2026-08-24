r"""Four memory sources, four answers.

Fifty-first coherence sweep. The axis picked itself: in the last day four
separate actors ran a hardware inventory before deciding whether to
install -- lscpu, nproc, MemTotal, lspci, nvidia-smi, uptime. So: do the
commands that answer "how much memory does this box have" agree?

CPU did. nproc, getconf, lscpu, /proc/cpuinfo, /sys/.../cpu/online and
the cpuN directory count all say 4, /proc/stat has four per-cpu lines,
and btime + uptime lands on now. Those are pinned here, not changed.

Memory did not. Four sources, four answers for free memory:

    /proc/meminfo MemFree      1129384 kB
    free -k                    1129384 kB   (reads meminfo)
    /proc/vmstat nr_free_pages  473688 kB   (118422 pages, hardcoded)
    vmstat                      151852 kB   (hardcoded row)

and for page cache: meminfo 482264, vmstat's row 1422956, /proc/vmstat
nr_file_pages 316472. A miner's installer that sizes the box twice by two
different means -- which is exactly what `free -m` plus `grep MemTotal`
is -- got two different boxes.

cmd_vmstat was three literal lines returned for every invocation:

  - `vmstat -s` is a completely different report and printed the default
    table instead.
  - `-S M`, `-a` and `--version` were ignored the same way.
  - The header was missing procps 4.0.4's `gu` column, while dpkg on the
    same box reports procps 2:4.0.4-8.

/proc/meminfo had seven keys where a real one has about fifty; Active,
Inactive, SReclaimable, AnonPages, Dirty and Slab were simply absent, so
`vmstat -s` would have reported zero active memory and `free`'s
buff/cache silently dropped the reclaimable slab.

free ignored -t and -w. `free -t | tail -1` is the ordinary way a script
reads total memory including swap, and it got the Swap row.

top ran whatever it was handed, so `top -v` printed a process table where
procps writes "top: invalid option -- 'v'" to stderr and exits 1, and
`top -V` could not report a version at all.

The fix is one memory table, MEMINFO_KB, that /proc/meminfo,
/proc/vmstat, free, top and vmstat all read -- the same second-source-of-
truth removal already done for sysctl.

Reference measured against real procps-ng 4.0.4, which is the version
this box's dpkg claims.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def run(script, user="root"):
    s = fs.Shell(fs.VFS(), user=user, peer="203.0.113.77")
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


def num(script):
    out, _ = run(script)
    m = re.search(r"-?\d+", out)
    return int(m.group(0)) if m else None


def meminfo():
    out, _ = run("cat /proc/meminfo")
    return {k: int(v) for k, v in re.findall(r"^(\S+):\s+(\d+)", out, re.M)}


def procvmstat():
    out, _ = run("cat /proc/vmstat")
    return {k: int(v) for k, v in re.findall(r"^(\S+)\s+(-?\d+)$", out, re.M)}


# -- the CPU side already agreed; keep it that way -----------------------

def t_cpu_count_agrees_everywhere():
    want = 4
    eq("nproc", num("nproc"), want)
    eq("getconf _NPROCESSORS_ONLN", num("getconf _NPROCESSORS_ONLN"), want)
    eq("lscpu CPU(s)", num("lscpu | grep -E '^CPU\\(s\\):'"), want)
    eq("/proc/cpuinfo", num("grep -c ^processor /proc/cpuinfo"), want)
    eq("cpuN dirs", num("ls -d /sys/devices/system/cpu/cpu[0-9]* | wc -l"), want)
    eq("/proc/stat per-cpu", num("grep -c '^cpu[0-9]' /proc/stat"), want)
    out, _ = run("cat /sys/devices/system/cpu/online")
    eq("cpu online range", out.strip(), "0-3")


def t_boot_time_plus_uptime_is_now():
    b = num("awk '/^btime/{print $2}' /proc/stat")
    u = num("cut -d. -f1 /proc/uptime")
    n = num("date +%s")
    check("btime + uptime == now", abs((b + u) - n) <= 3,
          "btime=%s uptime=%s now=%s drift=%s" % (b, u, n, n - b - u))


# -- one answer for free memory ------------------------------------------

def t_free_memory_agrees_across_sources():
    mi = meminfo()
    vm = procvmstat()
    a = mi["MemFree"]
    b = vm["nr_free_pages"] * 4
    c = num("free -k | awk '/^Mem:/{print $4}'")
    d = num("vmstat | tail -1 | awk '{print $4}'")
    eq("meminfo vs /proc/vmstat", b, a)
    eq("meminfo vs free -k", c, a)
    eq("meminfo vs vmstat row", d, a)


def t_page_cache_agrees():
    mi = meminfo()
    vm = procvmstat()
    eq("nr_file_pages vs Buffers+Cached",
       vm["nr_file_pages"] * 4, mi["Buffers"] + mi["Cached"])
    eq("free buff/cache", num("free -k | awk '/^Mem:/{print $6}'"),
       mi["Buffers"] + mi["Cached"] + mi["SReclaimable"])


def t_used_memory_agrees():
    used_free = num("free -k | awk '/^Mem:/{print $3}'")
    used_vmstat = num("vmstat -s | awk '/K used memory/{print $1}'")
    eq("free vs vmstat -s used", used_vmstat, used_free)


def t_meminfo_internal_arithmetic():
    mi = meminfo()
    eq("Active = anon + file", mi["Active"],
       mi["Active(anon)"] + mi["Active(file)"])
    eq("Inactive = anon + file", mi["Inactive"],
       mi["Inactive(anon)"] + mi["Inactive(file)"])
    eq("Slab = SReclaimable + SUnreclaim", mi["Slab"],
       mi["SReclaimable"] + mi["SUnreclaim"])
    eq("anon LRU = AnonPages + Shmem",
       mi["Active(anon)"] + mi["Inactive(anon)"],
       mi["AnonPages"] + mi["Shmem"])
    eq("file LRU = Buffers + Cached - Shmem",
       mi["Active(file)"] + mi["Inactive(file)"],
       mi["Buffers"] + mi["Cached"] - mi["Shmem"])
    check("MemFree <= MemTotal", mi["MemFree"] <= mi["MemTotal"])
    check("MemAvailable <= MemTotal", mi["MemAvailable"] <= mi["MemTotal"])


def t_meminfo_has_the_keys_a_real_one_has():
    mi = meminfo()
    for k in ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached",
              "SwapCached", "Active", "Inactive", "Active(anon)",
              "Inactive(anon)", "Active(file)", "Inactive(file)", "Dirty",
              "Writeback", "AnonPages", "Mapped", "Shmem", "Slab",
              "SReclaimable", "SUnreclaim", "KernelStack", "PageTables",
              "CommitLimit", "Committed_AS", "VmallocTotal", "Hugepagesize"):
        check("meminfo has %s" % k, k in mi)


def t_top_agrees_with_free():
    out, _ = run("top -bn1 | sed -n 4p")
    m = re.search(r"([\d.]+) total,\s+([\d.]+) free,\s+([\d.]+) used,"
                  r"\s+([\d.]+) buff/cache", out)
    check("top mem line parses", m is not None, out[:70])
    if not m:
        return
    mi = meminfo()
    eq("top total MiB", round(float(m.group(1))), round(mi["MemTotal"] / 1024.0))
    eq("top free MiB", round(float(m.group(2))), round(mi["MemFree"] / 1024.0))


# -- vmstat is a program, not a constant ---------------------------------

def t_vmstat_s_is_a_different_report():
    out, rc = run("vmstat -s")
    check("-s is not the default table", "procs -----------memory" not in out,
          out[:60])
    check("-s reports total memory", "K total memory" in out, out[:60])
    check("-s reports cpu ticks", "idle cpu ticks" in out, out[:60])
    check("-s reports boot time", "boot time" in out, out[:60])
    eq("-s rc", rc, 0)
    eq("-s total memory", num("vmstat -s | head -1"), meminfo()["MemTotal"])


def t_vmstat_s_paging_matches_proc():
    """vmstat -s passes /proc/vmstat's counters straight through.

    They advance between the two reads, as they do on a real box, so this
    checks they track rather than that they are frozen equal.
    """
    a = num("vmstat -s | awk '/K paged in/{print $1}'")
    b = procvmstat()["pgpgin"]
    check("paged in tracks pgpgin", abs(a - b) < 1000, "%s vs %s" % (a, b))
    check("paged in is not zero", a > 0, str(a))


def t_vmstat_S_changes_the_unit():
    free_k = num("vmstat | tail -1 | awk '{print $4}'")
    free_m = num("vmstat -S M | tail -1 | awk '{print $4}'")
    eq("-S M is KiB/1024", free_m, free_k // 1024)


def t_vmstat_a_swaps_the_columns():
    out, _ = run("vmstat -a")
    hdr = out.splitlines()[1]
    check("-a header says inact/active", "inact active" in hdr, hdr)
    check("-a header drops buff/cache", "buff  cache" not in hdr, hdr)
    mi = meminfo()
    eq("-a active column", num("vmstat -a | tail -1 | awk '{print $6}'"),
       mi["Active"])
    eq("-a inact column", num("vmstat -a | tail -1 | awk '{print $5}'"),
       mi["Inactive"])


def t_vmstat_default_header_is_procps_404():
    out, _ = run("vmstat")
    hdr = out.splitlines()[1]
    eq("default header", hdr,
       " r  b   swpd   free   buff  cache   si   so    bi    bo"
       "   in   cs us sy id wa st gu")
    check("gu column present", hdr.rstrip().endswith(" gu"), hdr)


def t_procps_tools_report_their_version():
    """dpkg says procps 2:4.0.4-8; the tools must not disagree."""
    out, rc = run("vmstat --version")
    eq("vmstat --version", out.strip(), "vmstat from procps-ng 4.0.4")
    eq("vmstat --version rc", rc, 0)
    out, _ = run("free --version")
    eq("free --version", out.strip(), "free from procps-ng 4.0.4")
    out, rc = run("top -V")
    eq("top -V", out.strip(), "top from procps-ng 4.0.4")
    eq("top -V rc", rc, 0)
    out, _ = run("dpkg -l procps | tail -1")
    check("dpkg still says 4.0.4", "4.0.4" in out, out[:60])


def t_top_rejects_an_unknown_flag():
    out, rc = run("top -v")
    eq("top -v message", out.strip(), "top: invalid option -- 'v'")
    eq("top -v rc", rc, 1)
    check("top -v printed no table", "PID USER" not in out, out[:60])


# -- free's ignored flags ------------------------------------------------

def t_free_t_adds_the_total_row():
    out, _ = run("free -t")
    lines = [l for l in out.splitlines() if l.strip()]
    check("Total: row present", lines[-1].startswith("Total:"), lines[-1])
    mi = meminfo()
    eq("Total: total", num("free -t | awk '/^Total:/{print $2}'"),
       mi["MemTotal"] + mi["SwapTotal"])


def t_free_w_splits_buffers_from_cache():
    out, _ = run("free -w")
    hdr = out.splitlines()[0]
    check("-w header has buffers", "buffers" in hdr, hdr)
    check("-w header has cache", "cache" in hdr, hdr)
    check("-w header drops buff/cache", "buff/cache" not in hdr, hdr)
    mi = meminfo()
    eq("-w buffers column", num("free -w | awk '/^Mem:/{print $6}'"),
       mi["Buffers"])
    eq("-w cache column", num("free -w | awk '/^Mem:/{print $7}'"),
       mi["Cached"] + mi["SReclaimable"])


def t_free_units_still_agree():
    mi = meminfo()
    eq("free -b total", num("free -b | awk '/^Mem:/{print $2}'"),
       mi["MemTotal"] * 1024)
    eq("free -m total", num("free -m | awk '/^Mem:/{print $2}'"),
       mi["MemTotal"] // 1024)
    eq("free -k total", num("free -k | awk '/^Mem:/{print $2}'"),
       mi["MemTotal"])


def t_the_attacker_recon_shapes_still_work():
    """The exact pipelines seen in the last day of sessions."""
    eq("grep MemTotal", num("grep MemTotal /proc/meminfo"),
       meminfo()["MemTotal"])
    eq("lscpu awk CPU(s)",
       num("lscpu 2>/dev/null | awk -F: '/^CPU\\(s\\):/ "
           "{gsub(/ /,\"\",$2); print $2}'"), 4)
    out, _ = run("lscpu | egrep 'Model name:' | cut -d ' ' -f 14-")
    check("model name survives cut", "Xeon" in out, out[:60])
    out, _ = run("uptime | grep -ohe 'up .*' | sed 's/,//g' "
                 "| awk '{ print $2\" \"$3 }'")
    check("uptime extraction", re.match(r"^\d+ days?$", out.strip()) is not None,
          out[:40])


TESTS = [t_cpu_count_agrees_everywhere, t_boot_time_plus_uptime_is_now,
         t_free_memory_agrees_across_sources, t_page_cache_agrees,
         t_used_memory_agrees, t_meminfo_internal_arithmetic,
         t_meminfo_has_the_keys_a_real_one_has, t_top_agrees_with_free,
         t_vmstat_s_is_a_different_report, t_vmstat_s_paging_matches_proc,
         t_vmstat_S_changes_the_unit, t_vmstat_a_swaps_the_columns,
         t_vmstat_default_header_is_procps_404,
         t_procps_tools_report_their_version, t_top_rejects_an_unknown_flag,
         t_free_t_adds_the_total_row, t_free_w_splits_buffers_from_cache,
         t_free_units_still_agree, t_the_attacker_recon_shapes_still_work]


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
