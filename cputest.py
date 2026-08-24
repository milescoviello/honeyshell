#!/usr/bin/env python3
"""Does the box describe a CPU that /sys actually contains?

lscpu is the command every recon script reaches for, and this one answered
questions about hardware the filesystem underneath it did not have.

  - It claimed "CPU max MHz: 3300.0000" and "CPU min MHz: 1200.0000".
    Those come from /sys/devices/system/cpu/cpu0/cpufreq, which did not
    exist -- and a KVM guest has no scaling driver at all, so reporting a
    scaling range contradicted the hypervisor lscpu admits to two lines
    lower. Checked against the real trixie KVM guest this honeypot runs
    on: no cpufreq directory, and no MHz lines in its lscpu.
  - Every flag was ignored. `lscpu -p` -- the parsable form a script uses
    to size a thread pool, and the reason a miner runs lscpu at all --
    returned the human table instead of CSV. So did -e.
  - lscpu printed no cache lines while `lscpu -p`'s own header names L1d,
    L1i, L2 and L3, and sysfs had a single index0 carrying a size but no
    type: nothing could tell which cache it described.
  - /sys/devices/system/cpu/vulnerabilities did not exist, so the box was
    silent on all seventeen questions a real trixie answers.
  - The layout was util-linux's nested style, which trixie does not
    produce. Real lscpu is flat with the value at column 42, so
    `awk -F: '/^Model name:/'` -- an ordinary thing to run, and the exact
    shape of the lscpu one-liner an actor ran here on 2026-08-20 -- matched
    nothing on this box while working everywhere else.

The label set is checked against a real Debian 13 KVM guest running
util-linux 2.41.5, and the -p/-e formats against util-linux on trixie.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                        # noqa: E402

PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-54s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def t_lscpu_is_flat_like_trixies():
    """Nested output meant every ^-anchored grep for a field missed."""
    s = sh()
    out, rc = run(s, "lscpu")
    eq("lscpu rc", rc, 0)
    for line in out.strip().splitlines():
        check("no leading whitespace: %r" % line[:24],
              not line.startswith(" "), line[:40])
        if ":" in line:
            label = line.split(":")[0]
            eq("value starts at column 42 for %r" % label[:22],
               len(line) - len(line.split(":", 1)[1].lstrip()), 41)


def t_anchored_greps_find_their_fields():
    """The shape the 2026-08-20 actor used, and the ones next to it."""
    s = sh()
    for field in ("Architecture", "CPU(s)", "Model name", "Vendor ID",
                  "Socket(s)", "Core(s) per socket", "Thread(s) per core",
                  "Hypervisor vendor", "L1d cache", "L3 cache",
                  "NUMA node(s)"):
        # Literal parens, not escaped: in a BRE \( opens a group, so
        # '^CPU\(s\):' looks for "CPUs:" and finds nothing.
        out, _ = run(s, "lscpu | grep -c '^%s:'" % field)
        eq("^%s: is findable" % field, out.strip(), "1")
    out, _ = run(s, "lscpu | awk -F: '/^Model name/ {gsub(/^ +/,\"\",$2); "
                    "print $2}'")
    eq("awk pulls the model name", out.strip(), fs.CPU_MODEL)


def t_no_scaling_range_without_a_scaling_driver():
    """A KVM guest has no cpufreq. Claiming max/min MHz contradicted both
    the missing sysfs and the hypervisor lscpu reports."""
    s = sh()
    out, _ = run(s, "lscpu")
    check("no CPU max MHz", "CPU max MHz" not in out, out[:60])
    check("no CPU min MHz", "CPU min MHz" not in out, out[:60])
    out2, rc = run(s, "ls /sys/devices/system/cpu/cpu0/cpufreq")
    eq("and no cpufreq directory to have read it from", rc, 2)
    out3, _ = run(s, "lscpu | grep -c 'Hypervisor vendor: *KVM'")
    eq("while still reporting KVM", out3.strip(), "1")


def t_parsable_output_is_parsable():
    """`lscpu -p` returned the human table, so anything feeding it to a
    parser got a header where it expected CSV."""
    s = sh()
    out, rc = run(s, "lscpu -p")
    eq("lscpu -p rc", rc, 0)
    lines = out.strip().splitlines()
    check("three comment lines then the column header",
          all(l.startswith("#") for l in lines[:4]), lines[:1])
    eq("header names the columns trixie names",
       lines[3], "# CPU,Core,Socket,Node,,L1d,L1i,L2,L3")
    body = lines[4:]
    eq("one row per cpu", len(body), fs.NCPU)
    for i, row in enumerate(body):
        cells = row.split(",")
        eq("row %d has 9 fields" % i, len(cells), 9)
        eq("row %d names cpu %d" % (i, i), cells[0], str(i))
        eq("row %d socket is 0" % i, cells[2], "0")
        eq("row %d L3 is shared" % i, cells[8], "0")


def t_parsable_honours_a_column_list():
    s = sh()
    out, rc = run(s, "lscpu -p=cpu,core,socket")
    eq("rc", rc, 0)
    lines = out.strip().splitlines()
    eq("header is the requested columns", lines[3], "# CPU,Core,Socket")
    eq("and rows are three wide", len(lines[4].split(",")), 3)


def t_extended_output_is_a_table():
    s = sh()
    out, rc = run(s, "lscpu -e")
    eq("lscpu -e rc", rc, 0)
    lines = out.strip().splitlines()
    eq("header", lines[0], "CPU NODE SOCKET CORE L1d:L1i:L2:L3 ONLINE")
    eq("one row per cpu", len(lines) - 1, fs.NCPU)
    check("rows say yes", all(l.endswith("yes") for l in lines[1:]),
          lines[1:2])


def t_the_caches_lscpu_names_are_in_sysfs():
    """-p's header names four caches; sysfs had one index with no type."""
    s = sh()
    out, _ = run(s, "ls /sys/devices/system/cpu/cpu0/cache/")
    eq("four cache indices", sorted(out.split()),
       ["index0", "index1", "index2", "index3"])
    for idx, (lvl, typ, size, ways, sets, shared) in enumerate(
            fs.CPU_CACHES):
        base = "/sys/devices/system/cpu/cpu0/cache/index%d" % idx
        for fname, want in (("level", str(lvl)), ("type", typ),
                            ("size", size),
                            ("ways_of_associativity", str(ways)),
                            ("number_of_sets", str(sets)),
                            ("coherency_line_size", "64")):
            o, rc = run(s, "cat %s/%s" % (base, fname))
            eq("index%d/%s" % (idx, fname), (o.strip(), rc), (want, 0))
        o, _ = run(s, "cat %s/shared_cpu_list" % base)
        eq("index%d is shared correctly" % idx, o.strip(),
           ("0-%d" % (fs.NCPU - 1)) if shared else "0")


def t_lscpu_cache_lines_match_the_geometry():
    """Sizes lscpu prints are per-instance size times instance count."""
    s = sh()
    out, _ = run(s, "lscpu")
    for label, want in (("L1d cache", "128 KiB (4 instances)"),
                        ("L1i cache", "128 KiB (4 instances)"),
                        ("L2 cache", "1 MiB (4 instances)"),
                        ("L3 cache", "25 MiB (1 instance)")):
        m = re.search(r"^%s:\s+(.+)$" % re.escape(label), out, re.M)
        check("%s is reported" % label, m, out[:60])
        if m:
            eq("%s total" % label, m.group(1).strip(), want)


def t_the_vulnerability_block_is_backed_by_sysfs():
    """lscpu prints these straight out of sysfs, and the directory was not
    there at all."""
    s = sh()
    out, _ = run(s, "ls /sys/devices/system/cpu/vulnerabilities/")
    eq("every file is present", sorted(out.split()),
       sorted(n for n, _v in fs.CPU_VULNS))
    lscpu, _ = run(s, "lscpu")
    for name, value in fs.CPU_VULNS:
        o, rc = run(s, "cat /sys/devices/system/cpu/vulnerabilities/%s"
                    % name)
        eq("sysfs %s" % name, (o.strip(), rc), (value, 0))
        lbl = name.replace("_", " ")
        lbl = "Vulnerability " + lbl[0].upper() + lbl[1:]
        m = re.search(r"^%s:\s+(.+)$" % re.escape(lbl), lscpu, re.M)
        check("lscpu reports %s" % lbl, m, lbl)
        if m:
            eq("and it matches sysfs: %s" % name, m.group(1).strip(), value)


def t_the_cpu_count_is_the_same_everywhere():
    """Five views of one number, which is what a miner sizes itself by."""
    s = sh()
    n = fs.NCPU
    eq("nproc", run(s, "nproc")[0].strip(), str(n))
    eq("/proc/cpuinfo", run(s, "grep -c ^processor /proc/cpuinfo")[0].strip(),
       str(n))
    eq("getconf", run(s, "getconf _NPROCESSORS_ONLN")[0].strip(), str(n))
    eq("sysfs cpu dirs",
       run(s, "ls -d /sys/devices/system/cpu/cpu[0-9] | wc -l")[0].strip(),
       str(n))
    eq("lscpu -p row count",
       run(s, "lscpu -p | grep -vc '^#'")[0].strip(), str(n))
    eq("lscpu -e row count",
       str(len(run(s, "lscpu -e")[0].strip().splitlines()) - 1), str(n))
    out, _ = run(s, "lscpu")
    m = re.search(r"^CPU\(s\):\s+(\d+)$", out, re.M)
    eq("lscpu CPU(s)", m.group(1) if m else None, str(n))


def t_topology_is_complete_enough_to_walk():
    s = sh()
    out, _ = run(s, "ls /sys/devices/system/cpu/cpu0/topology/")
    for f in ("core_id", "physical_package_id", "die_id", "core_cpus_list",
              "package_cpus_list", "thread_siblings_list"):
        check("topology/%s exists" % f, f in out.split(), out.split()[:5])
    o, _ = run(s, "cat /sys/devices/system/cpu/cpu3/topology/core_id")
    eq("cpu3 is core 3", o.strip(), "3")
    o, _ = run(s, "cat /sys/devices/system/cpu/cpu0/topology/"
                  "package_cpus_list")
    eq("all cpus in one package", o.strip(), "0-%d" % (fs.NCPU - 1))


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:6]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
