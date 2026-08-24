#!/usr/bin/env python3
"""Hugepages: one number, five places that report it.

Straight from the traffic. At 07:49 on 2026-08-24, 203.0.113.33 logged in
with zero prior failures, set `sysctl -w vm.nr_hugepages=1284`, appended it
to /etc/sysctl.conf and unpacked SRBMiner. That miner reads Hugepagesize to
size its allocation and HugePages_Free to decide whether to use hugepages at
all, so it is worth asking whether the box answers consistently. It did not.

Setting the knob moved `sysctl` and /proc/sys/vm/nr_hugepages and left
/proc/meminfo saying HugePages_Total: 0 and HugePages_Free: 0 and Hugetlb: 0
-- and /sys/kernel/mm/hugepages did not exist at all, so `cat
/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages` was "No such file or
directory" on a box where that path always exists. Three of the five places
a miner looks disagreed with the two that had been set.

Three /proc/sys/vm siblings were missing too -- nr_hugepages_mempolicy,
nr_overcommit_hugepages and hugetlb_shm_group -- so `sysctl -a | grep huge`
listed one knob where the guest lists four.

And the baseline formatting was wrong before anything was set.
/proc/meminfo's four HugePages_* counters are printed in a fixed 24-column
field; the generic "%-15s %8d" is right for the three whose label is 15
characters and one short for HugePages_Total:, whose label is 16, so its
value sat one column right of the three beside it. Anything reading meminfo
by column saw it misaligned.

The derivation is hooked on the write to /proc/sys/vm/nr_hugepages rather
than on sysctl, so every spelling agrees: `sysctl -w`, `echo N >`, `tee`,
anything. Reference values measured on the guest at n=4 -- Total 4, Free 4,
Rsvd 0, Surp 0, Hugepagesize 2048 kB, Hugetlb 8192 kB, sysfs nr and free
both 4 -- and the six meminfo lines are compared byte for byte.

Run from ~/opsec/honeypot:  python3 -W ignore hugetest.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

SYSFS = "/sys/kernel/mm/hugepages/hugepages-2048kB"

# Measured on the guest. n -> the six meminfo lines, verbatim.
GUEST = {
    0: ["HugePages_Total:       0",
        "HugePages_Free:        0",
        "HugePages_Rsvd:        0",
        "HugePages_Surp:        0",
        "Hugepagesize:       2048 kB",
        "Hugetlb:               0 kB"],
    4: ["HugePages_Total:       4",
        "HugePages_Free:        4",
        "HugePages_Rsvd:        0",
        "HugePages_Surp:        0",
        "Hugepagesize:       2048 kB",
        "Hugetlb:            8192 kB"],
}

# Every way a script sets it.
SETTERS = [
    "sysctl -w vm.nr_hugepages=%d",
    "echo %d > /proc/sys/vm/nr_hugepages",
    "printf %d | tee /proc/sys/vm/nr_hugepages >/dev/null",
    "sysctl vm.nr_hugepages=%d",
]

# The files the guest has under /proc/sys/vm and in the sysfs directory.
PROC_SYS = ["hugetlb_shm_group", "nr_hugepages", "nr_hugepages_mempolicy",
            "nr_overcommit_hugepages"]
SYSFS_FILES = ["free_hugepages", "nr_hugepages", "nr_hugepages_mempolicy",
               "nr_overcommit_hugepages", "resv_hugepages",
               "surplus_hugepages"]


def shell(vfs=None):
    sh = fs.Shell(vfs or fs.VFS())
    sh.exec_mode = True
    return sh


def meminfo_huge(sh):
    return [l.rstrip() for l in sh.run(
        "grep -E '^HugePages|^Hugetlb|^Hugepagesize' /proc/meminfo"
    ).splitlines() if l.strip()]


def main():
    verbose = "-v" in sys.argv
    ok = bad = 0

    def check(label, got, want):
        nonlocal ok, bad
        if got == want:
            ok += 1
            if verbose:
                print("  ok    %s" % label)
        else:
            bad += 1
            print("  FAIL  %s" % label)
            print("        got  %r" % (got,))
            print("        want %r" % (want,))

    # ---- the files exist at all ------------------------------------------
    sh = shell()
    have = set(sh.run("ls /proc/sys/vm/").split())
    for f in PROC_SYS:
        check("/proc/sys/vm/%s exists" % f, f in have, True)
    check("the sysfs hugepages directory exists",
          sh.run("test -d %s && echo yes || echo no" % SYSFS).strip(), "yes")
    check("...with the guest's six files",
          sorted(sh.run("ls %s" % SYSFS).split()), SYSFS_FILES)
    check("...and the directory is 0755",
          sh.run("stat -c %%a %s" % SYSFS).strip(), "755")
    check("...and its files 0644",
          sh.run("stat -c %%a %s/nr_hugepages" % SYSFS).strip(), "644")
    check("/sys/kernel/mm lists hugepages beside transparent_hugepage",
          "hugepages" in sh.run("ls /sys/kernel/mm/").split(), True)

    # ---- the untouched baseline matches the guest ------------------------
    check("meminfo hugepage lines at n=0 match the guest",
          meminfo_huge(shell()), GUEST[0])

    # ---- every setter moves every reader, identically --------------------
    for tmpl in SETTERS:
        for n in (4, 1284):
            sh = shell()
            sh.run(tmpl % n)
            label = tmpl % n
            check("%s -> sysctl" % label,
                  sh.run("sysctl -n vm.nr_hugepages").strip(), str(n))
            check("%s -> /proc/sys" % label,
                  sh.run("cat /proc/sys/vm/nr_hugepages").strip(), str(n))
            check("%s -> sysfs nr_hugepages" % label,
                  sh.run("cat %s/nr_hugepages" % SYSFS).strip(), str(n))
            check("%s -> sysfs free_hugepages" % label,
                  sh.run("cat %s/free_hugepages" % SYSFS).strip(), str(n))
            check("%s -> meminfo HugePages_Total" % label,
                  sh.run("grep HugePages_Total /proc/meminfo").split()[1],
                  str(n))
            check("%s -> meminfo HugePages_Free" % label,
                  sh.run("grep HugePages_Free /proc/meminfo").split()[1],
                  str(n))
            check("%s -> meminfo Hugetlb is n*2048 kB" % label,
                  sh.run("grep Hugetlb /proc/meminfo").split()[1],
                  str(n * 2048))
            check("%s leaves Hugepagesize alone" % label,
                  sh.run("grep Hugepagesize /proc/meminfo").split()[1],
                  "2048")
            check("%s leaves Rsvd and Surp at 0" % label,
                  [sh.run("grep HugePages_%s /proc/meminfo" % k).split()[1]
                   for k in ("Rsvd", "Surp")], ["0", "0"])

    # ---- byte-for-byte against the guest at n=4 ---------------------------
    sh = shell()
    sh.run("sysctl -w vm.nr_hugepages=4")
    check("meminfo hugepage lines at n=4 match the guest byte for byte",
          meminfo_huge(sh), GUEST[4])

    # ---- and back down again ---------------------------------------------
    sh.run("sysctl -w vm.nr_hugepages=0")
    check("setting it back to 0 restores every reader",
          meminfo_huge(sh), GUEST[0])
    check("...including the sysfs files",
          [sh.run("cat %s/%s" % (SYSFS, f)).strip()
           for f in ("nr_hugepages", "free_hugepages")], ["0", "0"])

    # ---- it survives the attacker coming back ----------------------------
    a = fs.VFS()
    sha = shell(a)
    sha.run("sysctl -w vm.nr_hugepages=1284")
    b = fs.VFS()
    b.load_journal(a.dump_journal())
    shb = shell(b)
    check("the setting survives a reconnect", [
        shb.run("sysctl -n vm.nr_hugepages").strip(),
        shb.run("cat %s/nr_hugepages" % SYSFS).strip(),
        shb.run("grep HugePages_Total /proc/meminfo").split()[1],
    ], ["1284", "1284", "1284"])

    # ---- rubbish in the knob does not corrupt the readers ----------------
    for junk in ("abc", "-5", ""):
        sh = shell()
        sh.run("printf '%s' > /proc/sys/vm/nr_hugepages" % junk)
        got = sh.run("grep HugePages_Total /proc/meminfo").split()
        check("a non-numeric write (%r) leaves meminfo parseable" % junk,
              len(got) == 2 and got[1].isdigit(), True)

    print("\nhugetest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
