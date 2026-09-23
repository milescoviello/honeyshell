#!/usr/bin/env python3
"""Does /proc report the numbers a kernel would, in the shape a kernel uses?

Two findings, both caught by comparing against a live KVM guest rather than
by reading our own output and deciding it looked plausible.

**The fork counter did not match the pid space.** /proc/stat's "processes"
is the total number of forks since boot, and the kernel hands pids out of
that same counter, so on a real box the two track each other -- measured on
the reference guest: processes 714456, highest pid 714458, two apart. Ours
was computed as `18400 + uptime/7`, which grew with uptime while the pid
ceiling did not. After 41 days it claimed 525528 forks against a highest pid
of 21435: half a million processes that left no trace in the pid space, and
a 25x contradiction anyone can see with two commands.

**/proc/meminfo was five fields short.** It carried 50 of the 55 a 6.x
kernel emits, missing Zswap, Zswapped, SecPageTables, HardwareCorrupted and
Unaccepted -- all zero on a guest, all present. And HardwareCorrupted: is 18
characters, so the generic "%-15s %8d" padded nothing and put the value at
column 27 where the kernel puts it at 24. That is the same trap the
HugePages_Total comment in _meminfo_line already describes, one label
longer.

The column rule is worth stating because it is not "everything ends at 24":
fifty of the fifty-one kB lines do, and VmallocTotal does not, because its
eleven-digit value overflows the field on a real kernel too. A box with more
RAM than the reference overflows on more lines for the same reason, so the
assertion here is about labels, not about values.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                           peer_port=40333)


def out(sh, cmd):
    try:
        return sh.run(cmd) or ""
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


#: The field list a 6.x kernel emits, in kernel order. Taken from a live
#: guest; the four HugePages_* counters carry no unit.
EXPECTED = [
    "MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapCached",
    "Active", "Inactive", "Active(anon)", "Inactive(anon)", "Active(file)",
    "Inactive(file)", "Unevictable", "Mlocked", "SwapTotal", "SwapFree",
    "Zswap", "Zswapped", "Dirty", "Writeback", "AnonPages", "Mapped",
    "Shmem", "KReclaimable", "Slab", "SReclaimable", "SUnreclaim",
    "KernelStack", "PageTables", "SecPageTables", "NFS_Unstable", "Bounce",
    "WritebackTmp", "CommitLimit", "Committed_AS", "VmallocTotal",
    "VmallocUsed", "VmallocChunk", "Percpu", "HardwareCorrupted",
    "AnonHugePages", "ShmemHugePages", "ShmemPmdMapped", "FileHugePages",
    "FilePmdMapped", "Unaccepted", "HugePages_Total", "HugePages_Free",
    "HugePages_Rsvd", "HugePages_Surp", "Hugepagesize", "Hugetlb",
    "DirectMap4k", "DirectMap2M", "DirectMap1G",
]


def main():
    sh = shell()

    # ---- the fork counter and the pid space -----------------------------
    stat = out(sh, "cat /proc/stat")
    forks = None
    for line in stat.splitlines():
        if line.startswith("processes"):
            forks = int(line.split()[1])
            break
    check("/proc/stat reports a fork counter", forks is not None, True)

    pids = [int(x) for x in out(sh, "ps -eo pid --no-headers").split()
            if x.isdigit()]
    check("the process table is readable", bool(pids), True)
    if forks is not None and pids:
        top = max(pids)
        # The counter is where pids come from, so it cannot be behind the
        # highest live pid, and it should not be wildly ahead of it either.
        check("the fork counter is not behind the highest pid",
              forks >= top, True, "forks=%d top pid=%d" % (forks, top))
        check("and not implausibly ahead of it",
              forks - top <= 1000, True,
              "forks=%d top pid=%d -- a box cannot fork half a million "
              "times without the pid counter moving" % (forks, top))

    # ---- meminfo: the fields a kernel emits -----------------------------
    lines = [l for l in out(sh, "cat /proc/meminfo").splitlines() if ":" in l]
    names = [l.split(":", 1)[0] for l in lines]
    check("meminfo has every field a 6.x kernel emits",
          [f for f in EXPECTED if f not in names], [])
    check("and no field a kernel does not",
          [f for f in names if f not in EXPECTED], [])
    check("in the kernel's order", names, EXPECTED)

    # ---- meminfo: the column the kernel puts the value in ---------------
    # Labels of 15 characters or fewer land the value at column 24. Longer
    # labels must too -- that is the whole bug. A value wider than the field
    # overflows on a real kernel as well, so those are exempt.
    bad = []
    for line in lines:
        if not line.endswith(" kB"):
            continue
        label, _, rest = line.partition(":")
        digits = rest.strip().split()[0]
        end = len(line) - len(" kB")
        # Does the value fit the field the kernel gives it? Short labels are
        # padded to 15 and the value printed in 8; a longer label eats into
        # the 24 columns directly. A value too wide for its field overflows
        # on a real kernel too -- VmallocTotal does it on the reference box,
        # and every line does on a machine with more RAM than 8 digits of
        # kB. Those are not misalignment, so only the ones that fit are
        # required to land on 24.
        lab = label + ":"
        fits = (len(digits) <= 8 if len(lab) <= 15
                else len(digits) <= 24 - len(lab))
        if fits and end != 24:
            bad.append((label, end))
    check("every meminfo value the field can hold ends at column 24",
          bad, [], "the kernel pads to 24; %-15s does nothing for a label "
                   "longer than 15")

    # The long label that started it, byte for byte.
    hc = [l for l in lines if l.startswith("HardwareCorrupted:")]
    check("HardwareCorrupted is present", bool(hc), True)
    if hc:
        check("HardwareCorrupted is aligned like the kernel's",
              hc[0], "HardwareCorrupted:     0 kB")

    print("%d/%d assertions pass" % (sum(CHECKS), len(CHECKS)))
    for f in FAILS:
        print(f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
