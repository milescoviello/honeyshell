#!/usr/bin/env python3
"""`dpkg -L` and the file it is supposed to be reading.

On a real box `dpkg -L pkg` is a cat of /var/lib/dpkg/info/pkg.list, so
the two cannot disagree and `ls /var/lib/dpkg/info/*.list | wc -l` matches
`dpkg -l | grep -c '^ii'`. Here they were computed twice from two copies
of one rule, and the result was:

    installed packages                      190
    packages with a .list file               71
    of those 71, agreeing with `dpkg -L`      0

`dpkg -L base-files` printed seven paths beside an
info/base-files.list that did not exist. That is two commands, one
question, no privileges needed.

The second half is the same defect one level up. The real fastfetch,
htop and btop read an exported copy of this tree under
/var/lib/honeypot/fakeroot, and export_static() skips the export when a
marker file is present. The marker was keyed on the CPU count, the DMI
table and the PCI device list -- so adding four packages rewrote
/var/lib/dpkg/status and changed nothing in the key. fastfetch went on
reporting `Packages: 186 (dpkg)` on a box whose own `dpkg -l` said 190.

That is the third time this marker has gone stale in a way the file's own
comments record: first keyed on a version, then on the CPU count, now on
hardware only. So the key covers the dpkg tree by content -- 96 nodes,
cheap -- while /sys stays keyed on the inputs that generate its 7,418.
"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell
import procexport

CHECKS = []
FAILS = []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.9",
                           peer_port=40111)


S = shell()
installed = [n for n, _v, _a in S.PACKAGES]
listfiles = sorted(f[:-5] for f in S.run("ls /var/lib/dpkg/info/").split()
                   if f.endswith(".list"))

# ------------------------------------------------ one file per package
check("every installed package has a .list",
      sorted(set(installed) - set(listfiles)), [],
      "119 of 190 had none, on a box where dpkg -L answered for them")
check("no .list belongs to a package that is not installed",
      sorted(set(listfiles) - set(installed)), [])
check("the two counts are the same number",
      (len(listfiles), len(installed)),
      (len(installed), len(installed)),
      "ls info/*.list | wc -l against dpkg -l | grep -c '^ii'")

# ------------------------------------------------ and it is what -L prints
bad = [p for p in installed
       if S.run("dpkg -L %s 2>/dev/null" % p)
       != S.run("cat /var/lib/dpkg/info/%s.list 2>/dev/null" % p)]
check("dpkg -L is a cat of the .list, for every package", bad[:4], [],
      "all 71 that had both disagreed; -L now reads the file")

# a package's own binaries appear in its list, and where they really are
adduser = S.run("cat /var/lib/dpkg/info/adduser.list").split()
check("a package's binaries are listed where they actually are",
      [p for p in adduser
       if p.startswith(("/usr/bin/", "/usr/sbin/"))
       and p.endswith(("/adduser", "/deluser"))],
      ["/usr/sbin/adduser", "/usr/sbin/deluser"],
      "the static bin/sbin rule put ten of these in /usr/bin")

# the file is dated like the rest of the database, not like right now
check("a .list is dated with the dpkg database, not with now",
      S.run("stat -c %y /var/lib/dpkg/info/adduser.list").strip(),
      S.run("stat -c %y /var/lib/dpkg/status").strip(),
      "a 55-day-old box whose package lists were written this second "
      "has answered the question by itself")

# ------------------------------------------------ the exported copy
# The tree the real fastfetch/htop/btop read. Exported once and skipped
# on a marker, so the marker has to move when the tree's contents do.
tmp = tempfile.mkdtemp(prefix="dpkginfotest")
try:
    first = procexport.export_static(S, tmp)
    check("the static tree exports", first > 0, True)
    check("...and is skipped when nothing has changed",
          procexport.export_static(S, tmp), 0,
          "the marker is what makes this cheap")

    def marker_of(root):
        return sorted(f for f in os.listdir(root)
                      if f.startswith(".static-done-"))

    before = marker_of(tmp)
    check("exactly one marker at a time", len(before), 1,
          "rebuilding replaces rather than overlays")

    exported = os.path.join(tmp, "var/lib/dpkg/status")
    check("the exported dpkg status is the one this box has",
          open(exported, encoding="latin-1").read().count("\nPackage: ") + 1,
          len(installed),
          "fastfetch counts packages out of this file, and read 186 "
          "while dpkg -l on the same box said 190")

    # Now change the package set and export again: the tree must rebuild.
    orig = fakeshell.Shell.PACKAGES
    fakeshell.Shell.PACKAGES = tuple(list(orig)
                                     + [("zzz-probe", "1.0-1", "amd64")])
    try:
        S2 = shell()
        again = procexport.export_static(S2, tmp)
        check("adding a package rebuilds the exported tree", again > 0, True,
              "this is the check that was missing: the key covered the CPU "
              "count, DMI and PCI, and none of those move when a package "
              "is installed")
        check("...and the marker moved with it",
              marker_of(tmp) != before, True)
        n_after = (open(exported, encoding="latin-1").read()
                   .count("\nPackage: ") + 1)
        check("...and the exported status has the new package",
              n_after, len(installed) + 1)
    finally:
        fakeshell.Shell.PACKAGES = orig
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("dpkginfotest: %d checks, %d failed" % (len(CHECKS), len(FAILS)))
for x in FAILS:
    print(x)
sys.exit(1 if FAILS else 0)
