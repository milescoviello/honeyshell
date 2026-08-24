#!/usr/bin/env python3
"""findmnt's columns, against the other commands that know the same facts.

The axis: `findmnt -no UUID /` came back empty while `blkid` and `lsblk
-no UUID /dev/sda1` both answered for the same filesystem. Fourteen of
findmnt's twenty columns were empty -- UUID, PARTUUID, LABEL, MAJ:MIN,
FSROOT, ID, PARENT, PROPAGATION, VFS-OPTIONS, FS-OPTIONS and the rest --
because it read /proc/mounts, which has six fields, while the answers sit
in /proc/self/mountinfo, blkid and lsblk. An unknown column printed a
blank line and exited 0, so "no such column" and "no value" looked the
same.

findmnt is a tool attackers actually run here: `findmnt -no SOURCE /`,
`findmnt -n -o SIZE,USED,AVAIL /`, `findmnt --df /` and `findmnt -rn -O
noexec -o TARGET | head -2` all arrived on 2026-08-22, the last one from
a loader looking for somewhere it can execute from.

Reference behaviour measured on the guest (Debian 13, util-linux 2.40).
"""
import sys
import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.61")
    s.exec_mode = True
    return v, s


def col(s, name, target="/"):
    return s.run("findmnt -no %s %s" % (name, target)).strip()


def main():
    v, s = sh()

    # -- the columns that were empty -----------------------------------------
    for name, want in (("SOURCE", "/dev/sda1"), ("TARGET", "/"),
                       ("FSTYPE", "ext4"), ("FSROOT", "/"),
                       ("PROPAGATION", "shared"), ("MAJ:MIN", "8:1")):
        check("findmnt -no %s" % name, col(s, name), want)
    check("findmnt -no UUID is not empty", col(s, "UUID") != "", True)
    check("findmnt -no ID is a number", col(s, "ID").isdigit(), True)
    check("findmnt -no PARENT is a number", col(s, "PARENT").isdigit(), True)

    # -- and the commands that already knew ----------------------------------
    # One question, and every tool that can answer it must agree.
    uuid = col(s, "UUID")
    check("findmnt and blkid agree on the UUID",
          uuid in s.run("blkid /dev/sda1"), True)
    check("findmnt and lsblk agree",
          s.run("lsblk -no UUID /dev/sda1").strip(), uuid)
    check("findmnt and /etc/fstab agree",
          ("UUID=" + uuid) in s.run("cat /etc/fstab"), True)
    check("findmnt and /dev/disk/by-uuid agree",
          s.run("readlink -f /dev/disk/by-uuid/%s" % uuid).strip(),
          "/dev/sda1")
    check("findmnt and lsblk -f agree",
          uuid in s.run("lsblk -f"), True)
    part = col(s, "PARTUUID")
    check("the PARTUUID is not the filesystem UUID", part == uuid, False)
    check("and blkid reports the same PARTUUID",
          'PARTUUID="%s"' % part in s.run("blkid /dev/sda1"), True)
    check("MAJ:MIN matches /proc/partitions",
          col(s, "MAJ:MIN").replace(":", " ") in
          " ".join(s.run("cat /proc/partitions").split()), True)
    check("findmnt SOURCE matches df",
          s.run("df / | tail -1").split()[0], col(s, "SOURCE"))
    check("findmnt ID matches /proc/self/mountinfo",
          [l.split()[0] for l in s.run("cat /proc/self/mountinfo").splitlines()
           if l.split()[4] == "/"][0], col(s, "ID"))

    # A tmpfs has no UUID, and saying so is not the same as having no column.
    check("tmpfs has no UUID", col(s, "UUID", "/tmp"), "")
    check("but it does have a device number",
          col(s, "MAJ:MIN", "/tmp").startswith("0:"), True)
    check("and a parent that is the root mount",
          col(s, "PARENT", "/tmp"), col(s, "ID"))

    # -- the VFS/superblock split ---------------------------------------------
    # mountinfo keeps the mount's own flags apart from the filesystem's, and
    # both halves were the whole /proc/mounts string -- so they overlapped,
    # which no mountinfo line does.
    check("VFS-OPTIONS is the mount's flags only",
          col(s, "VFS-OPTIONS"), "rw,relatime")
    check("FS-OPTIONS is the filesystem's",
          col(s, "FS-OPTIONS"), "rw,discard,errors=remount-ro")
    check("OPTIONS is still the union /proc/mounts prints",
          col(s, "OPTIONS"), "rw,relatime,discard,errors=remount-ro")
    check("/tmp splits the same way",
          (col(s, "VFS-OPTIONS", "/tmp"), col(s, "FS-OPTIONS", "/tmp")),
          ("rw,nosuid,nodev", "rw,nr_inodes=1048576,inode64"))

    # The invariant, over every mount on the box: the two halves of
    # mountinfo reconstruct the /proc/mounts option string exactly, and
    # they share nothing but rw/ro.
    mounts = {}
    for line in s.run("cat /proc/mounts").splitlines():
        f = line.split()
        if len(f) >= 4:
            mounts[f[1]] = set(f[3].split(","))
    seen, bad_union, overlap = 0, [], []
    for line in s.run("cat /proc/self/mountinfo").splitlines():
        f = line.split()
        if "-" not in f:
            continue
        sep = f.index("-")
        seen += 1
        vfs = set(f[5].split(","))
        sup = set(f[sep + 3].split(",")) if len(f) > sep + 3 else set()
        if vfs | (sup - {"rw", "ro"}) != mounts.get(f[4], set()):
            bad_union.append(f[4])
        if (vfs & sup) - {"rw", "ro"}:
            overlap.append(f[4])
    check("every mount was checked", seen > 20, True)
    check("the two halves rebuild /proc/mounts", bad_union, [])
    check("and they overlap only on rw/ro", overlap, [])

    # -- unknown and poll-only columns ----------------------------------------
    s._err = []
    out, rc = s.dispatch("findmnt", ["-no", "NOSUCHCOL", "/"], "")
    check("an unknown column exits 1", rc, 1)
    check("...prints nothing", out, "")
    check("...and names the column",
          "".join(s._err).strip(), "findmnt: unknown column: NOSUCHCOL")
    s._err = []
    out, rc = s.dispatch("findmnt", ["-no", "ACTION", "/"], "")
    check("a poll-only column exits 0", rc, 0)
    check("...and explains itself",
          "".join(s._err).strip(),
          "findmnt: ACTION column is requested, but --poll is not enabled")

    # -- layout ----------------------------------------------------------------
    # Measured byte for byte on the guest: the padding survives -n.
    check("MAJ:MIN,ID,PARENT lays out as the guest does",
          s.run("findmnt -no MAJ:MIN,ID,PARENT /"), "  8:1   28  1\n")
    check("MAJ:MIN alone keeps its centred field",
          s.run("findmnt -no MAJ:MIN /"), "  8:1  \n")
    check("a narrow numeric column is not padded",
          s.run("findmnt -no ID /"), "28\n")
    check("two text columns are one space apart",
          s.run("findmnt -no SOURCE,UUID /"), "/dev/sda1 %s\n" % uuid)
    check("with headings the column lines up",
          s.run("findmnt -o SOURCE,UUID /"),
          "SOURCE    UUID\n/dev/sda1 %s\n" % uuid)

    # -- what attackers actually ran on this box -------------------------------
    check("findmnt -no SOURCE /", s.run("findmnt -no SOURCE /"),
          "/dev/sda1\n")
    three = s.run("findmnt -n -o SIZE,USED,AVAIL /").split()
    check("findmnt -n -o SIZE,USED,AVAIL / gives three values",
          len(three), 3)
    # They must *not* match `df -h` character for character, and that is
    # correct: measured on the guest, df -h says 63G where findmnt says
    # 62.8G and lsblk says 63.9G, because coreutils rounds to three
    # significant digits, util-linux always prints one decimal, and lsblk
    # is describing the partition rather than the filesystem. Three tools,
    # three renderings of numbers that do agree underneath -- so the check
    # is against the raw KiB, which is the number they share.
    raw = [int(x) for x in s.run("df / | tail -1").split()[1:4]]
    def approx(text, kib):
        val = float(text.rstrip("KMGT"))
        unit = {"K": 1, "M": 1024, "G": 1024 ** 2, "T": 1024 ** 3}[text[-1]]
        return abs(val * unit - kib) < kib * 0.02 + 1024
    check("findmnt's size agrees with df's raw blocks",
          [approx(t, k) for t, k in zip(three, raw)], [True, True, True])
    check("and it is not simply df -h's string",
          three == s.run("df -h / | tail -1").split()[1:4], False)
    check("findmnt --df / names the source",
          s.run("findmnt --df /").splitlines()[-1].split()[0], "/dev/sda1")
    noexec = s.run("findmnt -rn -O noexec -o TARGET").split()
    check("findmnt -rn -O noexec -o TARGET finds the noexec mounts",
          all(o in s.run("findmnt -no OPTIONS " + t) for t, o in
              [(t, "noexec") for t in noexec]), True)
    check("...and does not list the root filesystem", "/" in noexec, False)

    # -- a path that is not a mountpoint ---------------------------------------
    check("a non-mountpoint matches nothing",
          s.run("findmnt /root").strip(), "")
    _o, rc = s.dispatch("findmnt", ["/root"], "")
    check("...and exits 1", rc, 1)
    check("-T falls back to the filesystem holding it",
          s.run("findmnt -no TARGET -T /root").strip(), "/")

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("fmtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
