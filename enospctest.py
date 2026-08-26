#!/usr/bin/env python3
"""Can this disk run out of space?

It could not. `dd if=/dev/zero of=/root/d bs=1M count=70000` on a 63 GiB
disk exited 0, wrote 73400320000 bytes, and left df reporting

    /dev/sda1  63G  72G  0  100% /

-- more used than the filesystem has. With the box at 100% full, `echo x
> /root/f` still succeeded, `cp` of a 56 GiB file still succeeded, and
`fallocate -l 60G` on 56 GiB of free space returned 0.

Checking free space before dropping a payload is something we watch
people do, and filling a disk to knock a service over is something else
they do. A box that cannot run out is a box where both of those answer
wrong, and "used > size" is arithmetic nobody has to check twice.

Measured on a real Debian 13 box, using a 2 MiB tmpfs so the reference
host survives the experiment:

    dd bs=1M count=5      3+0 records in / 2+0 records out, rc 1,
                          "dd: error writing '<f>': No space left on device"
    cp <5M> <full fs>     cp: error writing '<dst>': No space left on device
                          rc 1
    echo x >> <full fs>   bash: line 1: echo: write error: No space left
                          on device
    echo hi | tee <f>     "hi" on stdout, then
                          tee: <f>: No space left on device
    fallocate -l 5M       fallocate: fallocate failed: No space left on
                          device, rc 1 -- there is no short fallocate
    truncate -s 5M        rc 0. A hole costs nothing, so this is the one
                          that still works on a full disk
    touch / mkdir         rc 0
    df                    used == size exactly, avail 0, 100%

Two things this suite is careful about. /tmp is a tmpfs with its own
size, so filling / must not touch it and filling it must not touch /.
And a sparse file is not a full one: `truncate -s 100G` has to keep
working, with du reporting 0, while `fallocate -l 100G` fails.

Usage:  python3 enospctest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    fs = fakeshell.VFS()
    return fakeshell.Shell(vfs=fs, peer="198.51.100.17", peer_port=40555)


def out(sh, cmd):
    try:
        return sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def df(sh, path="/"):
    """(total, used, avail, pct) in 1K blocks for a mount point."""
    rows = [l.split() for l in out(sh, "df -k %s" % path).splitlines()[1:]
            if l.split()]
    if not rows or len(rows[0]) < 5:
        return (-1, -1, -1, "?")
    f = rows[0]
    return (int(f[1]), int(f[2]), int(f[3]), f[4])


def fill(sh, where="/root/fill"):
    """Fill the root filesystem, and return what df says afterwards."""
    out(sh, "dd if=/dev/zero of=%s bs=1M count=70000 2>/dev/null" % where)
    return df(sh)


S = shell()
total0, used0, avail0, _pct0 = df(S)
check("df starts with room", avail0 > 1024 * 1024, True,
      "the rest of this measures deltas against it")

# ------------------------------------------------------- used never exceeds
total, used, avail, pct = fill(S)
check("the disk stops at its own size", used <= total, True,
      "dd of 70 GiB onto a 63 GiB disk left df saying 72G used of 63G")
check("...exactly at it", used, total)
check("avail reaches zero", avail, 0)
check("and it says 100%", pct, "100%")
check("the file stops where the disk does",
      int(out(S, "stat -c %s /root/fill").strip() or -1),
      (total - used0) * 1024,
      "ls -l showed the full 73400320000 that was asked for")

# ------------------------------------------------- dd reports the short write
D = shell()
fill(D)
dd = out(D, "dd if=/dev/zero of=/root/more bs=1M count=10 2>&1")
check("dd says it ran out",
      "dd: error writing '/root/more': No space left on device" in dd, True)
check("...and exits 1",
      out(D, "dd if=/dev/zero of=/root/m2 bs=1M count=10 2>/dev/null; "
             "echo $?").strip(), "1")
check("...with a records-out line",
      bool(re.search(r"^\d+\+0 records out$", dd, re.M)), True)
check("...that is not the count it was asked for",
      "10+0 records out" in dd, False,
      "reporting the full count beside a file that stopped early is the "
      "same lie in two places")

# ------------------------------------------------------------ the other writers
for cmd, want, note in (
        ("echo x > /root/one",
         "bash: echo: write error: No space left on device",
         "it exited 0 and left a 0-byte file, with nothing said"),
        ("cp /root/fill /root/f2",
         "cp: error writing '/root/f2': No space left on device", ""),
        ("echo hi | tee /root/t", "tee: /root/t: No space left on device",
         "tee still writes its copy to stdout"),
        ("fallocate -l 1G /root/fa",
         "fallocate: fallocate failed: No space left on device",
         "there is no short fallocate -- it reserves the blocks up front")):
    W = shell()
    fill(W)
    got = out(W, "{ %s; } 2>&1" % cmd)
    check("%s reports" % cmd.split()[0], want in got, True,
          note + ("\n  got %r" % got.strip()[-90:] if got else ""))
    # Braced: `echo x > f >/dev/null` gives the command two stdout
    # redirects and the write lands in /dev/null, which is how a harness
    # passes a box that never wrote anything.
    check("%s exits non-zero" % cmd.split()[0],
          out(W, "{ %s; } >/dev/null 2>&1; echo $?" % cmd).strip() != "0",
          True)

check("tee still prints to stdout",
      out(shell(), "echo hi | tee /root/t").strip(), "hi")

# --------------------------------------------------- what still works when full
F = shell()
fill(F)
check("touch works on a full disk",
      out(F, "touch /root/tt; echo $?").strip(), "0",
      "an empty file needs an inode, not a block")
check("mkdir works on a full disk",
      out(F, "mkdir /root/dd; echo $?").strip(), "0")
check("truncate digs a hole",
      out(F, "truncate -s 100G /root/sp; echo $?").strip(), "0",
      "a sparse file costs nothing, which is why this is the one "
      "allocation that still works")
check("...and the hole is free", out(F, "du -sk /root/sp").split()[0], "0")
check("...but it is still 100G long",
      out(F, "stat -c %s /root/sp").strip(), str(100 * 1024 ** 3))
check("df did not move for the hole", df(F)[1], df(F)[0])

# -------------------------------------------------------------- and it frees
G = shell()
before = df(G)
fill(G)
check("filling moved df", df(G)[2], 0)
out(G, "rm -f /root/fill")
check("removing it gives the space back", df(G), before,
      "an accounting that only goes one way is not accounting")

# ----------------------------------------------------- /tmp is its own tmpfs
H = shell()
tmp_before = df(H, "/tmp")
fill(H)
check("filling / does not touch /tmp", df(H, "/tmp"), tmp_before,
      "/tmp is a tmpfs with its own size")
I = shell()
root_before = df(I)
out(I, "dd if=/dev/zero of=/tmp/big bs=1M count=4000 2>/dev/null")
check("filling /tmp does not touch /", df(I), root_before)
check("...and /tmp fills on its own", df(I, "/tmp")[2], 0)
check("...stopping at its own size", df(I, "/tmp")[1], df(I, "/tmp")[0])
check("a write to a full /tmp reports",
      "No space left on device" in out(I, "{ echo x > /tmp/y; } 2>&1"), True)
check("...while / still takes one",
      out(I, "echo x > /root/fine; echo $?").strip(), "0")

# ------------------------------------------------------- df agrees with itself
J = shell()
fill(J)
t, u, a, _p = df(J)
check("total is used plus avail plus the reserve", u + a <= t, True)
sf = out(J, "stat -f -c '%b %f %a' /").split()
if len(sf) == 3:
    check("stat -f agrees with df on the total", int(sf[0]) * 4, t,
          "one statfs call, two readers")
    check("stat -f agrees on avail", int(sf[2]) * 4, a)

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
