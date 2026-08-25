#!/usr/bin/env python3
"""How big is this disk, and how much of it is gone?

Six commands answer that, and on a real box all six are reading one statfs
call or one superblock. Here they were reading three different sets of
numbers, and the arithmetic between them did not close:

    df /            65782536 total   4290028 used   58719764 avail
    stat -f /       16445634 total  14689941 free   14679941 avail

Multiply stat's blocks by four and df's Used should be total minus free:
(16445634 - 14689941) * 4 = 7022772. df said 4290028. One filesystem, two
commands, 2.7 GB apart -- and free space is the number anyone checks before
dropping a payload. The cause was stat -f computing free as *available plus
40000*, a flat ten thousand blocks standing in for the root reserve, which
on this filesystem is 693186 blocks.

Two more from the same axis:

  * `du -sx /` reported 4562120 against df's Used of 4290028. A filesystem
    cannot hold less than the sum of the files on it. du's baseline was a
    literal chosen when the seeded tree was small, and the tree grew.
  * `tune2fs -l` and `dumpe2fs -h` printed "tune2fs 1.47.2 / Usage: ..."
    with rc 1 -- the unimplemented-binary fallback -- on a box where
    /usr/sbin/tune2fs exists and dpkg says e2fsprogs is installed. They are
    the third reader of these numbers and the only one that prints the
    reserve as a figure rather than as a gap.

And `df -i` did not line up with its own header: the header was a fixed
string and the rows a fixed format, so with a seven-digit inode count every
value sat one column right of the heading above it. Real df sizes each
column to the widest thing in it. The layout here is byte-for-byte what the
guest prints.
"""

import os
import re
import sys

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


S = fs.Shell(fs.VFS())
S.exec_mode = True


def R(cmd, s=None):
    t = s or S
    t._err = []
    out = t.run(cmd)
    return out or "", "".join(t._err), t.last_rc


def dfrow(cmd, s=None):
    out = R(cmd, s)[0].splitlines()
    return out[1].split() if len(out) > 1 else []


def statf(s=None):
    out = R("stat -f /", s)[0]
    g = lambda p: int(re.search(p, out).group(1))                # noqa: E731
    return {"total": g(r"Blocks: Total: (\d+)"),
            "free": g(r"Free: (\d+)"),
            "avail": g(r"Available: (\d+)"),
            "itotal": g(r"Inodes: Total: (\d+)"),
            "ifree": g(r"Inodes: Total: \d+\s+Free: (\d+)")}


# ---------------------------------------------------------------------------
# df and stat -f are one statfs call
# ---------------------------------------------------------------------------
def t_df_and_statf_agree_about_blocks():
    st = statf()
    row = dfrow("df -k /")
    check("df -k names the root device", row and row[0] == "/dev/sda1",
          str(row[:1]))
    total, used, avail = int(row[1]), int(row[2]), int(row[3])
    check("df's size is stat's total", total == st["total"] * 4,
          "%d vs %d" % (total, st["total"] * 4))
    check("df's Used is total minus free",
          used == (st["total"] - st["free"]) * 4,
          "%d vs %d" % (used, (st["total"] - st["free"]) * 4))
    check("df's Available is stat's available", avail == st["avail"] * 4,
          "%d vs %d" % (avail, st["avail"] * 4))
    check("free is never below available", st["free"] >= st["avail"],
          "free %d, avail %d" % (st["free"], st["avail"]))
    pct = int(row[4].rstrip("%"))
    want = used * 100.0 / (used + avail)
    check("Use%% is used over used-plus-available",
          abs(pct - want) <= 1, "%d%% vs %.1f%%" % (pct, want))


def t_df_and_statf_agree_about_inodes():
    st = statf()
    row = dfrow("df -i /")
    itot, iused, ifree = int(row[1]), int(row[2]), int(row[3])
    check("df -i total is stat's inode total", itot == st["itotal"],
          "%d vs %d" % (itot, st["itotal"]))
    check("df -i free is stat's inode free", ifree == st["ifree"],
          "%d vs %d" % (ifree, st["ifree"]))
    check("used plus free is the total", iused + ifree == itot,
          "%d + %d != %d" % (iused, ifree, itot))


def t_the_block_size_flags_scale_one_number():
    k = dfrow("df -k /")
    b1 = dfrow("df -B1 /")
    check("df -B1 is df -k times 1024",
          [int(b1[i]) for i in (1, 2, 3)]
          == [int(k[i]) * 1024 for i in (1, 2, 3)],
          "%s vs %s" % (b1[1:4], k[1:4]))
    m = dfrow("df -BM /")
    check("df -BM rounds the same total up",
          m[1].endswith("M") and int(m[1][:-1]) == -(-int(k[1]) // 1024),
          "%s vs %d" % (m[1], -(-int(k[1]) // 1024)))
    h = dfrow("df -h /")
    check("df -h is the same filesystem", h[0] == k[0], str(h[:1]))
    check("df -h's size is the size in G",
          h[1].endswith("G") and abs(float(h[1][:-1])
                                     - int(k[1]) / 1048576.0) < 0.6,
          "%s vs %.1fG" % (h[1], int(k[1]) / 1048576.0))


def t_du_cannot_exceed_what_df_says_is_used():
    """A filesystem cannot hold less than the sum of the files on it."""
    used = int(dfrow("df -k /")[2])
    du = R("du -sx / 2>/dev/null | tail -1")[0].split()
    check("du -sx / produced a number", du and du[0].isdigit(), str(du[:1]))
    if not (du and du[0].isdigit()):
        return
    total = int(du[0])
    check("du is not above df's Used", total <= used,
          "du %d > df %d" % (total, used))
    check("and not absurdly below it either", total > used * 0.9,
          "du %d, df %d" % (total, used))


def t_writing_a_file_moves_every_reader_together():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    before_df = int(dfrow("df -k /", s)[2])
    before_st = statf(s)
    R("dd if=/dev/zero of=/root/blob bs=1M count=64 2>/dev/null", s)
    after_df = int(dfrow("df -k /", s)[2])
    after_st = statf(s)
    check("df's Used went up by about 64M",
          60000 < after_df - before_df < 70000,
          "delta %d" % (after_df - before_df))
    check("stat -f's free went down by the same",
          abs((before_st["free"] - after_st["free"]) * 4
              - (after_df - before_df)) <= 8,
          "%d vs %d" % ((before_st["free"] - after_st["free"]) * 4,
                        after_df - before_df))
    check("available moved with it too",
          abs((before_st["avail"] - after_st["avail"])
              - (before_st["free"] - after_st["free"])) <= 8,
          "avail delta %d, free delta %d"
          % (before_st["avail"] - after_st["avail"],
             before_st["free"] - after_st["free"]))
    check("the two still agree after the write",
          int(dfrow("df -k /", s)[2])
          == (after_st["total"] - after_st["free"]) * 4,
          "df %d, stat %d" % (int(dfrow("df -k /", s)[2]),
                              (after_st["total"] - after_st["free"]) * 4))
    R("rm -f /root/blob", s)
    check("and deleting it gives the space back",
          abs(int(dfrow("df -k /", s)[2]) - before_df) <= 8,
          "%d vs %d" % (int(dfrow("df -k /", s)[2]), before_df))


# ---------------------------------------------------------------------------
# the superblock is the third reader
# ---------------------------------------------------------------------------
def sb():
    out = R("tune2fs -l /dev/sda1")[0]
    d = {}
    for line in out.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            d[k.strip()] = v.strip()
    return d


def t_tune2fs_prints_the_superblock():
    out, err, rc = R("tune2fs -l /dev/sda1")
    check("tune2fs -l exits 0", rc == 0, "rc=%s %s" % (rc, err[:50]))
    # tune2fs puts its banner on *stdout* and dumpe2fs puts its on stderr --
    # measured on the guest with the streams split, which is the opposite of
    # what this suite used to assert for tune2fs. `tune2fs -l dev
    # 2>/dev/null | head -1` gives the version there, so anything piping it
    # saw one line fewer here.
    check("it names its version on stdout, with the build date",
          out.splitlines()[:1] == ["tune2fs 1.47.2 (1-Jan-2025)"], out[:50])
    check("and nothing at all on stderr", err == "", repr(err[:60]))
    d = sb()
    for k in ("Inode count", "Block count", "Free blocks", "Free inodes",
              "Reserved block count", "Overhead clusters", "Block size",
              "Filesystem UUID", "Filesystem state"):
        check("the superblock has %s" % k, k in d, str(sorted(d)[:3]))
    check("the block size is 4096", d.get("Block size") == "4096",
          d.get("Block size"))
    check("the state is clean", d.get("Filesystem state") == "clean",
          d.get("Filesystem state"))
    check("the UUID is the one blkid and fstab use",
          d.get("Filesystem UUID") in R("blkid /dev/sda1")[0]
          or d.get("Filesystem UUID") in R("cat /etc/fstab")[0],
          d.get("Filesystem UUID"))


def t_the_superblock_closes_with_statfs():
    d, st = sb(), statf()
    blocks = int(d["Block count"])
    over = int(d["Overhead clusters"])
    check("block count minus overhead is what statfs counts",
          blocks - over == st["total"],
          "%d - %d != %d" % (blocks, over, st["total"]))
    check("free blocks is statfs's free", int(d["Free blocks"]) == st["free"],
          "%s vs %d" % (d["Free blocks"], st["free"]))
    check("free inodes is statfs's free inodes",
          int(d["Free inodes"]) == st["ifree"],
          "%s vs %d" % (d["Free inodes"], st["ifree"]))
    check("inode count is statfs's inode total",
          int(d["Inode count"]) == st["itotal"],
          "%s vs %d" % (d["Inode count"], st["itotal"]))
    # The reserve is the only reason Used and Available do not add up.
    check("the reserved count is exactly the free-minus-available gap",
          int(d["Reserved block count"]) == st["free"] - st["avail"],
          "%s vs %d" % (d["Reserved block count"], st["free"] - st["avail"]))
    row = dfrow("df -k /")
    check("...which is also the size df leaves unaccounted",
          int(d["Reserved block count"]) * 4
          == int(row[1]) - int(row[2]) - int(row[3]),
          "%s*4 vs %d" % (d["Reserved block count"],
                          int(row[1]) - int(row[2]) - int(row[3])))


def t_the_e2fs_tools_refuse_what_they_cannot_read():
    out, err, rc = R("tune2fs -l /dev/nosuchdev")
    check("a device that is not there exits 1", rc == 1, "rc=%s" % rc)
    check("named, with e2fsprogs' wording",
          "tune2fs: No such file or directory while trying to open "
          "/dev/nosuchdev" in err, err[:80])
    check("and the superblock line after it",
          "Couldn't find valid filesystem superblock." in err, err[:80])
    check("stdout carries only the banner", out.strip().splitlines()[-1:]
          == ["tune2fs 1.47.2 (1-Jan-2025)"], repr(out[:60]))
    err = R("tune2fs -l /dev/sda15")[1]
    check("a filesystem it does not understand says bad magic",
          "Bad magic number in super-block" in err, err[:70])
    out, err, rc = R("tune2fs /dev/sda1")
    check("no action means usage, rc 1", rc == 1 and "Usage: tune2fs" in err,
          "rc=%s %s" % (rc, err[:50]))
    # dumpe2fs reads the same superblock and says so with its own name.
    out, err, rc = R("dumpe2fs -h /dev/sda1")
    check("dumpe2fs -h exits 0", rc == 0, "rc=%s" % rc)
    check("with its own version line",
          err.splitlines()[:1] == ["dumpe2fs 1.47.2 (1-Jan-2025)"], err[:50])
    # Same superblock, but tune2fs prefixes its own banner on stdout and
    # dumpe2fs does not, so compare the fields rather than the raw streams.
    check("and the same superblock tune2fs printed",
          out == "".join(
              l + "\n" for l in R("tune2fs -l /dev/sda1")[0].splitlines()
              if not l.startswith("tune2fs ")), "differs")
    # ...and they agree whatever the gap between the two calls. "Last write
    # time" was rendered from the clock at the moment of asking, so the two
    # readers of one superblock disagreed whenever the calls straddled a
    # second. Back-to-back they matched, which is why this suite passed
    # standalone and failed only inside a full gate run -- the one place with
    # enough elapsed time between them.
    import time as _t
    _a = [l for l in R("tune2fs -l /dev/sda1")[0].splitlines()
          if not l.startswith("tune2fs ")]
    _t.sleep(1.2)
    _b = R("dumpe2fs -h /dev/sda1")[0].splitlines()
    check("the two readers agree across a second boundary",
          set(_a) == set(_b), repr(sorted(set(_a) ^ set(_b))[:2]))
    # s_wtime is a stored field: it moves when something writes, not when
    # someone looks.
    _w1 = [l for l in _a if "Last write time" in l]
    R("echo payload > /tmp/wtime_probe")
    _w2 = [l for l in R("tune2fs -l /dev/sda1")[0].splitlines()
           if "Last write time" in l]
    check("a write advances the last-write time", _w1 != _w2,
          "%r vs %r" % (_w1[:1], _w2[:1]))


# ---------------------------------------------------------------------------
# the table lines up
# ---------------------------------------------------------------------------
def t_df_i_columns_line_up():
    out = R("df -i")[0].splitlines()
    check("df -i printed a table", len(out) > 2, str(len(out)))
    ends = [[m.end() for m in re.finditer(r"\S+", l)] for l in out]
    head = ends[0]
    for i, row in enumerate(ends[1:], 1):
        # Five columns before the mount point: source, then four numbers.
        check("row %d lines up with the header" % i,
              row[1:5] == head[1:5],
              "%s vs %s" % (row[1:5], head[1:5]))
    check("the header is the guest's",
          out[0] == "Filesystem      Inodes IUsed   IFree IUse% Mounted on",
          repr(out[0]))
    root = [l for l in out if l.split()[-1] == "/"][0]
    check("and the root row is the guest's shape",
          re.match(r"^/dev/sda1\s+\d+ \d+ \d+\s+\d+% /$", root), repr(root))
    # A filesystem with no inodes prints dashes, not zeroes.
    efi = [l for l in out if l.endswith("/boot/efi")]
    check("a vfat filesystem shows dashes", efi and efi[0].split()[1] == "-",
          (efi or [""])[0][:50])


def t_df_i_and_df_describe_the_same_mounts():
    a = [l.split()[-1] for l in R("df")[0].splitlines()[1:]]
    b = [l.split()[-1] for l in R("df -i")[0].splitlines()[1:]]
    check("df and df -i list the same mount points, in order", a == b,
          "%s vs %s" % (a[:3], b[:3]))
    mounts = [l.split()[1] for l in R("cat /proc/mounts")[0].splitlines()
              if len(l.split()) > 2 and l.split()[2] not in fs.DUMMY_FS]
    check("and those are the mounts /proc/mounts lists", a == mounts,
          "%s vs %s" % (a[:3], mounts[:3]))


TESTS = [t_df_and_statf_agree_about_blocks,
         t_df_and_statf_agree_about_inodes,
         t_the_block_size_flags_scale_one_number,
         t_du_cannot_exceed_what_df_says_is_used,
         t_writing_a_file_moves_every_reader_together,
         t_tune2fs_prints_the_superblock,
         t_the_superblock_closes_with_statfs,
         t_the_e2fs_tools_refuse_what_they_cannot_read,
         t_df_i_columns_line_up,
         t_df_i_and_df_describe_the_same_mounts]


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
