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
    # df -h picks its unit from the size: a gigabyte-sized root prints G, a
    # terabyte one prints T. Pinning the letter only suited the smaller
    # persona, so compare the value after converting whichever unit it used.
    _unit = {"K": 1.0, "M": 1024.0, "G": 1048576.0, "T": 1073741824.0}
    check("df -h's size is the size, in whatever unit it chose",
          h[1][-1] in _unit
          and abs(float(h[1][:-1]) * _unit[h[1][-1]] - int(k[1]))
          < 0.6 * _unit[h[1][-1]],
          "%s vs %s 1K-blocks" % (h[1], k[1]))


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
    # The header's *columns*, not its spacing. This was the guest's exact
    # string, which pinned the widths to the digit counts a 2 GB box with
    # a 63 GiB root produces -- df sizes each column to its widest value,
    # so growing the persona to 1 TiB and 1.8 T legitimately moved them.
    # The alignment invariant is asserted above, row by row.
    check("the header names the guest's columns",
          out[0].split() == ["Filesystem", "Inodes", "IUsed", "IFree",
                             "IUse%", "Mounted", "on"],
          repr(out[0]))
    check("Filesystem is left-aligned in its column",
          out[0].startswith("Filesystem "), repr(out[0][:12]))
    root = [l for l in out if l.split()[-1] == "/"][0]
    check("and the root row is the guest's shape",
          re.match(r"^/dev/sda1\s+\d+\s+\d+\s+\d+\s+\d+% /$", root),
          repr(root))
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


def t_every_mount_has_its_own_st_dev():
    """stat() and the mount table, on which filesystem a path is.

    st_dev was the constant 2049 for every path on the box -- 0x801, which
    is 8:1, which is sda1 -- so stat(), the one reader here that is a bare
    syscall rather than an authored string, said /data, /boot/efi, /tmp,
    /dev/shm and /run were all the same filesystem, while df,
    /proc/mounts, lsblk and findmnt all insisted on two block devices and
    several tmpfses. `df -P` named /dev/nvme0n1p1 for a file whose stat
    said sda1.

    The encoding is glibc's makedev, (major << 8) | minor: sda1 2049,
    sda15 2063, nvme0n1p1 66305. Checked against a live box.
    """
    devs = {}
    for mnt in ("/", "/data", "/boot/efi", "/tmp", "/dev/shm", "/run"):
        d = R("stat -c '%d' " + mnt)[0].strip()
        devs[mnt] = d
        check("%s has an st_dev" % mnt, d.isdigit(), repr(d))
    check("the two block filesystems differ",
          devs.get("/") != devs.get("/data"),
          "/ %s vs /data %s" % (devs.get("/"), devs.get("/data")))
    check("the ESP is its own filesystem",
          devs.get("/boot/efi") not in (devs.get("/"), None),
          "%s" % devs.get("/boot/efi"))
    check("each tmpfs is its own filesystem",
          len({devs.get("/tmp"), devs.get("/dev/shm"),
               devs.get("/run")}) == 3,
          "tmp %s shm %s run %s" % (devs.get("/tmp"), devs.get("/dev/shm"),
                                    devs.get("/run")))
    check("a tmpfs is major 0, as the kernel allocates them",
          all(int(devs[m]) < 256 for m in ("/tmp", "/dev/shm", "/run")
              if devs.get(m, "").isdigit()),
          "tmp %s" % devs.get("/tmp"))
    # the exact numbers the mount table implies
    for mnt, want in (("/", "2049"), ("/data", "66305"),
                      ("/boot/efi", "2063")):
        check("%s is makedev of its maj:min" % mnt, devs.get(mnt) == want,
              "got %s want %s" % (devs.get(mnt), want))
    # and a file agrees with the mount it sits on, which is the pair an
    # auditor actually compares
    for path, mnt in (("/etc/hostname", "/"),
                      ("/data/runs/sft-70b/train.log", "/data")):
        fd = R("stat -c '%d' " + path)[0].strip()
        check("%s sits on %s" % (path, mnt), fd == devs.get(mnt),
              "file %s vs mount %s" % (fd, devs.get(mnt)))
        dev = R("df -P " + path)[0].splitlines()
        dev = dev[1].split()[0] if len(dev) > 1 else "?"
        check("...and df names the matching device for %s" % path,
              dev.startswith("/dev/") or dev == "tmpfs", dev)
    # all three of stat's spellings are one number
    d = R("stat -c '%d' /data")[0].strip()
    D = R("stat -c '%D' /data")[0].strip()
    plain = R("stat /data")[0]
    check("stat %d and %D are the same device",
          D.lower() == ("%x" % int(d)) if d.isdigit() else False,
          "%s vs %s" % (d, D))
    check("...and so is the Device: line",
          ("%dd" % int(d)) in plain if d.isdigit() else False,
          [l for l in plain.splitlines() if "Device" in l][:1])


def t_block_devices_are_not_hollow():
    """The bytes on the device against the strings the tools print.

    `dd if=/dev/sda bs=512 count=1` returned zero bytes -- no protective
    MBR -- and `dd if=/dev/sda1 bs=1024 count=2` returned zero bytes where
    ext4 keeps its superblock, while blkid printed a perfect UUID and LABEL
    for the same devices and fdisk described the whole partition table.
    read() is the one reader on this box that cannot be an authored
    string, so a device that is empty to dd and fully described by every
    tool is the sharpest contradiction available.

    Validated the hard way: the generated bytes were written to a scratch
    file and handed to the REAL file(1) and blkid, which called them
    "Linux rev 1.0 ext4 filesystem data" with the right UUID and volume
    name, and the disk head a DOS/MBR protective partition spanning the
    right sector count.
    """
    def same(name, got, want):
        check(name, got == want, "got %r want %r" % (got, want))

    same("sda's first sector is a full sector",
         R("dd if=/dev/sda bs=512 count=1 2>/dev/null | wc -c")[0].strip(),
         "512")
    same("...and ends in the boot signature",
         R("od -A n -t x1 -j 510 -N 2 /dev/sda")[0].split(), ["55", "aa"])
    same("...with a 0xEE protective partition",
         R("od -A n -t x1 -j 450 -N 1 /dev/sda")[0].strip(), "ee")
    same("LBA1 is a GPT header",
         R("dd if=/dev/sda bs=1 skip=512 count=8 2>/dev/null")[0].strip(),
         "EFI PART")
    same("nvme0n1 has a first sector too",
         R("dd if=/dev/nvme0n1 bs=512 count=1 2>/dev/null | wc -c")[0].strip(),
         "512")
    for dev in ("/dev/sda1", "/dev/nvme0n1p1"):
        same("%s has 2 KiB of superblock" % dev,
             R("dd if=%s bs=1024 count=2 2>/dev/null | wc -c"
               % dev)[0].strip(), "2048")
        same("%s carries the ext4 magic" % dev,
             R("od -A n -t x1 -j 1080 -N 2 %s" % dev)[0].split(),
             ["53", "ef"])
        raw = "".join(R("od -A n -t x1 -j 1128 -N 16 %s" % dev)[0].split())
        ondisk = "%s-%s-%s-%s-%s" % (raw[0:8], raw[8:12], raw[12:16],
                                     raw[16:20], raw[20:32])
        same("%s: the on-disk UUID is blkid's" % dev, ondisk,
             R("blkid -s UUID -o value %s" % dev)[0].strip())
    same("the data volume's label is in its superblock",
         R("dd if=/dev/nvme0n1p1 bs=1 skip=1144 count=6 "
           "2>/dev/null")[0].strip(), "shards")
    check("file -s names the filesystem on sda1",
          "ext4 filesystem data" in R("file -s /dev/sda1")[0],
          R("file -s /dev/sda1")[0].strip()[:70])
    check("file -s names the volume on the data disk",
          'volume name "shards"' in R("file -s /dev/nvme0n1p1")[0],
          R("file -s /dev/nvme0n1p1")[0].strip()[:70])
    check("file without -s still just stats it",
          "block special" in R("file /dev/sda1")[0],
          R("file /dev/sda1")[0].strip()[:50])
    same("a read past the end yields nothing",
         R("dd if=/dev/sda bs=512 count=1 skip=9999999999 "
           "2>/dev/null | wc -c")[0].strip(), "0")


def t_od_honours_its_offset_and_format():
    """od -j and the separated -A/-t spellings, against the real od.

    -A and -t were only recognised glued to their value and -j was not
    implemented at all, so `od -A d -t x1 -j 510 -N 2 /dev/sda` -- the
    obvious way to look at a boot signature -- printed two-byte octal
    groups from offset zero. Three flags ignored in one command, and no
    offset in any file or device could be examined.
    """
    def same(name, got, want):
        check(name, got == want, "got %r want %r" % (got, want))

    S.run("printf 'ABCDEFGHIJKLMNOP' > /tmp/odc.bin")
    # od closes with the end address on a line of its own, which the real
    # one does too -- so compare the data line, not the whole output.
    same("-j skips and -t x1 is single-byte hex",
         R("od -A d -t x1 -j 4 -N 4 /tmp/odc.bin")[0].splitlines()[0].split(),
         ["0000004", "45", "46", "47", "48"])
    same("...and closes with the end address",
         R("od -A d -t x1 -j 4 -N 4 /tmp/odc.bin")[0].splitlines()[1].strip(),
         "0000008")
    same("addresses count from the start of the file",
         R("od -A d -c -j 8 -N 4 /tmp/odc.bin")[0].split()[0], "0000008")
    same("--skip-bytes= is the same flag",
         R("od -A d -t x1 --skip-bytes=4 -N 4 /tmp/odc.bin")[0].split()[1:5],
         ["45", "46", "47", "48"])
    same("the glued spelling still works",
         R("od -Ad -tx1 -j4 -N4 /tmp/odc.bin")[0].split()[1:5],
         ["45", "46", "47", "48"])


def t_sysfs_knows_which_drives_these_are():
    """The device identity sysfs keeps, against the one fdisk prints.

    `cat /sys/block/sda/device/model` was "No such file or directory" on a
    box whose fdisk says "Disk model: QEMU HARDDISK", and the same for the
    NVMe against "SOLIDIGM SBFPF2BU307T". Two sources of truth for one
    drive with only one of them populated -- and sysfs is the one lsblk,
    udev and every inventory script actually read.

    The strings come from DISKS, the table fdisk prints from. The field
    layout was measured on a real QEMU guest, which is what this persona
    is: vendor is the 8-char INQUIRY vendor and model is the FULL 16-char
    product string, not the remainder after the vendor word.

        vendor "QEMU    "   model "QEMU HARDDISK   "   rev "2.5+"
    """
    def same(name, got, want):
        check(name, got == want, "got %r want %r" % (got, want))

    fd = R("fdisk -l 2>/dev/null")[0]
    for dev, needle in (("sda", "QEMU HARDDISK"),
                        ("nvme0n1", "SOLIDIGM SBFPF2BU307T")):
        m = R("cat /sys/block/%s/device/model" % dev)[0].strip()
        same("/sys/block/%s/device/model" % dev, m, needle)
        check("...and fdisk says the same for %s" % dev, needle in fd,
              fd[:70])
    same("sda's INQUIRY vendor",
         R("cat /sys/block/sda/device/vendor")[0].strip(), "QEMU")
    same("sda's revision", R("cat /sys/block/sda/device/rev")[0].strip(),
         "2.5+")
    # the controller, which nvme tools read and which is a different path
    same("/sys/class/nvme/nvme0/model",
         R("cat /sys/class/nvme/nvme0/model")[0].strip(),
         "SOLIDIGM SBFPF2BU307T")
    check("...and it carries a serial",
          len(R("cat /sys/class/nvme/nvme0/serial")[0].strip()) > 4,
          R("cat /sys/class/nvme/nvme0/serial")[0].strip())
    same("...over pcie",
         R("cat /sys/class/nvme/nvme0/transport")[0].strip(), "pcie")


def t_threads_have_names():
    """/proc/<pid>/task/<tid>/comm, for a process with twelve threads.

    Every one of them read back empty, on a process whose own comm says
    python3 and whose status says Threads: 12 -- and `ls /proc/<pid>/task`
    is how anyone enumerates threads without ps. The path never reached
    the generator: the /proc regex stopped at one level, so anything under
    task/ fell through to the node table, which holds the directories and
    nothing inside them.

    Linux gives a thread the process's comm unless it renames itself with
    prctl, so mirroring is the correct default rather than an invention.
    """
    def same(name, got, want):
        check(name, got == want, "got %r want %r" % (got, want))

    pid = "21400"
    n = R("grep ^Threads /proc/%s/status" % pid)[0].split()
    tids = R("ls /proc/%s/task" % pid)[0].split()
    same("task/ has one entry per thread", str(len(tids)),
         n[1] if len(n) > 1 else "?")
    comm = R("cat /proc/%s/comm" % pid)[0].strip()
    check("the process has a comm", bool(comm), repr(comm))
    empties = [t for t in tids
               if not R("cat /proc/%s/task/%s/comm" % (pid, t))[0].strip()]
    check("no thread has an empty comm", empties == [],
          "%d of %d empty" % (len(empties), len(tids)))
    mismatched = [t for t in tids
                  if R("cat /proc/%s/task/%s/comm"
                       % (pid, t))[0].strip() != comm]
    check("every thread carries the process's comm", mismatched == [],
          "%d differ" % len(mismatched))
    # the main thread is always there and is always the process
    check("the main thread is in task/", pid in tids, tids[:4])


def t_lsblk_b_prints_bytes():
    """-b was accepted and ignored, so the exact byte count was unaskable.

    `lsblk -bno SIZE /dev/sda` is the standard way to get a disk's size
    without parsing a human suffix. It answered "1.8T", and the box then
    contradicted itself: /sys/block/sda/size times 512 is 1978349387776,
    which is the number -b has to print. Measured on the Debian 13 host
    this persona is modelled on: -b turns SIZE, FSSIZE, FSAVAIL and
    FSUSED into plain byte counts and leaves the rest alone.
    """
    b = R("lsblk -bno SIZE /dev/sda")[0].strip()
    check("lsblk -b prints a byte count", b.isdigit(), repr(b))
    sysb = int(R("cat /sys/block/sda/size")[0].strip()) * 512
    check("...the same one /sys gives", b == str(sysb),
          "%s vs %s" % (b, sysb))
    fd = re.search(r"(\d+) bytes", R("fdisk -l /dev/sda")[0])
    check("...and the same one fdisk gives", bool(fd) and fd.group(1) == b,
          "fdisk=%s" % (fd.group(1) if fd else "?"))
    check("--bytes is the same flag",
          R("lsblk --bytes -no SIZE /dev/sda")[0].strip() == b, "")
    check("without -b it is still human",
          R("lsblk -no SIZE /dev/sda")[0].strip().endswith(("T", "G", "M", "K")),
          repr(R("lsblk -no SIZE /dev/sda")[0].strip()))


def t_lsblk_b_filesystem_columns_match_df():
    """The FS columns are the same statfs df reads, so -b has to agree."""
    got = [R("lsblk -bno %s /dev/sda1" % c)[0].strip()
           for c in ("FSSIZE", "FSUSED", "FSAVAIL")]
    want = R("df -B1 --output=size,used,avail / | tail -1")[0].split()
    check("lsblk -b FSSIZE/FSUSED/FSAVAIL equal df -B1",
          got == want, "lsblk=%s df=%s" % (got, want))


def t_lsblk_r_is_raw():
    """-r means parsable: no tree glyphs, no padding.

    `lsblk -rno NAME` is how a script asks for the device names. It came
    back with the tree drawing still attached -- the first partition read
    as a box-drawing character, not as sda1 -- and every field padded.
    """
    names = R("lsblk -rno NAME")[0].split()
    check("no tree glyphs survive -r",
          all(n.isascii() and n[0].isalnum() for n in names if n),
          repr(names[:4]))
    check("...and the disk and its partitions are all there",
          {"sda", "sda1", "sda14", "sda15"} <= set(names), repr(names[:6]))
    rows = [l for l in R("lsblk -r -o NAME,SIZE,TYPE")[0].splitlines() if l]
    check("-r keeps the heading", rows[0].split() == ["NAME", "SIZE", "TYPE"],
          repr(rows[0]))
    check("-r pads nothing",
          all("  " not in l for l in rows), repr(rows[1] if len(rows) > 1 else ""))
    check("-rn drops the heading",
          not R("lsblk -rn -o NAME,SIZE,TYPE")[0].startswith("NAME"), "")
    check("the default output still draws the tree",
          any(l.startswith(("\u251c", "\u2514"))
              for l in R("lsblk -no NAME")[0].splitlines()),
          "-r must not change what plain lsblk prints")


TESTS = [t_df_and_statf_agree_about_blocks,
         t_df_and_statf_agree_about_inodes,
         t_the_block_size_flags_scale_one_number,
         t_du_cannot_exceed_what_df_says_is_used,
         t_writing_a_file_moves_every_reader_together,
         t_tune2fs_prints_the_superblock,
         t_the_superblock_closes_with_statfs,
         t_the_e2fs_tools_refuse_what_they_cannot_read,
         t_df_i_columns_line_up,
         t_lsblk_b_prints_bytes,
         t_lsblk_b_filesystem_columns_match_df,
         t_lsblk_r_is_raw,
         t_df_i_and_df_describe_the_same_mounts,
         t_every_mount_has_its_own_st_dev,
         t_block_devices_are_not_hollow,
         t_od_honours_its_offset_and_format,
         t_sysfs_knows_which_drives_these_are,
         t_threads_have_names]


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
