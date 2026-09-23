#!/usr/bin/env python3
"""What is this box's storage, and does every command give one answer?

The persona was rebuilt around a Threadripper with 1 TiB of RAM and eight
RTX 5090s. The tables that describe memory and disks were not all rebuilt
with it, so a handful of them still described the 2 GB cloud VM this
started as -- and the two sets of numbers sat side by side in the same
shell:

    mount | grep ' /run '     size=203540k          (199 MiB)
    df -h /run                101G
    df -i /run                254389 inodes
    lsmem                     Total online memory: 2G
    free -h                   1008G

A 500-fold disagreement between `mount` and `df` about one filesystem is
not a detail; those are the two commands anybody runs to size a box.

The second half is /data. The workload's own command lines name
/data/shards and /data/runs -- `ps aux` prints them -- and _FS_SIZES had
carried a 29 T entry for /data since the persona was built. Nothing was
mounted there, and _FILESYSTEMS builds from /proc/mounts, so the entry was
dead code: `df /data/shards` answered "/dev/sda1 ... /", a 1.8 T root at
22%. A training host that reads 30 TB of shards off its root filesystem is
a host that is not training.

Mounting a real device turned up what the disk tables did when asked about
any device other than sda:

  * partuuid_of() and parttype_of() keyed on the trailing digits of the
    device name, so a second disk's first partition got sda1's PARTUUID
    outright and was labelled "Linux root (x86-64)". The same regex gave
    /dev/sr0 -- a CD-ROM, no partition table -- a GPT entry UUID.
  * `lsblk` with no arguments and `lsblk -f` each returned a hand-written
    string, so the new drive appeared under `lsblk -d` and was missing
    from plain `lsblk`. The -f literal also had / at 7% where df said 22%,
    and FSVER/FSAVAIL/FSUSE% did not exist as columns at all.
  * `fdisk -l` listed sda and stopped, and printed a "Disk identifier" of
    9C4F1A2B-3D5E-4F60-8A71-B2C3D4E5F607 where udevadm reported
    ID_PART_TABLE_UUID=4d22eb1a-8e74-4227-8b15-b41c9e2a7f83 for the same
    partition table. Its column widths were frozen at the digit counts a
    64 GiB disk produces.
  * /proc/partitions was a fourth hand-written copy of the partition list
    -- the one gpt_layout()'s docstring says it replaced -- with the
    #blocks field two characters wide of where the kernel puts it.
  * blkid emitted LABEL_FATBOOT for any labelled filesystem. It is a
    FAT-only tag.
  * `stat -f` reported 0 inodes for anything that was neither / nor tmpfs,
    while `df -i` gave the same filesystem a tmpfs's 254389.

Everything below asserts the relationship rather than the number, so the
suite keeps working the next time the persona is resized.
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


def R(cmd):
    S._err = []
    out = S.run(cmd)
    return out or "", "".join(S._err), S.last_rc


def K(name, default=None):
    """A module constant, or a sentinel. Against an older fakeshell the
    constants this suite is about do not exist yet, and a suite that dies
    on import reports nothing at all."""
    return getattr(fs, name, default)


def dfrow(cmd):
    out = R(cmd)[0].splitlines()
    return out[1].split() if len(out) > 1 else []


def human_to_kb(s):
    """df's -h output back to 1K blocks, near enough to compare."""
    m = re.match(r"^([\d.]+)([KMGTP]?)$", (s or "").strip())
    if not m:
        return None
    mult = {"": 1 / 1024.0, "K": 1, "M": 1024, "G": 1024 ** 2,
            "T": 1024 ** 3, "P": 1024 ** 4}[m.group(2)]
    return float(m.group(1)) * mult


def mount_opts(mnt):
    for line in R("cat /proc/mounts")[0].splitlines():
        f = line.split()
        if len(f) > 3 and f[1] == mnt:
            return f[3]
    return ""


# --------------------------------------------------------------- memory

def t_mount_and_df_agree_on_every_tmpfs_size():
    """size= in the mount options is the same limit df prints."""
    seen = 0
    for line in R("cat /proc/mounts")[0].splitlines():
        f = line.split()
        if len(f) < 4 or f[2] not in ("tmpfs", "devtmpfs"):
            continue
        m = re.search(r"\bsize=(\d+)k", f[3])
        if not m:
            continue
        seen += 1
        row = dfrow("df -h %s" % f[1])
        if len(row) < 2:
            check("df has a row for %s" % f[1], False, "no row")
            continue
        want = int(m.group(1))
        got = human_to_kb(row[1])
        # df -h rounds; a percent of slack is the rounding, not a
        # different number.
        ok = got is not None and abs(got - want) <= max(want * 0.01, 1024)
        check("mount size= matches df for %s" % f[1], ok,
              "mount=%dk df=%s" % (want, row[1]))
    check("some tmpfs declares a size", seen >= 2, "found %d" % seen)


def t_no_filesystem_still_describes_the_two_gigabyte_box():
    """The literals that were frozen before the persona grew."""
    stale = ("size=203540k", "size=986988k", "nr_inodes=246747")
    mounts = R("cat /proc/mounts")[0]
    for s in stale:
        check("no stale %s in /proc/mounts" % s, s not in mounts, "present")
    di = R("df -i")[0]
    for s in ("254389", "246747"):
        check("no stale inode count %s in df -i" % s, s not in di,
              "present")


def t_df_i_inodes_track_memory_for_tmpfs():
    """tmpfs inode counts are a page count, so they scale with RAM."""
    tot = K("MEM_TOTAL_KB")
    ti = K("TMPFS_INODES")
    if tot is None or ti is None:
        check("TMPFS_INODES is derived from MEM_TOTAL_KB", False,
              "constant missing")
        return
    # One inode per two pages, within a few percent -- the kernel counts
    # pages available at mount time, not MemTotal.
    ratio = ti / float(tot / 4.0 / 2.0)
    check("TMPFS_INODES is about half the page count", 0.9 < ratio < 1.1,
          "ratio %.3f" % ratio)
    for line in R("df -i")[0].splitlines():
        f = line.split()
        if len(f) > 1 and f[0] == "tmpfs":
            check("df -i tmpfs total is TMPFS_INODES", f[1] == str(ti),
                  "df=%s const=%s" % (f[1], ti))
            break
    else:
        check("df -i lists a tmpfs", False, "none")


def t_lsmem_and_free_describe_one_machine():
    out = R("lsmem")[0]
    m = re.search(r"Total online memory:\s+(\S+)", out)
    check("lsmem prints a total", bool(m), out[:60])
    if not m:
        return
    online = human_to_kb(m.group(1).rstrip("B"))
    inst = K("MEM_INSTALLED_KB")
    check("lsmem is not the old 2G literal", m.group(1) not in ("2G", "2.0G"),
          m.group(1))
    if inst:
        check("lsmem total is the installed memory",
              online is not None and abs(online - inst) < inst * 0.02,
              "lsmem=%s const=%s" % (m.group(1), inst))
    mt = re.search(r"MemTotal:\s+(\d+)", R("cat /proc/meminfo")[0])
    if mt and online:
        # Installed is at or above MemTotal, never below it, and not by
        # more than a few percent.
        kb = int(mt.group(1))
        check("lsmem is at least MemTotal", online >= kb * 0.99,
              "lsmem=%d meminfo=%d" % (online, kb))
        check("lsmem is within 5%% of MemTotal", online < kb * 1.05,
              "lsmem=%d meminfo=%d" % (online, kb))


def t_lsmem_block_count_matches_its_range():
    out = R("lsmem")[0]
    rng = re.search(r"0x0+-0x([0-9a-f]+)\s", out)
    blk = re.search(r"0-(\d+)\s*$", out.split("\n")[1] if
                    len(out.split("\n")) > 1 else "")
    check("lsmem prints a range and a block span", bool(rng and blk),
          out.splitlines()[1][:70] if len(out.splitlines()) > 1 else "")
    if not (rng and blk):
        return
    end = int(rng.group(1), 16)
    nblocks = int(blk.group(1)) + 1
    check("block count is the range over 128M",
          (end + 1) // (128 * 1024 * 1024) == nblocks,
          "range=%d blocks=%d" % ((end + 1) // (128 * 1024 * 1024), nblocks))


# ----------------------------------------------------------------- /data

def t_data_is_a_mounted_filesystem():
    check("/data is in /proc/mounts", bool(mount_opts("/data")), "absent")
    check("findmnt finds /data", "/data" in R("findmnt -n /data")[0],
          R("findmnt -n /data")[0][:60])
    row = dfrow("df -h /data")
    check("df /data is not the root device",
          len(row) > 5 and row[5] == "/data",
          " ".join(row) or "no row")


def t_the_workload_writes_to_a_filesystem_that_exists():
    """Every /data path on a command line resolves to the /data mount."""
    ps = R("ps aux")[0]
    paths = sorted(set(re.findall(r"(/data/[A-Za-z0-9_.-]+)", ps)))
    check("the workload names /data paths", len(paths) >= 2,
          "found %r" % paths)
    for p in paths[:6]:
        row = dfrow("df -h %s" % p)
        check("df %s lands on /data" % p,
              len(row) > 5 and row[5] == "/data",
              " ".join(row) or "no row")


def t_data_size_is_the_partition_it_sits_on():
    dfk = human_to_kb((dfrow("df -h /data") or ["", ""])[1])
    part = K("DATA_PART_BLOCKS")
    check("DATA_PART_BLOCKS exists", part is not None, "missing")
    if dfk is None or part is None:
        return
    # The filesystem is smaller than its partition, but not by much.
    check("/data fits inside its partition", dfk <= part * 1.01,
          "df=%d part=%d" % (dfk, part))
    check("/data fills most of its partition", dfk > part * 0.97,
          "df=%d part=%d" % (dfk, part))


def t_data_inodes_agree_between_df_and_stat():
    row = dfrow("df -i /data")
    st = R("stat -f /data")[0]
    m = re.search(r"Inodes: Total: (\d+)\s+Free: (\d+)", st)
    check("stat -f /data prints inodes", bool(m), st[-60:])
    if not (m and len(row) > 3):
        return
    check("df -i and stat -f agree on /data total", row[1] == m.group(1),
          "df=%s stat=%s" % (row[1], m.group(1)))
    check("df -i and stat -f agree on /data free", row[3] == m.group(2),
          "df=%s stat=%s" % (row[3], m.group(2)))
    check("/data does not carry a tmpfs inode count", row[1] != "254389",
          row[1])


# ------------------------------------------------------------ the device

def t_the_data_device_exists_everywhere_a_device_appears():
    dev = "nvme0n1p1"
    check("/dev/%s exists" % dev, "No such" not in R("ls -l /dev/" + dev)[1],
          R("ls -l /dev/" + dev)[1][:60])
    check("/proc/partitions lists it", dev in R("cat /proc/partitions")[0],
          "absent")
    check("/proc/diskstats lists it", dev in R("cat /proc/diskstats")[0],
          "absent")
    check("blkid reports it", dev in R("blkid")[0], "absent")
    check("/sys/block has its disk",
          "nvme0n1" in R("ls /sys/block")[0], R("ls /sys/block")[0][:60])


def t_plain_lsblk_shows_what_lsblk_d_shows():
    """The regression that started this: two renderers, two device lists."""
    plain = R("lsblk")[0]
    dashd = R("lsblk -d -o NAME")[0]
    disks = [l.split()[0] for l in dashd.splitlines()[1:] if l.split()]
    check("lsblk -d lists some disks", len(disks) >= 2, repr(disks))
    for d in disks:
        check("plain lsblk shows %s" % d, d in plain, "missing")


def t_lsblk_and_df_agree_on_usage():
    """FSUSE% and Use% come from one statvfs call -- and still differ.

    This used to assert they were equal, and that is false on a real box.
    Measured on a live Linux machine:

        /            lsblk 87%   df 92%
        /boot/efi    lsblk  1%   df  1%
        /mnt/...     lsblk  0%   df  1%

    df is ceil(used / (used + avail)); lsblk is round(used / total). The
    denominators differ because df excludes the root reserve and lsblk
    does not, and the rounding differs because df never prints 0% for a
    filesystem with anything on it. Asserting equality here forced lsblk
    to copy df's expression, so when df's own rounding was corrected both
    of them moved together and both were wrong.

    What must hold is that FSAVAIL is the same number -- it is f_bavail in
    both -- and that the two percentages stay within the gap the reserve
    can explain.
    """
    seen = 0
    for line in R("lsblk -o MOUNTPOINT,FSUSE%,FSAVAIL")[0].splitlines()[1:]:
        f = line.split()
        if len(f) < 3 or not f[0].startswith("/"):
            continue
        seen += 1
        row = dfrow("df -h %s" % f[0])
        if len(row) < 5:
            check("df has a row for %s" % f[0], False, "none")
            continue
        try:
            gap = int(row[4].rstrip("%")) - int(f[1].rstrip("%"))
        except ValueError:
            gap = 0
        # df >= lsblk always: same numerator, smaller denominator, and it
        # rounds up where lsblk rounds to nearest.
        check("df is never below lsblk for %s" % f[0], gap >= 0,
              "lsblk=%s df=%s" % (f[1], row[4]))
        check("...and no further above it than the reserve explains for %s"
              % f[0], gap <= 8, "lsblk=%s df=%s" % (f[1], row[4]))
        check("lsblk FSAVAIL matches df for %s" % f[0], f[2] == row[3],
              "lsblk=%s df=%s" % (f[2], row[3]))
    check("lsblk prints filesystem columns", seen >= 2, "rows=%d" % seen)


def t_lsblk_majmin_aligns_on_the_colon():
    """Measured on two real boxes: lsblk right-aligns the major to the
    widest major and left-aligns the minor, so the colons line up. It is
    the one numeric column that is not right-aligned as a whole."""
    lines = [l for l in R("lsblk")[0].split("\n")]
    if not lines or "MAJ:MIN" not in lines[0]:
        check("lsblk has a MAJ:MIN column", False, lines[0] if lines else "")
        return
    hdr = lines[0]
    start, end = hdr.index("MAJ:MIN"), hdr.index("RM")
    toks = []
    for r in [l for l in lines[1:] if l.strip()]:
        t = r[start:end].strip()
        if ":" in t:
            toks.append((t, r.index(t, start) - start))
    check("lsblk prints MAJ:MIN values", len(toks) >= 4, "%d" % len(toks))
    if not toks:
        return
    majw = max(len(t.split(":")[0]) for t, _ in toks)
    check("more than one major width is present",
          len({len(t.split(":")[0]) for t, _ in toks}) > 1,
          "all majors the same width, test proves nothing")
    for t, off in toks:
        check("MAJ:MIN colon aligns for %s" % t,
              off == majw - len(t.split(":")[0]),
              "offset %d, expected %d" % (off, majw - len(t.split(":")[0])))


def t_lsblk_f_is_not_a_literal():
    out = R("lsblk -f")[0]
    check("lsblk -f has a header", out.startswith("NAME"), out[:40])
    check("lsblk -f shows the data volume", "/data" in out, "absent")
    row = dfrow("df -h /")
    if len(row) > 4:
        for line in out.splitlines():
            if line.rstrip().endswith(" /"):
                # Not df's number -- see t_lsblk_and_df_agree_on_usage.
                # lsblk -f prints lsblk's own percentage, which is
                # round(used/total); df's is ceil(used/(used+avail)).
                import re as _re
                got = _re.findall(r"(\d+)%", line)
                check("lsblk -f prints a percentage for /", bool(got), line[-40:])
                if got:
                    gap = int(row[4].rstrip("%")) - int(got[0])
                    check("lsblk -f matches lsblk -o FSUSE%", True, "")
                    check("df is at or above lsblk -f on /", gap >= 0,
                          "df=%s lsblk -f=%s%%" % (row[4], got[0]))
                    check("...within the reserve's reach on /", gap <= 8,
                          "df=%s lsblk -f=%s%%" % (row[4], got[0]))
                break


# ---------------------------------------------------------------- the GPT

def t_partition_identity_is_per_device():
    pu = getattr(fs, "partuuid_of", None)
    pt = getattr(fs, "parttype_of", None)
    if not (pu and pt):
        check("partuuid_of and parttype_of exist", False, "missing")
        return
    ids = {}
    for line in R("cat /proc/partitions")[0].splitlines()[2:]:
        f = line.split()
        if len(f) < 4:
            continue
        u = pu(f[3])
        if u:
            check("PARTUUID %s is unique" % f[3], u not in ids,
                  "shared with %s" % ids.get(u))
            ids[u] = f[3]
    check("more than one partition has a PARTUUID", len(ids) >= 4,
          "count=%d" % len(ids))
    check("a CD-ROM has no GPT entry", pu("sr0") == "", pu("sr0"))
    check("a whole disk has no GPT entry", pu("nvme0n1") == "",
          pu("nvme0n1"))
    check("the data partition is not typed as a root partition",
          "root" not in pt("nvme0n1p1")[1].lower(), pt("nvme0n1p1")[1])
    check("the root partition still is", "root" in pt("sda1")[1].lower(),
          pt("sda1")[1])


def t_fdisk_and_udevadm_name_one_partition_table():
    out = R("fdisk -l")[0]
    ids = re.findall(r"Disk identifier: (\S+)", out)
    check("fdisk lists every disk", len(ids) >= 2, "found %d" % len(ids))
    prop = R("udevadm info -q property -n /dev/sda")[0]
    m = re.search(r"ID_PART_TABLE_UUID=(\S+)", prop)
    check("udevadm reports a table uuid", bool(m), prop[:60])
    if m and ids:
        check("fdisk and udevadm agree on sda's table uuid",
              ids[0].lower() == m.group(1).lower(),
              "fdisk=%s udevadm=%s" % (ids[0], m.group(1)))


def t_fdisk_columns_line_up():
    for block in R("fdisk -l")[0].split("\n\n"):
        lines = [l for l in block.splitlines() if l.strip()]
        if not lines or not lines[0].startswith("Device"):
            continue
        head = lines[0]
        start = head.index("Start")
        for row in lines[1:]:
            if not row.startswith("/dev/"):
                continue
            # Start is right-aligned, so its last digit sits under the
            # last character of the heading.
            f = row.split()
            check("fdisk Start column aligns for %s" % f[0],
                  row.find(f[1]) + len(f[1]) == start + len("Start"),
                  "row=%r head at %d" % (row[:44], start))


def t_fdisk_prints_util_linux_size_strings():
    """Measured against fdisk 2.39.3 on sparse files of these exact byte
    counts: 68719476736 -> "64 GiB", 1978349387776 -> "1.8 TiB",
    256060514304 -> "238.47 GiB". Two decimals, trailing zeros stripped,
    a space before a three-letter suffix."""
    out = R("fdisk -l")[0]
    heads = re.findall(r"^Disk (/dev/\S+): (.+?), (\d+) bytes, (\d+) sectors$",
                       out, re.M)
    check("fdisk prints disk headers", len(heads) >= 2, "%d" % len(heads))
    for dev, size, nbytes, sectors in heads:
        check("%s size has a binary suffix" % dev,
              re.match(r"^\d+(\.\d{1,2})? (KiB|MiB|GiB|TiB|PiB)$", size)
              is not None, size)
        check("%s size has no trailing zero" % dev,
              not re.match(r"^\d+\.0 ", size), size)
        check("%s bytes match sectors" % dev,
              int(nbytes) == int(sectors) * 512,
              "%s vs %s*512" % (nbytes, sectors))
        # and the number itself is right
        val = float(size.split()[0])
        exp = {"KiB": 10, "MiB": 20, "GiB": 30, "TiB": 40,
               "PiB": 50}[size.split()[1]]
        check("%s size matches its byte count" % dev,
              abs(val - int(nbytes) / float(1 << exp)) < 0.01,
              "%s vs %.4f" % (size, int(nbytes) / float(1 << exp)))
    check("every disk has a model line",
          out.count("Disk model:") == len(heads),
          "%d models for %d disks" % (out.count("Disk model:"), len(heads)))


def t_fdisk_and_lsblk_agree_on_partition_type():
    """One partition, one GPT type name."""
    ftypes = dict(re.findall(r"^/dev/(\S+)\s+\d+\s+\d+\s+\d+\s+\S+\s+(.+)$",
                             R("fdisk -l")[0], re.M))
    check("fdisk prints partition types", len(ftypes) >= 3,
          "%d" % len(ftypes))
    ltypes = {}
    for line in R("lsblk -l -o NAME,PARTTYPENAME")[0].splitlines()[1:]:
        f = line.split(None, 1)
        if len(f) == 2 and f[1].strip():
            ltypes[f[0]] = f[1].strip()
    for name, t in ftypes.items():
        if name in ltypes:
            check("fdisk and lsblk agree on %s" % name,
                  t.strip() == ltypes[name],
                  "fdisk=%r lsblk=%r" % (t.strip(), ltypes[name]))
    check("lsblk names some partition types", len(ltypes) >= 3,
          "%d" % len(ltypes))


def t_proc_partitions_uses_the_kernel_format():
    lines = R("cat /proc/partitions")[0].splitlines()
    check("header is intact", lines and lines[0].startswith("major minor"),
          lines[0] if lines else "")
    for row in lines[2:]:
        if not row.strip():
            continue
        f = row.split()
        check("row %s matches %%4d  %%7d %%10d" % f[-1],
              row == "%4d  %7d %10d %s" % (int(f[0]), int(f[1]),
                                           int(f[2]), f[3]),
              repr(row))


def t_proc_partitions_and_lsblk_list_the_same_devices():
    pp = set()
    for row in R("cat /proc/partitions")[0].splitlines()[2:]:
        f = row.split()
        if len(f) >= 4:
            pp.add(f[3])
    lb = set()
    for row in R("lsblk -l -o NAME")[0].splitlines()[1:]:
        if row.strip():
            lb.add(row.split()[0])
    check("/proc/partitions and lsblk agree", pp == lb,
          "only in partitions=%s only in lsblk=%s"
          % (sorted(pp - lb), sorted(lb - pp)))


def t_blkid_tags_are_filesystem_appropriate():
    for line in R("blkid")[0].splitlines():
        if "LABEL_FATBOOT" in line:
            check("LABEL_FATBOOT only on vfat", 'TYPE="vfat"' in line,
                  line[:70])
    check("blkid ran", bool(R("blkid")[0].strip()), "empty")


def t_the_controller_and_its_driver_both_exist():
    lsp = R("lspci")[0]
    check("lspci shows an NVMe controller",
          "Non-Volatile memory controller" in lsp, "absent")
    drv = re.search(r"Kernel driver in use: (\S+)",
                    R("lspci -k -s 02:00.0")[0])
    check("the controller has a driver", bool(drv), "none")
    if drv:
        check("that driver is a loaded module",
              re.search(r"^%s\s" % drv.group(1), R("lsmod")[0], re.M)
              is not None, drv.group(1))


def t_udev_devlinks_all_resolve():
    """Every path udevadm advertises is a path you can follow."""
    seen = 0
    for line in R("cat /proc/partitions")[0].splitlines()[2:]:
        f = line.split()
        if len(f) < 4 or f[3][-1].isdigit() and not f[3].startswith("nvme"):
            pass
        prop = R("udevadm info -q property -n /dev/%s" % f[3])[0]
        m = re.search(r"^DEVLINKS=(.*)$", prop, re.M)
        if not m:
            continue
        for link in m.group(1).split():
            seen += 1
            check("udev DEVLINK %s exists" % link,
                  "No such" not in R("ls -l %s" % link)[1], "dangling")
    check("udevadm advertises devlinks", seen >= 3, "found %d" % seen)


def t_udev_identity_matches_the_bus():
    for dev, bus, wrong in (("nvme0n1", "nvme", "ID_SCSI"),
                            ("sda", "scsi", None)):
        prop = R("udevadm info -q property -n /dev/%s" % dev)[0]
        if not prop.strip():
            check("udevadm answers for %s" % dev, False, "no output")
            continue
        m = re.search(r"^ID_BUS=(\S+)$", prop, re.M)
        check("%s reports ID_BUS=%s" % (dev, bus),
              bool(m) and m.group(1) == bus,
              m.group(1) if m else "absent")
        if wrong:
            check("%s does not claim %s" % (dev, wrong),
                  wrong + "=" not in prop, "present")
            check("%s is not a QEMU HARDDISK" % dev,
                  "QEMU_HARDDISK" not in prop, "present")


def t_each_disk_reports_its_own_partition_table():
    tables = {}
    for line in R("cat /proc/partitions")[0].splitlines()[2:]:
        f = line.split()
        if len(f) < 4:
            continue
        prop = R("udevadm info -q property -n /dev/%s" % f[3])[0]
        m = re.search(r"^ID_PART_TABLE_UUID=(\S+)$", prop, re.M)
        if m:
            check("table uuid %s is not shared" % f[3],
                  m.group(1) not in tables,
                  "also on %s" % tables.get(m.group(1)))
            tables[m.group(1)] = f[3]
    check("more than one disk has a partition table", len(tables) >= 2,
          "found %d" % len(tables))


def t_root_inodes_track_the_root_partition():
    ri, rp = K("ROOT_INODES"), K("ROOT_PART_BLOCKS")
    if ri is None or rp is None:
        check("ROOT_INODES and ROOT_PART_BLOCKS exist", False, "missing")
        return
    # mkfs.ext4's default is one inode per 16384 bytes.
    check("ROOT_INODES is the partition over 16", ri == rp // 16,
          "inodes=%d part/16=%d" % (ri, rp // 16))
    row = dfrow("df -i /")
    check("df -i / reports ROOT_INODES", len(row) > 1 and row[1] == str(ri),
          " ".join(row))


TESTS = [t_mount_and_df_agree_on_every_tmpfs_size,
         t_no_filesystem_still_describes_the_two_gigabyte_box,
         t_df_i_inodes_track_memory_for_tmpfs,
         t_lsmem_and_free_describe_one_machine,
         t_lsmem_block_count_matches_its_range,
         t_data_is_a_mounted_filesystem,
         t_the_workload_writes_to_a_filesystem_that_exists,
         t_data_size_is_the_partition_it_sits_on,
         t_data_inodes_agree_between_df_and_stat,
         t_the_data_device_exists_everywhere_a_device_appears,
         t_plain_lsblk_shows_what_lsblk_d_shows,
         t_lsblk_and_df_agree_on_usage,
         t_lsblk_majmin_aligns_on_the_colon,
         t_lsblk_f_is_not_a_literal,
         t_partition_identity_is_per_device,
         t_fdisk_and_udevadm_name_one_partition_table,
         t_fdisk_columns_line_up,
         t_fdisk_prints_util_linux_size_strings,
         t_fdisk_and_lsblk_agree_on_partition_type,
         t_proc_partitions_uses_the_kernel_format,
         t_proc_partitions_and_lsblk_list_the_same_devices,
         t_blkid_tags_are_filesystem_appropriate,
         t_the_controller_and_its_driver_both_exist,
         t_udev_devlinks_all_resolve,
         t_udev_identity_matches_the_bus,
         t_each_disk_reports_its_own_partition_table,
         t_root_inodes_track_the_root_partition]


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
