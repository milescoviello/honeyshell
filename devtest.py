#!/usr/bin/env python3
"""Does the disk story hold together from /etc/fstab down to /dev?

fstab names a UUID, blkid maps UUIDs to devices, /dev/disk/by-uuid is the
symlink farm the kernel builds for exactly that lookup, lsblk draws the
partition table and /dev holds the nodes. Five views of one disk, and they
did not agree.

  - /dev/disk/by-uuid held two links and both were wrong, crossed with each
    other: the vfat UUID pointed at sda1 while blkid put it on sda15, and
    the ext4 UUID pointed at sda2 -- a partition that appears in neither
    blkid nor lsblk. Following the UUID out of fstab therefore landed on the
    wrong device.
  - /dev/sda15 did not exist in /dev at all, though fstab, blkid and lsblk
    all name it. /dev/sda2 did exist, and nothing else mentioned it.
  - The block devices were regular files: `ls -l /dev/sda` printed
    "-rw-rw---- ... 0" where a real box prints "brw-rw---- ... 8, 0" -- the
    wrong type character, and a size where the device numbers belong.
  - The character devices did have their numbers but padded the minor to
    three columns, so /dev/null read "1,   3" against coreutils' "1, 3".
  - sda14, the BIOS boot partition every Debian cloud image carries, was
    missing from /dev, blkid and lsblk. It has no filesystem, so blkid
    prints only its PARTUUID -- and printing the other fields anyway gave
    UUID="None" TYPE="None", which no blkid has produced.
  - lsblk drew its tree with |- and `- where lsblk uses box-drawing
    characters.
  - /dev/disk had two subdirectories; a real one has six.

Sizes stay as this persona's own (63G root, 976M ESP) rather than the
guest's, because df, fstab and lsblk already agree on them here. The bug was
never the numbers, it was that the five views disagreed about which device
was which.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

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
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def t_the_fstab_uuid_chain_resolves():
    """The contradiction this sweep started from."""
    s = sh()
    fstab, _ = run(s, "cat /etc/fstab")
    m = re.search(r"UUID=(\S+)\s+(\S+)", fstab)
    check("fstab mounts something by UUID", m, fstab[:80])
    if not m:
        return
    uuid, mnt = m.group(1), m.group(2)
    o, rc = run(s, "readlink -f /dev/disk/by-uuid/%s" % uuid)
    eq("by-uuid has a link for it", rc, 0)
    dev = o.strip()
    check("it resolves to a device", dev.startswith("/dev/"), dev)
    o2, _ = run(s, "blkid | grep -F %s" % uuid)
    check("blkid puts that UUID on the same device",
          o2.split(":")[0] == dev, "%s vs %r" % (dev, o2.split(":")[0]))
    o3, _ = run(s, "findmnt -n -o SOURCE %s" % mnt)
    eq("and that is what is mounted there", o3.strip(), dev)
    o4, rc4 = run(s, "test -b %s && echo yes" % dev)
    eq("the device node exists and is a block device",
       (o4.strip(), rc4), ("yes", 0))


def t_every_by_uuid_link_resolves():
    s = sh()
    out, _ = run(s, "ls /dev/disk/by-uuid")
    names = out.split()
    check("by-uuid is populated", len(names) >= 2, str(names))
    for n in names:
        o, _ = run(s, "readlink -f /dev/disk/by-uuid/%s" % n)
        tgt = o.strip()
        o2, rc = run(s, "test -b %s && echo yes" % tgt)
        eq("%s -> %s exists" % (n, tgt), (o2.strip(), rc), ("yes", 0))
        # ...and blkid agrees that UUID belongs to that device.
        o3, _ = run(s, "blkid %s" % tgt)
        check("blkid confirms %s on %s" % (n, tgt), n in o3, o3.strip()[:70])


def t_block_devices_are_block_devices():
    s = sh()
    for dev, major, minor in (("sda", 8, 0), ("sda1", 8, 1),
                              ("sda14", 8, 14), ("sda15", 8, 15),
                              ("sr0", 11, 0)):
        o, rc = run(s, "test -b /dev/%s && echo yes" % dev)
        eq("/dev/%s is a block device" % dev, (o.strip(), rc), ("yes", 0))
        o2, _ = run(s, "ls -l /dev/%s" % dev)
        check("/dev/%s shows type b" % dev, o2.lstrip().startswith("b"),
              o2.strip()[:50])
        check("/dev/%s shows %d, %d" % (dev, major, minor),
              "%d, %d" % (major, minor) in o2, o2.strip()[:60])
    o, _ = run(s, "stat -c %F /dev/sda1")
    eq("stat calls it a block special file", o.strip(), "block special file")


def t_character_devices_keep_their_numbers():
    """These were right except for the padding."""
    s = sh()
    for dev, major, minor in (("null", 1, 3), ("zero", 1, 5),
                              ("urandom", 1, 9), ("full", 1, 7)):
        o, _ = run(s, "ls -l /dev/%s" % dev)
        check("/dev/%s is char type c" % dev, o.lstrip().startswith("c"),
              o.strip()[:50])
        check("/dev/%s shows %d, %d without padding" % (dev, major, minor),
              "%d, %d " % (major, minor) in o, repr(o.strip()[:52]))


def t_no_device_nothing_else_mentions():
    """/dev/sda2 existed and no other view knew about it."""
    s = sh()
    out, _ = run(s, "ls /dev")
    devs = {d for d in out.split() if re.fullmatch(r"sd[a-z]\d*", d)}
    lsblk, _ = run(s, "lsblk")
    blkid, _ = run(s, "blkid")
    for d in sorted(devs):
        if d == "sda":
            continue
        check("%s appears in lsblk" % d, d in lsblk, "in /dev only")
        check("%s appears in blkid" % d, d in blkid, "in /dev only")
    # ...and the reverse: nothing in lsblk missing from /dev.
    for d in sorted(set(re.findall(r"sda\d+", lsblk))):
        o, rc = run(s, "test -e /dev/%s && echo yes" % d)
        eq("lsblk's %s exists in /dev" % d, (o.strip(), rc), ("yes", 0))


def t_lsblk_draws_a_tree():
    s = sh()
    out, rc = run(s, "lsblk")
    eq("lsblk works", rc, 0)
    check("it uses box-drawing branches",
          "├─" in out and "└─" in out,
          repr(out[:90]))
    check("no ASCII fallback branches", "|-" not in out and "`-" not in out,
          repr(out[:90]))
    check("the header is lsblk's", out.splitlines()[0].split() ==
          ["NAME", "MAJ:MIN", "RM", "SIZE", "RO", "TYPE", "MOUNTPOINTS"],
          out.splitlines()[0])
    # Majors and minors have to match the device nodes.
    for dev, mm in (("sda1", "8:1"), ("sda14", "8:14"), ("sda15", "8:15"),
                    ("sr0", "11:0")):
        line = [l for l in out.splitlines() if dev in l]
        check("lsblk gives %s as %s" % (dev, mm),
              line and mm in line[0], line[:1])


def t_blkid_omits_fields_it_cannot_know():
    """A partition with no filesystem has no UUID or TYPE to print."""
    s = sh()
    out, _ = run(s, "blkid")
    check("nothing reports a None value", "None" not in out, out[:90])
    line = [l for l in out.splitlines() if "sda14" in l]
    check("sda14 is listed", line, "absent")
    if line:
        check("with only a PARTUUID", "PARTUUID=" in line[0]
              and "UUID=\"" not in line[0].replace("PARTUUID=\"", ""),
              line[0])
    for l in out.splitlines():
        m = re.match(r"(/dev/\S+):", l)
        if m:
            o, rc = run(s, "test -b %s && echo yes" % m.group(1))
            eq("blkid's %s exists" % m.group(1), (o.strip(), rc),
               ("yes", 0))


def t_partuuids_match_the_partition_numbers():
    s = sh()
    out, _ = run(s, "blkid")
    for l in out.splitlines():
        m = re.match(r"/dev/sda(\d+):.*PARTUUID=\"[^-]+-(\d+)\"", l)
        if m:
            eq("sda%s has PARTUUID -%s" % (m.group(1), m.group(1)),
               int(m.group(2)), int(m.group(1)))


def t_disk_symlink_farm_is_populated():
    s = sh()
    out, _ = run(s, "ls /dev/disk")
    subs = set(out.split())
    for d in ("by-uuid", "by-partuuid", "by-label", "by-id", "by-path",
              "by-diskseq"):
        check("/dev/disk/%s exists" % d, d in subs, str(sorted(subs)))
    # by-label must name the ESP that blkid labels UEFI.
    o, rc = run(s, "readlink -f /dev/disk/by-label/UEFI")
    eq("by-label/UEFI resolves", rc, 0)
    o2, _ = run(s, "blkid %s" % o.strip())
    check("to the device blkid labels UEFI", 'LABEL="UEFI"' in o2,
          o2.strip()[:70])


def t_sizes_stay_self_consistent():
    """df, fstab and lsblk already agreed; the sweep must not break that."""
    s = sh()
    df, _ = run(s, "df -h /")
    lsblk, _ = run(s, "lsblk")
    root = [l for l in lsblk.splitlines() if "part /" in l and "efi" not in l]
    check("lsblk shows the root partition", root, "absent")
    check("df names the same device",
          root and root[0].split()[1].split(":")[0] == "8", df[:70])
    esp, _ = run(s, "df -h /boot/efi")
    check("df knows the ESP", "/boot/efi" in esp, esp[:70])


def t_findmnt_answers_about_size():
    """`findmnt -n -o SIZE,USED,AVAIL /` returned nothing at all, while df
    knew all three for the same filesystem. Two views of one number, one of
    them silent -- and RedTail's setup.sh already calls findmnt, so it is a
    tool actors reach for on this box."""
    s = sh()
    o, rc = run(s, "findmnt -n -o SIZE,USED,AVAIL /")
    eq("rc", rc, 0)
    parts = o.split()
    eq("three values", len(parts), 3)
    check("size is in findmnt's format", parts[0].endswith("G"), o[:40])
    o2, _rc = run(s, "df -h / | tail -1")
    eq("df names the same source", o2.split()[0], "/dev/sda1")
    o3, _rc = run(s, "findmnt -no SOURCE /")
    eq("and so does findmnt", o3.strip(), "/dev/sda1")


def t_findmnt_takes_bundled_short_options():
    """`findmnt -no SOURCE /` is the idiomatic one-field query, and we
    answered "unrecognized option '-no'"."""
    s = sh()
    for cmd, want in (("findmnt -no SOURCE /", "/dev/sda1"),
                      ("findmnt -no FSTYPE /", "ext4"),
                      ("findmnt -no TARGET /", "/")):
        o, rc = run(s, cmd)
        eq("%s rc" % cmd, rc, 0)
        eq(cmd, o.strip(), want)


def t_findmnt_df_mode():
    """-D/--df was rejected outright. Real findmnt lists only filesystems
    that have a size: sysfs and proc are absent, not blank."""
    s = sh()
    o, rc = run(s, "findmnt --df /")
    eq("--df rc", rc, 0)
    lines = o.strip().splitlines()
    eq("header", lines[0].split(),
       ["SOURCE", "FSTYPE", "SIZE", "USED", "AVAIL", "USE%", "TARGET"])
    eq("one row for /", len(lines), 2)
    eq("naming the root device", lines[1].split()[0], "/dev/sda1")
    o, _rc = run(s, "findmnt -D")
    names = [l.split()[-1] for l in o.strip().splitlines()[1:]]
    check("-D omits sysfs and proc",
          "/sys" not in names and "/proc" not in names, str(names))
    check("-D includes the real filesystems",
          "/" in names and "/boot/efi" in names, str(names))


def t_lsblk_honours_its_options():
    """Every invocation printed the whole default tree: -o, -n and even a
    device argument were ignored, so `lsblk -no SIZE,MOUNTPOINTS /dev/sda1`
    -- one device, two fields, no header -- returned six lines of table."""
    s = sh()
    o, rc = run(s, "lsblk -no SIZE,MOUNTPOINTS /dev/sda1")
    eq("one device two fields rc", rc, 0)
    eq("exactly one line", len(o.strip().splitlines()), 1)
    eq("size and mountpoint", o.split(), ["63G", "/"])
    o, _rc = run(s, "lsblk -o NAME,SIZE")
    eq("header is the requested columns", o.splitlines()[0].split(),
       ["NAME", "SIZE"])
    eq("every device still listed", len(o.strip().splitlines()), 6)
    o, _rc = run(s, "lsblk -n")
    check("no header with -n", not o.startswith("NAME"), o[:30])
    eq("still five devices", len(o.strip().splitlines()), 5)
    o, rc = run(s, "lsblk /dev/nope")
    eq("an unknown device is rejected", rc, 32)
    check("with lsblk's wording", "not a block device" in o, o[:50])


def t_lsblk_default_output_is_unchanged():
    """The structured path must not disturb the plain call."""
    s = sh()
    o, rc = run(s, "lsblk")
    eq("rc", rc, 0)
    lines = o.strip().splitlines()
    eq("header", lines[0].split(),
       ["NAME", "MAJ:MIN", "RM", "SIZE", "RO", "TYPE", "MOUNTPOINTS"])
    eq("six lines", len(lines), 6)
    check("tree glyphs kept", lines[2].startswith(u"\u251c\u2500sda1"),
          lines[2][:20])
    check("last child uses the corner",
          lines[4].startswith(u"\u2514\u2500sda15"), lines[4][:20])


TESTS = [t_the_fstab_uuid_chain_resolves, t_every_by_uuid_link_resolves,
         t_block_devices_are_block_devices,
         t_character_devices_keep_their_numbers,
         t_no_device_nothing_else_mentions, t_lsblk_draws_a_tree,
         t_blkid_omits_fields_it_cannot_know,
         t_partuuids_match_the_partition_numbers,
         t_disk_symlink_farm_is_populated, t_sizes_stay_self_consistent,
         t_findmnt_answers_about_size,
         t_findmnt_takes_bundled_short_options,
         t_findmnt_df_mode, t_lsblk_honours_its_options,
         t_lsblk_default_output_is_unchanged]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
