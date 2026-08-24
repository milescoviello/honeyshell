#!/usr/bin/env python3
"""Does the box agree with itself about what is mounted?

Six commands read one mount table -- mount, findmnt, mountpoint, df,
stat -f and /proc/self/mountinfo -- and an attacker reads it to answer two
questions: where can I write, and where can I execute. The box had two
tables and neither matched a real trixie.

  - /proc/mounts had 9 mounts where the guest has 29. No cgroup2, on a box
    whose every service publishes a MEMORY_PRESSURE_WATCH path under
    /sys/fs/cgroup -- a directory that did not exist. No securityfs, on a
    box with /sys/kernel/security/lsm. No tmpfs on /tmp, which trixie
    mounts by default and which decides whether a dropper's payload
    survives a reboot.
  - df kept its own six-row table beside that nine-line file, maintained by
    hand, so the two could and did drift. It reads /proc/mounts now and
    skips the same dummy filesystems GNU df skips.
  - /proc/self/mountinfo was a byte-for-byte copy of /proc/mounts. They
    describe the same mounts in different formats -- six fields against
    eleven -- so anything parsing mountinfo, which is what container
    detection reads, got the wrong columns from field three onwards.
  - `stat -f` answered for the root filesystem whatever path you gave it:
    `stat -f /tmp` said ext2/ext3 with /'s block counts while `df /tmp` and
    `findmnt /tmp` said tmpfs.
  - Growth was charged to / wherever it happened, so a payload staged in
    /tmp filled the root filesystem of a box where /tmp is a tmpfs.

The mount list, its options, the mountinfo format and every df row here
were measured on the real Debian 13 cloud guest this box imitates.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
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


def targets(s):
    o, _ = run(s, "cat /proc/mounts")
    return [l.split()[1] for l in o.splitlines() if l.strip()]


# --- one table, six readers -------------------------------------------------

def t_mount_and_proc_mounts_are_the_same_list():
    s = sh()
    o, _ = run(s, "mount")
    m = [(l.split(" on ")[0], l.split(" on ")[1].split(" type ")[0])
         for l in o.splitlines() if " on " in l]
    p, _ = run(s, "cat /proc/mounts")
    pm = [(l.split()[0], l.split()[1]) for l in p.splitlines() if l.strip()]
    eq("mount prints exactly what /proc/mounts holds", m, pm)
    check("and there are as many as a real trixie has", len(pm) > 20, len(pm))


def t_mtab_is_the_symlink_debian_ships():
    s = sh()
    o, _ = run(s, "ls -l /etc/mtab")
    check("/etc/mtab is a symlink into /proc",
          "-> ../proc/self/mounts" in o, o[:70])
    a, _ = run(s, "cat /etc/mtab")
    b, _ = run(s, "cat /proc/mounts")
    eq("so it cannot say anything different", a, b)


def t_findmnt_reads_the_same_file():
    s = sh()
    for t in ("/", "/tmp", "/dev/shm", "/boot/efi", "/sys/fs/cgroup"):
        o, rc = run(s, "findmnt -n -o TARGET,FSTYPE %s" % t)
        eq("findmnt knows %s" % t, rc, 0)
        p, _ = run(s, "grep ' %s ' /proc/mounts" % t)
        check("...with the fstype /proc/mounts gives it",
              o.split()[1] == p.split()[2], "%s vs %s" % (o, p[:40]))
    # -l is list mode; without it findmnt draws the tree, which is what a
    # bare `findmnt` on the guest does too.
    o2, _ = run(s, "findmnt -ln -o TARGET")
    eq("and lists every one of them", sorted(o2.split()), sorted(targets(s)))
    o3, _ = run(s, "findmnt -n -o TARGET")
    check("the default listing is a tree",
          any(l.startswith(("\u251c", "\u2514", "\u2502"))
              for l in o3.splitlines()), o3[:60])


def t_mountpoint_agrees_with_the_table():
    s = sh()
    for t in ("/", "/tmp", "/sys/fs/cgroup", "/run/lock"):
        o, rc = run(s, "mountpoint %s" % t)
        eq("%s is a mountpoint" % t, (o.strip(), rc),
           ("%s is a mountpoint" % t, 0))
    for t in ("/etc", "/root", "/var/log"):
        o, rc = run(s, "mountpoint %s" % t)
        eq("%s is not" % t, (o.strip(), rc),
           ("%s is not a mountpoint" % t, 1))


def t_df_comes_from_proc_mounts():
    s = sh()
    o, _ = run(s, "df")
    listed = [l.split()[-1] for l in o.splitlines()[1:] if l.strip()]
    have = targets(s)
    for m in listed:
        check("df's %s is in /proc/mounts" % m, m in have, have[:4])
    check("df lists the tmpfs mounts", "/tmp" in listed and
          "/dev/shm" in listed, listed)
    for skipped in ("/proc", "/sys", "/dev/pts", "/sys/fs/cgroup"):
        check("df leaves out %s, as GNU df does" % skipped,
              skipped not in listed, listed)


def t_mountinfo_is_the_other_format():
    s = sh()
    o, _ = run(s, "cat /proc/self/mountinfo")
    p, _ = run(s, "cat /proc/mounts")
    eq("one line per mount", len(o.splitlines()), len(p.splitlines()))
    check("it is not a copy of /proc/mounts", o != p, o[:60])
    for line in o.splitlines():
        f = line.split()
        check("mount id is a number: %s" % line[:20], f[0].isdigit(), f[:2])
        check("major:minor in field three", re.fullmatch(r"\d+:\d+", f[2]),
              f[:3])
        check("a separator before the fstype", "-" in f, line[:40])
    first = o.splitlines()[0].split()
    idx = first.index("-")
    eq("the root of the mount is /", first[3], "/")
    check("the fstype follows the separator",
          first[idx + 1] in p, first[idx + 1])


def t_mountinfo_parents_are_real_mounts():
    s = sh()
    o, _ = run(s, "cat /proc/self/mountinfo")
    ids = {}
    for line in o.splitlines():
        f = line.split()
        ids[int(f[0])] = f[4]
    for line in o.splitlines():
        f = line.split()
        parent, target = int(f[1]), f[4]
        if parent == 1:
            continue
        check("%s is mounted under %s" % (target, ids.get(parent)),
              ids.get(parent) and target.startswith(
                  ids[parent].rstrip("/") + "/"),
              "%s parent %s" % (target, ids.get(parent)))


# --- the mounts a trixie really has -----------------------------------------

def t_the_pseudo_filesystems_are_there():
    s = sh()
    have = set(targets(s))
    for t in ("/sys/kernel/security", "/sys/fs/cgroup", "/sys/fs/pstore",
              "/sys/fs/bpf", "/sys/kernel/debug", "/sys/kernel/tracing",
              "/dev/hugepages", "/dev/mqueue", "/sys/kernel/config",
              "/proc/sys/fs/binfmt_misc"):
        check("%s is mounted" % t, t in have, sorted(have)[:5])
        o, _ = run(s, "test -d %s && echo ok" % t)
        eq("...and the directory exists", o.strip(), "ok")


def t_the_cgroup_mount_holds_the_paths_services_publish():
    s = sh()
    o, _ = run(s, "cat /proc/701/environ | tr '\\0' '\\n' | grep PRESSURE_WATCH")
    path = o.split("=", 1)[1].strip() if "=" in o else ""
    check("a service publishes a pressure path", path.startswith(
        "/sys/fs/cgroup/"), path)
    o2, _ = run(s, "findmnt -n -o FSTYPE /sys/fs/cgroup")
    eq("and the filesystem it names is mounted", o2.strip(), "cgroup2")


def t_tmp_is_a_tmpfs():
    s = sh()
    o, _ = run(s, "findmnt -n -o FSTYPE,OPTIONS /tmp")
    eq("trixie mounts /tmp as tmpfs", o.split()[0], "tmpfs")
    check("nosuid and nodev", "nosuid" in o and "nodev" in o, o)
    check("but not noexec -- a dropper can still run from it",
          "noexec" not in o, o)
    o2, _ = run(s, "ls -ld /tmp")
    check("and it is still the sticky world-writable directory",
          o2.startswith("drwxrwxrwt"), o2[:20])


def t_a_payload_in_tmp_fills_tmpfs_not_the_disk():
    s = sh()
    before_root, _ = run(s, "df -k --output=used / | tail -1")
    before_tmp, _ = run(s, "df -k --output=used /tmp | tail -1")
    run(s, "dd if=/dev/zero of=/tmp/stage bs=1M count=32 2>/dev/null")
    after_root, _ = run(s, "df -k --output=used / | tail -1")
    after_tmp, _ = run(s, "df -k --output=used /tmp | tail -1")
    grew_tmp = int(after_tmp) - int(before_tmp)
    grew_root = int(after_root) - int(before_root)
    check("the tmpfs took the 32M", 32000 <= grew_tmp <= 33500, grew_tmp)
    eq("and the root filesystem did not move", grew_root, 0)
    run(s, "rm -f /tmp/stage")
    back, _ = run(s, "df -k --output=used /tmp | tail -1")
    eq("deleting it gives the space back", back.strip(), before_tmp.strip())


# --- statfs -----------------------------------------------------------------

def t_stat_f_answers_for_the_right_filesystem():
    s = sh()
    o, _ = run(s, "stat -f /tmp")
    check("stat -f /tmp says tmpfs", "Type: tmpfs" in o, o[:120])
    o2, _ = run(s, "stat -f /")
    check("and / says ext2/ext3, which is what statfs calls ext4",
          "Type: ext2/ext3" in o2, o2[:120])
    o3, _ = run(s, "stat -f /boot/efi")
    check("the ESP says msdos", "Type: msdos" in o3, o3[:120])
    ids = set()
    for p in ("/", "/tmp", "/boot/efi"):
        o4, _ = run(s, "stat -f %s | sed -n 2p" % p)
        ids.add(o4.split()[1])
    eq("three filesystems have three ids", len(ids), 3)


def t_stat_f_c_reads_the_same_statfs():
    """The formatted form had its own hardcoded copy of the numbers."""
    s = sh()
    for p, want in (("/", "ext2/ext3"), ("/tmp", "tmpfs"),
                    ("/boot/efi", "msdos")):
        o, _ = run(s, "stat -f -c %%T %s" % p)
        eq("stat -f -c %%T %s" % p, o.strip(), want)
        a, _ = run(s, "stat -f -c %%a %s" % p)
        b, _ = run(s, "stat -f %s | sed -n 4p" % p)
        eq("...and -c %%a matches the block it prints without a format",
           a.strip(), re.search(r"Available: (\d+)", b).group(1))
    ids = set()
    for p in ("/", "/tmp", "/boot/efi"):
        o, _ = run(s, "stat -f -c %%i %s" % p)
        ids.add(o.strip())
    eq("and each filesystem has its own id", len(ids), 3)


def t_stat_f_and_df_count_the_same_blocks():
    s = sh()
    for p in ("/", "/tmp", "/dev/shm"):
        o, _ = run(s, "stat -f %s | sed -n 4p" % p)
        total = int(re.search(r"Total: (\d+)", o).group(1))
        d, _ = run(s, "df -k --output=size %s | tail -1" % p)
        eq("statfs and df agree on the size of %s" % p,
           total * 4, int(d.strip()))


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:10]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
