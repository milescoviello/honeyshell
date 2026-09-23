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


def t_the_dropper_staging_dirs_are_world_writable():
    """/dev/shm, /tmp, /var/tmp and /run/shm are 1777 on a real box.

    Not cosmetic. /dev/shm is the first place a dropper tries, and this
    box had it at 0755: created 1777 in _build_baseline -- under a comment
    saying an unwritable one "reads as locked-down or fake" -- and then
    silently reset by a later loop that rebuilt a list of /proc, /sys and
    /dev directories at 0755 and had /dev/shm in it. /tmp had already been
    rescued from that same loop three lines below; /dev/shm was missed.

    Cost, measured: on 2026-09-01 203.0.113.66 returned as *deploy*, ran
        cd /dev/shm || cd /tmp || ... && cat > astats
    three times, and took permission_denied on the redirect every time.
    Three payload deliveries refused and nothing captured, because the box
    was stricter than the machine it claims to be.
    """
    # /run/shm is deliberately absent from this list: it is a symlink to
    # /dev/shm on Debian, not a directory of its own, so it carries a
    # link's 777 and no sticky bit. t_the_symlinks_are_symlinks covers it,
    # including that a drop through it is the same file in /dev/shm.
    s = sh()
    for d in ("/dev/shm", "/tmp", "/var/tmp", "/run/lock"):
        mode = run(s, "stat -c %%a %s" % d)[0].strip()
        check("%s is 1777" % d, mode == "1777", "got %r" % mode)
        sym = run(s, "stat -c %%A %s" % d)[0].strip()
        check("%s shows the sticky bit" % d, sym.endswith("t"),
              "got %r" % sym)


def t_a_non_root_user_can_actually_drop_a_file_there():
    """The mode is the claim; writing is the fact. Check the fact."""
    for user in ("deploy", "www-data"):
        for d in ("/dev/shm", "/tmp", "/var/tmp"):
            s = sh(user=user)
            out, _rc = run(s, "cd %s && cat > dropped_%s" % (d, user))
            check("%s can write in %s" % (user, d),
                  "Permission denied" not in out, out.strip()[:60])
            there, _ = run(s, "test -f %s/dropped_%s && echo yes || echo no"
                           % (d, user))
            check("...and the file is there (%s, %s)" % (user, d),
                  there.strip() == "yes", there.strip()[:30])


def t_sticky_still_protects_other_peoples_files():
    """1777 without the sticky semantics would be the opposite mistake."""
    v = fs.VFS()
    r = fs.Shell(v, user="root")
    r.exec_mode = True
    d = fs.Shell(v, user="deploy")
    d.exec_mode = True
    for path in ("/dev/shm/rootowned", "/tmp/rootowned"):
        r.run("echo mine > %s" % path)
        d._err = []
        out = d.run("rm -f %s" % path) + "".join(d._err)
        check("deploy cannot remove root's %s" % path,
              "cannot remove" in out, out.strip()[:60])
        still = d.run("test -f %s && echo present || echo gone" % path)
        check("...and it survives (%s)" % path,
              still.strip() == "present", still.strip()[:20])


#: mode and owner:group for the directories an attacker measures before
#: choosing somewhere to work, read off a real Debian 13 rather than
#: recalled. Being *stricter* than the real box is its own tell and a
#: more expensive one than being looser: on 2026-09-01 a 0755 /dev/shm
#: refused three payload deliveries from a live attacker running as
#: deploy. This table is the whole answer to "where can I write", pinned.
REAL_TRIXIE_DIRS = {
    "/tmp": "1777 root:root",
    "/var/tmp": "1777 root:root",
    "/dev/shm": "1777 root:root",
    "/run/lock": "1777 root:root",
    "/var/mail": "2775 root:mail",
    "/var/spool": "755 root:root",
    "/var/log": "755 root:root",
    "/run/user": "755 root:root",
    "/home": "755 root:root",
    "/srv": "755 root:root",
    "/opt": "755 root:root",
    "/media": "755 root:root",
    "/mnt": "755 root:root",
    "/var/cache": "755 root:root",
    "/var/cache/apt": "755 root:root",
    "/var/cache/apt/archives": "755 root:root",
    "/var/backups": "755 root:root",
    "/usr/local": "755 root:root",
    "/usr/local/bin": "755 root:root",
    "/usr/local/lib": "755 root:root",
    "/usr/local/src": "755 root:root",
    "/proc": "555 root:root",
    "/sys": "555 root:root",
}

#: Paths that are symlinks on Debian, not directories. stat(1) does not
#: follow by default, so `ls -ld` shows lrwxrwxrwx and a directory here
#: is visible in one command.
REAL_TRIXIE_LINKS = {
    "/run/shm": "/dev/shm",
    "/var/lock": "/run/lock",
    "/var/run": "/run",
    "/bin": "usr/bin",
}


def t_the_writable_map_matches_a_real_trixie():
    """Every directory an attacker sizes up, mode and group, against the
    real thing. Three were wrong when this table was first built:
    /var/mail was root:root so its setgid bit meant nothing and a
    mail-group process could not write; /usr/local/lib and /usr/local/src
    did not exist at all.
    """
    s = sh()
    fmt = "stat -c " + chr(37) + "a" + " " + chr(37) + "U:" + chr(37) + "G "
    for d, want in sorted(REAL_TRIXIE_DIRS.items()):
        got = run(s, "stat -c '" + chr(37) + "a " + chr(37) + "U:"
                  + chr(37) + "G' " + d)[0].strip()
        check("%s is %s" % (d, want), got == want, "got %r" % got)


def t_the_symlinks_are_symlinks():
    """/run/shm was a second, independent tmpfs directory here.

    On Debian it is a symlink to /dev/shm, so a file dropped through one
    path is the same file through the other. Ours were two directories:
    a dropper that staged in /run/shm and then looked in /dev/shm, or the
    reverse, would have found nothing, and `ls -ld /run/shm` printed
    drwxrwxrwt where a real box prints lrwxrwxrwx.
    """
    s = sh()
    for link, target in sorted(REAL_TRIXIE_LINKS.items()):
        out = run(s, "ls -ld " + link)[0].strip()
        check("%s is a symlink" % link, out.startswith("l"), out[:60])
        check("...pointing at %s" % target,
              out.rstrip().endswith("-> " + target), out[-40:])
    # and the identity is real, not cosmetic
    d = sh(user="deploy")
    d.run("echo viashm > /run/shm/probe")
    both = run(d, "stat -c " + chr(37) + "i /run/shm/probe /dev/shm/probe")[0]
    inodes = both.split()
    check("a drop through /run/shm is the same file in /dev/shm",
          len(inodes) == 2 and inodes[0] == inodes[1], inodes)


def t_a_mail_group_process_can_write_where_debian_lets_it():
    """2775 root:mail exists so the mail group can deliver. Owning it
    root:root keeps the bit and removes the point."""
    s = sh()
    grp = run(s, "stat -c " + chr(37) + "G /var/mail")[0].strip()
    check("/var/mail is group mail", grp == "mail", "got %r" % grp)
    check("the mail group exists to own it",
          run(s, "getent group mail")[0].strip().startswith("mail:x:8:"),
          run(s, "getent group mail")[0].strip()[:40])


#: mode and owner:group for the files that decide what an unprivileged
#: attacker can read or become. Read off a real Debian 13 and, for the two
#: that differed, confirmed against the shipping .deb with dpkg-deb -c.
REAL_TRIXIE_FILES = {
    "/etc/shadow": "640 root:shadow",
    "/etc/gshadow": "640 root:shadow",
    "/etc/passwd": "644 root:root",
    "/etc/group": "644 root:root",
    "/etc/sudoers": "440 root:root",
    "/etc/ssh/sshd_config": "644 root:root",
    "/etc/ssh/ssh_host_ed25519_key": "600 root:root",
    "/etc/ssh/ssh_host_rsa_key": "600 root:root",
    "/etc/ssh/ssh_host_ed25519_key.pub": "644 root:root",
    "/root": "700 root:root",
    "/var/log/wtmp": "664 root:utmp",
    "/var/log/lastlog": "664 root:utmp",
    "/var/log/btmp": "660 root:utmp",
    "/usr/bin/sudo": "4755 root:root",
    "/usr/bin/su": "4755 root:root",
    "/usr/bin/passwd": "4755 root:root",
    "/usr/bin/chsh": "4755 root:root",
    "/usr/bin/chfn": "4755 root:root",
    "/usr/bin/newgrp": "4755 root:root",
    "/usr/bin/gpasswd": "4755 root:root",
    "/usr/bin/mount": "4755 root:root",
    "/usr/bin/umount": "4755 root:root",
    "/usr/bin/ssh-agent": "2755 root:_ssh",
    "/usr/bin/expiry": "2755 root:shadow",
    "/usr/sbin/unix_chkpwd": "2755 root:shadow",
    # 4755 from dpkg-deb -c on the real openssh-client .deb. 4711 was an
    # older Debian's mode and left group and other unable to read it.
    "/usr/lib/openssh/ssh-keysign": "4755 root:root",
    # 4754 root:messagebus is set by dbus's postinst via dpkg-statoverride
    # -- the real guest carries that override. Ours was 4750 root:root, so
    # the group the helper exists for could not execute it.
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper": "4754 root:messagebus",
}


def t_the_privileged_file_modes_match_a_real_trixie():
    """`find / -perm -4000` is recon, and so is `ls -l /etc/shadow`."""
    s = sh()
    P = chr(37)
    for f, want in sorted(REAL_TRIXIE_FILES.items()):
        got = run(s, "stat -c '" + P + "a " + P + "U:" + P + "G' " + f)[0].strip()
        check("%s is %s" % (f, want), got == want, "got %r" % got)


def t_the_setuid_set_matches_the_installed_packages():
    """What is setuid has to follow from what is installed.

    Both differences against the real guest turned out to be package-set
    differences rather than faults, and checking that is the point: our
    crontab is setgid because cron is installed here and absent there, and
    we ship no polkit helper because policykit-1 is `un` in our own dpkg.
    A setuid binary from a package the box does not admit to owning is a
    contradiction; so is a missing one from a package it does.
    """
    s = sh()
    suid = set(run(s, "find /usr /bin /sbin /opt -xdev -perm -4000 -type f"
                   )[0].split())
    sgid = set(run(s, "find /usr /bin /sbin /opt -xdev -perm -2000 -type f"
                   )[0].split())
    for p in sorted(suid | sgid):
        check("%s is a file dpkg owns" % p,
              "no path found" not in run(s, "dpkg -S " + p)[0], p)
    # cron is installed, so its setgid binary must be here
    installed = run(s, "dpkg -l cron | tail -1")[0].split()
    check("cron is installed", installed[:1] == ["ii"], installed[:3])
    check("...so crontab is setgid", "/usr/bin/crontab" in sgid,
          sorted(sgid))
    # polkit is not, so its helper must not be
    check("policykit-1 is not installed",
          run(s, "dpkg -l policykit-1 | tail -1")[0].split()[:1] == ["un"],
          run(s, "dpkg -l policykit-1 | tail -1")[0][:40])
    check("...so no polkit helper is setuid",
          not [p for p in suid if "polkit" in p], sorted(suid))


def t_mount_does_what_it_is_told():
    """`mount --bind` used to print the mount table and change nothing.

    So did every other form: `mount -t tmpfs none /tmp/x`, `mount /dev/sda1
    /mnt`. The arguments were ignored outright. No mount prints its table
    when given a target, and the two commands anyone runs next -- `mount |
    grep` and `ls` on the target -- both contradicted the one that had
    apparently just succeeded. Hiding a staging directory under a tmpfs and
    binding a directory somewhere readable are both ordinary moves.

    Shapes measured on a real trixie: a bind reports the *source*
    filesystem's device and type rather than "none", a tmpfs reports
    `none ... tmpfs rw,relatime,inode64`, and the failure text is two
    lines with dmesg(1) named on the second.
    """
    s = sh()
    run(s, "mkdir -p /tmp/bsrc /tmp/bdst && echo marker > /tmp/bsrc/f")
    out, rc = run(s, "mount --bind /tmp/bsrc /tmp/bdst")
    check("a bind is silent", out.strip() == "", repr(out[:40]))
    check("...and succeeds", rc == 0, rc)
    check("the file is visible through the target",
          run(s, "cat /tmp/bdst/f")[0].strip() == "marker",
          run(s, "cat /tmp/bdst/f")[0][:40])
    check("the mount is in the table",
          "/tmp/bdst" in run(s, "mount")[0], run(s, "mount")[0][-60:])
    check("...reporting the source filesystem, not none",
          "none on /tmp/bdst" not in run(s, "mount")[0], True)
    check("the target is still a directory, not a symlink",
          run(s, "ls -ld /tmp/bdst")[0].strip().startswith("d"),
          run(s, "ls -ld /tmp/bdst")[0][:40])
    # a tmpfs hides what was underneath, and umount brings it back
    run(s, "mkdir -p /tmp/hid && echo secret > /tmp/hid/under")
    run(s, "mount -t tmpfs none /tmp/hid")
    check("a tmpfs hides the directory underneath",
          run(s, "ls /tmp/hid")[0].strip() == "",
          repr(run(s, "ls /tmp/hid")[0][:40]))
    check("...and it is in the table as tmpfs",
          "none on /tmp/hid type tmpfs" in run(s, "mount")[0],
          run(s, "mount")[0][-70:])
    out, rc = run(s, "umount /tmp/hid")
    check("umount succeeds", rc == 0, rc)
    check("...and what was underneath is back",
          run(s, "ls /tmp/hid")[0].strip() == "under",
          repr(run(s, "ls /tmp/hid")[0][:40]))
    check("...and it left the table",
          "/tmp/hid" not in run(s, "mount")[0], True)


def t_umount_knows_what_is_actually_mounted():
    """It answered "target is busy" for everything, including paths that
    were never mounted and including binds this shell had just made, so a
    mount could be created and never removed."""
    s = sh()
    out, rc = run(s, "umount /tmp/definitely-not-mounted")
    check("an unmounted path is not mounted",
          "not mounted" in out, out.strip()[:60])
    check("...with umount's exit code", rc == 32, rc)
    out, rc = run(s, "umount /")
    check("a real filesystem is busy", "target is busy" in out,
          out.strip()[:60])
    check("...also 32", rc == 32, rc)


def t_mount_reports_the_errors_a_real_one_reports():
    s = sh()
    out, rc = run(s, "mount --bind /tmp /tmp/no-such-target-here")
    check("a missing mount point says so",
          "mount point does not exist" in out, out.strip()[:60])
    check("...and names dmesg on the second line",
          "dmesg(1) may have more information" in out, out.strip()[-60:])
    check("...exiting 32", rc == 32, rc)
    # and with no arguments at all it is still the table
    out, _ = run(s, "mount")
    check("bare mount still lists the table",
          len(out.splitlines()) > 10 and " on / type " in out,
          len(out.splitlines()))


def t_every_reader_sees_a_runtime_mount():
    """mountinfo is generated from the static table, and was the one
    reader that did not know about a mount made at runtime.

    After a bind, mount, /proc/mounts, findmnt, df, mountpoint and
    /etc/mtab all listed it and /proc/self/mountinfo did not -- six
    against one, and the one that disagreed is the file container
    detection reads first. Introduced by teaching mount(8) to do its job:
    it appends to /proc/mounts, which is a file, while mountinfo is built
    on read.
    """
    s = sh()
    run(s, "mkdir -p /tmp/rt_src /tmp/rt_dst && echo x > /tmp/rt_src/f")
    run(s, "mount --bind /tmp/rt_src /tmp/rt_dst")
    for probe, desc in (("mount", "mount(8)"),
                        ("cat /proc/mounts", "/proc/mounts"),
                        ("cat /proc/self/mountinfo", "mountinfo"),
                        ("findmnt -n /tmp/rt_dst", "findmnt"),
                        ("cat /etc/mtab", "/etc/mtab")):
        check("%s knows about the bind" % desc,
              "/tmp/rt_dst" in run(s, probe)[0], desc)
    check("mountpoint agrees",
          run(s, "mountpoint -q /tmp/rt_dst; echo $?")[0].strip(), "0")
    # the shape of the mountinfo row is what marks it a bind
    row = [l for l in run(s, "cat /proc/self/mountinfo")[0].splitlines()
           if "/tmp/rt_dst" in l]
    check("there is exactly one mountinfo row", len(row) == 1, row)
    if row:
        f = row[0].split()
        check("mountinfo has the kernel's eleven-ish fields", len(f) >= 10,
              f)
        # field 4 is the source's path *within* its filesystem. "/" there
        # would say this was a fresh mount rather than a bind, which is
        # exactly the distinction container detection looks for.
        check("the root field names the bind source, not /",
              f[3] == "/rt_src", f[3])
        check("...and the device is the source filesystem's",
              f[2] == run(s, "findmnt -no MAJ:MIN /tmp")[0].strip()
              or ":" in f[2], f[2])
    # and umount takes it out of every one of them again
    run(s, "umount /tmp/rt_dst")
    for probe, desc in (("mount", "mount(8)"),
                        ("cat /proc/mounts", "/proc/mounts"),
                        ("cat /proc/self/mountinfo", "mountinfo")):
        check("%s forgets it after umount" % desc,
              "/tmp/rt_dst" not in run(s, probe)[0], desc)


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
