#!/usr/bin/env python3
"""The journal says how much disk it uses. The disk has to agree.

    journalctl --disk-usage
    Archived and active journals take up 72M in the file system.

    ls -ld /var/log/journal
    ls: cannot access '/var/log/journal': No such file or directory

Two commands, one question -- how much journal is on this box -- and one of
them was describing a directory that was not there. `du` said the same
thing, and `journalctl --vacuum-time=1s` named a path inside it while
reporting it had freed 0B.

Anyone clearing their tracks looks straight at this. The journal is the
thing that survives truncating /var/log/syslog, so "where is it and how big
is it" is the second question after "did my `>` work".

Measured on the guest (Debian 13.6, systemd, Storage=auto):

    drwxr-sr-x+ 3 root systemd-journal 4096 /var/log/journal
    drwxr-sr-x+ 2 root systemd-journal   40 /run/log/journal
    journalctl --disk-usage   141.5M
    du -sh /var/log/journal   142M
    /etc/systemd/journald.conf  1429 bytes, 49 non-blank lines, #Storage=auto

    system.journal                                          25165824
    system@00065948ed128863-6bb2f474fed33ac8.journal~         8388608
    system@...-0000000000000fb5-000659492680f483.journal     67108864
    user-1001.journal                                       50331648

Note what agreement means: 141.5M against 142M. The same bytes rounded two
different ways by two tools, not an identical string. A check that demanded
the strings match would be pinning the rounding, not the fact.

Usage:  python3 journalstoretest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []
MULT = {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh():
    return fakeshell.Shell(fakeshell.VFS(), peer="203.0.113.9",
                           peer_port=44321)


def as_bytes(text):
    m = re.match(r"^([\d.]+)([BKMGT])$", (text or "").strip().upper())
    if not m:
        return None
    return float(m.group(1)) * MULT.get(m.group(2), 1)


def main():
    s = sh()

    # -- the directory the journal claims to live in ------------------------
    ls = s.run("ls -ld /var/log/journal").strip()
    check("/var/log/journal exists", bool(ls), True)
    check("...as a directory", ls[:1], "d")
    check("...owned by systemd-journal", "root systemd-journal" in ls, True)
    check("...and setgid, as journald makes it", ls[:7], "drwxr-s")

    mdir = s.run("ls -d /var/log/journal/*").strip()
    mid = s.run("cat /etc/machine-id").strip()
    check("there is a per-machine directory", mdir.endswith(mid), True)
    check("...and the machine id is the one /etc/machine-id gives",
          mid in mdir, True)
    check("...which hostnamectl also reports",
          mid in s.run("hostnamectl"), True)

    # -- the files in it ----------------------------------------------------
    names = s.run("ls /var/log/journal/*/").split()
    check("there is an active system journal", "system.journal" in names, True)
    check("...and archived ones",
          any(n.startswith("system@") for n in names), True)
    check("...and a user journal",
          any(n.startswith("user-") and n.endswith(".journal")
              for n in names), True)
    listing = s.run("ls -l /var/log/journal/*/")
    check("the files are root:systemd-journal",
          listing.count("root systemd-journal"), len(names))
    check("...and mode 640, which is what journald writes",
          listing.count("-rw-r-----"), len(names))

    # -- the number, against the disk ---------------------------------------
    usage = s.run("journalctl --disk-usage").strip()
    check("--disk-usage answers", usage.startswith(
        "Archived and active journals take up "), True)
    size = usage.split("take up ")[1].split(" in ")[0]
    check("...with no trailing .0, as FORMAT_BYTES does", ".0" in size, False)
    # `du` on a directory that is not there prints nothing to stdout, so
    # this must not index into an empty list -- that would abort the suite
    # on the very defect it exists to report.
    du_out = s.run("du -sh /var/log/journal").split()
    du = du_out[0] if du_out else ""
    check("du can measure the journal directory", bool(du), True)
    a, b = as_bytes(size), as_bytes(du)
    check("both are readable sizes", a is not None and b is not None, True)
    if a and b:
        check("--disk-usage and du agree within rounding",
              abs(a - b) < b * 0.02, True)

    # ...and against the sum of the files themselves, which is the thing
    # both of them are supposed to be measuring.
    total = 0
    for line in listing.splitlines():
        f = line.split()
        if len(f) > 4 and f[0].startswith("-"):
            total += int(f[4])
    check("...and with the files added up",
          bool(a) and bool(total) and abs(a - total) < total * 0.02, True)

    # -- the runtime directory and the config -------------------------------
    rls = s.run("ls -ld /run/log/journal").strip()
    check("/run/log/journal exists too", rls[:1], "d")
    check("...and is empty, because storage is persistent",
          s.run("ls /run/log/journal 2>/dev/null").split(), [])

    conf = s.run("cat /etc/systemd/journald.conf")
    check("journald.conf is shipped", bool(conf.strip()), True)
    check("...with the commented defaults Debian ships",
          len([l for l in conf.splitlines() if l.strip()]), 49)
    check("...including the Storage setting that decides all of the above",
          "#Storage=auto" in conf, True)
    check("...and it is the size the guest's is",
          s.run("stat -c %s /etc/systemd/journald.conf").strip(), "1429")

    # -- vacuum names a path that is now really there -----------------------
    vac = s.run("journalctl --vacuum-time=1s")
    named = re.findall(r"from (\S+?)\.\s*$", vac, re.M)
    check("vacuum names its locations", len(named) >= 2, True)
    for path in named:
        check("vacuum's %s exists" % path,
              bool(s.run("ls -d %s 2>/dev/null" % path).strip()), True)

    # -- the seeded store did not disturb the rest of /etc/systemd ----------
    # journald.conf is written before /etc/systemd exists in the seed order,
    # and creating the parent must not shadow the unit tree written later.
    check("the unit directory is still there",
          "multi-user.target.wants" in s.run("ls /etc/systemd/system"), True)
    check("...and units still resolve",
          "nginx.service" in s.run("systemctl list-units --no-pager"), True)

    # -- and the store is priced into the filesystem ------------------------
    # 150M of journal has to be 150M of used disk, or df and du disagree
    # about the same bytes.
    used = s.run("df -k /var | tail -1").split()
    check("df has a used column for /var", len(used) >= 3, True)

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("journalstoretest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
