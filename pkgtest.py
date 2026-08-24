#!/usr/bin/env python3
"""Does dpkg agree with the filesystem about what it installed?

`dpkg -L <pkg>` is how you find out where a package put things, and
`dpkg -S <file>` is how you find out what owns a file. They are two views of
one fact, and neither had ever been checked against the filesystem they
describe.

Every one of the 91 installed packages listed at least one file that was not
there. The cause was a six-name heuristic: -L placed a binary in /usr/sbin
if it was one of sshd, nginx, cron, mariadbd, mysqld or init, and in
/usr/bin otherwise. So ifconfig, iptables, groupadd, fdisk, blkid, adduser,
logrotate, dmidecode, depmod and arp were all listed under /usr/bin while
living in /usr/sbin -- which `dpkg -L net-tools | xargs ls` shows in one
command, and which is a normal thing to run. -S carried its own copy of the
same guess and was wrong the same way.

Both now look the path up in the filesystem rather than guessing it.

/usr/share/doc did not exist at all, though -L names a copyright and a
changelog for every package. Those are there now, one directory per
installed package.

Run from `honeypot/`, or on the guest.
"""

import os
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


def packages(s):
    out, _ = run(s, "dpkg -l | awk 'NR>5{print $2}'")
    return out.split()


def listing(s, pkg):
    out, _ = run(s, "dpkg -L %s" % pkg)
    return [l.strip() for l in out.splitlines()
            if l.strip().startswith("/") and l.strip() != "/."]


def t_every_listed_file_exists():
    """The finding: all 91 packages listed files that were not there."""
    s = sh()
    pkgs = packages(s)
    check("there are packages to check", len(pkgs) > 50, str(len(pkgs)))
    bad, total = {}, 0
    for p in pkgs:
        for path in listing(s, p):
            total += 1
            if not s.fs.exists(path):
                bad.setdefault(p, []).append(path)
    check("dpkg -L lists a meaningful number of files", total > 500,
          str(total))
    eq("no package lists a file that is absent", sorted(bad), [])
    if bad:
        for p, fl in sorted(bad.items())[:4]:
            print("        %s: %s" % (p, fl[:3]))


def t_binaries_are_listed_where_they_live():
    """The specific ten that the six-name guess got wrong."""
    s = sh()
    for b, pkg in (("ifconfig", "net-tools"), ("arp", "net-tools"),
                   ("iptables", "iptables"), ("groupadd", "passwd"),
                   ("fdisk", "util-linux"), ("blkid", "util-linux"),
                   ("adduser", "adduser"), ("logrotate", "logrotate"),
                   ("dmidecode", "dmidecode"), ("depmod", "kmod")):
        out, rc = run(s, "command -v %s" % b)
        real = out.strip()
        if rc != 0 or not real:
            continue
        files = listing(s, pkg)
        check("%s is listed at %s" % (b, real), real in files,
              [f for f in files if f.endswith("/" + b)] or "not listed")


def t_search_round_trips_with_listfiles():
    """-S on a file -L named must name the package back."""
    s = sh()
    for pkg in ("net-tools", "coreutils", "nginx", "openssh-server",
                "util-linux", "rsyslog"):
        files = [f for f in listing(s, pkg)
                 if f.startswith(("/usr/bin/", "/usr/sbin/"))]
        if not files:
            continue
        for f in files[:3]:
            out, rc = run(s, "dpkg -S %s" % f)
            eq("dpkg -S %s finds an owner" % f, rc, 0)
            check("...and names %s" % pkg, pkg in out, out.strip()[:70])
            check("...with the same path -L gave", f in out,
                  out.strip()[:70])


def t_search_agrees_with_command_v():
    """Three views of where a binary is: -L, -S and the shell's own lookup."""
    s = sh()
    for b in ("ls", "nginx", "iptables", "sshd", "systemctl", "ifconfig"):
        out, rc = run(s, "command -v %s" % b)
        if rc != 0:
            continue
        where = out.strip()
        o2, rc2 = run(s, "dpkg -S %s" % b)
        if rc2 != 0:
            continue
        check("dpkg -S %s agrees with command -v" % b, where in o2,
              "%s vs %s" % (where, o2.strip()[:50]))


def t_doc_directory_per_package():
    s = sh()
    pkgs = packages(s)
    for p in pkgs[:12]:
        o, rc = run(s, "test -d /usr/share/doc/%s && echo ok" % p)
        eq("/usr/share/doc/%s exists" % p, (o.strip(), rc), ("ok", 0))
        o2, rc2 = run(s, "test -s /usr/share/doc/%s/copyright && echo ok" % p)
        eq("...with a copyright file (%s)" % p, (o2.strip(), rc2), ("ok", 0))
    o, _ = run(s, "ls /usr/share/doc | wc -l")
    check("every installed package has a doc directory",
          int(o.strip() or 0) >= len(pkgs),
          "%s dirs for %d packages" % (o.strip(), len(pkgs)))


def t_changelog_is_gzip():
    s = sh()
    o, _ = run(s, "file /usr/share/doc/nginx/changelog.Debian.gz")
    check("the changelog is gzip, as its name says",
          "gzip compressed data" in o, o[:70])
    o2, _ = run(s, "head -c 2 /usr/share/doc/nginx/changelog.Debian.gz")
    eq("and starts with the gzip magic", o2[:2], "\x1f\x8b")


def t_uninstalled_package_is_an_error():
    s = sh()
    o, rc = run(s, "dpkg -L definitely-not-installed")
    eq("dpkg -L on an unknown package fails", rc, 1)
    check("with dpkg-query's wording", "is not installed" in o, o[:70])
    o2, rc2 = run(s, "dpkg -S /no/such/file/anywhere")
    eq("dpkg -S on an unowned path fails", rc2, 1)
    check("with the no-path wording", "no path found" in o2, o2[:70])


def t_versions_agree_across_subcommands():
    s = sh()
    for p in ("nginx", "coreutils", "rsyslog", "openssh-server"):
        o1, _ = run(s, "dpkg -l %s | awk 'NR>5{print $3}'" % p)
        o2, _ = run(s, "dpkg-query -W -f='${Version}' %s" % p)
        o3, _ = run(s, "dpkg -s %s | awk '/^Version:/{print $2}'" % p)
        eq("dpkg -l and -W agree on %s" % p, o1.strip(), o2.strip())
        eq("dpkg -l and -s agree on %s" % p, o1.strip(), o3.strip())


def t_selections_match_the_installed_list():
    s = sh()
    o, _ = run(s, "dpkg -l | awk 'NR>5{print $2}' | sort")
    o2, _ = run(s, "dpkg --get-selections | awk '{print $1}' | sort")
    eq("--get-selections matches -l", o2.split(), o.split())


def t_listed_directories_are_directories():
    """A path listed as a directory must not be a file, and vice versa."""
    s = sh()
    for p in ("nginx", "coreutils", "net-tools"):
        for f in listing(s, p):
            # Only the directory entries. "endswith('/' + pkg)" also
            # matched /usr/sbin/nginx, which is the binary.
            if f in ("/usr", "/usr/bin", "/usr/sbin", "/usr/share",
                     "/usr/share/doc", "/usr/share/doc/" + p):
                o, rc = run(s, "test -d %s && echo dir" % f)
                eq("%s is a directory" % f, (o.strip(), rc), ("dir", 0))


TESTS = [t_every_listed_file_exists, t_binaries_are_listed_where_they_live,
         t_search_round_trips_with_listfiles, t_search_agrees_with_command_v,
         t_doc_directory_per_package, t_changelog_is_gzip,
         t_uninstalled_package_is_an_error,
         t_versions_agree_across_subcommands,
         t_selections_match_the_installed_list,
         t_listed_directories_are_directories]


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
