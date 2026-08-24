#!/usr/bin/env python3
"""Which directory is this binary in, and does everything agree?

wheretest.py asks whether the five ways of locating a program agree with each
other. This asks the different question of whether they agree with Debian,
which only `dpkg -S` on the guest can answer. Twelve did not.

The placement rule, Shell._SBIN, is a single source feeding both the
filesystem and the package .list files -- good design, wrong contents. Nine
binaries were in /usr/bin here and are in /usr/sbin on the guest: bridge, tc,
sysctl, ldconfig, modinfo, killall5, fstab-decode, nologin and
update-ca-certificates. deb-systemd-helper was the other way round. An init
script calling /usr/sbin/sysctl or /usr/sbin/ldconfig by absolute path --
which is how init scripts call them -- got "No such file or directory" on a
box whose dpkg said the package was installed. 203.0.113.30 called
/usr/bin/nproc by absolute path here at 08:49 today, so this is not
hypothetical.

Then three layers disagreeing about `ss`. A second hand-written list put
/usr/sbin/{ip,ss,iptables,sshd,useradd,service} on disk regardless of the
rule, so the filesystem held /usr/sbin/ss *and* /usr/bin/ss; the package
.list, written from the rule, held only /usr/bin/ss; and `dpkg -L`, which
probes the disk sbin-first rather than reading the list it wrote, reported
/usr/sbin/ss. Three answers to one question, and the guest has no
/usr/sbin/ss at all. That list derives from the rule now, and -L consults
the rule before searching.

kmod and iproute2 ship lsmod and ip in *both* directories, which a
single-location rule cannot express, so there is a second set for those.
`dpkg -S ip` prints both paths on the guest and printed one here.

And `dpkg -S` answered with the wrong path outright: asked about
/usr/bin/lsmod it replied "kmod: /usr/sbin/lsmod", resolving by basename
instead of answering about the file it was given. A spelled-out path that
exists is now answered with itself.

Reference values are `dpkg -S` on the guest. Also checks root's PATH order,
because that decides which of two copies `command -v` finds: the guest's
root PATH is /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,
so /usr/sbin wins for ip and /usr/bin is the only option for ss.

Run from ~/opsec/honeypot:  python3 -W ignore bindirtest.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

# Measured with `dpkg -S` on the guest. name -> the directories it is in.
GUEST = {
    "bridge": ["/usr/sbin"],
    "deb-systemd-helper": ["/usr/bin"],
    "fstab-decode": ["/usr/sbin"],
    "killall5": ["/usr/sbin"],
    "ldconfig": ["/usr/sbin"],
    "modinfo": ["/usr/sbin"],
    "nologin": ["/usr/sbin"],
    "ss": ["/usr/bin"],
    "sysctl": ["/usr/sbin"],
    "tc": ["/usr/sbin"],
    "update-ca-certificates": ["/usr/sbin"],
    "ip": ["/usr/bin", "/usr/sbin"],
    "lsmod": ["/usr/bin", "/usr/sbin"],
    # a spread of names that were already right, so a fix cannot silently
    # move them
    "nproc": ["/usr/bin"],
    "lscpu": ["/usr/bin"],
    "ps": ["/usr/bin"],
    "top": ["/usr/bin"],
    "uptime": ["/usr/bin"],
    "lspci": ["/usr/bin"],
    "pgrep": ["/usr/bin"],
    "ifconfig": ["/usr/sbin"],
    "iptables": ["/usr/sbin"],
    "sshd": ["/usr/sbin"],
    "useradd": ["/usr/sbin"],
    "fdisk": ["/usr/sbin"],
    "blkid": ["/usr/sbin"],
    "logrotate": ["/usr/sbin"],
    "modprobe": ["/usr/sbin"],
    "depmod": ["/usr/sbin"],
    "insmod": ["/usr/sbin"],
}

# What `command -v` must return under root's PATH on the guest.
COMMAND_V = {
    "ip": "/usr/sbin/ip",
    "ss": "/usr/bin/ss",
    "sysctl": "/usr/sbin/sysctl",
    "lsmod": "/usr/sbin/lsmod",
    "nproc": "/usr/bin/nproc",
    "ldconfig": "/usr/sbin/ldconfig",
    "tc": "/usr/sbin/tc",
    "bridge": "/usr/sbin/bridge",
    "deb-systemd-helper": "/usr/bin/deb-systemd-helper",
    "update-ca-certificates": "/usr/sbin/update-ca-certificates",
}

OWNER = {"ip": "iproute2", "ss": "iproute2", "bridge": "iproute2",
         "tc": "iproute2", "lsmod": "kmod", "modinfo": "kmod",
         "sysctl": "procps", "ldconfig": "libc-bin",
         "nologin": "login", "killall5": "sysvinit-utils",
         "fstab-decode": "sysvinit-utils",
         "update-ca-certificates": "ca-certificates",
         "deb-systemd-helper": "init-system-helpers"}


def main():
    verbose = "-v" in sys.argv
    ok = bad = 0
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True

    def check(label, got, want):
        nonlocal ok, bad
        if got == want:
            ok += 1
            if verbose:
                print("  ok    %s" % label)
        else:
            bad += 1
            print("  FAIL  %s" % label)
            print("        got  %r" % (got,))
            print("        want %r" % (want,))

    # ---- the file is where Debian puts it, and nowhere else --------------
    for name, dirs in sorted(GUEST.items()):
        got = [d for d in ("/usr/bin", "/usr/sbin")
               if sh.run("test -e %s/%s && echo y" % (d, name)).strip() == "y"]
        check("%s is in %s" % (name, ",".join(dirs)), got, dirs)

    # ---- and the placement rule says the same thing ----------------------
    for name, dirs in sorted(GUEST.items()):
        want = "/usr/sbin" in dirs
        both = dirs == ["/usr/bin", "/usr/sbin"]
        _both_set = getattr(fs.Shell, "_BIN_AND_SBIN", frozenset())
        check("_SBIN agrees about %s" % name,
              (name in fs.Shell._SBIN or name in _both_set), want)
        check("_BIN_AND_SBIN agrees about %s" % name,
              name in _both_set, both)

    # ---- command -v resolves the way root's PATH resolves ---------------
    check("root's PATH matches the guest",
          sh.run("echo $PATH").strip(),
          "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    for name, path in sorted(COMMAND_V.items()):
        check("command -v %s" % name,
              sh.run("command -v %s" % name).strip(), path)
        check("which %s agrees" % name,
              sh.run("which %s" % name).strip(), path)
        check("type -p %s agrees" % name,
              sh.run("type -p %s" % name).strip(), path)

    # ---- dpkg answers about the file it was asked about ------------------
    for name, dirs in sorted(OWNER.items()):
        for d in dirs and GUEST[name]:
            check("dpkg -S %s/%s names itself" % (d, name),
                  sh.run("dpkg -S %s/%s" % (d, name)).strip(),
                  "%s: %s/%s" % (OWNER[name], d, name))
    check("dpkg -S on a both-directories name prints both",
          sorted(x.split(": ")[1]
                 for x in sh.run("dpkg -S ip").strip().splitlines()),
          ["/usr/bin/ip", "/usr/sbin/ip"])
    check("dpkg -S lsmod prints both too",
          sorted(x.split(": ")[1]
                 for x in sh.run("dpkg -S lsmod").strip().splitlines()),
          ["/usr/bin/lsmod", "/usr/sbin/lsmod"])
    check("dpkg -S on a path that does not exist still refuses",
          sh.run("dpkg -S /no/such/file 2>&1").strip(),
          "dpkg-query: no path found matching pattern /no/such/file")

    # ---- dpkg -L agrees with the .list it wrote and with the disk --------
    for pkg in ("iproute2", "kmod", "procps", "libc-bin", "sysvinit-utils"):
        listed = [x for x in sh.run("dpkg -L %s" % pkg).split()
                  if "/bin/" in x or "/sbin/" in x]
        missing = [p for p in listed
                   if sh.run("test -e %s && echo y" % p).strip() != "y"]
        check("every binary dpkg -L %s lists is on disk" % pkg, missing, [])
        onfile = [x for x in
                  sh.run("cat /var/lib/dpkg/info/%s.list" % pkg).split()
                  if "/bin/" in x or "/sbin/" in x]
        check("dpkg -L %s matches the .list file" % pkg,
              sorted(listed), sorted(onfile))

    print("\nbindirtest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
