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

## and whether it is a file at all

The sibling question, asked 2026-09-18: not *which directory*, but *file or
link, and to what*. Both bin directories were listed on the guest and here
and the whole of the 380 paths they share compared. Thirty disagreed, every
one of them a symlink there and a regular ELF here, and none of the
eighteen links already modelled had a wrong target.

It is not cosmetic, because the paths include the ones an attacker
rewrites. `/usr/bin/last` is a link to `wtmpdb` on trixie, so
203.0.113.82's `tee /usr/bin/last` on 2026-09-17 would have landed on
/usr/bin/wtmpdb: the link stays a 6-byte link, `dpkg -V wtmpdb` names
wtmpdb, and `last` runs the replacement. Here the write replaced the link
itself, dpkg -V named last, and -- worse -- the box went on answering as
the real `last`, because the replaced-binary check looked at the link node,
which has no content of its own. The kmod family is six names for one
binary that did not exist here at all, and `ls -l /usr/sbin/init` is how
you ask which init system this is.

Twenty-two are fixed; eight remain and are checked as known-absent below,
because they go through /etc/alternatives and need the alternatives
entries, the second hop and `update-alternatives --display` to agree
before the link is worth anything.

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

    # ---- a symlink is not a file -----------------------------------------
    # (path, one-hop target, what readlink -f resolves to), every row from
    # readlink and readlink -f on the guest.
    links = [
        ("/usr/bin/last", "wtmpdb", "/usr/bin/wtmpdb"),
        ("/usr/bin/lsmod", "kmod", "/usr/bin/kmod"),
        ("/usr/sbin/depmod", "../bin/kmod", "/usr/bin/kmod"),
        ("/usr/sbin/insmod", "../bin/kmod", "/usr/bin/kmod"),
        ("/usr/sbin/lsmod", "../bin/kmod", "/usr/bin/kmod"),
        ("/usr/sbin/modinfo", "../bin/kmod", "/usr/bin/kmod"),
        ("/usr/sbin/modprobe", "../bin/kmod", "/usr/bin/kmod"),
        ("/usr/sbin/rmmod", "../bin/kmod", "/usr/bin/kmod"),
        ("/usr/bin/dnsdomainname", "hostname", "/usr/bin/hostname"),
        ("/usr/bin/domainname", "hostname", "/usr/bin/hostname"),
        ("/usr/bin/nisdomainname", "hostname", "/usr/bin/hostname"),
        ("/usr/bin/ypdomainname", "hostname", "/usr/bin/hostname"),
        ("/usr/bin/pidof", "../sbin/killall5", "/usr/sbin/killall5"),
        ("/usr/bin/apropos", "whatis", "/usr/bin/whatis"),
        ("/usr/bin/ping6", "ping", "/usr/bin/ping"),
        ("/usr/bin/reset", "tset", "/usr/bin/tset"),
        ("/usr/bin/sg", "newgrp", "/usr/bin/newgrp"),
        ("/usr/bin/sudoedit", "sudo", "/usr/bin/sudo"),
        ("/usr/bin/unxz", "xz", "/usr/bin/xz"),
        ("/usr/bin/xzcat", "xz", "/usr/bin/xz"),
        ("/usr/sbin/addgroup", "adduser", "/usr/sbin/adduser"),
        ("/usr/sbin/delgroup", "deluser", "/usr/sbin/deluser"),
        ("/usr/sbin/init", "../lib/systemd/systemd",
         "/usr/lib/systemd/systemd"),
    ]
    for path, target, final in links:
        line = sh.run("ls -l %s" % path).strip()
        check("%s is a symlink" % path, line[:1], "l")
        check("...to %s" % target, sh.run("readlink %s" % path).strip(),
              target)
        check("...resolving to %s" % final,
              sh.run("readlink -f %s" % path).strip(), final)
        # A symlink's size is the length of its target, which is how
        # `ls -l` and `stat -c %s` agree about one on a real box.
        check("...with the target's length as its size: %s" % path,
              sh.run("stat -c %%s %s" % path).strip(), str(len(target)))
        check("...and the target exists: %s" % final,
              sh.run("test -e %s && echo y" % final).strip(), "y")

    # The eight still to do, so the count is stated rather than implied.
    # Each needs /etc/alternatives to carry the name first.
    for path in ("/usr/bin/which", "/usr/sbin/iptables",
                 "/usr/sbin/iptables-save", "/usr/sbin/iptables-restore",
                 "/usr/sbin/ip6tables", "/usr/sbin/ip6tables-save",
                 "/usr/sbin/ip6tables-restore", "/usr/bin/py3versions"):
        check("known gap, alternatives not modelled: %s" % path,
              sh.run("readlink %s" % path).strip(), "")

    # ---- init is systemd under another name ------------------------------
    # Measured with systemd-sysv installed: systemd reads argv[0], so the
    # link answers as init and not as systemd. Adding the symlink without
    # this made the bare name follow it to a target called systemd, which
    # has no handler, so `init` said "command not found".
    check("init is systemd-sysv's file, not sysvinit-utils'",
          sh.run("dpkg -S /usr/sbin/init").strip(),
          "systemd-sysv: /usr/sbin/init")
    check("init with no argument says what telinit says",
          sh.run("init 2>&1").strip(), "init: required argument missing.")
    check("...and refuses --version by argv[0] rather than inventing one",
          sh.run("init --version 2>&1").strip(),
          "init: unrecognized option '--version'")
    check("...while --help is telinit's help",
          sh.run("init --help").strip().split("\n")[0],
          "init [OPTIONS...] COMMAND")
    check("...naming the man page at the end",
          sh.run("init --help").strip().split("\n")[-1],
          "See the telinit(8) man page for details.")
    check("the name and the absolute path agree",
          sh.run("/usr/sbin/init 2>&1").strip(),
          sh.run("init 2>&1").strip())

    # ---- kmod is one binary with seven names -----------------------------
    check("the kmod binary itself exists",
          sh.run("test -f /usr/bin/kmod && echo y").strip(), "y")
    check("...and dpkg owns it",
          sh.run("dpkg -S /usr/bin/kmod").strip(), "kmod: /usr/bin/kmod")
    check("...at the version trixie ships",
          sh.run("dpkg-query -W -f '${Version}' kmod").strip(), "34.2-2")
    check("...and dpkg -L lists all eight paths",
          sorted(x for x in sh.run("dpkg -L kmod").split()
                 if "/bin/" in x or "/sbin/" in x),
          ["/usr/bin/kmod", "/usr/bin/lsmod", "/usr/sbin/depmod",
           "/usr/sbin/insmod", "/usr/sbin/lsmod", "/usr/sbin/modinfo",
           "/usr/sbin/modprobe", "/usr/sbin/rmmod"])

    # ---- and writing to a link writes to the file ------------------------
    # Measured in a debian:trixie container with wtmpdb installed: the
    # link keeps its mode and target, wtmpdb's bytes change, dpkg -V names
    # wtmpdb, and `last` runs what was written.
    w = fs.Shell(fs.VFS())
    w.exec_mode = True
    w.run("printf '#!/bin/sh\\necho replaced\\n' > /usr/bin/last")
    check("a write through the link leaves the link alone",
          w.run("ls -l /usr/bin/last").strip()[:1], "l")
    check("...and lands on the target",
          w.run("cat /usr/bin/wtmpdb").strip(), "#!/bin/sh\necho replaced")
    check("...so dpkg -V names the file whose bytes changed",
          w.run("dpkg -V wtmpdb").strip(), "??5??????   /usr/bin/wtmpdb")
    check("...and the name runs what the attacker put there",
          w.run("last").strip(), "replaced")
    # rm takes the link, not the target: unlink does not follow.
    w.run("rm -f /usr/bin/last")
    check("rm removes the link and not its target",
          [w.run("test -e /usr/bin/last && echo y").strip(),
           w.run("test -f /usr/bin/wtmpdb && echo y").strip()], ["", "y"])
    # chattr +i on the target refuses a write through the link, because the
    # kernel checks the inode it is about to write.
    w2 = fs.Shell(fs.VFS())
    w2.exec_mode = True
    w2.run("chattr +i /usr/bin/wtmpdb")
    w2.run("printf x > /usr/bin/last")
    check("an immutable target refuses a write through the link",
          w2.run("stat -c %s /usr/bin/wtmpdb").strip(), "166955")

    print("\nbindirtest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
