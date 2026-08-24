#!/usr/bin/env python3
"""The name-service databases, and the three things that read them.

The axis: "what port is this service on" has three answers on a Linux
box -- the file, getent, and dpkg's claim about who put the file there.
All three disagreed.

    /etc/services      5 lines, against 365 on a real trixie
    getent services ssh    silent, on a box whose ss reports a listener
                           on 22 and whose /etc/services says ssh 22/tcp
    dpkg -S /etc/services  "no path found matching", for a file the box
                           was perfectly happy to cat

/etc/protocols had four lines against 68, and /etc/rpc and
/etc/ethertypes did not exist at all, on a box where `dpkg -l netbase`
denied the package that owns all four was installed.

`grep 3306 /etc/services` and `getent services mysql` are things people
type on a box they have just taken, to find out what it runs. Both
answered wrongly, and `wc -l /etc/services` answering 5 is a one-glance
tell.

Reference data and layout measured on the guest (Debian 13, netbase 6.5).
"""
import sys
import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.90")
    s.exec_mode = True
    return v, s


def main():
    v, s = sh()

    # -- the files are the real ones ----------------------------------------
    for path, lines in (("/etc/services", 365), ("/etc/protocols", 68),
                        ("/etc/rpc", 41), ("/etc/networks", 4),
                        ("/etc/ethertypes", 48)):
        check("%s has %d lines" % (path, lines),
              s.run("wc -l < %s" % path).strip(), str(lines))

    # -- getent answers from them -------------------------------------------
    # Layout measured with cat -A: the name is padded to 22 for services,
    # protocols and networks, and to 16 with the number padded to 8 for rpc.
    for query, want in (
            ("services ssh", "ssh                   22/tcp\n"),
            ("services http", "http                  80/tcp www\n"),
            ("services mysql", "mysql                 3306/tcp\n"),
            ("protocols tcp", "tcp                   6 TCP\n"),
            ("protocols ipv6-icmp", "ipv6-icmp             58 IPv6-ICMP\n"),
            ("rpc portmapper",
             "portmapper      100000  portmap sunrpc rpcbind\n")):
        check("getent %s" % query, s.run("getent %s" % query), want)
    check("getent networks lists all three",
          s.run("getent networks"),
          "default               0.0.0.0\n"
          "loopback              127.0.0.0\n"
          "link-local            169.254.0.0\n")

    # A number or a port/proto pair is a key too -- that is how you go the
    # other way, from a port you found in ss to the name for it.
    check("getent services 22/tcp", s.run("getent services 22/tcp"),
          "ssh                   22/tcp\n")
    check("getent protocols 6", s.run("getent protocols 6"),
          "tcp                   6 TCP\n")
    check("an alias resolves too",
          s.run("getent services www"), "http                  80/tcp www\n")

    # Enumeration returns the whole database, comments and blanks dropped.
    check("getent services enumerates 322 entries",
          s.run("getent services | wc -l").strip(), "322")
    check("no comment line survives",
          "#" in s.run("getent services"), False)

    # -- and the file agrees, because it is the same file --------------------
    # Two, not one: the real file has mysql and mysql-proxy. Checked
    # against the guest rather than assumed -- the first draft of this
    # expected 1 and the box was right.
    check("grep finds both mysql entries in the file",
          s.run("grep -c '^mysql' /etc/services").strip(), "2")
    check("the file and getent say the same thing",
          s.run("getent services mysql").split()[1],
          s.run("grep '^mysql\\b' /etc/services").split()[1])
    check("a service the box does not run is still listed",
          s.run("getent services postgresql").split()[1], "5432/tcp")
    # The listener ss reports has a name in the database.
    port = [l for l in s.run("ss -tlnp").splitlines() if ":3306" in l]
    check("ss reports mysql's port", bool(port), True)
    check("...and getent names it",
          s.run("getent services 3306/tcp").split()[0], "mysql")

    # -- exit codes ----------------------------------------------------------
    s._err = []
    out, rc = s.dispatch("getent", ["services", "nosuchsvc"], "")
    check("a missing key is rc 2", (out, rc), ("", 2))
    s._err = []
    out, rc = s.dispatch("getent", ["nosuchdb", "foo"], "")
    check("an unknown database is rc 1", rc, 1)
    check("...and names it",
          "Unknown database: nosuchdb" in "".join(s._err), True)
    s._err = []
    _o, rc = s.dispatch("getent", ["ethers"], "")
    check("ethers cannot be enumerated", rc, 1)
    check("...and says which database",
          "Enumeration not supported on ethers" in "".join(s._err), True)

    # -- dpkg owns them ------------------------------------------------------
    for path in ("/etc/services", "/etc/protocols", "/etc/rpc",
                 "/etc/ethertypes"):
        check("dpkg -S %s" % path, s.run("dpkg -S %s" % path),
              "netbase: %s\n" % path)
    check("netbase is installed",
          s.run("dpkg -l netbase | tail -1").split()[:3],
          ["ii", "netbase", "6.5"])
    check("with its real description",
          s.run("dpkg -l netbase").splitlines()[-1].split("all")[-1].strip(),
          "Basic TCP/IP networking system")
    check("dpkg -L lists the files that exist",
          all(s.run("test -f %s && echo y" % p).strip() == "y"
              for p in s.run("dpkg -L netbase").split()
              if p.startswith("/etc/")), True)
    # Other packages' config files resolve too -- the lookup used to know
    # about two packages only.
    check("dpkg -S /etc/security/limits.conf",
          s.run("dpkg -S /etc/security/limits.conf").strip(),
          "libpam-modules: /etc/security/limits.conf")
    check("dpkg -S /etc/default/cron",
          s.run("dpkg -S /etc/default/cron").strip(),
          "cron: /etc/default/cron")

    # -- dpkg -l's columns ---------------------------------------------------
    # Measured on the guest: Name is at least 14 wide and Version at least
    # 12, so one package prints the same shape as a hundred.
    check("dpkg -l bash lines up like the guest's",
          s.run("dpkg -l bash").splitlines()[-1],
          "ii  bash           5.2.37-2+b9  amd64        GNU Bourne Again SHell")
    check("a long name widens the column, not the rule",
          s.run("dpkg -l ca-certificates").splitlines()[-2],
          "+++-===============-============-============-"
          + "=" * 33)
    check("and the rule is 33 wide either way",
          s.run("dpkg -l netbase").splitlines()[-2],
          "+++-==============-============-============-" + "=" * 33)

    # -- changelogs ----------------------------------------------------------
    # Every package has changelog.gz; only one with a Debian revision --
    # a hyphen in its version -- also has changelog.Debian.gz, because a
    # native package's changelog *is* the Debian one. We shipped the
    # .Debian name for all 101 packages and the plain name for none, so
    # `ls /usr/share/doc/netbase` was wrong in both directions. Measured
    # on the guest across four native and four non-native packages.
    for pkg, native in (("netbase", True), ("base-files", True),
                        ("adduser", True), ("apt", True),
                        ("bash", False), ("coreutils", False),
                        ("sudo", False)):
        want = ["changelog.gz", "copyright"] if native else [
            "changelog.Debian.gz", "changelog.gz", "copyright"]
        check("/usr/share/doc/%s" % pkg,
              sorted(s.run("ls /usr/share/doc/%s" % pkg).split()), want)
    check("dpkg -L names the changelog that exists",
          "/usr/share/doc/netbase/changelog.gz"
          in s.run("dpkg -L netbase").split(), True)
    check("...and not the one that does not",
          "/usr/share/doc/netbase/changelog.Debian.gz"
          in s.run("dpkg -L netbase").split(), False)

    # -- /etc/hosts ----------------------------------------------------------
    # The real file puts localhost on the ::1 line as well, which is why
    # `getent hosts localhost` answers with the IPv6 address first.
    hosts = s.run("cat /etc/hosts")
    check("cloud-init's header is there",
          "manage_etc_hosts" in hosts, True)
    check("::1 is called localhost too",
          "::1 localhost ip6-localhost ip6-loopback" in hosts, True)
    check("the multicast lines are there",
          ("ff02::1 ip6-allnodes" in hosts
           and "ff02::2 ip6-allrouters" in hosts), True)
    # A name in the file is answered from the file: every name on that
    # line, the address padded to 15, and the v6 line winning when a name
    # is on both. Measured on the guest, where `getent hosts localhost`
    # answers ::1 even though 127.0.0.1 localhost appears first.
    check("localhost resolves to the ::1 line",
          s.run("getent hosts localhost"),
          "::1             localhost ip6-localhost ip6-loopback\n")
    check("the box's own name resolves",
          s.run("getent hosts web01.example.net"),
          "127.0.1.1       web01.example.net web01\n")
    check("a v6-only name resolves",
          s.run("getent hosts ip6-allnodes"),
          "ff02::1         ip6-allnodes\n")
    check("an alias on the line is a key too",
          s.run("getent hosts ip6-loopback").split()[0], "::1")
    check("a name that is in no line is rc 2",
          s.dispatch("getent", ["hosts", "no.such.host.invalid"], "")[1], 2)

    # -- the databases that are not files ------------------------------------
    check("passwd still works", s.run("getent passwd root").strip(),
          "root:x:0:0:root:/root:/bin/bash")
    check("group still works",
          s.run("getent group sudo").startswith("sudo:x:27:"), True)
    check("shadow still works",
          s.run("getent shadow root").startswith("root:$y$"), True)

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("nsstest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
