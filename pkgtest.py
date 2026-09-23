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
                   # fdisk moved into its own package; util-linux's deb
                   # does not contain /usr/sbin/fdisk. blkid still does.
                   ("fdisk", "fdisk"), ("blkid", "util-linux"),
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


def t_debian_owns_the_files_debian_ships():
    """Which package owns a file is Debian's answer, not upstream's.

    Two of these were credited to the wrong package, and both are checkable
    against the guest, where the owning packages are installed:

      /usr/bin/pidof     procps here; sysvinit-utils there, beside
                         killall5 and fstab-decode. procps upstream does
                         ship a pidof and Debian does not use it, so the
                         plausible answer is the wrong one.
      /usr/bin/rename    util-linux here -- a package that contains no such
                         path. Debian reserves the bare name for the perl
                         file-rename via alternatives and trixie installs
                         neither, so `ls /usr/bin/rename*` on the guest is
                         rename.ul alone.
    """
    s = sh()
    # pidof: one owner, and the other package must not claim it.
    own = run(s, "dpkg -S /usr/bin/pidof")[0].strip()
    check("pidof is owned by sysvinit-utils",
          own.startswith("sysvinit-utils:"), own)
    check("...and procps does not list it",
          "/usr/bin/pidof" not in run(s, "dpkg -L procps")[0],
          "procps upstream ships one; Debian's package does not")
    check("...while sysvinit-utils does",
          "/usr/bin/pidof" in run(s, "dpkg -L sysvinit-utils")[0])
    check("...and pidof still works",
          run(s, "pidof systemd")[0].strip().isdigit(),
          run(s, "pidof systemd")[0].strip())

    # rename: the util-linux binary is rename.ul, and there is no `rename`.
    check("util-linux ships rename.ul",
          run(s, "dpkg -S /usr/bin/rename.ul")[0].strip().startswith(
              "util-linux:"),
          run(s, "dpkg -S /usr/bin/rename.ul")[0].strip())
    check("there is no bare /usr/bin/rename",
          run(s, "ls /usr/bin/rename* 2>&1")[0].split()
          == ["/usr/bin/rename.ul"],
          run(s, "ls /usr/bin/rename* 2>&1")[0].strip())
    check("...so `rename` is not a command",
          "command not found" in run(s, "rename --version 2>&1")[0],
          run(s, "rename --version 2>&1")[0].strip()[:60])
    check("...and rename.ul is",
          run(s, "rename.ul --version 2>&1")[0].startswith(
              "rename.ul from"),
          run(s, "rename.ul --version 2>&1")[0].strip()[:60])
    # dpkg -S has to disown the path that is gone, not just stop shipping it.
    check("dpkg -S finds no owner for the old path",
          "no path found" in run(s, "dpkg -S /usr/bin/rename 2>&1")[0],
          run(s, "dpkg -S /usr/bin/rename 2>&1")[0].strip()[:70])


def t_a_stock_binary_answers_the_same_either_way():
    """One binary, two spellings, one answer.

    `agetty --version` said "agetty from util-linux 2.41" and
    `/usr/sbin/agetty --version` said "agetty 2.41", because the name form
    reaches the central hook and the path form lands in the
    unimplemented-binary answer, and for util-linux and procps those two
    generators disagree. colcrt and getty had it too; badblocks and mandb
    did not, only because their family's banner happens to be the generic
    "<name> <version>".

    --help had the identical split: `colcrt --help` was 303 bytes by name
    and 48 by path. cat did not diverge only because cat is implemented.
    Both flags are swept here, over every stock binary, rather than the
    one instance that happened to be noticed.

    Pre-existing and general. It surfaced because probesuite reported one
    instance -- "differ by absolute path: getty" -- after getty was added
    to util-linux's file list, which is the second time today a survey
    passed while the thing it surveys was broken.
    """
    s = sh()
    bad = []
    for name in sorted(getattr(s.fs, "stock_bins", ()))[:120]:
        path, _rc = run(s, "command -v %s" % name)
        path = path.strip()
        if not path.startswith("/"):
            continue
        for flag in ("--version", "--help"):
            by_name, _rc = run(s, "%s %s" % (name, flag))
            by_path, _rc = run(s, "%s %s" % (path, flag))
            if by_name == by_path:
                continue
            # ifconfig prints the interface list, whose counters advance
            # between two calls, so it differs for a reason that has
            # nothing to do with how it was spelled.
            if name == "ifconfig":
                continue
            bad.append("%s %s: %r vs %r"
                       % (name, flag, by_name[:34], by_path[:34]))
    check("no stock binary answers --version or --help two ways", not bad,
          "; ".join(bad[:4]))


def t_a_link_names_the_right_program():
    """Which name a program prints is not always the one you typed.

    pstree.x11's banner says "pstree (PSmisc) 23.7" -- the compiled-in
    name -- while its errors say "pstree.x11: unrecognized option", which
    is argv[0]. Both measured on the guest. getty is the other way round:
    it is agetty under another name and its version does use argv[0].
    uncompress is a third answer again -- gunzip is a /bin/sh script
    interpolating $0, so through that name it prints /usr/bin/uncompress.

    Three programs, three conventions. This is why the symlink work is
    still queued rather than done: a link table cannot express any of it.
    """
    s = sh()
    got, _rc = run(s, "pstree.x11 --version")
    eq("pstree.x11's banner names pstree", got.strip(),
       "pstree (PSmisc) 23.7")
    got, _rc = run(s, "pstree.x11 --help")
    check("...but its error names pstree.x11",
          got.startswith("pstree.x11: unrecognized option"), got[:44])
    got, _rc = run(s, "pstree --help")
    check("...and plain pstree errors too, not a tree",
          got.startswith("pstree: unrecognized option"), got[:44])
    got, _rc = run(s, "getty --version")
    # One binary under two names: the name comes from argv[0] and the
    # feature list is compiled in, so it is the same list either way.
    # This asserted the bare banner, which was written before that list
    # was measured on the guest -- so it read as "getty is correct" while
    # the whole family was missing it.
    check("getty names getty, not agetty",
          got.startswith("getty from util-linux ") and "agetty" not in got,
          got[:48])
    check("...and carries agetty's compiled-in feature list",
          "(flow control, hints, issue, issue.d, keyboard mode, plymouth,"
          " reload, syslog, systemd, widechar)" in got, got[:80])
    got, _rc = run(s, "uncompress --help")
    check("uncompress names itself, not gunzip",
          got.startswith("Usage: /usr/bin/uncompress"), got[:48])
    got, _rc = run(s, "gunzip --help")
    check("...and gunzip still names gunzip",
          got.startswith("Usage: /usr/bin/gunzip"), got[:48])


def t_ip_reports_its_own_version():
    """`ip -V` printed the interface list.

    An option iproute2 did not know was ignored and the command fell
    through to its default object. The two versions in the banner come
    from this box's dpkg, not the guest's: the guest runs iproute2 6.15.0
    and this persona runs 6.14.0, so copying its line would contradict our
    own package list.
    """
    s = sh()
    ipv, _rc = run(s, "dpkg-query -W -f='${Version}' iproute2")
    bpf, _rc = run(s, "dpkg-query -W -f='${Version}' libbpf1")
    want = ("ip utility, iproute2-%s, libbpf %s"
            % (ipv.strip().split("-")[0],
               bpf.strip().split(":")[-1].split("-")[0]))
    for spelling in ("-V", "-Version"):
        got, _rc = run(s, "ip %s" % spelling)
        eq("ip %s" % spelling, got.strip(), want)
    # and --version is NOT one of them: iproute2's long options take a
    # single dash, so it reads as -version and iproute2 says so by name.
    # An earlier draft of this test asserted --version gave the banner,
    # which would have invented a spelling the real one rejects.
    got, rc = run(s, "ip --version")
    eq("ip --version names the option it could not read", got.strip(),
       'Option "-version" is unknown, try "ip -help".')
    eq("...and exits 255", rc, 255)
    got, _rc = run(s, "ip -o link show eth0")
    check("...and ip still lists links", "eth0" in got, got[:40])


def t_setterm_is_here_at_all():
    """util-linux ships setterm and this box did not have it.

    Not on disk, not in the package's file list, and
    `dpkg -S /usr/bin/setterm` answered "no path found matching pattern"
    on a box whose dpkg claims the package that owns it. Three readers
    agreeing that a file is absent is not the same as it being absent
    correctly.

    Measured on the guest, including both error paths, which carry the
    "Try 'setterm --help'" second line the rest of util-linux uses.
    """
    s = sh()
    got, _rc = run(s, "command -v setterm")
    eq("setterm is on PATH", got.strip(), "/usr/bin/setterm")
    got, _rc = run(s, "dpkg -S /usr/bin/setterm")
    eq("...and util-linux owns it", got.strip(),
       "util-linux: /usr/bin/setterm")
    got, _rc = run(s, "setterm --version")
    eq("...and it names its family", got.strip(),
       "setterm from util-linux 2.41")
    got, rc = run(s, "setterm")
    eq("no arguments is bad usage", got.splitlines()[:2],
       ["setterm: bad usage",
        "Try 'setterm --help' for more information."])
    eq("...and exits 1", rc, 1)
    got, rc = run(s, "setterm --zzz")
    eq("an option it does not have is refused", got.splitlines()[:2],
       ["setterm: unrecognized option '--zzz'",
        "Try 'setterm --help' for more information."])
    eq("...and exits 1 too", rc, 1)
    # its job is writing escapes at a terminal, and there is none here
    got, rc = run(s, "setterm --blank=5")
    eq("an option it does have produces nothing", got, "")
    eq("...and succeeds", rc, 0)


def t_the_package_symlinks_are_links():
    """Six files Debian ships as symlinks were ELFs here.

    `readlink /usr/bin/pkill` answered "pgrep" on the guest and nothing
    here, because the seeding loop makes a binary for every name a package
    lists and could not express a link.
    """
    s = sh()
    for path, target in (("/usr/bin/pkill", "pgrep"),
                         ("/usr/bin/snice", "skill"),
                         ("/usr/bin/pstree.x11", "pstree"),
                         ("/usr/sbin/ip", "../bin/ip"),
                         ("/usr/sbin/getty", "agetty"),
                         ("/usr/bin/uncompress", "gunzip")):
        got, _rc = run(s, "readlink %s" % path)
        eq("readlink %s" % path, got.strip(), target)
        got, _rc = run(s, "ls -l %s" % path)
        check("ls -l shows the arrow: %s" % path,
              ("%s -> %s" % (path, target)) in got, got[-40:])
    # The target is a real file, not another link -- a link to nothing is
    # the failure this box already swept out of /sys.
    for target in ("/usr/bin/pgrep", "/usr/bin/skill", "/usr/bin/pstree",
                   "/usr/bin/ip", "/usr/sbin/agetty", "/usr/bin/gunzip"):
        got, _rc = run(s, "test -f %s && echo yes" % target)
        eq("target exists: %s" % target, got.strip(), "yes")


def t_a_link_keeps_the_name_it_was_invoked_by():
    """Which name a program prints through a link is per-program.

    The package links keep argv[0]; the alternatives links beside them let
    the target answer. Both measured on the guest, which is why this is a
    table and not a rule.
    """
    s = sh()
    for cmd, want in (
            ("/usr/bin/pkill --version", "pkill from procps-ng"),
            ("/usr/bin/snice --version", "snice from procps-ng"),
            ("/usr/sbin/getty --version", "getty from util-linux"),
            ("/usr/bin/uncompress --help", "Usage: /usr/bin/uncompress"),
            ("/usr/bin/pstree.x11 --version", "pstree (PSmisc)")):
        got, _rc = run(s, cmd)
        check("by path: %s" % cmd, got.startswith(want), got[:52])
    # ...and the bare name gives the same answer, which is the invariant
    # probesuite reports on.
    for name, path in (("pkill", "/usr/bin/pkill"),
                       ("snice", "/usr/bin/snice"),
                       ("uncompress", "/usr/bin/uncompress")):
        a, _ = run(s, "%s --version" % name)
        b, _ = run(s, "%s --version" % path)
        eq("name and path agree: %s" % name, a, b)
    # The alternatives links must still resolve to their target.
    got, _rc = run(s, "/usr/bin/editor --help")
    check("editor is still nano", got.startswith("Usage: nano"), got[:40])
    # gzip's helpers split the two questions inside one program: --version
    # names the *target* and usage names argv[0], because the scripts
    # hardcode the one and interpolate $0 for the other.
    for name, want in (("gzip", "gzip 1.13"),
                       ("gunzip", "gunzip (gzip) 1.13"),
                       ("zcat", "zcat (gzip) 1.13"),
                       ("gzexe", "gzexe (gzip) 1.13"),
                       ("zgrep", "zgrep (gzip) 1.13"),
                       ("uncompress", "gunzip (gzip) 1.13"),
                       ("zegrep", "zgrep (gzip) 1.13"),
                       ("zfgrep", "zgrep (gzip) 1.13")):
        got, _rc = run(s, "%s --version" % name)
        eq("%s --version" % name, got.strip(), want)
    got, _rc = run(s, "uncompress --help")
    check("...but uncompress's usage still names itself",
          got.startswith("Usage: /usr/bin/uncompress"), got[:44])


def t_a_deleted_link_stays_deleted():
    """The seeding loop respects is_unlinked; an earlier attempt built the
    links in a pass of its own that did not, so `rm /usr/sbin/ip` came back
    and a directory an attacker had emptied still held getty and ip."""
    s = sh()
    run(s, "rm -f /usr/bin/pkill")
    got, _rc = run(s, "ls /usr/bin/pkill 2>&1")
    check("rm of a link sticks", "No such file" in got, got[:48])
    got, rc = run(s, "readlink /usr/bin/pkill")
    eq("...and readlink finds nothing", got.strip(), "")


def t_pstree_refuses_the_options_it_does_not_know():
    """It ignored them, so `pstree --zz` drew the tree: silent success for
    a request the program refuses. The error names argv[0]."""
    s = sh()
    got, rc = run(s, "pstree --zz")
    check("pstree rejects --zz",
          "pstree: unrecognized option '--zz'" in got, got[:52])
    eq("...rc 1", rc, 1)
    check("...and prints its usage after it", "Usage: pstree [-acglpsStTuZ]"
          in got, got[:80])
    got, _rc = run(s, "pstree.x11 --zz")
    check("through the link it names the link",
          "pstree.x11: unrecognized option '--zz'" in got, got[:52])
    got, rc = run(s, "pstree --color")
    check("an option that needs a value says so",
          "option '--color' requires an argument" in got, got[:52])
    eq("...rc 1 too", rc, 1)
    got, rc = run(s, "pstree --show-pids")
    eq("a real long option still works", rc, 0)


def t_the_interpreter_has_a_package():
    """`python3 -V` said 3.13.5 while dpkg could not name what provides it.

    python3 and python3-minimal are unversioned metapackages and they were
    all this box had. On a Debian 13 with python3 installed, python3
    Depends on python3.13, which Depends on python3.13-minimal and the two
    libpython3.13 packages -- none of which were here. So `dpkg -S` on the
    interpreter named the wrong package and `dpkg -l | grep python3`
    described a machine no installer builds.
    """
    s = sh()
    for pkg, ver in (("python3", "3.13.5-1"),
                     ("python3-minimal", "3.13.5-1"),
                     ("python3.13", "3.13.5-2+deb13u4"),
                     ("python3.13-minimal", "3.13.5-2+deb13u4"),
                     ("libpython3.13-minimal", "3.13.5-2+deb13u4"),
                     ("libpython3.13-stdlib", "3.13.5-2+deb13u4"),
                     ("libpython3-stdlib", "3.13.5-1")):
        got, _rc = run(s, "dpkg-query -W -f='${Version}' %s" % pkg)
        eq("dpkg knows %s" % pkg, got.strip(), ver)
    # The interpreter carries a security update the metapackage has not,
    # which is why these two versions differ and must keep differing.
    a, _ = run(s, "dpkg-query -W -f='${Version}' python3")
    b, _ = run(s, "dpkg-query -W -f='${Version}' python3.13")
    check("the metapackage and the interpreter are not the same version",
          a.strip() != b.strip(), "%r == %r" % (a, b))


def t_python3_is_a_link_to_the_versioned_interpreter():
    s = sh()
    got, _rc = run(s, "readlink /usr/bin/python3")
    eq("/usr/bin/python3 -> python3.13", got.strip(), "python3.13")
    got, _rc = run(s, "dpkg -S /usr/bin/python3")
    check("the link belongs to python3-minimal",
          got.startswith("python3-minimal:"), got[:44])
    got, _rc = run(s, "dpkg -S /usr/bin/python3.13")
    check("...and the interpreter to python3.13-minimal",
          got.startswith("python3.13-minimal:"), got[:44])
    # python3-minimal ships three helper scripts beside the link.
    got, _rc = run(s, "dpkg -L python3-minimal")
    for f in ("/usr/bin/py3clean", "/usr/bin/py3compile",
              "/usr/bin/py3versions", "/usr/bin/python3"):
        check("python3-minimal ships %s" % f, f in got, got[:60])
    # Both spellings still run, and the link keeps its own name.
    for cmd in ("python3 -V", "/usr/bin/python3 -V", "python3.13 -V"):
        got, _rc = run(s, cmd)
        eq("still runs: %s" % cmd, got.strip(), "Python 3.13.5")
    got, _rc = run(s, "/usr/bin/python3 -c 'print(6*7)'")
    eq("...and executes through the link", got.strip(), "42")


def t_python3_dash_VV_names_the_build():
    """-VV printed nothing. It is the spelling for "which build is this",
    and the build stamp is compiled in."""
    s = sh()
    want = "Python 3.13.5 (main, Jul 15 2026, 20:25:40) [GCC 14.2.0]"
    got, _rc = run(s, "python3 -VV")
    eq("python3 -VV", got.strip(), want)
    got, _rc = run(s, "python3 -V -V")
    eq("...and the repeated spelling agrees", got.strip(), want)
    got, _rc = run(s, "python3 -V")
    eq("one -V is still the short form", got.strip(), "Python 3.13.5")
    check("...and the short form is a prefix of the long one",
          want.startswith(got.strip()), got[:40])


TESTS = [t_debian_owns_the_files_debian_ships,
         t_setterm_is_here_at_all,
         t_a_stock_binary_answers_the_same_either_way,
         t_a_link_names_the_right_program,
         t_ip_reports_its_own_version,
         t_every_listed_file_exists, t_binaries_are_listed_where_they_live,
         t_search_round_trips_with_listfiles, t_search_agrees_with_command_v,
         t_doc_directory_per_package, t_changelog_is_gzip,
         t_uninstalled_package_is_an_error,
         t_versions_agree_across_subcommands,
         t_selections_match_the_installed_list,
         t_listed_directories_are_directories,
         t_the_package_symlinks_are_links,
         t_a_link_keeps_the_name_it_was_invoked_by,
         t_a_deleted_link_stays_deleted,
         t_pstree_refuses_the_options_it_does_not_know,
         t_the_interpreter_has_a_package,
         t_python3_is_a_link_to_the_versioned_interpreter,
         t_python3_dash_VV_names_the_build]


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
