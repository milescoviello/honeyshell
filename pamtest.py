#!/usr/bin/env python3
"""Does the box agree with itself that it authenticates anybody?

web01 runs sshd, and ships su, sudo and passwd setuid root. Every one of
those is a PAM service: they will not authenticate without a stack in
/etc/pam.d, and the modules they name read /etc/security. Three views of
the box said PAM was there -- a running sshd, the setuid bits, and the
packages that depend on it -- and two said it was not:

  - /etc/pam.d existed and was empty. `cat /etc/pam.d/sshd` returned
    nothing on a box whose sshd was answering on port 22.
  - /etc/security existed and was empty, so /etc/security/limits.conf --
    a libpam-modules conffile present on every Debian install -- was
    absent.
  - dpkg denied all of it: no libpam0g, no libpam-modules, no
    libpam-runtime, and `dpkg -S /etc/security/limits.conf` found no
    owner.

Privilege-escalation enumeration reads these files directly: nullok in
common-auth, pam_wheel on su, and limits.conf for the resource ceilings.
An empty /etc/pam.d is both a contradiction and a missing answer.

Separately, ping is not setuid here and carries no file capability. On a
real trixie that is correct -- unprivileged ICMP is allowed by the
ping_group_range sysctl -- but that sysctl did not exist, so nothing on
the box explained how a non-root user could ping.

Contents are verbatim from debian:trixie-slim with openssh-server and
sudo installed, so these are checked against dpkg's own conffiles rather
than against this implementation.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                        # noqa: E402

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
        print("  FAIL %-54s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# Debian's own file list, read off a trixie with openssh-server and sudo.
# `cron` is here too: this box claims cron 3.0pl1-198 installed, and cron
# authenticates through PAM, so its stack belongs. The reference container
# this list came from did not have cron, which is how the one service whose
# package we claim ended up as the one service with no stack -- caught by
# reading RedTail's clean.sh, which walks the cron directories by name.
PAMD_EXPECTED = sorted([
    "chfn", "chpasswd", "chsh", "common-account", "common-auth",
    "common-password", "common-session", "common-session-noninteractive",
    "cron", "login", "newusers", "other", "passwd", "runuser", "runuser-l",
    "sshd", "su", "su-l", "sudo", "sudo-i"])

SECURITY_EXPECTED = sorted([
    "access.conf", "faillock.conf", "group.conf", "limits.conf",
    "limits.d", "namespace.conf", "namespace.d", "namespace.init",
    "opasswd", "pam_env.conf", "pwhistory.conf", "sepermit.conf",
    "time.conf"])


def t_the_pam_directory_is_not_empty():
    """The contradiction this sweep started from: sshd was running and
    /etc/pam.d had nothing in it."""
    s = sh()
    o, rc = run(s, "ls /etc/pam.d")
    eq("ls /etc/pam.d succeeds", rc, 0)
    eq("and lists what trixie ships", sorted(o.split()), PAMD_EXPECTED)


def t_etc_security_is_not_empty():
    s = sh()
    o, rc = run(s, "ls /etc/security")
    eq("ls /etc/security succeeds", rc, 0)
    eq("and lists what libpam-modules ships", sorted(o.split()),
       SECURITY_EXPECTED)


def t_every_pam_file_has_content():
    """An empty file is the same failure as a missing one to anything that
    greps it."""
    s = sh()
    for n in PAMD_EXPECTED:
        o, rc = run(s, "wc -c < /etc/pam.d/%s" % n)
        eq("/etc/pam.d/%s readable" % n, rc, 0)
        check("/etc/pam.d/%s is not empty" % n,
              o.strip().isdigit() and int(o.strip()) > 0, o[:40])


def t_a_service_that_authenticates_has_a_stack():
    """Each of these binaries is on the box and cannot work without its
    stack, so the stack has to name the module that does the work."""
    s = sh()
    for svc, needle in (("sshd", "@include common-auth"),
                        ("su", "pam_rootok.so"),
                        ("sudo", "@include common-auth"),
                        ("login", "@include common-auth"),
                        ("passwd", "@include common-password")):
        o, rc = run(s, "cat /etc/pam.d/%s" % svc)
        eq("cat /etc/pam.d/%s" % svc, rc, 0)
        check("%s stack names %s" % (svc, needle), needle in o, o[:70])


def t_the_common_stack_is_what_privesc_scripts_read():
    s = sh()
    o, _ = run(s, "grep -c nullok /etc/pam.d/common-auth")
    eq("common-auth mentions nullok once", o.strip(), "1")
    o, _ = run(s, "grep pam_unix.so /etc/pam.d/common-account")
    check("common-account uses pam_unix", "pam_unix.so" in o, o[:60])
    o, _ = run(s, "grep -o yescrypt /etc/pam.d/common-password | head -1")
    eq("common-password hashes with yescrypt", o.strip(), "yescrypt")


def t_limits_conf_is_the_real_conffile():
    s = sh()
    o, rc = run(s, "cat /etc/security/limits.conf")
    eq("limits.conf readable", rc, 0)
    check("and is the shipped one", "#<domain>" in o and "nofile" in o,
          o[:70])
    o, _ = run(s, "ls -l /etc/security/opasswd")
    check("opasswd is root-only", o.startswith("-rw-------"), o[:40])
    o, _ = run(s, "test -x /etc/security/namespace.init && echo yes")
    eq("namespace.init is executable", o.strip(), "yes")


def t_dpkg_admits_pam_is_installed():
    s = sh()
    for pkg in ("libpam0g", "libpam-modules", "libpam-modules-bin",
                "libpam-runtime", "libpam-systemd"):
        o, rc = run(s, "dpkg -l %s" % pkg)
        eq("dpkg -l %s rc" % pkg, rc, 0)
        check("dpkg lists %s as installed" % pkg,
              ("ii" in o and pkg in o), o[-70:])


def t_dpkg_owns_the_files_it_shipped():
    s = sh()
    for name, pkg in (("sshd", "openssh-server"), ("su", "util-linux"),
                      ("sudo", "sudo"), ("login", "login"),
                      ("passwd", "passwd"), ("other", "libpam-runtime")):
        path = "/etc/pam.d/" + name
        o, rc = run(s, "dpkg -S %s" % path)
        eq("dpkg -S %s rc" % path, rc, 0)
        eq("dpkg -S %s" % path, o.strip(), "%s: %s" % (pkg, path))
    o, rc = run(s, "dpkg -S /etc/security/limits.conf")
    eq("limits.conf belongs to libpam-modules", o.strip(),
       "libpam-modules: /etc/security/limits.conf")


def t_the_generated_stack_has_no_owner():
    """pam-auth-update writes common-* at configure time, so real dpkg finds
    no package for them. Claiming one would be a fresh lie in place of the
    old one."""
    s = sh()
    for n in ("common-auth", "common-account", "common-password",
              "common-session"):
        o, rc = run(s, "dpkg -S /etc/pam.d/%s" % n)
        eq("dpkg -S %s is unowned" % n, rc, 1)
        check("and says so the way dpkg does", "no path found" in o, o[:70])


def t_a_full_path_answers_about_itself():
    """/etc/pam.d/sshd and /usr/sbin/sshd share a basename. Matching on the
    basename first made `dpkg -S /usr/sbin/sshd` name the right package
    against the wrong file -- a wrong answer delivered with rc 0."""
    s = sh()
    for path, pkg in (("/usr/sbin/sshd", "openssh-server"),
                      ("/etc/pam.d/sshd", "openssh-server"),
                      ("/usr/bin/su", "util-linux"),
                      ("/etc/pam.d/su", "util-linux"),
                      ("/usr/bin/passwd", "passwd"),
                      ("/etc/pam.d/passwd", "passwd")):
        o, rc = run(s, "dpkg -S %s" % path)
        eq("dpkg -S %s names itself" % path, o.strip(),
           "%s: %s" % (pkg, path))
        eq("dpkg -S %s rc" % path, rc, 0)


def t_dpkg_L_lists_files_that_are_there():
    """The failure pkgtest found for other packages, checked for these."""
    s = sh()
    for pkg in ("libpam-modules", "libpam-runtime"):
        o, rc = run(s, "dpkg -L %s" % pkg)
        eq("dpkg -L %s rc" % pkg, rc, 0)
        for line in o.split():
            if not line.startswith("/etc/"):
                continue
            o2, rc2 = run(s, "test -e %s && echo yes" % line)
            eq("%s: %s exists" % (pkg, line), (o2.strip(), rc2), ("yes", 0))


def t_ping_can_explain_itself():
    """ping is not setuid and has no capability. That is right for trixie,
    but only because unprivileged ICMP is open -- and the sysctl saying so
    was missing, leaving no account of how a non-root user pings."""
    s = sh()
    o, _ = run(s, "ls -l /usr/bin/ping")
    check("ping is not setuid", o.startswith("-rwxr-xr-x"), o[:40])
    o, rc = run(s, "sysctl net.ipv4.ping_group_range")
    eq("the sysctl exists", rc, 0)
    eq("and opens ICMP to every group", o.split("=")[-1].split(),
       ["0", "2147483647"])
    o2, _ = run(s, "cat /proc/sys/net/ipv4/ping_group_range")
    eq("proc and sysctl agree", o2.split(), ["0", "2147483647"])


def t_the_setuid_set_is_debians():
    """What `find / -perm -4000` returns is the first thing a privesc script
    collects, so the set has to be the one trixie actually ships."""
    s = sh()
    o, rc = run(s, "find /usr/bin /usr/sbin /bin -perm -4000 2>/dev/null")
    eq("the find succeeds", rc, 0)
    got = sorted(os.path.basename(x) for x in o.split())
    eq("setuid set matches trixie", got,
       ["chfn", "chsh", "gpasswd", "mount", "newgrp", "passwd", "su",
        "sudo", "umount"])


def t_dpkg_does_not_invent_an_owner_for_a_path():
    """Found while seeding the PAM files. `dpkg -S` fell back to the
    basename for any argument, so a path that does not exist got a
    confident owner as long as its last component matched some command:
    `dpkg -S /no/such/file` answered "file: /usr/bin/file". The one command
    whose entire job is to say what owns a given file was answering about a
    different file."""
    s = sh()
    for bogus in ("/no/such/file", "/tmp/file", "/home/user/ls",
                  "/no/such/file/anywhere"):
        o, rc = run(s, "dpkg -S %s" % bogus)
        eq("dpkg -S %s fails" % bogus, rc, 1)
        check("and says no path found", "no path found" in o, o[:70])
    # The /usr merge still has to resolve: /bin and /sbin are symlinks, and
    # dpkg answers with the real location under /usr.
    # dpkg does NOT resolve the merge. Measured on the guest: `dpkg -S
    # /bin/bash` and `dpkg -S /sbin/ifconfig` are both "no path found",
    # rc 1, while the /usr spellings answer. This asserted the opposite --
    # the check was even named "resolves the merge" -- which is a
    # reasonable thing to assume and not what the tool does.
    for spelled, real, pkg in (("/bin/bash", "/usr/bin/bash", "bash"),
                               ("/sbin/ifconfig", "/usr/sbin/ifconfig",
                                "net-tools")):
        o, rc = run(s, "dpkg -S %s" % spelled)
        eq("dpkg -S %s rc" % spelled, rc, 1)
        eq("dpkg -S %s refuses the pre-merge spelling" % spelled, o.strip(),
           "dpkg-query: no path found matching pattern %s" % spelled)
        o2, rc2 = run(s, "dpkg -S %s" % real)
        eq("dpkg -S %s rc" % real, rc2, 0)
        eq("dpkg -S %s answers" % real, o2.strip(), "%s: %s" % (pkg, real))


def t_a_bare_name_lists_every_file_that_matches():
    """Real dpkg -S on a bare name is a search: `dpkg -S sshd` prints the
    PAM file and the daemon both. Returning only the first match meant
    seeding /etc/pam.d/sshd silently displaced /usr/sbin/sshd from the
    answer."""
    s = sh()
    o, rc = run(s, "dpkg -S sshd")
    eq("dpkg -S sshd rc", rc, 0)
    lines = sorted(o.split())
    check("names the daemon", "/usr/sbin/sshd" in lines, o[:80])
    check("and the pam stack", "/etc/pam.d/sshd" in lines, o[:80])
    o, _ = run(s, "command -v sshd")
    check("agrees with command -v", o.strip() in run(s, "dpkg -S sshd")[0],
          o[:60])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
