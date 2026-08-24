#!/usr/bin/env python3
"""What does this box actually have installed, and what can it do with it?

Two questions an attacker asks in the first ten seconds -- `command -v X`
to pick a tool, and `find / -perm -4000` to pick a way up -- and the box
answered both wrongly.

  - 34 commands ran with nothing on disk behind them. `base64 -d` worked
    and `command -v base64` failed; the same for sha512sum, cksum, mkfifo,
    mknod, numfmt and twenty more coreutils programs, for zegrep and
    zfgrep, and for chroot. A loader that gates on `command -v base64 ||
    command -v openssl` reads the answer that says no.
  - The other half of that list should not exist and did: `write`,
    `python`, `zsh`, `ash` and `yum` all ran on a box with no file, no
    package and a `command -v` that said no. `command -v python ||
    command -v python3` is the standard first line of a dropper.
    A command answers now only if the box has a file for it, decided by
    the same code `type` and `command -v` use, so the three cannot drift.
  - Every set-gid binary was group root. `find / -perm -2000` listed five
    and `ls -l` showed all five as root:root -- a set-gid-root helper,
    which confers nothing and exists on no Debian. chage and expiry are
    group shadow, crontab is group crontab, ssh-agent is _ssh, and the
    _ssh group was not in /etc/group at all.
  - /usr/sbin/unix_chkpwd was missing on a box with libpam-modules-bin
    installed and pam_unix in every pam.d file -- the one set-gid shadow
    binary a non-root attacker can use to test passwords.
  - /usr/bin/wall was set-gid; on trixie it is a plain 755. /usr/bin/write
    was set-gid and belonged to no package at all -- bsdextrautils is not
    installed here.
  - bash's builtin list was 42 of its 61 entries, so `command -v ulimit`,
    `type history` and `command -v wait` all said the builtin did not
    exist on a shell that runs every one of them.
  - `dpkg -l a b c` and `getent group a b c` read the first operand and
    dropped the rest -- the same shape as `wc -c a b`, and the reason to
    check for a family of bugs rather than one instance.
  - `passwd --help` answered "Authentication token manipulation error":
    the flag fell through to the change-password path, so the box reported
    a PAM failure for a command that never reached PAM.

Every set-gid group, package name and usage string here was measured on
the real Debian 13 cloud guest this box imitates.

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


# --- does it exist? ---------------------------------------------------------

GONE = ("write", "python", "zsh", "ash", "yum")
PRESENT = ("base64", "base32", "b2sum", "sha512sum", "sha224sum", "cksum",
           "mkfifo", "mknod", "numfmt", "tsort", "expand", "unexpand",
           "dircolors", "hostid", "link", "pathchk", "pr", "ptx", "csplit",
           "fmt", "chcon", "runcon", "basenc", "zegrep", "zfgrep", "chroot")


def t_a_command_answers_only_if_a_file_backs_it():
    s = sh()
    for nm in GONE:
        o, rc = run(s, "%s --version" % nm)
        eq("%s is not found" % nm, rc, 127)
        check("%s says command not found" % nm,
              "command not found" in o, o[:60])
        o2, rc2 = run(s, "command -v %s" % nm)
        eq("...and command -v agrees about %s" % nm, rc2, 1)
        o3, rc3 = run(s, "ls /usr/bin/%s /usr/sbin/%s 2>&1 | grep -c 'No such'"
                      % (nm, nm))
        eq("...and there is no file for %s" % nm, o3.strip(), "2")


def t_the_commands_that_do_run_have_files():
    s = sh()
    for nm in PRESENT:
        o, rc = run(s, "command -v %s" % nm)
        eq("command -v finds %s" % nm, rc, 0)
        path = o.strip()
        o2, rc2 = run(s, "test -x %s && echo ok" % path)
        eq("%s is executable on disk" % path, (o2.strip(), rc2), ("ok", 0))
        o3, rc3 = run(s, "dpkg -S %s" % path)
        eq("a package owns %s" % path, rc3, 0)
        check("...and it is an installed one",
              run(s, "dpkg -l %s > /dev/null" % o3.split(":")[0])[1] == 0,
              o3[:60])


def t_base64_is_there_because_loaders_ask_for_it():
    s = sh()
    o, _ = run(s, "command -v base64")
    eq("base64 is where coreutils puts it", o.strip(), "/usr/bin/base64")
    o2, _ = run(s, "echo hi | base64")
    eq("and it still works", o2.strip(), "aGkK")
    o3, _ = run(s, "dpkg -S /usr/bin/base64")
    check("owned by coreutils", o3.startswith("coreutils:"), o3[:50])


def t_which_type_and_command_agree():
    s = sh()
    for nm in ("base64", "curl", "python3", "sha512sum", "unix_chkpwd"):
        a, _ = run(s, "command -v %s" % nm)
        b, _ = run(s, "which %s" % nm)
        c, _ = run(s, "type -P %s" % nm)
        eq("which agrees with command -v for %s" % nm, b.strip(), a.strip())
        eq("type -P agrees too for %s" % nm, c.strip(), a.strip())


def t_the_builtin_list_is_bashs():
    s = sh()
    o, _ = run(s, "compgen -b")
    have = set(o.split())
    for nm in ("ulimit", "history", "wait", "return", "break", "continue",
               "kill", "mapfile", "readarray", "pushd", "popd", "dirs",
               "bind", "fc", "complete", "compopt", "help", "[", ":", "."):
        check("compgen -b lists %s" % nm, nm in have, sorted(have)[:6])
    for nm in ("ulimit", "history", "wait"):
        o2, rc = run(s, "command -v %s" % nm)
        eq("command -v %s" % nm, (o2.strip(), rc), (nm, 0))
        o3, _ = run(s, "type %s" % nm)
        check("type calls %s a builtin" % nm, "shell builtin" in o3, o3[:50])


# --- what privilege does it carry? ------------------------------------------

def suid_rows(s):
    o, _ = run(s, "find / -perm -4000 -type f -exec ls -l {} + 2>/dev/null")
    return [l.split(None, 8) for l in o.splitlines() if l.startswith("-")]


def sgid_rows(s):
    o, _ = run(s, "find / -perm -2000 -type f -exec ls -l {} + 2>/dev/null")
    return [l.split(None, 8) for l in o.splitlines() if l.startswith("-")]


def t_no_setgid_binary_is_group_root():
    """The finding this sweep started from."""
    s = sh()
    rows = sgid_rows(s)
    check("there are set-gid binaries", len(rows) >= 4, len(rows))
    bad = [r[-1] for r in rows if r[3] == "root"]
    eq("no set-gid binary belongs to group root", bad, [])
    for r in rows:
        grp = r[3]
        o, rc = run(s, "getent group %s" % grp)
        eq("group %s exists" % grp, rc, 0)
        check("...and ls's name matches the gid on disk",
              run(s, "stat -c %%G %s" % r[-1])[0].strip() == grp,
              "%s vs %s" % (grp, r[-1]))


def t_the_setgid_groups_are_the_ones_debian_uses():
    s = sh()
    want = {"/usr/bin/chage": "shadow", "/usr/bin/expiry": "shadow",
            "/usr/sbin/unix_chkpwd": "shadow", "/usr/bin/crontab": "crontab",
            "/usr/bin/ssh-agent": "_ssh"}
    got = {r[-1]: r[3] for r in sgid_rows(s)}
    for path, grp in want.items():
        eq("%s is set-gid %s" % (path, grp), got.get(path), grp)


def t_unix_chkpwd_is_there_because_pam_needs_it():
    s = sh()
    o, rc = run(s, "test -u /usr/sbin/unix_chkpwd; echo $?")
    o2, _ = run(s, "stat -c '%a %U %G' /usr/sbin/unix_chkpwd")
    eq("unix_chkpwd is 2755 root shadow", o2.strip(), "2755 root shadow")
    o3, _ = run(s, "dpkg -S /usr/sbin/unix_chkpwd")
    check("owned by libpam-modules-bin",
          o3.startswith("libpam-modules-bin:"), o3[:60])
    o4, _ = run(s, "grep -l pam_unix /etc/pam.d/* | head -1")
    check("and pam_unix, which needs it, is stacked", o4.strip(), o4[:60])


def t_wall_and_write_match_trixie():
    s = sh()
    o, _ = run(s, "stat -c '%a %U %G' /usr/bin/wall")
    eq("wall is a plain 755 root root", o.strip(), "755 root root")
    o2, rc = run(s, "ls /usr/bin/write")
    eq("write is not on the box", rc, 2)
    o3, rc3 = run(s, "dpkg -l bsdextrautils")
    eq("because the package that ships it is not installed", rc3, 1)


def t_suid_bits_agree_across_every_reader():
    s = sh()
    rows = suid_rows(s)
    check("there are set-uid binaries", len(rows) >= 9, len(rows))
    for r in rows:
        path = r[-1]
        check("ls shows the s bit on %s" % path, r[0][3] == "s", r[0])
        mode, _ = run(s, "stat -c %%a %s" % path)
        check("stat agrees for %s" % path, mode.strip().startswith("4"),
              mode.strip())
        o, rc = run(s, "dpkg -S %s" % path)
        eq("a package owns %s" % path, rc, 0)
        eq("...and dpkg -l says that package is installed",
           run(s, "dpkg -l %s > /dev/null" % o.split(":")[0])[1], 0)
    o, _ = run(s, "find / -perm -4000 -type f 2>/dev/null | sort")
    o2, _ = run(s, "find / -perm /4000 -type f 2>/dev/null | sort")
    eq("-perm -4000 and -perm /4000 find the same files",
       o.split(), o2.split())
    o3, _ = run(s, "find /usr/bin -perm 4700 -type f | wc -l")
    eq("an exact-mode match is exact", o3.strip(), "0")


def t_find_by_group_finds_the_setgid_set():
    s = sh()
    o, _ = run(s, "find /usr -group shadow -type f 2>/dev/null | sort")
    want = sorted(r[-1] for r in sgid_rows(s) if r[3] == "shadow")
    eq("find -group shadow matches what ls reported", o.split(), want)


# --- one operand or several -------------------------------------------------

def t_getent_answers_every_key():
    s = sh()
    o, rc = run(s, "getent group shadow crontab _ssh")
    eq("rc", rc, 0)
    eq("one line per group asked for",
       [l.split(":")[0] for l in o.splitlines()],
       ["shadow", "crontab", "_ssh"])
    o2, rc2 = run(s, "getent passwd root deploy")
    eq("and for passwd too",
       [l.split(":")[0] for l in o2.splitlines()], ["root", "deploy"])
    o3, rc3 = run(s, "getent group nosuch1 nosuch2")
    eq("nothing found is still rc 2", rc3, 2)
    eq("and prints nothing", o3.strip(), "")
    o4, rc4 = run(s, "getent group shadow nosuchgroup")
    eq("a partial hit is a hit", rc4, 0)
    eq("printing what it found", o4.strip(), "shadow:x:42:")


def t_dpkg_l_answers_every_pattern():
    s = sh()
    o, rc = run(s, "dpkg -l iptables ca-certificates mariadb-client")
    eq("rc", rc, 0)
    named = [l.split()[1] for l in o.splitlines() if l.startswith("ii ")]
    eq("one row per package asked for", sorted(named),
       ["ca-certificates", "iptables", "mariadb-client"])
    o2, rc2 = run(s, "dpkg -l bash nosuchpkg")
    eq("an unmatched pattern makes it rc 1", rc2, 1)
    check("the pattern is named", "no packages found matching nosuchpkg" in o2,
          o2[-70:])
    check("and the one that matched is still listed",
          any(l.startswith("ii  bash") for l in o2.splitlines()), o2[:60])


def t_passwd_help_is_a_usage_message():
    s = sh()
    o, rc = run(s, "passwd --help")
    eq("rc", rc, 0)
    check("it starts with the usage line",
          o.startswith("Usage: passwd [options] [LOGIN]"), o[:60])
    check("and lists the flags", "-S, --status" in o, o[:80])
    check("no PAM error anywhere in it",
          "Authentication token" not in o, o[:80])
    o2, rc2 = run(s, "passwd -h")
    eq("-h is the same thing", o2, o)
    o3, rc3 = run(s, "passwd --nosuchflag")
    eq("an unknown flag is rc 1", rc3, 1)
    check("named in the error", "unrecognized option '--nosuchflag'" in o3,
          o3[:70])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:12]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
