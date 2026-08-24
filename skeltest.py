#!/usr/bin/env python3
"""What does this box give a new account, and does it match the ones on it?

Adding a user is a persistence move, and `useradd -m` is how it is done.
The -m is the whole point of the command: it makes the home and fills it
from /etc/skel. /etc/skel was an empty directory.

    useradd -m eviluser
    ls -a /home/eviluser        .  ..
    ls -a /home/deploy          .  ..  .bashrc  .profile  .bash_logout  ...

The homes already on the box carry the three files skel is where they come
from, and the box could not produce them. The copies it had were stubs of
themselves too: /home/deploy/.bash_logout was 17 bytes against Debian's
220, and nobody edits .bash_logout.

Underneath that, /etc/login.defs held eight directives against the guest's
thirty, and the missing ones were not decoration:

  * HOME_MODE decides the mode useradd gives a new home. With none set the
    umask was the only rule there was, so a new home came out 0755 next to
    a /home/deploy of 0700 -- and Debian's login.defs says 0700.
  * SUB_UID_MIN and SUB_UID_COUNT decide the range useradd writes to
    /etc/subuid. Both that file and /etc/subgid were simply absent, so
    `cat /etc/subuid` on a box with two ordinary accounts said No such
    file or directory.
  * USERGROUPS_ENAB decides whether a matching group is made.

Every byte here was read off the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402
import skeldb                                                   # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-58s %s" % (name, detail))


def sh():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    return s


def R(cmd, s):
    s._err = []
    out = s.run(cmd)
    return out or "", "".join(s._err), s.last_rc


SKEL = {".bashrc": skeldb.SKEL_BASHRC,
        ".profile": skeldb.SKEL_PROFILE,
        ".bash_logout": skeldb.SKEL_BASH_LOGOUT}


# ---------------------------------------------------------------------------
# /etc/skel exists and is Debian's
# ---------------------------------------------------------------------------
def t_skel_holds_the_three_files():
    s = sh()
    have = set(R("ls -a /etc/skel/", s)[0].split()) - {".", ".."}
    check("skel has exactly the three Debian ships", have == set(SKEL),
          str(sorted(have)))
    for name, body in SKEL.items():
        got = R("stat -c %%s /etc/skel/%s" % name, s)[0].strip()
        check("/etc/skel/%s is the guest's size" % name,
              got == str(len(body)), "%s vs %d" % (got, len(body)))
        check("/etc/skel/%s is mode 644" % name,
              R("stat -c %%a /etc/skel/%s" % name, s)[0].strip() == "644",
              R("stat -c %%a /etc/skel/%s" % name, s)[0].strip())
    check(".bashrc is the real 113-line one",
          R("wc -l < /etc/skel/.bashrc", s)[0].strip() == "113",
          R("wc -l < /etc/skel/.bashrc", s)[0].strip())
    check(".bash_logout clears the console, as Debian's does",
          "clear_console" in R("cat /etc/skel/.bash_logout", s)[0],
          R("cat /etc/skel/.bash_logout", s)[0][:60])
    check(".profile sources .bashrc",
          '. "$HOME/.bashrc"' in R("cat /etc/skel/.profile", s)[0],
          R("cat /etc/skel/.profile", s)[0][:60])


def t_the_existing_homes_match_skel():
    """A file nobody edits has to be the file skel handed out."""
    s = sh()
    for name in (".bash_logout", ".profile"):
        a = R("cat /home/deploy/%s" % name, s)[0]
        b = R("cat /etc/skel/%s" % name, s)[0]
        check("/home/deploy/%s is skel's" % name, a == b,
              "%d vs %d bytes" % (len(a), len(b)))
    check("/home/deploy/.bashrc exists too",
          R("test -f /home/deploy/.bashrc", s)[2] == 0, "missing")


# ---------------------------------------------------------------------------
# useradd -m does what -m is for
# ---------------------------------------------------------------------------
def t_useradd_m_fills_the_home():
    s = sh()
    _o, err, rc = R("useradd -m -s /bin/bash eviluser", s)
    check("useradd exits 0", rc == 0, "rc=%s %s" % (rc, err[:40]))
    have = set(R("ls -a /home/eviluser", s)[0].split()) - {".", ".."}
    check("the new home has skel's files", have == set(SKEL),
          str(sorted(have)))
    for name, body in SKEL.items():
        got = R("cat /home/eviluser/%s" % name, s)[0]
        check("%s was copied byte for byte" % name, got == body,
              "%d vs %d bytes" % (len(got), len(body)))
        own = R("stat -c '%%U %%G' /home/eviluser/%s" % name, s)[0].split()
        check("%s belongs to the new user" % name,
              own == ["eviluser", "eviluser"], str(own))
    check("the home is 0700, from HOME_MODE",
          R("stat -c %a /home/eviluser", s)[0].strip() == "700",
          R("stat -c %a /home/eviluser", s)[0].strip())
    check("and it belongs to them",
          R("stat -c '%U %G' /home/eviluser", s)[0].split()
          == ["eviluser", "eviluser"],
          R("stat -c '%U %G' /home/eviluser", s)[0])
    # ...and no -m makes no home at all.
    s2 = sh()
    R("useradd nohome", s2)
    check("without -m there is no home", R("test -d /home/nohome", s2)[2] != 0,
          "created anyway")


def t_the_home_mode_comes_from_the_file():
    s = sh()
    body = R("cat /etc/login.defs", s)[0]
    check("login.defs sets HOME_MODE 0700",
          any(l.split()[:2] == ["HOME_MODE", "0700"]
              for l in body.splitlines() if l.strip()), "not set")
    R("useradd -m a1", s)
    check("useradd used it", R("stat -c %a /home/a1", s)[0].strip() == "700",
          R("stat -c %a /home/a1", s)[0].strip())
    # Change the file and the next account follows it, which is the point
    # of reading it rather than hardcoding either value.
    R("sed -i 's/^HOME_MODE\\t0700/HOME_MODE\\t0751/' /etc/login.defs", s)
    R("useradd -m a2", s)
    check("changing HOME_MODE changes the next home",
          R("stat -c %a /home/a2", s)[0].strip() == "751",
          R("stat -c %a /home/a2", s)[0].strip())
    check("and the first one is untouched",
          R("stat -c %a /home/a1", s)[0].strip() == "700",
          R("stat -c %a /home/a1", s)[0].strip())


def t_login_defs_is_the_guests():
    s = sh()
    body = R("cat /etc/login.defs", s)[0]
    check("login.defs is the guest's file", body == skeldb.LOGIN_DEFS,
          "%d vs %d bytes" % (len(body), len(skeldb.LOGIN_DEFS)))
    keys = [l.split()[0] for l in body.splitlines()
            if l[:1].isupper() and l.split()]
    check("it has the guest's thirty directives", len(keys) == 30,
          str(len(keys)))
    for k in ("HOME_MODE", "USERGROUPS_ENAB", "SUB_UID_MIN", "SUB_UID_COUNT",
              "UID_MIN", "ENCRYPT_METHOD", "PASS_MAX_DAYS"):
        check("login.defs sets %s" % k, k in keys, str(sorted(keys)[:4]))
    # UID_MIN has to be the number useradd actually starts from.
    R("useradd u9", s)
    uid = R("id -u u9", s)[0].strip()
    m = [l.split()[1] for l in body.splitlines()
         if l.split()[:1] == ["UID_MIN"]]
    check("the first new uid is at or above UID_MIN",
          uid.isdigit() and m and int(uid) >= int(m[0]),
          "%s vs UID_MIN %s" % (uid, m))
    # ENCRYPT_METHOD has to be the scheme a password actually gets.
    R("echo 'u9:hunter2' | chpasswd", s)
    line = [l for l in R("cat /etc/shadow", s)[0].splitlines()
            if l.startswith("u9:")]
    check("a password uses the method login.defs names",
          line and line[0].split(":")[1].startswith("$y$"),
          (line or [""])[0][:40])


# ---------------------------------------------------------------------------
# the subordinate ranges
# ---------------------------------------------------------------------------
def t_subuid_and_subgid_exist_and_move_together():
    s = sh()
    for p in ("/etc/subuid", "/etc/subgid"):
        check("%s exists" % p, R("test -f %s" % p, s)[2] == 0, "missing")
        check("%s lists the account already here" % p,
              R("grep -c '^deploy:' %s" % p, s)[0].strip() == "1",
              R("cat %s" % p, s)[0][:40])
        check("%s is mode 644" % p,
              R("stat -c %%a %s" % p, s)[0].strip() == "644",
              R("stat -c %%a %s" % p, s)[0].strip())
    before = R("cat /etc/subuid", s)[0]
    R("useradd -m eviluser", s)
    after = R("cat /etc/subuid", s)[0]
    check("useradd adds a range", after != before and "eviluser:" in after,
          after[:60])
    check("subgid got the same line",
          R("grep '^eviluser:' /etc/subgid", s)[0]
          == R("grep '^eviluser:' /etc/subuid", s)[0], "differ")
    f = R("grep '^eviluser:' /etc/subuid", s)[0].strip().split(":")
    check("the range is SUB_UID_COUNT wide", f[2:3] == ["65536"], str(f))
    check("and starts past the existing one", f[1:2] == ["165536"], str(f))
    R("useradd -m third", s)
    g = R("grep '^third:' /etc/subuid", s)[0].strip().split(":")
    check("a third account starts past the second", g[1:2] == ["231072"],
          str(g))
    check("no account has two ranges",
          R("cut -d: -f1 /etc/subuid | sort | uniq -d", s)[0].strip() == "",
          R("cat /etc/subuid", s)[0])
    R("userdel -r eviluser", s)
    check("userdel takes the range away",
          "eviluser:" not in R("cat /etc/subuid", s)[0],
          R("cat /etc/subuid", s)[0][:60])
    check("from subgid too",
          "eviluser:" not in R("cat /etc/subgid", s)[0],
          R("cat /etc/subgid", s)[0][:60])
    check("and leaves the others alone",
          "deploy:" in R("cat /etc/subuid", s)[0]
          and "third:" in R("cat /etc/subuid", s)[0],
          R("cat /etc/subuid", s)[0][:60])


def t_a_new_account_is_consistent_everywhere():
    """The readers that already agreed, held against the new files."""
    s = sh()
    R("useradd -m -s /bin/bash eviluser", s)
    uid = R("id -u eviluser", s)[0].strip()
    for cmd, want in (("getent passwd eviluser", uid),
                      ("grep '^eviluser:' /etc/passwd", uid)):
        check("%s knows the uid" % cmd.split()[0],
              uid and uid in R(cmd, s)[0], R(cmd, s)[0][:50])
    check("the home in /etc/passwd is the one that exists",
          R("test -d $(getent passwd eviluser | cut -d: -f6)", s)[2] == 0,
          R("getent passwd eviluser", s)[0][:60])
    check("the shell in /etc/passwd is a file",
          R("test -x $(getent passwd eviluser | cut -d: -f7)", s)[2] == 0,
          R("getent passwd eviluser", s)[0][:60])
    check("a matching group exists, as USERGROUPS_ENAB says",
          R("getent group eviluser", s)[2] == 0,
          R("getent group eviluser", s)[1][:40])
    check("and it is the account's primary group",
          R("id -gn eviluser", s)[0].strip() == "eviluser",
          R("id -gn eviluser", s)[0].strip())
    # su into it and land in the home skel filled.
    out = R("su - eviluser -c 'pwd; ls -a | tr \"\\n\" \" \"'", s)[0]
    check("su lands in the new home", "/home/eviluser" in out, out[:60])
    check("and the dotfiles are there", ".bashrc" in out, out[:80])


TESTS = [t_skel_holds_the_three_files,
         t_the_existing_homes_match_skel,
         t_useradd_m_fills_the_home,
         t_the_home_mode_comes_from_the_file,
         t_login_defs_is_the_guests,
         t_subuid_and_subgid_exist_and_move_together,
         t_a_new_account_is_consistent_everywhere]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
