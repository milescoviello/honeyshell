#!/usr/bin/env python3
"""An immutable directory freezes its entries, not its files' contents.

`chattr -R +i /bin /usr/bin /sbin /usr/sbin` is the last thing the SRBMiner
installer runs, after replacing twenty-odd tools. The point is that nothing
can be added to those directories afterwards -- and, just as much, that
nothing can be taken out of them.

Measured on the guest's ext4, with the directory +i:

    touch new inside      rc 1   touch: ... Operation not permitted
    rm an existing file   rc 1   rm: ... Operation not permitted   (survives)
    append to that file   rc 0   -- the bytes are not frozen
    truncate it           rc 0
    chmod it              rc 0
    rename inside         rc 1   mv: cannot move 'a' to 'b': Operation not...
    mkdir inside          rc 1   mkdir: cannot create directory 'x': Oper...
    rmdir the directory   rc 1   rmdir: ... Operation not permitted

Creation consulted the lock and deletion did not, so the recursive +i
stopped anything being added to /usr/bin and let everything be removed --
the opposite of what the flag is for, on the one directory set an
anti-forensics script cares about.

Three of the messages were wrong even where the exit code happened to be
right. `mv` delegated to cp and reported cp's failure with only the prefix
rewritten, so a refused rename said "cannot create regular file ... No such
file or directory": the wrong tool and the wrong reason. `rmdir` said
"Directory not empty" for an immutable directory, which is a different
reason and would not apply to an empty one. `mkdir` said nothing at all.

And rmdir never worked. `remove()` refuses a directory unless called with
recursive=True, and the return value was thrown away, so `rmdir emptydir`
reported success, left the directory, and `ls` right afterwards still listed
it. Two commands disagreeing about whether a directory exists, one of them
having just claimed to delete it.

One reference was nearly taken from the wrong filesystem: /tmp on the guest
is tmpfs, where lsattr shows no extent flag, and the emulator's root is
ext4, where it shows one. Measuring the lock in /tmp and the attribute
string on / is how "----i---------e-------" nearly got "fixed" into being
wrong.

Usage:  python3 dirlocktest.py
"""

import sys

import fakeshell as F

CHECKS, FAILS = [], []

#: (rc, exact stderr) with /root/d immutable. Measured.
MATRIX = [
    ("touch /root/d/new", "1",
     "touch: cannot touch '/root/d/new': Operation not permitted"),
    ("rm -f /root/d/existing", "1",
     "rm: cannot remove '/root/d/existing': Operation not permitted"),
    ("echo b >> /root/d/existing", "0", ""),
    (": > /root/d/existing", "0", ""),
    ("chmod 700 /root/d/existing", "0", ""),
    ("mv /root/d/existing /root/d/x", "1",
     "mv: cannot move '/root/d/existing' to '/root/d/x': "
     "Operation not permitted"),
    ("rmdir /root/d", "1",
     "rmdir: failed to remove '/root/d': Operation not permitted"),
    ("mkdir /root/d/sub", "1",
     "mkdir: cannot create directory ‘/root/d/sub’: "
     "Operation not permitted"),
]


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def locked_shell():
    s = F.Shell()
    s.run("mkdir -p /root/d; echo a > /root/d/existing; chattr +i /root/d")
    return s


def t_the_matrix():
    for cmd, rc, msg in MATRIX:
        s = locked_shell()
        check("%s: rc" % cmd,
              s.run("%s >/dev/null 2>&1; echo $?" % cmd).strip(), rc)
        s2 = locked_shell()
        check("%s: message" % cmd, s2.run("%s 2>&1" % cmd).strip(), msg)


def t_a_refused_delete_leaves_the_file():
    """rc is not enough: the file has to still be there."""
    s = locked_shell()
    s.run("rm -f /root/d/existing")
    check("the file survived a refused rm",
          s.run("test -e /root/d/existing; echo $?").strip(), "0")
    check("...and still has its contents",
          s.run("cat /root/d/existing").strip(), "a")
    # While the bytes remain writable, which is the half that is allowed.
    s.run("echo b >> /root/d/existing")
    check("appending to it worked",
          s.run("wc -l < /root/d/existing").strip(), "2")


def t_rmdir_actually_removes():
    """It reported success and left the directory there."""
    s = F.Shell()
    s.run("mkdir -p /root/gone")
    check("rmdir succeeds on an empty directory",
          s.run("rmdir /root/gone; echo $?").strip(), "0")
    check("and the directory is actually gone",
          s.run("test -d /root/gone; echo $?").strip(), "1")
    check("ls agrees it is gone",
          "No such file" in s.run("ls -d /root/gone 2>&1"), True)
    # The other three corners.
    s.run("mkdir -p /root/full; echo a > /root/full/x")
    check("a non-empty directory is refused",
          s.run("rmdir /root/full 2>&1").strip(),
          "rmdir: failed to remove '/root/full': Directory not empty")
    check("...and survives", s.run("test -d /root/full; echo $?").strip(), "0")


def t_the_recursive_lock_the_installer_sets():
    """chattr -R +i /bin /usr/bin /sbin /usr/sbin, then try to use them."""
    s = F.Shell()
    s.run("chattr -R +i /bin /usr/bin /sbin /usr/sbin")
    for d in ("/usr/bin", "/sbin"):
        check("nothing can be added to %s" % d,
              s.run("touch %s/newtool 2>&1; echo $?" % d).strip().endswith("1"),
              True)
        check("...and nothing removed from %s" % d,
              "Operation not permitted" in
              s.run("rm -f %s/ls 2>&1" % d) or
              "Operation not permitted" in s.run("rm -f %s/ip 2>&1" % d), True)
    # A file that was already there is still there.
    check("/usr/bin/curl survived", s.run("test -x /usr/bin/curl; echo $?")
          .strip(), "0")


def t_lsattr_matches_the_root_filesystem():
    """Measured on / (ext4), not on /tmp (tmpfs, which has no extent flag)."""
    s = F.Shell()
    s.run("mkdir -p /root/attr")
    check("a plain directory on / shows the extent flag",
          s.run("lsattr -d /root/attr").split()[0], "--------------e-------")
    s.run("chattr +i /root/attr")
    check("and the immutable one adds i",
          s.run("lsattr -d /root/attr").split()[0], "----i---------e-------")


def t_mkdir_quotes_differently_from_the_others():
    """GNU mkdir uses U+2018/U+2019; rm, rmdir, touch and mv use ASCII."""
    s = F.Shell()
    check("mkdir uses curly quotes",
          "‘/root’" in s.run("mkdir /root 2>&1"), True)
    check("...for every mkdir error, not just one",
          "‘/nope/sub’" in s.run("mkdir /nope/sub 2>&1"), True)
    for cmd, tool in (("rmdir /nope", "rmdir"), ("rm /nope/x", "rm"),
                      ("touch /nope/x", "touch")):
        out = s.run("%s 2>&1" % cmd)
        check("%s uses the ascii apostrophe" % tool,
              "'" in out and "‘" not in out, True)


def main():
    for fn in (t_the_matrix,
               t_a_refused_delete_leaves_the_file,
               t_rmdir_actually_removes,
               t_the_recursive_lock_the_installer_sets,
               t_lsattr_matches_the_root_filesystem,
               t_mkdir_quotes_differently_from_the_others):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-52s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("dirlocktest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
