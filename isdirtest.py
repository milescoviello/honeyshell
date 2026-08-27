#!/usr/bin/env python3
"""A redirect at a directory is EISDIR, and the directory survives it.

Found by asking what an attacker's staged filesystem looks like after the
round trip that eviction now performs on every returning source. The round
trip turned out to be clean; the staging was not.

    $ mkdir -p /tmp/d/adir
    $ echo x > /tmp/d/adir ; echo rc=$?
    rc=0
    $ ls -ld /tmp/d/adir
    -rwxr-xr-x 1 root root 0 Aug 27 03:42 /tmp/d/adir

Verified over real SSH against the live honeypot. The redirect reported
success and **replaced the directory node with a regular file**, so `mkdir`
and `ls -ld` disagreed about what the path was -- the directory an
attacker had just created was destroyed by a redirect that a real box
refuses outright.

Measured on the guest, which is Debian 13.6:

    echo x > dir        bash: line 1: dir: Is a directory     rc 1
    echo x >> dir       bash: line 1: dir: Is a directory     rc 1
    ls /etc 2> dir      bash: line 1: dir: Is a directory     rc 1
    ls -ld dir          drwxr-xr-x 2 root root 40 ...         intact

EISDIR outranks the attribute checks the way the kernel orders them: an
immutable directory still reports "Is a directory", not "Operation not
permitted". The write path checks it first for that reason.

Four call sites discarded the failed write rather than reporting it --
the two stdout redirects already went through _write_fail, but both
stderr paths (command produced errors, and command produced none) and
their group-form twin threw the result away, which is why `cmd 2>dir`
printed the command's stdout and exited 0.

Usage:  python3 isdirtest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    fs = fakeshell.VFS()
    return fakeshell.Shell(vfs=fs, peer="198.51.100.15", peer_port=40444)


def run(sh, cmd):
    """(stdout, rc, stderr-produced-by-this-command).

    Guarded: a suite that raises against the broken tree reports a
    traceback instead of the failures it was written to find.
    """
    before = len(getattr(sh, "_err", []) or [])
    try:
        out = sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return ("<raised %s: %s>" % (type(exc).__name__, exc), -1, "")
    err = "".join((getattr(sh, "_err", []) or [])[before:])
    return (out, getattr(sh, "last_rc", None), err)


sh = shell()
run(sh, "mkdir -p /tmp/d/adir")

# --------------------------------------------------- the destructive part
run(sh, "echo x > /tmp/d/adir")
listing, _, _ = run(sh, "ls -ld /tmp/d/adir")
check("a redirect does not turn a directory into a file",
      listing[:1], "d",
      "this came back '-rwxr-xr-x 1 root root 0' on the live box: mkdir "
      "made a directory and a redirect quietly destroyed it")
check("...and it is still listed with a directory's link count",
      listing.split()[1] if len(listing.split()) > 1 else "", "2")

# ------------------------------------------------------ every write spelling
for label, cmd in (("truncating redirect", "echo x > /tmp/d/adir"),
                   ("appending redirect", "echo x >> /tmp/d/adir"),
                   ("stderr redirect, command silent",
                    "ls /etc 2> /tmp/d/adir"),
                   ("stderr redirect, command noisy",
                    "ls /nosuchpath 2> /tmp/d/adir")):
    out, rc, err = run(sh, cmd)
    check("%s: exits 1" % label, rc, 1,
          "bash refuses the open and never runs the command")
    check("%s: says Is a directory" % label,
          "Is a directory" in err, True, "got stderr %r" % err[:120])
    check("%s: prints no stdout" % label, out.strip(), "",
          "bash produces nothing when the redirection fails")

# ------------------------------------------------ EISDIR outranks the attrs
run(sh, "chattr +i /tmp/d/adir")
out, rc, err = run(sh, "echo x > /tmp/d/adir")
check("an immutable directory still says Is a directory",
      "Is a directory" in err, True,
      "the kernel reports EISDIR before EPERM; saying Operation not "
      "permitted here would be the wrong errno. got %r" % err[:120])
run(sh, "chattr -i /tmp/d/adir")

# ------------------------------------------------------- files still work
out, rc, err = run(sh, "echo hello > /tmp/d/file")
check("a redirect at an ordinary file still works", rc, 0)
out, _, _ = run(sh, "cat /tmp/d/file")
check("...and the bytes arrive", out.strip(), "hello")
out, rc, err = run(sh, "ls /etc 2> /tmp/d/file")
check("a stderr redirect at an ordinary file still works", rc, 0)
check("...and the command still produces its stdout", bool(out.strip()), True)
out, rc, _ = run(sh, "echo more >> /tmp/d/file")
check("appending to an ordinary file still works", rc, 0)

# ----------------------------------------- the immutable file case is intact
run(sh, "head -c 100 /dev/urandom > /tmp/d/imm")
run(sh, "chattr +i /tmp/d/imm")
out, rc, err = run(sh, "echo x > /tmp/d/imm")
check("an immutable file still says Operation not permitted",
      "Operation not permitted" in err, True,
      "sweep 191 must not have traded one errno for another. got %r"
      % err[:120])
check("...and still exits 1", rc, 1)

for f in FAILS:
    print(" ", f)
print("   isdir: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
