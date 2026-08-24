#!/usr/bin/env python3
r"""Filenames that need quoting, and the contexts that render them.

coreutils shell-quotes a name that needs it -- but only when its output
is going to a terminal, which is what an interactive session has. ls
never quoted at all, in any mode, so on a pty a file called `a b.txt`
looked like two files and there was no way to tell which. -Q, -N, -b and
--quoting-style= were all accepted and ignored, so the four flags whose
entire job is to choose the rendering chose nothing.

Measured on the guest, over a pty and over a pipe:

    tty        'a b.txt'  "it's.txt"   plain.txt
    ls -l      ... 'a b.txt' / "it's.txt" / ' plain.txt'   <- indented
    piped      a b.txt / it's.txt / plain.txt              <- raw
    -Q         "a b.txt"  "it's.txt"  "plain.txt"
    escape     a\ b.txt  it's.txt  plain.txt
    shell-always  'a b.txt'  "it's.txt"  'plain.txt'

The same signal drives the layout: one name per line when stdout is not
a terminal, columns when it is. `ls | cat` inside a pty was printing
columns, because only the session type was consulted and not the pipe.
"""
import sys

import re

import fakeshell as F


def lname(line):
    """The name column of an `ls -l` row -- everything after the time.

    The row has nine fields before it, not seven; splitting on a count
    left the timestamp glued to the name, which is a bug in this file and
    not in the box.
    """
    m = re.match(r"^\S+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+\d+\s+[\d:]+ (.*)$",
                 line)
    return m.group(1) if m else line


FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh(tty=True):
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.66")
    s.exec_mode = not tty
    s.run("mkdir -p /tmp/q")
    s.fs.write("/tmp/q/a b.txt", b"")
    s.fs.write("/tmp/q/it's.txt", b"")
    s.fs.write("/tmp/q/plain.txt", b"")
    s.fs.write('/tmp/q/we"ird', b"")
    return v, s


def main():
    v, s = sh(tty=True)

    # -- on a terminal ---------------------------------------------------------
    out = s.run("cd /tmp/q && ls -1")
    check("a space gets single quotes",
          "'a b.txt'" in out, True)
    check("a single quote gets double quotes",
          '"it\'s.txt"' in out, True)
    check("a double quote gets single quotes",
          "'we\"ird'" in out, True)
    check("a plain name gets nothing",
          any(l == "plain.txt" for l in out.splitlines()), True)
    check("every name is accounted for", len(out.splitlines()), 4)

    # -- ls -l indents the bare ones -------------------------------------------
    lout = s.run("cd /tmp/q && ls -l")
    names = [lname(l) for l in lout.splitlines() if l.startswith("-rw")]
    check("ls -l quotes the same way",
          sorted(n for n in names if n.startswith(("'", '"'))),
          sorted(["'a b.txt'", '"it\'s.txt"', "'we\"ird'"]))
    check("...and pads the unquoted one so the column lines up",
          [n for n in names if not n.startswith(("'", '"'))],
          [" plain.txt"])
    # A directory with nothing odd in it is not indented.
    v2, s2 = sh(tty=True)
    s2.run("mkdir -p /tmp/plainonly && touch /tmp/plainonly/a /tmp/plainonly/b")
    check("no quoting means no padding",
          [l.split()[-1] for l in s2.run("ls -l /tmp/plainonly").splitlines()
           if l.startswith("-")], ["a", "b"])

    # -- a pipe is not a terminal ----------------------------------------------
    piped = s.run("cd /tmp/q && ls | cat")
    check("piped output is raw",
          sorted(piped.splitlines()),
          sorted(["a b.txt", "it's.txt", "plain.txt", 'we"ird']))
    check("...and one name per line", len(piped.splitlines()), 4)
    check("the terminal form is columnar",
          len(s.run("cd /tmp/q && ls").splitlines()), 1)
    # An exec channel has no terminal at all.
    v3, s3 = sh(tty=False)
    check("an exec channel is raw too",
          sorted(s3.run("cd /tmp/q && ls").splitlines()),
          sorted(["a b.txt", "it's.txt", "plain.txt", 'we"ird']))
    check("...and one per line", len(s3.run("cd /tmp/q && ls").splitlines()),
          4)
    check("...even for ls -l",
          [lname(l) for l in
           s3.run("cd /tmp/q && ls -l").splitlines() if l.startswith("-rw")],
          ["a b.txt", "it's.txt", "plain.txt", 'we"ird'])
    # ...but -C forces columns wherever the output goes.
    check("-C forces columns on a pipe",
          len(s3.run("cd /tmp/q && ls -C").splitlines()), 1)

    # -- the styles --------------------------------------------------------------
    for style, want in (
            ("literal", ["a b.txt", "it's.txt", "plain.txt", 'we"ird']),
            ("escape", ["a\\ b.txt", "it's.txt", "plain.txt", 'we"ird']),
            ("c", ['"a b.txt"', '"it\'s.txt"', '"plain.txt"',
                   '"we\\"ird"']),
            ("shell-always", ["'a b.txt'", '"it\'s.txt"', "'plain.txt'",
                              "'we\"ird'"])):
        check("--quoting-style=%s" % style,
              sorted(s.run("cd /tmp/q && ls -1 --quoting-style=%s"
                           % style).splitlines()), sorted(want))
    check("-Q is the c style",
          s.run("cd /tmp/q && ls -1 -Q"),
          s.run("cd /tmp/q && ls -1 --quoting-style=c"))
    check("-N is literal",
          s.run("cd /tmp/q && ls -1 -N"),
          s.run("cd /tmp/q && ls -1 --quoting-style=literal"))
    check("-b is escape",
          s.run("cd /tmp/q && ls -1 -b"),
          s.run("cd /tmp/q && ls -1 --quoting-style=escape"))
    check("shell-escape is an alias of shell",
          s.run("cd /tmp/q && ls -1 --quoting-style=shell-escape"),
          s.run("cd /tmp/q && ls -1"))
    check("a style survives only for its own invocation",
          s.run("cd /tmp/q && ls -1 --quoting-style=c >/dev/null; "
                "ls -1 /tmp/q | head -1").strip(), "a b.txt")

    # -- -F and -i put their marks outside the quotes ---------------------------
    v4, s4 = sh(tty=True)
    s4.run("mkdir -p '/tmp/q/a dir'")
    check("a classifier goes outside the quotes",
          "'a dir'/" in s4.run("cd /tmp/q && ls -F"), True)
    check("an inode number goes before them",
          bool([l for l in s4.run("cd /tmp/q && ls -1i").splitlines()
                if l.endswith("'a b.txt'") and l.split()[0].isdigit()]),
          True)

    # -- a symlink's two names are quoted separately ----------------------------
    v5, s5 = sh(tty=True)
    s5.run("ln -s '/tmp/q/a b.txt' '/tmp/q/my link'")
    row = [l for l in s5.run("cd /tmp/q && ls -l").splitlines()
           if l.startswith("l")][0]
    check("the link and its target are quoted as two names",
          lname(row), "'my link' -> '/tmp/q/a b.txt'")

    # -- and the rest of the box is unaffected ----------------------------------
    check("a plain listing is unchanged",
          s.run("ls /root").split(),
          ["backup.sql", "deploy.log", "scripts"])
    check("find does not quote",
          "a b.txt" in s.run("find /tmp/q -name 'a b.txt'"), True)
    check("...and neither does echo of a glob",
          s.run("cd /tmp/q && echo *.txt").strip(),
          "a b.txt it's.txt plain.txt")
    check("stat names the file plainly",
          s.run("stat -c %n '/tmp/q/a b.txt'").strip(), "/tmp/q/a b.txt")

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("quotetest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
