#!/usr/bin/env python3
r"""grep's colour, and the terminal signal that decides it.

Sweep 99 gave the box a real "is stdout a terminal" signal and used it
for ls. grep needs the same one, and it had nothing at all:

    grep --color=always root /etc/passwd | cat

emitted bare text where every real grep emits escape codes. "always" is
the spelling a script uses precisely because it wants the codes through a
pipe, so this is the one form where the answer cannot depend on where the
output goes -- and it was the form that produced nothing.

Measured on the guest with cat -A. GNU grep's defaults wrap each part in
an SGR plus \e[K, so a colour survives a line-clear:

    match      \e[01;31m\e[K ... \e[m\e[K
    line no    \e[32m\e[K
    filename   \e[35m\e[K
    separator  \e[36m\e[K

-c colours the name and the separator but not the count, -l colours the
name alone, -v has nothing to highlight, and a context line pulled in by
-A is left plain.
"""
import sys

import fakeshell as F

FAILS, CHECKS = [], []
M = "\x1b[01;31m\x1b[K%s\x1b[m\x1b[K"
N = "\x1b[32m\x1b[K%s\x1b[m\x1b[K"
FN = "\x1b[35m\x1b[K%s\x1b[m\x1b[K"
SEP = "\x1b[36m\x1b[K%s\x1b[m\x1b[K"


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh(tty=False):
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.77")
    s.exec_mode = not tty
    s.fs.write("/tmp/g1.txt", b"alpha root\nbeta\ngamma root\n")
    s.fs.write("/tmp/g2.txt", b"delta root\n")
    return v, s


def main():
    v, s = sh()

    # -- always colours, wherever the output goes -----------------------------
    check("a match is wrapped in red",
          s.run("grep --color=always root /tmp/g1.txt"),
          "alpha %s\ngamma %s\n" % (M % "root", M % "root"))
    check("-n colours the line number and the separator",
          s.run("grep --color=always -n root /tmp/g1.txt").splitlines()[0],
          "%s%salpha %s" % (N % "1", SEP % ":", M % "root"))
    check("two files colour the name and the separator",
          s.run("grep --color=always root /tmp/g1.txt "
                "/tmp/g2.txt").splitlines()[0],
          "%s%salpha %s" % (FN % "/tmp/g1.txt", SEP % ":", M % "root"))
    check("-H -n stacks both",
          s.run("grep --color=always -Hn root /tmp/g1.txt").splitlines()[0],
          "%s%s%s%salpha %s" % (FN % "/tmp/g1.txt", SEP % ":", N % "1",
                                SEP % ":", M % "root"))
    check("-c colours the name but not the count",
          s.run("grep --color=always -c root /tmp/g1.txt "
                "/tmp/g2.txt").splitlines(),
          ["%s%s2" % (FN % "/tmp/g1.txt", SEP % ":"),
           "%s%s1" % (FN % "/tmp/g2.txt", SEP % ":")])
    check("-l colours the name alone",
          s.run("grep --color=always -l root /tmp/g1.txt "
                "/tmp/g2.txt").splitlines(),
          [FN % "/tmp/g1.txt", FN % "/tmp/g2.txt"])
    check("-v has nothing to highlight",
          s.run("grep --color=always -v root /tmp/g1.txt"), "beta\n")
    check("a context line stays plain",
          s.run("grep --color=always -A1 alpha /tmp/g1.txt"),
          "%s root\nbeta\n" % (M % "alpha"))

    # -- egrep and fgrep carry their flag -----------------------------------
    # `cmd_egrep = cmd_grep` dropped the -E, so `egrep 'ro+t'` ran a basic
    # regex where + is a literal plus and matched nothing -- and that alias
    # shadowed a correct two-line cmd_egrep defined earlier in the class.
    v9, s9 = sh()
    s9.fs.write("/tmp/g9.txt", b"root root\nxrootx\nro+t\n")
    check("egrep is grep -E",
          s9.run("egrep 'ro+t' /tmp/g9.txt").splitlines()[:2],
          ["root root", "xrootx"])
    check("...and grep alone is not",
          s9.run("grep 'ro+t' /tmp/g9.txt"), "ro+t\n")
    check("fgrep is grep -F",
          s9.run("fgrep 'ro+t' /tmp/g9.txt"), "ro+t\n")
    check("there is one definition of each",
          (F.Shell.cmd_egrep is F.Shell.cmd_grep,
           F.Shell.cmd_fgrep is F.Shell.cmd_grep), (False, False))

    # -- auto follows the terminal ---------------------------------------------
    check("auto is bare when there is no terminal",
          s.run("grep --color=auto root /tmp/g1.txt"),
          "alpha root\ngamma root\n")
    check("...and so is a bare --color",
          s.run("grep --color root /tmp/g1.txt"),
          "alpha root\ngamma root\n")
    check("never is bare too",
          s.run("grep --color=never root /tmp/g1.txt"),
          "alpha root\ngamma root\n")
    check("and no flag at all is bare",
          s.run("grep root /tmp/g1.txt"), "alpha root\ngamma root\n")

    v2, s2 = sh(tty=True)
    check("auto colours on a terminal",
          s2.run("grep --color=auto root /tmp/g1.txt"),
          "alpha %s\ngamma %s\n" % (M % "root", M % "root"))
    check("...and a bare --color does as well",
          s2.run("grep --color root /tmp/g1.txt"),
          "alpha %s\ngamma %s\n" % (M % "root", M % "root"))
    check("never stays bare even on a terminal",
          s2.run("grep --color=never root /tmp/g1.txt"),
          "alpha root\ngamma root\n")
    # ...and a pipe inside that terminal session is not a terminal.
    check("auto is bare through a pipe on a tty",
          s2.run("grep --color=auto root /tmp/g1.txt | cat"),
          "alpha root\ngamma root\n")
    check("always still colours through that pipe",
          M % "root" in s2.run("grep --color=always root /tmp/g1.txt | cat"),
          True)

    # -- the highlighting itself -------------------------------------------------
    v3, s3 = sh()
    s3.fs.write("/tmp/g3.txt", b"root root\nxrootx\n")
    check("every match on a line is wrapped",
          s3.run("grep --color=always root /tmp/g3.txt").splitlines()[0],
          "%s %s" % (M % "root", M % "root"))
    check("a match inside a word is wrapped in place",
          s3.run("grep --color=always root /tmp/g3.txt").splitlines()[1],
          "x%sx" % (M % "root"))
    check("two patterns colour one match once",
          s3.run("grep --color=always -e roo -e root "
                 "/tmp/g3.txt").splitlines()[1],
          "x%sx" % (M % "root"))
    check("-i colours what it matched, not what was typed",
          s3.run("grep --color=always -i ROOT /tmp/g3.txt").splitlines()[1],
          "x%sx" % (M % "root"))
    check("-o gives the match without the line",
          s3.run("grep --color=always -o root /tmp/g3.txt").splitlines()[0],
          "root")

    # -- and the box is otherwise unchanged ---------------------------------------
    check("egrep is still grep -E",
          s3.run("egrep --color=always 'ro+t' /tmp/g3.txt").splitlines()[0],
          "%s %s" % (M % "root", M % "root"))
    check("a miss is still rc 1",
          s3.dispatch("grep", ["--color=always", "zzz", "/tmp/g1.txt"],
                      "")[1], 1)
    check("stdin still works",
          s3.run("echo 'has root here' | grep --color=always root"),
          "has %s here\n" % (M % "root"))

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("colortest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
