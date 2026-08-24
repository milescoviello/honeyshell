#!/usr/bin/env python3
"""Does pathname expansion match the real shell's?

Twelfth coherence sweep. Globs are in every payload that touches more than
one file -- `cat /etc/*release`, `ls /proc/[0-9]*`, `rm -rf /tmp/*`,
`for f in /tmp/.ICE-unix/*` -- and expansion had never been tested as an
axis.

Found in one pass:

  * A glob in a `for` list was not expanded at all. `for f in /tmp/*` ran
    once, with f set to the literal string "/tmp/*". That is the shape of
    every loop that walks a directory of dropped files.
  * `*/` matched everything rather than directories only, so `ls -d */`
    listed the whole directory.
  * Sort order sent me the wrong way first. Expansion sorted in byte order
    while the dev host's bash sorted by en_US collation, so I "fixed" the
    emulator to match the dev host -- and the guest then disagreed, because
    it runs C.UTF-8. Checking what the box itself claimed settled it: it
    advertised LANG=en_US.UTF-8 while having no locales package, no
    /etc/default/locale, and a `locale -a` that printed nothing. It was
    claiming a locale it had no support for. A stock Debian image is
    C.UTF-8, where collation is byte order, so the original behaviour was
    right and the persona was wrong. LANG is C.UTF-8 now and `locale` and
    `locale -a` answer.
  * `ls a.txt b.txt` printed a "name:" heading above each file. GNU ls heads
    only *directory* operands, and lists file operands first and plainly.

The fixture is built identically on both sides -- same names, same contents,
same trailing newlines -- so a difference is the shell's and not the
harness's.
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

NAMES = ("a.txt", "b.txt", "c.log", ".dot", "x1", "x2", "x10", "X.TXT",
         "f-1", "f_2")

CASES = [
    "echo {D}/*.txt",
    "echo {D}/*",
    "echo {D}/x?",
    "echo {D}/x[12]",
    "echo {D}/[abc]*",
    "echo {D}/[a-c]*",
    "echo {D}/[!x]*.txt",
    "echo {D}/x*",
    "echo {D}/*.log",
    "echo {D}/??.txt",
    "echo {D}/.*",
    "echo {D}/nomatch*",
    "echo {D}/*/*.txt",
    "echo {D}/*.{{txt,log}}",
    "ls {D}/*.txt",
    "ls -d {D}/*/",
    "ls {D}/a.txt {D}/b.txt",
    "ls {D}/a.txt {D}/sub",
    "for f in {D}/*.txt; do echo \"[$f]\"; done",
    "for f in {D}/nomatch*; do echo \"[$f]\"; done",
    "for f in {D}/*; do printf '%s|' \"$(basename $f)\"; done; echo",
    "cat {D}/*.txt | wc -l",
    "rm -f {D}/nope*; echo rc=$?",
    "echo {D}/sub/*",
    "cd {D} && echo *.txt",
    "cd {D} && echo *",
    "cd {D} && ls *.log",
]


def main():
    verbose = "-v" in sys.argv
    real = tempfile.mkdtemp(prefix="globtest-")
    ours = "/tmp/globtest"
    # Same tree on both sides, contents written the same way so wc -l agrees.
    build = ("mkdir -p {D}/sub {D}/.hidden; "
             + "".join("echo x > {D}/%s; " % n for n in NAMES)
             + "echo y > {D}/sub/inner.txt")
    subprocess.run(["bash", "-c", "umask 022\n" + build.replace("{D}", real)],
                   capture_output=True,
                   env=dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8"))
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.run("rm -rf %s; " % ours + build.replace("{D}", ours))

    ok = bad = 0
    for tpl in CASES:
        rcmd = tpl.replace("{D}", real)
        ocmd = tpl.replace("{D}", ours)
        try:
            # The box is C.UTF-8, so the reference must be too: collation
            # decides glob order, and the dev host runs en_US.UTF-8 while
            # the guest runs C.UTF-8. Without pinning it the same suite
            # disagreed with itself across the two machines.
            env = dict(os.environ, LC_ALL="C.UTF-8", LANG="C.UTF-8")
            r = subprocess.run(["bash", "--noprofile", "--norc", "-c", rcmd],
                               capture_output=True, text=True, timeout=20,
                               env=env)
        except (OSError, subprocess.TimeoutExpired):
            continue
        want = r.stdout.replace(real, "<G>")
        got = sh.run(ocmd).replace(ours, "<G>")
        sh._err.clear()
        if want == got:
            ok += 1
            if verbose:
                print("  ok   %-42s %r" % (tpl.replace("{D}", "<G>")[:42],
                                           want[:34]))
        else:
            bad += 1
            print("  DIFF %s" % tpl.replace("{D}", "<G>"))
            print("       real %r" % want[:80])
            print("       ours %r" % got[:80])

    print()
    print("=" * 60)
    print("%d/%d match  (%d differ)" % (ok, ok + bad, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
