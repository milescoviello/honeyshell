#!/usr/bin/env python3
"""From a written file to a running process: chmod, the shebang, and source.

Every loader on this box does the same three things -- write a script, make
it executable, run it -- and there are several ways to do each. exectest.py
covers how execution *fails*. This asks whether the ways of succeeding agree
with each other, and they did not.

chmod's leading-dash modes never worked at all. The argument parser dropped
every "-<letter>" as an option, so `chmod -x`, `-w`, `-r`, `-s`, `-t` and
`-rwx` silently changed nothing with one operand and failed with "invalid
mode" with two, and `chmod -r` was routed to the recursive branch, which is
`-R` only. Disabling a dropped binary with `chmod -x` is ordinary
housekeeping and it had never once worked. Separately, a clause with no
who-class is limited by the umask -- `chmod +w` on a 0444 file gives 0644,
not the 0666 we produced -- except for `=`, which is not limited, and GNU
warns and exits 1 when the umask blocks a bare `-`. All of that is measured
against the real chmod here, 340 combinations of mode and starting
permission, one and two operands.

The shebang did not decide what shell the script ran in. A child gets the
environment, and BASH_VERSION is not exported by a real bash either, so a
script run through its own `#!/bin/bash` had no BASH_VERSION while the
identical file run as `bash s.sh` did -- and `[ -n "$BASH_VERSION" ]` is the
standard way a stager picks its syntax. `#!/bin/sh` now yields a shell with
BASH_VERSION unset, which is what tells dash from bash on Debian.

source got four things wrong. `exit` in a sourced file must end the calling
shell -- it runs in the current shell, the same rule the `{ ... }` group
already followed -- and instead the caller carried on, so we ran commands a
real box would never have reached. `return` must end only the file, and once
`exit` propagated it killed the caller too. `. f a b` sets the positional
parameters and did not, so a sourced stager saw $# of 0. And a missing file
was reported as "bash: source: x: ..." where bash says "bash: line 1: x:".

Machine-independent: every case runs against real bash and real coreutils in
a fresh temp directory and against the emulator, and stdout and stderr must
match. The build host's bash version differs from the persona's by design
and is normalised; nothing else is.

Run from ~/opsec/honeypot:  python3 -W ignore scripttest.py
"""
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

SETUP = [
    r"""printf '#!/bin/bash\necho "dollar0=$0"\necho "count=$#"\necho "one=$1"\nMARK=set-by-script\necho "shell=${BASH_VERSION:+bash}${BASH_VERSION:-nobash}"\nexit 7\n' > s.sh""",
    r"""printf '#!/bin/sh\necho plain-sh\n' > p.sh""",
    r"""printf 'echo noshebang\n' > n.sh""",
    r"""printf '#!/bin/sh\necho "sh-shell=${BASH_VERSION:+bash}${BASH_VERSION:-nobash}"\n' > d.sh""",
    r"""printf '#!/usr/bin/env bash\necho "env-shell=${BASH_VERSION:+bash}${BASH_VERSION:-nobash}"\n' > e.sh""",
    r"""printf 'VAR=fromsource\nreturn 4\necho notreached\n' > r.sh""",
    r"""printf 'echo inner\n. ./r.sh\necho after-inner\n' > o.sh""",
    r"""printf 'f(){ exit 9; }\nf\necho notreached\n' > fx.sh""",
    "chmod +x s.sh p.sh d.sh e.sh",
]

INVOKE = [
    # the same script, run every way a loader runs one
    "./s.sh; echo rc=$?",
    "./s.sh a b; echo rc=$?",
    "sh s.sh; echo rc=$?",
    "bash s.sh; echo rc=$?",
    "bash s.sh a b; echo rc=$?",
    "sh -c ./s.sh; echo rc=$?",
    "cat s.sh | sh; echo rc=$?",
    "cat s.sh | bash; echo rc=$?",
    "bash ./s.sh; echo rc=$?",
    "/bin/sh s.sh; echo rc=$?",
    "command ./s.sh; echo rc=$?",
    "exec 2>/dev/null; ./s.sh; echo rc=$?",
    "eval \"$(cat n.sh)\"; echo rc=$?",
    "./n.sh; echo rc=$?",
    "sh n.sh; echo rc=$?",
    "./p.sh; echo rc=$?",
    "bash -c 'echo $0' ; echo rc=$?",
    "sh -c 'echo $0 $1' x y; echo rc=$?",
    # which shell the shebang actually picks
    "./d.sh; echo rc=$?",
    "./e.sh; echo rc=$?",
    "sh d.sh; echo rc=$?",
    "bash d.sh; echo rc=$?",
    "bash -c 'echo ${BASH_VERSION:+bash}${BASH_VERSION:-nobash}'",
    "sh -c 'echo ${BASH_VERSION:+bash}${BASH_VERSION:-nobash}'",
    # source: exit ends the caller, return ends only the file
    "MARK=orig; . ./s.sh; echo rc=$?; echo mark=$MARK",
    "MARK=orig; ./s.sh >/dev/null; echo mark=$MARK",
    ". ./r.sh; echo rc=$?; echo var=$VAR",
    "source ./r.sh; echo rc=$?; echo var=$VAR",
    ". ./o.sh; echo rc=$?",
    ". ./fx.sh; echo after",
    ". ./nosuch.sh; echo rc=$?",
    ". ./n.sh; echo rc=$?",
    ". ./s.sh a b",
    "echo 'exit 5' > z.sh; . ./z.sh; echo after",
    # the execute bit actually gating execution
    "chmod 644 s.sh; ./s.sh; echo rc=$?",
    "chmod 755 s.sh; ./s.sh; echo rc=$?",
    "chmod -x s.sh; ./s.sh; echo rc=$?",
    "chmod -x s.sh; sh s.sh; echo rc=$?",
    "chmod +x n.sh; ./n.sh; echo rc=$?",
    "set -e; ./s.sh; echo after",
]

MODES = [
    "+x", "-x", "+w", "-w", "+r", "-r", "+rwx", "-rwx",
    "a+x", "a-x", "u+x", "u-x", "g-w", "o-r", "go-w", "go-rwx",
    "u=rwx,go=", "a=r", "u+s", "g+s", "+t", "-t", "+s", "-s",
    "u+rw,g-w,o=", "=x", "a+X", "u+X", "+X",
    "0755", "755", "4755", "0644", "1777",
]
STARTS = ["0664", "0755", "0600", "0777", "0444"]


def devers(t):
    """The persona's bash version against the build host's, by design."""
    return re.sub(r"bash5\.\d+\.\d+\(1\)-release", "bashVER", t)


def real_sh(cmd):
    """Fresh directory per case: a `chmod -x` must not leak into the next."""
    tmp = tempfile.mkdtemp()
    subprocess.run(["bash", "-c", "umask 022; " + "; ".join(SETUP)],
                   cwd=tmp, capture_output=True)
    p = subprocess.run(["bash", "--noprofile", "--norc", "-c",
                        "export LC_ALL=C; " + cmd],
                       capture_output=True, text=True, timeout=20, cwd=tmp)
    return devers(p.stdout), devers(p.stderr)


def ours_sh(cmd):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.run("rm -rf /work; mkdir -p /work")
    sh.cwd = "/work"
    for step in SETUP:
        sh.run(step)
    del sh._err[:]
    return devers(sh.run(cmd)), devers("".join(sh._err))


def real_chmod(mode, start, nfiles):
    tmp = tempfile.mkdtemp()
    files = " ".join("f%d" % i for i in range(nfiles))
    p = subprocess.run(
        ["bash", "-c",
         "export LC_ALL=C; umask 022; touch %s; chmod %s %s; "
         "chmod %s %s; echo rc=$?; stat -c '%%a' %s"
         % (files, start, files, mode, files, files)],
        capture_output=True, text=True, timeout=20, cwd=tmp)
    return p.stdout, p.stderr


def ours_chmod(mode, start, nfiles):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.run("rm -rf /w; mkdir -p /w")
    sh.cwd = "/w"
    files = " ".join("f%d" % i for i in range(nfiles))
    sh.run("touch %s" % files)
    sh.run("chmod %s %s" % (start, files))
    del sh._err[:]
    out = sh.run("chmod %s %s; echo rc=$?; stat -c '%%a' %s"
                 % (mode, files, files))
    return out, "".join(sh._err)


def main():
    verbose = "-v" in sys.argv
    ok = bad = 0

    def compare(label, real, ours):
        nonlocal ok, bad
        if real == ours:
            ok += 1
            if verbose:
                print("  ok      %s" % label)
            return
        bad += 1
        print("  DIFFER  %s" % label)
        if real[0] != ours[0]:
            print("     real out: %r" % real[0][:200])
            print("     ours out: %r" % ours[0][:200])
        if real[1] != ours[1]:
            print("     real err: %r" % real[1][:200])
            print("     ours err: %r" % ours[1][:200])

    for cmd in INVOKE:
        try:
            compare("$ " + cmd, real_sh(cmd), ours_sh(cmd))
        except Exception as exc:                              # noqa: BLE001
            bad += 1
            print("  ERROR   $ %s -> %r" % (cmd, exc))

    for nfiles in (1, 2):
        for start in STARTS:
            for mode in MODES:
                label = "chmod %s (from %s, %d file%s)" % (
                    mode, start, nfiles, "" if nfiles == 1 else "s")
                try:
                    compare(label, real_chmod(mode, start, nfiles),
                            ours_chmod(mode, start, nfiles))
                except Exception as exc:                      # noqa: BLE001
                    bad += 1
                    print("  ERROR   %s -> %r" % (label, exc))

    print("\nscripttest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
