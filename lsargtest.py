#!/usr/bin/env python3
"""ls with more than one operand -- order, grouping, and shared columns.

Every other ls suite here lists one thing. An attacker rarely does: the
203.0.113.26 session on 2026-08-23 ran a single `ls -la` over eight paths
at once -- Telegram tdata, SMS-gateway spool files, modem device nodes --
most of which did not exist. That is the shape this suite covers.

Four defects it froze, all of them silent wrong answers rather than errors:

  * operands were never sorted. `ls f2 f1` printed them as typed and
    `ls d2 d1` put d2's block first, where GNU ls sorts operands with the
    same comparator it uses for directory entries.
  * -t and -S tie-broke on VFS insertion order instead of the name, so a
    dropper writing five files in one script -- one mtime to the second --
    listed them in an order no real ls produces, under the very command
    used to see what just landed.
  * every non-directory operand was rendered as its own block, so the
    long-format column widths were computed per file: `ls -l f1 big`
    printed "5" and "41" unaligned instead of right-aligning both.
  * a failed operand still counted as a preceding block, so `ls nope d1`
    opened with a blank line.

Machine-independent: each case runs against real bash and real coreutils ls
in a temp directory and against the emulator's VFS, and stdout, stderr and
exit status must all match. Ownership, inode numbers and the clock differ
between the two worlds by construction and are normalised out; nothing
about ordering or column layout is.

Run from ~/opsec/honeypot:  python3 -W ignore lsargtest.py
"""
import os
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

SETUP = [
    "mkdir -p d1 d2 emptyd d1/sub",
    "printf 'aaaa\\n' > f1",
    "printf 'bb\\n' > f2",
    "printf '%s\\n' xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx > big",
    "printf 'x\\n' > d1/a", "printf 'yy\\n' > d1/b", "printf 'z\\n' > d2/c",
    "mkdir -p a b", "touch a/b b/a",
    "ln -s f1 s1",
    # One explicit mtime everywhere, so -t and -S are tested on their
    # tie-break rather than on whichever filesystem has finer timestamps.
    "touch -d '2025-01-01 00:00:00' f1 f2 big d1 d2 emptyd d1/a d1/b d2/c "
    "a b a/b b/a d1/sub",
]

CASES = [
    # the mixed-operand basics
    "ls f1 f2", "ls f2 f1", "ls f1 f1", "ls f1 f1 f1",
    "ls d1 d2", "ls d2 d1", "ls f1 d1", "ls d1", "ls d1/sub d1",
    "ls . d1", "ls b/a a/b", "ls d1/a d1",
    # operands that do not exist: message, order, rc, and no stray blank line
    "ls nope", "ls nope f1", "ls nope2 nope f1", "ls nope d1",
    "ls nope nope2", "ls -d nope d1", "ls nope*",
    "ls -l nope f1", "ls -l nope f1 big",
    # long format shares its column widths across the whole file block
    "ls -l f1 f2", "ls -l f1 big", "ls -lh f1 big", "ls -l d1 d2",
    "ls -l emptyd d1", "ls -n f1", "ls -g f1", "ls -o f1",
    # the sort flags reach the operands too
    "ls -U f2 f1", "ls -r f2 f1", "ls -t f1 f2", "ls -tr f1 f2",
    "ls -S f1 big f2", "ls -X f2 f1", "ls -rt d1 d2", "ls -U d2 d1",
    "ls -r d1 d2", "ls -r f1 d1", "ls -U d1 f1",
    # ...but the file/directory split is fixed, whatever the sort says
    "ls -d d1 d2", "ls -ld d1 d2", "ls -ld f1 d1", "ls -d .", "ls -d d1",
    # recursion, emptiness, symlinks, and the per-entry prefixes
    "ls", "ls .", "ls -l", "ls -a", "ls -A",
    "ls -R", "ls -R .", "ls -Rl d1", "ls -R d1", "ls -Ra d2",
    "ls -R d1 d2 f1", "ls -lR d2 emptyd",
    "ls emptyd", "ls -l emptyd", "ls emptyd d1", "ls d1 emptyd",
    "ls s1", "ls -l s1", "ls -l s1 f1", "ls -L s1", "ls s1 f1",
    "ls -F s1 d1 f1", "ls -i f1 f2", "ls -s f1 big", "ls -ls d1",
    "ls -1 f1 f2", "ls -la d1 d2", "ls -a d2 emptyd", "ls f1 emptyd f2",
]


def norm(t):
    """Strip what differs between the two worlds by construction.

    The emulator is root-owned, has its own inode space, and its VFS root is
    0755 where a mkdtemp directory is 0700. None of that is ordering or
    layout, which is all this suite is about.
    """
    t = t.replace("miles miles", "OWNER").replace("root root", "OWNER")
    t = t.replace("1000 1000", "OWNER").replace(" 0 0 ", " OWNER ")
    t = re.sub(r"\b1 (miles|root) ", "1 OWNER ", t)
    t = re.sub(r"\b[A-Z][a-z]{2} [ 0-9]\d[ 0-9:]{5,6}\b", "TIME", t)
    t = re.sub(r"(?m)^\d{4,} ", "INO ", t)
    t = re.sub(r"(?m)^d\S{9}( \d+ OWNER +4096 TIME \.\.)$", r"dMODE\1", t)
    return t


def real(cmd, tmp):
    p = subprocess.run(["bash", "--noprofile", "--norc", "-c",
                        "export LC_ALL=C; " + cmd],
                       capture_output=True, text=True, timeout=20, cwd=tmp)
    return norm(p.stdout), p.stderr, p.returncode


def ours(cmd):
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.run("rm -rf /work; mkdir -p /work; cd /work")
    sh.cwd = "/work"
    for step in SETUP:
        sh.run(step)
    # run() returns stdout only; stderr is a separate buffer the SSH layer
    # drains, which is why a suite must read _err rather than redirect.
    del sh._err[:]
    out = sh.run(cmd)
    return norm(out), "".join(sh._err), sh.last_rc


# `ls -U` means "do not sort", so the order is whatever order readdir hands
# the entries back in -- the filesystem's choice, not ls's and certainly not
# this emulator's. These two passed on ext4, passed on btrfs, passed on a
# local overlayfs, and failed on the overlayfs GitHub Actions gives a
# container. A test that depends on the host's directory hashing is testing
# the host. The entry *set* is the emulator's contract, so compare that.
FS_ORDER = {"ls -U d2 d1", "ls -U d1 f1"}


def unordered(t):
    return "\n".join(sorted(t.split("\n")))


def main():
    verbose = "-v" in sys.argv
    tmp = tempfile.mkdtemp()
    subprocess.run(["bash", "-c", "umask 022; " + "; ".join(SETUP)], cwd=tmp,
                   capture_output=True)
    ok = bad = 0
    for cmd in CASES:
        try:
            ro, re_, rrc = real(cmd, tmp)
            oo, oe, orc = ours(cmd)
        except Exception as exc:                              # noqa: BLE001
            bad += 1
            print("  ERROR   $ %s -> %r" % (cmd, exc))
            continue
        if cmd in FS_ORDER:
            ro, oo = unordered(ro), unordered(oo)
        which = ([] + (["stdout"] if ro != oo else [])
                 + (["stderr"] if re_ != oe else [])
                 + (["rc"] if rrc != orc else []))
        if not which:
            ok += 1
            if verbose:
                print("  ok      $ %s" % cmd)
            continue
        bad += 1
        print("  DIFFER  $ %s  [%s]" % (cmd, ",".join(which)))
        if ro != oo:
            print("     real out: %r" % ro[:200])
            print("     ours out: %r" % oo[:200])
        if re_ != oe:
            print("     real err: %r" % re_[:200])
            print("     ours err: %r" % oe[:200])
        if rrc != orc:
            print("     real rc=%s  ours rc=%s" % (rrc, orc))
    print("\nlsargtest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
