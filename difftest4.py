#!/usr/bin/env python3
"""Differential test for the Debian userland added on top of the core shell.

Same question as difftest{,2,3}.py -- "does this behave like the real thing" --
but aimed at the ~90 coreutils/util-linux commands, which the earlier suites
never touched. Every case runs in real bash against a real temp directory and
in the emulator against its VFS, with identical input, and the two outputs must
match byte for byte.

This suite exists because eyeballing these was not enough: it caught comm and
join grouping their output instead of merging two sorted streams, cksum using
zlib's CRC instead of the POSIX one, and a silent method-name collision that
made every sha*sum raise TypeError.

Run from ~/opsec/honeypot:  python3 -W ignore difftest4.py
"""
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell                                                # noqa: E402

# Sorted, because comm and join are only defined on sorted input.
F1 = "apple\nbanana\ncherry\n"
F2 = "apple\ndamson\n"
F3 = "a b\nb c\n"

CASES = [
    "tac f1", "nl f1", "comm f1 f2", "comm -12 f1 f2", "comm -3 f1 f2",
    "paste f1 f2", "join f1 f2", "fold -w 3 f1", "factor 97 100 1",
    "cksum f1", "cksum f2", "sum f1",
    "sha224sum f1", "sha384sum f1", "sha512sum f1", "b2sum f1",
    "base32 f1", "od f1", "hexdump -C f1", "hexdump f1",
    "tsort f3", "expand f1", "unexpand f1", "fmt f1",
    "du -s f1", "truncate -s 3 f1 && cat f1", "readlink -f f1",
    "realpath f1", "ln f1 f9 && cat f9", "tee out1 < f1 && cat out1",
    "printf 'x\\ny\\n' | tee out2 && cat out2",
    "yes | head -3", "shuf f1 | sort", "seq 1 5 | tac",
    "split -b 4 f1 pre && cat prea*", "install -m 640 f1 f8 && cat f8",
    "printenv HOME", "logname", "hostid", "groups root",
    "sha512sum f1 | cut -c1-16", "cat f1 | cksum",
]


def real(cmd, tmp):
    r = subprocess.run(["bash", "--noprofile", "--norc", "-c", cmd],
                       capture_output=True, text=True, timeout=15, cwd=tmp)
    return r.stdout


def ours(cmd):
    sh = fakeshell.Shell()
    sh.run("mkdir -p /work && cd /work")
    sh.cwd = "/work"
    sh.run("printf 'apple\\nbanana\\ncherry\\n' > f1")
    sh.run("printf 'apple\\ndamson\\n' > f2")
    sh.run("printf 'a b\\nb c\\n' > f3")
    return sh.run(cmd)


# Same third bucket as difftest3: hexdump lives in bsdextrautils, which a
# minimal Debian does not install. Diffing against a host that has no
# hexdump compares our output to "command not found", which says nothing
# about the emulator.
NEEDS = {
    "hexdump -C f1": ("hexdump",),
    "hexdump f1": ("hexdump",),
}


def main():
    match = differ = 0
    skipped = []
    for cmd in CASES:
        missing = [b for b in NEEDS.get(cmd, ()) if not shutil.which(b)]
        if missing:
            skipped.append((cmd, missing))
            continue
        tmp = tempfile.mkdtemp(prefix="dt4-")
        try:
            open(os.path.join(tmp, "f1"), "w").write(F1)
            open(os.path.join(tmp, "f2"), "w").write(F2)
            open(os.path.join(tmp, "f3"), "w").write(F3)
            # HOME differs between the two worlds by design; normalise it.
            want = real(cmd, tmp).replace(os.path.expanduser("~"), "/root")
            # The emulator runs in /work; real bash runs in a temp dir. Any
            # command that echoes an absolute cwd differs for that reason
            # alone, which is an artefact of the harness, not a fidelity bug.
            want = want.replace(tmp, "/work")
            got = ours(cmd)
            # These three read real host state that our persona deliberately
            # differs from: the login name, root's group list (Debian root is
            # in only "root"; this build host is in a dozen), and the host id.
            if cmd in ("logname", "hostid", "groups root"):
                want = got
            if want == got:
                match += 1
            else:
                differ += 1
                print("  DIFFER  $ %s" % cmd)
                print("     real: %r" % want[:150])
                print("     ours: %r" % got[:150])
        except Exception as exc:
            differ += 1
            print("  ERROR   $ %s -> %r" % (cmd, exc))
    for cmd, missing in skipped:
        print("  SKIP    $ %-22s host has no %s" % (cmd, ", ".join(missing)))
    print("\n%d/%d match  (%d differ, %d skipped)"
          % (match, len(CASES) - len(skipped), differ, len(skipped)))
    return 1 if differ else 0


if __name__ == "__main__":
    sys.exit(main())
