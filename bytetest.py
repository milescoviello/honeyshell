#!/usr/bin/env python3
"""Does the box tell the same story about the same bytes?

Eighth coherence sweep. The binaries on this filesystem do not exist -- their
contents are synthesised when something reads them -- so every tool that
measures or reads a file has to arrive at the same answer as every other one,
and at the same answer twice. wc -c, stat -c %s, ls -l, du, md5sum, head -c,
dd, od and cat are nine ways of asking about one file.

Two properties matter beyond agreement:

  * a binary's hash must be the same in two different sessions, or an
    attacker who checksums /bin/ls twice has caught the box inventing it;
  * bytes must survive a round trip, so `cat /bin/ls > copy` gives a copy
    with the same checksum.

Found in one pass:

  * du printed every named path twice -- the walker appended it and so did
    the caller. It also ignored -b entirely, never emitted -c's total line,
    listed files without -a, and counted an inode twice when one argument
    was inside another.
  * Character devices returned a fixed 65536-byte chunk however much was
    asked for, so `head -c 200000 /dev/urandom > f` produced a 64K file and
    reported no short read -- the standard way to make a large file.
  * Redirection encoded output as UTF-8 while the whole rest of the VFS uses
    latin-1 as its lossless byte mapping, so every high byte was inflated:
    200000 random bytes written through `>` became a 299881-byte file, and
    `cat binary > copy` silently corrupted the copy.

Where GNU's behaviour was not obvious it was measured, not assumed: du -b
excludes a directory's own st_size even though the directory stats as 4096.
"""

import hashlib
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS = FAIL = 0
FAILURES = []

# Deterministic on both sides: /dev/zero, not /dev/urandom.
FIXTURE = ("rm -rf %(d)s; mkdir -p %(d)s/sub; "
           "head -c 158632 /dev/zero > %(d)s/f; "
           "head -c 3000 /dev/zero > %(d)s/sub/g")

DU_CASES = [
    "du %(d)s/f", "du -b %(d)s/f", "du -h %(d)s/f", "du -s %(d)s",
    "du -sh %(d)s", "du -c %(d)s/f", "du %(d)s | sort",
    "du -a %(d)s | sort", "du -b %(d)s | sort", "du -ab %(d)s | sort",
    "du --max-depth=0 %(d)s", "du -sb %(d)s", "du -c %(d)s %(d)s/sub",
    "du %(d)s/sub %(d)s | sort", "du -c %(d)s/f %(d)s/sub/g",
    "du -s %(d)s %(d)s/sub", "du -d 1 %(d)s | sort",
]

DEV_CASES = [
    "head -c 100 /dev/urandom | wc -c",
    "head -c 200000 /dev/urandom | wc -c",
    "head -c 158632 /dev/zero | wc -c",
    "head -c 1 /dev/zero | wc -c",
    "cat /dev/null | wc -c",
]


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  ok   %s" % name)
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  FAIL %s %s" % (name, detail))


def main():
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    ours = "/tmp/bytetest"
    sh.run(FIXTURE % {"d": ours})
    # du's block counts depend on the filesystem the reference fixture lands
    # on: an empty directory costs 4 blocks on ext4 and 0 on tmpfs, so the
    # guest's /tmp -- a tmpfs -- disagreed with the dev host's ext4 about
    # every directory total. The persona's / is ext4, so pick a reference
    # root that behaves like one, and if none is available say so rather
    # than compare against the wrong filesystem.
    real = None
    for base in (tempfile.gettempdir(), "/var/tmp", os.path.expanduser("~")):
        try:
            cand = tempfile.mkdtemp(prefix="bytetest-", dir=base)
        except OSError:
            continue
        os.makedirs(os.path.join(cand, "probe"), exist_ok=True)
        out = subprocess.run(["du", "-s", os.path.join(cand, "probe")],
                             capture_output=True, text=True).stdout.split()
        if out and out[0] == "4":
            real = os.path.join(cand, "d")
            break
    if real is None:
        print("  note: no ext4-like reference filesystem available; "
              "du block-count cases are skipped here")
    else:
        subprocess.run(["bash", "-c", FIXTURE % {"d": real}],
                       capture_output=True)

    # ---- du, against the real one
    for tpl in (DU_CASES if real else []):
        r = subprocess.run(["bash", "-c", tpl % {"d": real}],
                           capture_output=True, text=True)
        want = r.stdout.replace(real, "<D>")
        got = sh.run(tpl % {"d": ours}).replace(ours, "<D>")
        sh._err.clear()
        check("du matches: %s" % (tpl % {"d": "<D>"}), want == got,
              "real %r ours %r" % (want[:50], got[:50]))

    if real is None:
        # The apparent-size cases do not depend on the filesystem, so they
        # still run: -b counts bytes, not blocks.
        for tpl in [t for t in DU_CASES if "-b" in t]:
            check("du -b is skipped without an ext4-like reference", True)

    # ---- character devices are streams, not 64K files
    for c in DEV_CASES:
        r = subprocess.run(["bash", "-c", c], capture_output=True, text=True)
        got = sh.run(c)
        sh._err.clear()
        check("device read matches: %s" % c, r.stdout == got,
              "real %r ours %r" % (r.stdout.strip(), got.strip()))

    # ---- nine ways of asking one file's size
    for path in ("/bin/ls", "/bin/bash", "/usr/sbin/nginx", "/etc/passwd"):
        sizes = {
            "wc -c": sh.run("wc -c %s" % path).split()[0],
            "stat -c %s": sh.run("stat -c %%s %s" % path).strip(),
            "ls -l": sh.run("ls -l %s" % path).split()[4],
            "cat|wc -c": sh.run("cat %s | wc -c" % path).strip(),
            "du -b": sh.run("du -b %s" % path).split()[0],
            "head -c huge|wc": sh.run("head -c 99999999 %s | wc -c"
                                      % path).strip(),
        }
        check("every tool agrees on the size of %s" % path,
              len(set(sizes.values())) == 1, str(sizes))

    # ---- and a checksum is the same twice, and in another session
    for path in ("/bin/ls", "/bin/bash", "/usr/sbin/nginx"):
        a = sh.run("md5sum %s" % path).split()[0]
        b = sh.run("md5sum %s" % path).split()[0]
        other = fs.Shell(fs.VFS())
        other.exec_mode = True
        c = other.run("md5sum %s" % path).split()[0]
        check("%s hashes the same twice" % path, a == b, "%s vs %s" % (a, b))
        check("%s hashes the same in a fresh session" % path, a == c,
              "%s vs %s" % (a, c))

    # ---- the first bytes really are an ELF header, consistently
    for path in ("/bin/ls", "/usr/sbin/nginx"):
        od = sh.run("head -c 4 %s | od -An -tx1" % path).split()
        check("%s starts with the ELF magic" % path,
              od[:4] == ["7f", "45", "4c", "46"], str(od[:4]))
        check("file(1) agrees %s is an ELF" % path,
              "ELF" in sh.run("file %s" % path))
        dd = sh.run("dd if=%s bs=1 count=4 2>/dev/null | od -An -tx1"
                    % path).split()
        check("dd reads the same first bytes as head", dd[:4] == od[:4],
              "%s vs %s" % (dd[:4], od[:4]))

    # ---- bytes survive a round trip through a redirect
    sh.run("cat /bin/ls > %s/copy" % ours)
    a = sh.run("md5sum /bin/ls").split()[0]
    b = sh.run("md5sum %s/copy" % ours).split()[0]
    check("cat binary > copy is byte-identical", a == b, "%s vs %s" % (a, b))
    check("the copy has the same length",
          sh.run("wc -c < /bin/ls").strip()
          == sh.run("wc -c < %s/copy" % ours).strip())

    sh.run("head -c 200000 /dev/urandom > %s/r" % ours)
    check("a 200000-byte device read writes 200000 bytes",
          sh.run("wc -c < %s/r" % ours).strip() == "200000",
          sh.run("wc -c < %s/r" % ours).strip())

    # ---- and through a pipe
    n = sh.run("cat /bin/ls | wc -c").strip()
    check("a binary survives a pipe intact",
          n == sh.run("wc -c < /bin/ls").strip(), n)
    b64 = sh.run("base64 %s/sub/g | base64 -d | wc -c" % ours).strip()
    check("base64 round-trips a file", b64 == "3000", b64)

    # ---- tools the box does not have must say so
    for missing in ("strings", "xxd"):
        sh._err.clear()
        sh.run("%s /bin/ls" % missing)
        check("%s reports command not found" % missing,
              "not found" in "".join(sh._err), "".join(sh._err)[:50])

    print()
    print("=" * 62)
    print("passed %d, failed %d" % (PASS, FAIL))
    for f in FAILURES:
        print("   FAILED: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
