#!/usr/bin/env python3
"""The same bytes, every way of moving them: do the answers agree?

Started by checking whether an attacker can get data *off* this box, since
chantest covers `scp -t` (upload) and nothing covered the other direction.
They can, and it is exact: scp and sftp both deliver /etc/shadow, /etc/passwd,
binaries, empty files and 4MB blobs with sizes and md5s matching what the
shell itself reports. That part was already right. Asking the question turned
up four things that were not.

base64 -d did not round-trip binary. The encode used latin-1 and the decode
used utf-8 with "replace", so every byte sequence that is not valid utf-8
became U+FFFD and multi-byte runs collapsed into one character: a 1000-byte
random file came back wrong and an 8MB one came back 5% short. Two halves of
one command disagreeing about the codec, on the single most common way there
is to land a binary through a shell -- `echo <b64> | base64 -d > /tmp/x`.
It produced a corrupted file and, because the capture reads what was written,
a corrupted record of the payload too.

Then three short reads with one cause. MAX_OUTPUT caps a command's output at
4MB, which is a guard against a generator that grows without limit -- `seq 1
5000000` alone once peaked at 3GB RSS against a 256MB service. But a command
told exactly how many bytes to produce, or copying a file whose size is
known, is not unbounded. `head -c 8388608 /dev/zero`, `tail -c` and `cat` on
an 8MB file all returned 4MB, silently and with status 0, while cp, dd, tar,
truncate, fallocate, wc and stat all agreed the file was 8MB. Six commands
describing one file and three of them short. They now declare their bound and
dispatch honours it up to 64MB, the same ceiling the character devices
already refuse to exceed; anything that has not declared one is capped as
before, which the last two checks here confirm.

Machine-independent: sizes and round-trips are diffed against the real
coreutils on this host, and the emulator's own commands are diffed against
each other, which needs no reference at all.

Run from ~/opsec/honeypot:  python3 -W ignore bigfiletest.py
"""
import hashlib
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

SIZES = [0, 1, 1000, 65536, 1048576, 4194303, 4194304, 4194305, 8388608]


def shell():
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    sh.run("rm -rf /w; mkdir -p /w")
    sh.cwd = "/w"
    return sh


def shell_list(sh4):
    """The listing tar produced for the truncated archive."""
    sh5 = shell()
    sh5.fs.write("/w/t.tar.gz", sh4.fs.read("/w/trunc.tar.gz"), mode=0o644)
    return sh5.run("tar tzf t.tar.gz")


def main():
    verbose = "-v" in sys.argv
    ok = bad = 0

    def check(label, got, want):
        nonlocal ok, bad
        if got == want:
            ok += 1
            if verbose:
                print("  ok    %s" % label)
        else:
            bad += 1
            print("  FAIL  %s" % label)
            print("        got  %r" % (got,))
            print("        want %r" % (want,))

    # ---- base64 round-trips the bytes, whatever they are -----------------
    sh = shell()
    for n in (0, 1, 3, 1000, 65536, 1048576, 8388608):
        sh.run("rm -f s b r")
        if n:
            sh.run("head -c %d /dev/urandom > s" % n)
        else:
            sh.run(": > s")
        sh.run("base64 s > b; base64 -d b > r")
        check("base64 round-trip is identical at %d bytes" % n,
              sh.run("cmp -s s r && echo same || echo differ").strip(), "same")
        check("...and the size is unchanged at %d" % n,
              sh.run("stat -c %s r").strip(), str(n))
    sh.run("head -c 65536 /dev/urandom > s")
    sh.run("base64 -w0 s > b0; base64 -d b0 > r0")
    check("base64 -w0 round-trips too",
          sh.run("cmp -s s r0 && echo same || echo differ").strip(), "same")
    check("high bytes survive a round-trip",
          sh.run(r"""printf '\x7fELF\x02\x01\x01\x00\xff\xfe\x80' > e
base64 e | base64 -d > e2
cmp -s e e2 && echo same || echo differ""").strip(), "same")
    check("and text still works",
          sh.run("echo hello | base64 | base64 -d").strip(), "hello")

    # ---- against the real coreutils --------------------------------------
    tmp = tempfile.mkdtemp()
    blob = os.urandom(1048576)
    open(os.path.join(tmp, "r.bin"), "wb").write(blob)
    real = subprocess.run(
        ["bash", "-c", "base64 r.bin | base64 -d | md5sum | cut -d' ' -f1"],
        capture_output=True, text=True, cwd=tmp).stdout.strip()
    sh2 = shell()
    sh2.fs.write("/w/r.bin", blob, mode=0o644)
    check("base64 round-trip md5 matches the real coreutils",
          sh2.run("base64 r.bin | base64 -d | md5sum | cut -d' ' -f1").strip(),
          real)
    check("...and it is the md5 of the bytes themselves",
          real, hashlib.md5(blob).hexdigest())

    # ---- and every way of hashing it agrees what it is -------------------
    # `md5sum f` hashed the file's bytes; `md5sum < f` hashed stdin through a
    # bare .encode(), which is utf-8, so the two spellings disagreed on every
    # file with a byte above 0x7F. Verifying a transferred payload is the
    # whole job of these commands.
    for algo, py in (("md5", hashlib.md5), ("sha1", hashlib.sha1),
                     ("sha256", hashlib.sha256)):
        for n in (1000, 65536, 1048576):
            raw = os.urandom(n)
            sh3 = shell()
            sh3.fs.write("/w/h.bin", raw, mode=0o644)
            want = py(raw).hexdigest()
            for spelling in ("%ssum h.bin" % algo,
                             "%ssum < h.bin" % algo,
                             "cat h.bin | %ssum" % algo,
                             "base64 h.bin | base64 -d | %ssum" % algo):
                check("%s (%d bytes)" % (spelling, n),
                      sh3.run(spelling).split()[0], want)

    # ---- every command agrees how big the file is ------------------------
    for n in SIZES:
        sh = shell()
        if n:
            sh.run("head -c %d /dev/zero > big" % n)
        else:
            sh.run(": > big")
        want = str(n)
        answers = {
            "stat": "stat -c %s big",
            "wc -c": "wc -c < big",
            "head -c": "head -c %d big > o; stat -c %%s o" % max(n, 1),
            "tail -c": "tail -c %d big > o; stat -c %%s o" % max(n, 1),
            "cat": "cat big > o; stat -c %s o",
            "cp": "cp big o2; stat -c %s o2",
            "tar": "tar cf t.tar big; mkdir -p ex; tar xf t.tar -C ex; "
                   "stat -c %s ex/big",
        }
        for name, cmd in answers.items():
            got = sh.run(cmd).strip().splitlines()
            check("%s says %d for a %d-byte file" % (name, n, n),
                  got[-1] if got else "(nothing)", want)
        check("cat produces the same bytes at %d" % n,
              sh.run("cat big > c1; cmp -s big c1 && echo same || echo differ"
                     ).strip(), "same")

    # ---- the other ways of making one agree too --------------------------
    sh = shell()
    for name, cmd in (("dd", "dd if=/dev/zero of=f bs=1M count=8 2>/dev/null"),
                      ("truncate", "truncate -s 8388608 f"),
                      ("fallocate", "fallocate -l 8388608 f"),
                      ("head -c", "head -c 8388608 /dev/zero > f")):
        sh.run("rm -f f; " + cmd)
        check("%s makes an 8MB file" % name,
              sh.run("stat -c %s f").strip(), "8388608")

    # ---- a truncated archive is an error, not an exception ---------------
    # This is what the short read actually cost. 203.0.113.33 came back at
    # 07:49 on 2026-08-24, downloaded an 8MB SRBMiner archive that our copy
    # of had been cut to 4MB, and ran `tar xzf` over it. A gzip member is
    # decompressed lazily, so the truncated body raised EOFError on the first
    # read, nothing caught it, and it left the shell as an unhandled
    # exception that ended the session -- logged as exec_crashed. Both halves
    # are fixed: the archive is no longer short, and a short one now says
    # what tar says.
    sh4 = shell()
    sh4.run("mkdir -p src; head -c 200000 /dev/urandom > src/big")
    sh4.run("tar czf good.tar.gz src")
    full = int(sh4.run("stat -c %s good.tar.gz").strip())
    sh4.run("head -c %d good.tar.gz > trunc.tar.gz" % (full // 2))
    for form, twice in (("xzf", True), ("tzf", False)):
        sh5 = shell()
        sh5.fs.write("/w/t.tar.gz",
                     sh4.fs.read("/w/trunc.tar.gz"), mode=0o644)
        del sh5._err[:]
        try:
            out = sh5.run("tar %s t.tar.gz; echo rc=$?" % form)
            err = "".join(sh5._err)
        except Exception as exc:                              # noqa: BLE001
            out, err = "raised %r" % (exc,), ""
        check("tar %s on a truncated archive exits 2" % form,
              out.strip().splitlines()[-1], "rc=2")
        check("tar %s reports the gzip EOF" % form,
              "gzip: stdin: unexpected end of file" in err, True)
        check("tar %s reports the archive EOF %s" % (form,
              "twice" if twice else "once"),
              err.count("tar: Unexpected EOF in archive"), 2 if twice else 1)
        check("tar %s gives up recoverably" % form,
              "tar: Error is not recoverable: exiting now" in err, True)
    check("tzf still lists the members it could read",
          "src/big" in shell_list(sh4), True)
    check("an intact archive still extracts",
          sh4.run("mkdir -p ex; tar xzf good.tar.gz -C ex; "
                  "stat -c %s ex/src/big").strip(), "200000")

    # ---- and the ceiling is still a ceiling ------------------------------
    sh = shell()
    ceiling = getattr(fs, "BOUNDED_OUTPUT_MAX", 64 * 1024 * 1024)
    check("head -c above the hard ceiling is capped",
          sh.run("head -c 134217728 /dev/zero > f; stat -c %s f").strip(),
          str(ceiling))
    check("an unbounded generator is still capped",
          len(sh.run("seq 1 5000000")) <= fs.MAX_OUTPUT, True)
    check("a character device with no count is still one chunk",
          len(sh.run("cat /dev/zero")), 65536)
    check("the exemption does not leak to the next command",
          len(shell().run("head -c 8388608 /dev/zero > f\nseq 1 5000000"))
          <= fs.MAX_OUTPUT, True)

    print("\nbigfiletest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
