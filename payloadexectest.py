"""A dropped binary is its bytes, not its filename.

From a live capture on 2026-08-30. 203.0.113.65 brute-forced root:123456
after 30 failures, uploaded 30,304,472 bytes over SFTP to
/root/.7111935220753178194/sshd
(sha256 94f2e4d8d4436874785cd14e6e6d403507b8750852f7f2040352069a75da4c00,
the same payload already captured from 203.0.113.63), and ran

    chmod +x ./.7111935220753178194/sshd
    nohup ./.7111935220753178194/sshd 203.0.113.79 203.0.113.68 ... &

with about fifty IP arguments. This box answered, on stderr, in OpenSSH's
voice:

    sshd re-exec requires execution with an absolute path

which is proof the payload was never executed -- no dropper prints the host
sshd's re-exec error. The path-exec branch dispatched on the *basename*, so
an uploaded file answered as whatever it happened to be called. Calling it
`ls`, `ps` or `top` would have been just as good.

The comment two lines below the bug already knew the answer -- it greps the
bytes for `Usage: NAME [OPTION` before trusting a name -- but the bare-name
shortcut ran first and never reached it.

What separates a payload from a legitimate copy is the bytes. node.elf is
set only for the synthesised stock binaries, whose contents are generated on
read, and a copy of one carries the stock byte count. A dropped payload
carries neither, so it falls through to the unknown-binary branch: resident,
silent, rc 0, which is what `nohup`ing a real daemon looks like.

Usage:  python3 payloadexectest.py

## and what it prints, for the ones whose bytes have been read

Second half, from 2026-09-18. A 348-byte static i386 ELF has been dropped
into /bin under a random name sixteen times from fifteen addresses since
2026-08-30, run once, and deleted four seconds later. It prints
`Hello, world!` -- a capability probe, whose output the actor already
knows, so silence is the answer that identifies this box.

A real trixie prints the string: Debian's amd64 kernels build with IA32
emulation and a static i386 binary needs no 32-bit libraries. Answering it
does *not* require running it. The program was decoded out of the captured
file -- mov edx,14; mov ecx,<string>; mov ebx,1; mov eax,4; int 0x80; then
exit(0) -- so the answer is a lookup on sha256, decided once from the
bytes. Shell.KNOWN_DROP_OUTPUT carries it, a changed byte misses and falls
back to silence, and nothing interprets attacker instructions at run time.

The checks below build the same program rather than shipping the
attacker's copy, so this repo carries no dropped binary: an entry for the
synthetic one proves the wiring, its absence proves the fallback, and the
two real sha256s are pinned as data.
"""

import base64
import struct
import sys

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


import fakeshell                                           # noqa: E402


def txt(o):
    return ((o[0] if isinstance(o, tuple) else o) or "")


def new_shell(port):
    sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.70",
                         peer_port=port)
    sh.run("true")
    return sh


def elf_bytes(pad=400):
    """A well-formed x86-64 ELF header -- runnable as far as the kernel cares."""
    hdr = bytearray(64)
    hdr[0:4] = b"\x7fELF"
    hdr[4], hdr[5], hdr[6] = 2, 1, 1
    hdr[16:18] = struct.pack("<H", 2)        # ET_EXEC
    hdr[18:20] = struct.pack("<H", 0x3E)     # x86-64
    return bytes(hdr) + b"\x00" * pad


def drop(sh, path, data=None):
    """Put a payload on the box the way an upload would leave it."""
    d = path.rsplit("/", 1)[0]
    sh.run("mkdir -p " + d)
    sh.run("echo %s | base64 -d > %s"
           % (base64.b64encode(data or elf_bytes()).decode(), path))
    sh.run("chmod +x " + path)


def first(sh, cmd):
    out = txt(sh.run(cmd + " 2>&1")).strip()
    rc = txt(sh.run("echo $?")).strip()
    return ((out.splitlines() or [""])[0]), rc


# --------------- a payload named after a system binary is not that binary
for name in ("sshd", "ls", "ps", "top", "systemctl"):
    sh = new_shell(42200 + len(name))
    drop(sh, "/root/.d/%s" % name)
    line, rc = first(sh, "/root/.d/%s 1.2.3.4" % name)
    check("dropped %-9s prints nothing" % name, line, "",
          "answering here proves the bytes were never run")
    check("dropped %-9s exits 0" % name, rc, "0")

# the exact shape from the capture
sh = new_shell(42260)
drop(sh, "/root/.7111935220753178194/sshd")
line, rc = first(sh, "cd /root && chmod +x ./.7111935220753178194/sshd;"
                     "nohup ./.7111935220753178194/sshd 203.0.113.79 "
                     "203.0.113.68 &")
check("the captured command line prints nothing", line, "",
      "it printed 'sshd re-exec requires execution with an absolute path'")
check("the captured command line exits 0", rc, "0")

# ------------------------------------------- and it stays resident, as a daemon
ps = txt(sh.run("ps aux"))
rows = [l for l in ps.splitlines() if "7111935" in l]
check("payload appears once in ps aux", len(rows), 1,
      "a dropper checks that its payload survived")
check("payload appears in ps -ef",
      sum(1 for l in txt(sh.run("ps -ef")).splitlines() if "7111935" in l), 1)
check("pgrep finds it",
      "7111935" in txt(sh.run("pgrep -af 7111935")), True)

pid = rows[0].split()[1] if rows else "0"
check("/proc/<pid> exists",
      txt(sh.run("ls -d /proc/%s 2>&1" % pid)).strip(), "/proc/%s" % pid,
      "a process with no /proc directory is a process that does not exist")
check("/proc/<pid>/exe points at the dropped file",
      txt(sh.run("readlink /proc/%s/exe" % pid)).strip(),
      "/root/.7111935220753178194/sshd")
check("/proc/<pid>/cmdline carries the argv",
      txt(sh.run("cat /proc/%s/cmdline | tr '\\0' ' '" % pid)).strip(),
      "./.7111935220753178194/sshd 203.0.113.79 203.0.113.68")
check("/proc/<pid>/comm is the file's name",
      txt(sh.run("cat /proc/%s/comm" % pid)).strip(), "sshd")
check("it can be killed",
      "7111935" in txt(sh.run("kill %s; ps aux" % pid)), False)

# ---------------------------------- the real binaries are still themselves
sh = new_shell(42280)
for cmd, want in (("/usr/bin/id", "uid=0(root)"),
                  ("sshd", "sshd re-exec requires execution"),
                  ("/usr/sbin/sshd", "sshd re-exec requires execution")):
    line, _ = first(sh, cmd)
    check("%-16s still answers" % cmd, want in line, True, line[:70])

# ---------------------------------------- and so is a copy of a real binary
for cmd, want in (("cp /usr/bin/id /tmp/x && /tmp/x", "uid=0(root)"),
                  ("cp /usr/bin/uname /tmp/u && /tmp/u -m", "x86_64"),
                  ("cp /usr/sbin/sshd /tmp/s && /tmp/s",
                   "sshd re-exec requires execution")):
    line, _ = first(sh, cmd)
    check("copy still answers: %-38s" % cmd.split("&&")[-1].strip(),
          want in line, True,
          "the bare-name shortcut existed for this case -- narrowing it "
          "must not break it: " + line[:60])

# ---- what it prints, when the bytes are known ------------------------
import hashlib                                                  # noqa: E402


def i386_hello():
    """The probe's own program, assembled here rather than shipped.

    Same instruction sequence read out of the captured file, so the test
    exercises the real path without this repo carrying an attacker's
    binary.
    """
    msg = b"Hello, world!\n"
    base, ehdr_sz, phdr_sz = 0x08048000, 52, 32
    code_off = ehdr_sz + phdr_sz
    msg_addr = base + code_off + 24
    code = (b"\xba" + struct.pack("<I", len(msg)) +
            b"\xb9" + struct.pack("<I", msg_addr) +
            b"\xbb\x01\x00\x00\x00" + b"\xb8\x04\x00\x00\x00" + b"\xcd\x80" +
            b"\xbb\x00\x00\x00\x00" + b"\xb8\x01\x00\x00\x00" + b"\xcd\x80")
    body = code + msg
    ehdr = (b"\x7fELF\x01\x01\x01" + b"\x00" * 9 +
            struct.pack("<HHI", 2, 3, 1) +
            struct.pack("<III", base + code_off, ehdr_sz, 0) +
            struct.pack("<IHHHHHH", 0, ehdr_sz, phdr_sz, 1, 40, 0, 0))
    phdr = struct.pack("<IIIIIIII", 1, 0, base, base,
                       code_off + len(body), code_off + len(body), 5, 0x1000)
    return ehdr + phdr + body


_blob = i386_hello()
_sha = hashlib.sha256(_blob).hexdigest()
_table = getattr(fakeshell.Shell, "KNOWN_DROP_OUTPUT", None)
check("the box has a table of known dropped payloads", _table is not None, True,
      "without it a probe whose output the actor knows is answered by silence")
# Every check below runs whether or not the table exists, so a build
# without it fails them rather than skipping them.
if _table is not None:
    _table[_sha] = ("Hello, world!\n", "", 0)
try:
    s1 = new_shell(41001)
    s1.fs.write("/bin/probe-known", _blob, mode=0o755)
    s1._err = []
    out = s1.run("/bin/probe-known")
    check("a dropped binary whose bytes are known prints what they print",
          (out, s1.last_rc), ("Hello, world!\n", 0),
          "decoded from the file, not run: mov edx,14; mov eax,4; int 0x80")
    check("...and does not stay in ps, because it returned",
          "probe-known" in (s1.run("ps aux") or ""), False)
finally:
    if _table is not None:
        _table.pop(_sha, None)
s2 = new_shell(41002)
s2.fs.write("/bin/probe-unknown", _blob, mode=0o755)
out2 = s2.run("/bin/probe-unknown")
check("one whose bytes are not known keeps the old answer",
      (out2, s2.last_rc), ("", 0),
      "silent and resident is what a miner or a loader looks like")
check("...and that one does stay resident",
      "probe-unknown" in (s2.run("ps aux") or ""), True)
# The two real deliveries, pinned as data. Hashes, not payloads.
for sha in ("f74a8b06db4f8f48f4a19ea5c01bade2a0dfb9290c4ed04a3f1a3eaa"
            "298a843d",
            "e374a7ad447d2cf791ecae122894a51ba723901ea132e7fa16cd47c4"
            "4e4a1769"):
    check("the probe seen on the wire is in the table: %s..." % sha[:12],
          (_table or {}).get(sha), ("Hello, world!\n", "", 0),
          "sixteen deliveries from fifteen addresses since 2026-08-30")

for f in FAILS:
    print(" ", f)
print("   payloadexec: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
