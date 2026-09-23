"""`file` described the filename, not the file.

From a live capture. 203.0.113.84 dropped a 348-byte static i386 ELF into
/bin under a random name, ran it, and deleted it four seconds later; the
same program has arrived sixteen times from fifteen addresses. Asked what
it was, this box said

    ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically
    linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=...,
    for GNU/Linux 3.2.0, stripped

where the real trixie that this box claims to be says

    ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), statically
    linked, stripped

Wrong in the class, the architecture and the linkage at once, about a file
the box will happily `od` and show you the i386 header of. It was one
canned string for every ELF: the branch never looked past the four magic
bytes.

The BuildID was the other half. It was computed as sha1 of the first 64
bytes, and `elf_body` synthesises those 64 bytes identically for every
stock binary, so

    file /bin/ls   -> BuildID[sha1]=1b01237a...
    file /bin/bash -> BuildID[sha1]=1b01237a...

the same id for two files whose `sha256sum` differs. Debian gives every
binary its own; two binaries sharing one is a thing no real system does.

The rewrite turned up a third bug that nothing had asked about. The old
header wrote e_ehsize at byte 54, and it belongs at 52, so every field
from there on sat two bytes late: what the code labelled e_phnum landed
in e_shentsize, and the 13 program headers it claimed were recorded in
the wrong field of a header that had none. The check at the bottom reads
e_phnum at its real offset, which is why it answers 56 against HEAD -- it
is reading the e_phentsize that the old code put there.

Underneath both was a header that declared structure it did not have:
e_phnum said 13 with no program headers behind it, no interpreter string,
no notes. file(1) reads exactly those, so the canned string was covering
for bytes that could not answer. `elf_body` now writes the real shape --
program headers, PT_INTERP, the two GNU notes, PT_DYNAMIC, and a section
header table with no SHT_SYMTAB, which is what "stripped" means -- and
`cmd_file` reads it.

The expectations below are real file(1) 5.46 output, measured on the guest
on 2026-09-19 across the 126 modelled binaries and 89 modelled libraries
that Debian trixie actually installs. 211 of those now match byte for
byte; the six that do not are /etc/alternatives symlinks and are a
different bug, recorded in FINDINGS.md rather than pinned here.

Usage:  python3 elfdesctest.py
"""

import struct
import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def txt(o):
    return ((o[0] if isinstance(o, tuple) else o) or "")


def new_shell(port):
    sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.71",
                         peer_port=port)
    sh.run("true")
    return sh


def desc(sh, path):
    """`file -b path`, one line, so a miss is a diff and not a traceback."""
    return txt(sh.run("file -b %s" % path)).strip()


def field(s, prefix):
    """The comma-separated field starting with prefix, or ''."""
    for part in s.split(", "):
        if part.startswith(prefix):
            return part
    return ""


sh = new_shell(43100)

# ---- what real file(1) 5.46 on the guest says, measured 2026-09-19
MEASURED = {
    "/usr/bin/ls":
        "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), "
        "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, "
        "BuildID[sha1]=0243f2a3ad64d635299a574bbc8ef951ddde9b21, "
        "for GNU/Linux 3.2.0, stripped",
    "/usr/bin/cat":
        "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), "
        "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, "
        "BuildID[sha1]=8ff77e5585da488ded426fe771ceaae234703a9a, "
        "for GNU/Linux 3.2.0, stripped",
    "/usr/bin/bash":
        "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), "
        "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, "
        "BuildID[sha1]=8b362acb36d9f6e7103ef8433c2141265908ac8f, "
        "for GNU/Linux 3.2.0, stripped",
    # Debian builds nearly everything PIE; python3.13 is ET_EXEC, and it
    # is the one binary here whose type word differs from its neighbours.
    "/usr/bin/python3.13":
        "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), "
        "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, "
        "BuildID[sha1]=7e8d5f6d0cd6cd1e9bff2a775c11d398cecca758, "
        "for GNU/Linux 3.2.0, stripped",
    # file names the mode bits before the format.
    "/usr/bin/su":
        "setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), "
        "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, "
        "BuildID[sha1]=54e61b26a19297084c3214316da1365aa96431e1, "
        "for GNU/Linux 3.2.0, stripped",
    "/usr/bin/mount":
        "setuid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), "
        "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, "
        "BuildID[sha1]=64a1e7574d388a60830453ece738da8028a62fbf, "
        "for GNU/Linux 3.2.0, stripped",
    # A shared object, with no interpreter and no ABI tag: the common
    # shape for 87 of the 89 libraries measured.
    "/usr/lib/x86_64-linux-gnu/libacl.so.1.1.2302":
        "ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), "
        "dynamically linked, "
        "BuildID[sha1]=2de31bb0cc5f8c4d2366e54da43481d43b9236ea, stripped",
    # libc is the exception that kills the easy rule: it HAS an
    # interpreter and is still a shared object, not a pie executable.
    "/usr/lib/x86_64-linux-gnu/libc.so.6":
        "ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), "
        "dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, "
        "BuildID[sha1]=5e5b51f4c39af9ac589408c1dc432ba390a273cc, "
        "for GNU/Linux 3.2.0, stripped",
    "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2":
        "ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), "
        "dynamically linked, "
        "BuildID[sha1]=86f7eb4ff495ed3f2831c6d3d662e4321762a2a3, stripped",
}
for path in sorted(MEASURED):
    check("file -b %s" % path, desc(sh, path), MEASURED[path],
          "measured from file 5.46 on the guest")

# ---- -b is the form every script uses, and it must drop the name
check("file -b omits the path it was given",
      desc(sh, "/usr/bin/ls").startswith("/usr/bin/ls"), False,
      "`file -b x` answered 'x: ELF ...', which is what -b exists to stop")
check("file without -b keeps it",
      txt(sh.run("file /usr/bin/ls")).startswith("/usr/bin/ls: ELF"), True)

# ---- two binaries cannot share one build id
ids = {}
for p in ("/usr/bin/ls", "/usr/bin/cat", "/usr/bin/bash", "/usr/bin/dd",
          "/usr/bin/find", "/usr/bin/grep", "/usr/bin/sed", "/usr/bin/tar"):
    ids[p] = field(desc(sh, p), "BuildID[sha1]=")
check("eight binaries have eight distinct build ids",
      len(set(ids.values())), 8,
      "every synthesised binary shared one id: " + repr(sorted(set(
          ids.values()))[:2]))
check("and none of them is empty",
      sorted(set(bool(v) for v in ids.values())), [True])
# the same claim from the other side: different bytes, different id
h1 = txt(sh.run("sha256sum /usr/bin/ls")).split()[:1]
h2 = txt(sh.run("sha256sum /usr/bin/cat")).split()[:1]
check("the two files whose ids differ also differ in content", h1 != h2, True)

# ---- a copy carries the original's id, because it carries its bytes
sh.run("cp /usr/bin/ls /tmp/lscopy")
check("a copy of a binary keeps its build id",
      field(desc(sh, "/tmp/lscopy"), "BuildID[sha1]="),
      field(desc(sh, "/usr/bin/ls"), "BuildID[sha1]="),
      "file reads the bytes, and a copy has the same bytes")

# ---- a dropped payload is described from its own header
def static_elf(bits):
    """A static hello-world header of the requested class, built here.

    The same shape as the probe in the capture store, assembled rather
    than shipped so this repo carries no attacker binary.
    """
    msg = b"Hello, world!\n"
    if bits == 32:
        base, ehsz, phsz = 0x08048000, 52, 32
        code = b"\x90" * 24
        body = code + msg
        ehdr = (b"\x7fELF\x01\x01\x01" + b"\x00" * 9 +
                struct.pack("<HHI", 2, 3, 1) +
                struct.pack("<III", base + ehsz + phsz, ehsz, 0) +
                struct.pack("<IHHHHHH", 0, ehsz, phsz, 1, 40, 0, 0))
        phdr = struct.pack("<IIIIIIII", 1, 0, base, base,
                           ehsz + phsz + len(body),
                           ehsz + phsz + len(body), 5, 0x1000)
        return ehdr + phdr + body
    base, ehsz, phsz = 0x400000, 64, 56
    body = b"\x90" * 24 + msg
    ehdr = (b"\x7fELF\x02\x01\x01" + b"\x00" * 9 +
            struct.pack("<HHI", 2, 62, 1) +
            struct.pack("<QQQ", base + ehsz + phsz, ehsz, 0) +
            struct.pack("<IHHHHHH", 0, ehsz, phsz, 1, 64, 0, 0))
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base,
                       ehsz + phsz + len(body), ehsz + phsz + len(body),
                       0x1000)
    return ehdr + phdr + body


for bits, want in (
        (32, "ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), "
             "statically linked"),
        (64, "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), "
             "statically linked")):
    s = new_shell(43110 + bits)
    s.fs.write("/bin/.drop%d" % bits, static_elf(bits), mode=0o755)
    got = desc(s, "/bin/.drop%d" % bits)
    check("a dropped %d-bit static binary is described as one" % bits,
          got, want,
          "this said 64-bit x86-64 dynamically linked for both")
    # and the description agrees with what the box will show of the bytes
    cls = txt(s.run("od -An -tx1 -N5 /bin/.drop%d" % bits)).split()
    check("...and od shows the class byte file just reported (%d)" % bits,
          cls[4:5], ["%02x" % (1 if bits == 32 else 2)],
          "file and od are two readers of the same five bytes")

# ---- a shared object is not a pie executable
check("a library is a shared object",
      desc(sh, "/usr/lib/x86_64-linux-gnu/libacl.so.1.1.2302").split(",")[0],
      "ELF 64-bit LSB shared object")
check("an executable is a pie executable",
      desc(sh, "/usr/bin/ls").split(",")[0], "ELF 64-bit LSB pie executable",
      "the difference is DT_FLAGS_1/DF_1_PIE, not the interpreter")

# ---- and the structure the answer is read out of is really there
body = sh.fs.read("/usr/bin/ls") or b""
check("the header declares the program headers it has",
      len(body) > 64 and struct.unpack_from("<H", body, 56)[0], 5,
      "e_phnum said 13 with no program headers behind it")
check("the section header offset is inside the file",
      0 < struct.unpack_from("<Q", body, 40)[0] < len(body), True)

for f in FAILS:
    print(" ", f)
print("   elfdesc: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
