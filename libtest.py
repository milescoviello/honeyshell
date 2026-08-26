#!/usr/bin/env python3
"""Shared libraries: what links against what, and who agrees.

Four things on this box know about shared libraries -- ldd, ldconfig, the
filesystem, and dpkg -- and no two of them were reading the same data.

    ldd /bin/ls          three lines
    ldd /usr/bin/ssh     the same three lines
    ldd /etc/passwd      the same three lines, for a text file
    ldconfig -p          ldconfig 2.41 / Usage: ldconfig [OPTION]...
    ls /etc/ld.so.conf   No such file or directory
    ls /etc/ld.so.cache  No such file or directory
    dpkg -S .../libc.so.6   no path found matching pattern
    dpkg -L libc6        eight doc files, no libraries

`ldd` was a constant. Every path it was handed came back with libc, the
vdso and the loader, which is right for about forty per cent of coreutils
and wrong for everything anyone actually asks about: a loader choosing
between a glibc build and a musl one by looking at what curl links learned
nothing, and neither did one counting whether ssh has libcrypto.

Handing that answer back for `ldd /etc/passwd` is the part that costs
nothing to check. A real ldd says "not a dynamic executable" for a text
file, a script or a directory -- one command, no privileges, no ambiguity.

`ldconfig -p` is how you ask a box what libraries it has. It was on the
list of programs that print a version banner and a usage line, so it
answered the question with an error, and the three files that decide where
libraries are found -- ld.so.conf, ld.so.conf.d and the cache itself --
were not on the box at all. /etc/ld.so.preload was, because an earlier
sweep needed it.

Measured on the guest (Debian 13.6) and in a debian:trixie container:

    ldd /etc/passwd      \tnot a dynamic executable    rc 1, on stderr
    ldd /usr/bin/which   the same -- it is a shell script
    ldd /tmp             ldd: /tmp: not regular file   rc 1
    ldd /nonexistent     ldd: ...: No such file...     rc 1
    ldd /bin/true        vdso, libc, ld.so             rc 0
    ldconfig -p          174 libs found in cache `/etc/ld.so.cache'
                         \tlibz.so.1 (libc6,x86-64) => /lib/.../libz.so.1
    ldconfig             as non-root: Can't create temporary cache file
                         /etc/ld.so.cache~: Permission denied
    ldconfig --version   ldconfig (Debian GLIBC 2.41-12+deb13u3) 2.41
    /etc/ld.so.conf      include /etc/ld.so.conf.d/*.conf
    ld.so.cache header   magic, nlibs and len_strings as LE u32, flags 2
    dpkg -S <multiarch>  zlib1g:amd64: /usr/lib/x86_64-linux-gnu/libz.so.1
    dpkg -S <not>        sudo: /usr/libexec/sudo/libsudo_util.so.0

and the dependency lists themselves came from running real ldd over 339
binaries this persona claims to have.

The suite does not pin the library list. It asks the four readers to close
the loop: ldd names a soname, ldconfig -p lists it, the file is there, and
dpkg says which package put it there.

Usage:  python3 libtest.py
"""

import re
import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    fs = fakeshell.VFS()
    return fakeshell.Shell(vfs=fs, peer="198.51.100.9", peer_port=40111)


def out(sh, cmd):
    try:
        return sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def table(name):
    """A module table, or an empty one if this build has no such thing."""
    return getattr(fakeshell, name, {}) or {}


S = shell()
SHARED = table("SHARED_LIBS")
PRIVATE = table("PRIVATE_LIBS")


def deps(binary):
    fn = getattr(fakeshell, "lib_deps", None)
    if fn is None:
        return ()
    try:
        return tuple(fn(binary))
    except Exception:                                          # noqa: BLE001
        return ("<raised>",)


# ------------------------------------------------------------ ldd refuses
# The cheapest detector in the file: ldd answering for something that is
# not an ELF.
for path, want_err, want_rc in (
        ("/etc/passwd", "\tnot a dynamic executable", 1),
        ("/etc/hostname", "\tnot a dynamic executable", 1),
        ("/tmp", "ldd: /tmp: not regular file", 1),
        ("/nonexistent", "ldd: /nonexistent: No such file or directory", 1)):
    # rstrip("\n"), not strip(): the leading tab on "not a dynamic
    # executable" is part of what ldd prints, and stripping it is how a
    # suite passes a box that gets it wrong.
    got = out(S, "ldd %s 2>&1; echo rc=$?" % path).rstrip("\n").splitlines()
    check("ldd %s refuses" % path, got, [want_err, "rc=%d" % want_rc],
          "a text file, a directory and a missing path are three different "
          "errors, and none of them is a library list")

# ...and answers for something that is.
elf = out(S, "ldd /bin/true 2>&1; echo rc=$?").rstrip("\n").splitlines()
check("ldd /bin/true succeeds", elf[-1], "rc=0")
check("ldd names the vdso first",
      bool(elf and elf[0].startswith("\tlinux-vdso.so.1 (0x")), True)
check("ldd names the loader last",
      bool(len(elf) > 2
           and elf[-2].startswith("\t/lib64/ld-linux-x86-64.so.2 (0x")), True)

# ------------------------------------------------------- ldd reads the ELF
def sonames(binary):
    got = []
    for line in out(S, "ldd %s" % binary).splitlines():
        if "=>" in line:
            got.append(line.split("=>")[0].strip())
    return got


ls_libs, ssh_libs = sonames("/bin/ls"), sonames("/usr/bin/ssh")
check("ls and ssh do not link against the same set",
      ls_libs == ssh_libs, False,
      "every binary got one constant answer; `file` calls them different "
      "ELFs and ldd could not tell them apart")
check("ldd /bin/ls matches the table", tuple(ls_libs), deps("ls"))
check("ldd /usr/bin/ssh matches the table", tuple(ssh_libs), deps("ssh"))
check("ssh links against libcrypto", "libcrypto.so.3" in ssh_libs, True,
      "counting what ssh links is how a loader decides whether a box has "
      "openssl at all")
check("a path and its merged-/usr twin agree",
      sonames("/bin/ls"), sonames("/usr/bin/ls"),
      "same binary, two spellings")

# Addresses move. Two runs that agree to the digit are one run.
a1 = out(S, "ldd /bin/ls")
a2 = out(S, "ldd /bin/ls")
check("the load addresses differ between runs", a1 == a2, False,
      "the loader maps somewhere new each time; identical output twice is "
      "a printed constant")
check("...but the sonames do not",
      [l.split("=>")[0] for l in a1.splitlines() if "=>" in l],
      [l.split("=>")[0] for l in a2.splitlines() if "=>" in l])

# ------------------------------------------- every named library is there
missing, unowned = [], []
for binary in ("ls", "ssh", "curl", "wget", "nginx", "python3", "bash",
               "sudo", "top", "ss", "openssl", "systemctl", "dpkg", "tar"):
    for so in deps(binary):
        if so.startswith("<"):
            continue
        line = [l for l in out(S, "ldd $(command -v %s 2>/dev/null || "
                                  "echo /usr/bin/%s)" % (binary, binary)
                               ).splitlines() if l.strip().startswith(so)]
        if not line:
            continue
        if "not found" in line[0]:
            missing.append((binary, so))
            continue
        path = line[0].split("=>")[1].split("(")[0].strip()
        if out(S, "test -e %s && echo yes" % path).strip() != "yes":
            missing.append((binary, so, path))
check("no binary links against a library that is not on the box",
      missing, [],
      "ldd naming a path that does not exist is the box contradicting "
      "itself in one line")

# --------------------------------------------------------------- ldconfig
p = out(S, "ldconfig -p")
rows = [l for l in p.splitlines() if l.startswith("\t")]
head = p.splitlines()[0] if p else ""
m = re.match(r"^(\d+) libs found in cache `/etc/ld\.so\.cache'$", head)
check("ldconfig -p prints the cache header", bool(m), True,
      "it printed `ldconfig 2.41` and a usage line -- ldconfig -p is the "
      "question, not a mistake; got %r" % head[:60])
check("the header count matches the rows",
      int(m.group(1)) if m else -1, len(rows))
check("every row has the cache's format",
      [r for r in rows
       if not re.match(r"^\t\S+ \(libc6,x86-64\) => /\S+$", r)], [])
check("ldconfig -p is not empty", len(rows) > 20, True)

# What -p lists and what ldd resolves to have to be the same files.
cache = {}
for r in rows:
    so = r.strip().split()[0]
    cache[so] = r.split("=>")[1].strip()
for so in ls_libs + ssh_libs:
    check("ldconfig -p lists %s" % so, so in cache, True,
          "ldd resolved it, so the cache has to know it")
    if so in cache:
        resolved = [l.split("=>")[1].split("(")[0].strip()
                    for l in out(S, "ldd /usr/bin/ssh").splitlines()
                    + out(S, "ldd /bin/ls").splitlines()
                    if l.strip().startswith(so) and "=>" in l]
        check("...at the path ldd gave", cache[so],
              resolved[0] if resolved else "<ldd named no path>")

# A private library is named by ldd and is deliberately NOT in the cache.
for so in sorted(PRIVATE):
    check("%s is not in the cache" % so, so in cache, False,
          "it lives outside the directories ld.so.conf lists, so the cache "
          "cannot contain it -- and ldd still names it by full path")

# The other invocations.
ver = out(S, "ldconfig --version").splitlines()
check("--version names the packaged glibc",
      bool(ver and re.match(r"^ldconfig \(Debian GLIBC \S+\) \S+$", ver[0])),
      True, "got %r" % (ver[0] if ver else ""))
# Guarded, not indexed: on a build where --version prints the stub banner
# there is no "GLIBC " to split on, and a suite that dies here reports
# nothing about the twenty checks below it.
deb = ver[0].split("GLIBC ")[1].split(")")[0] \
    if ver and "GLIBC " in ver[0] and ")" in ver[0] else "<no version line>"
check("...the same version dpkg has",
      deb, out(S, "dpkg-query -W -f='${Version}' libc6").strip(),
      "two places naming a glibc version is one place too many")

# Rebuilding it is a write to /etc, so it depends on who you are.
root_rc = out(S, "ldconfig >/dev/null 2>&1; echo $?").strip()
check("root may rebuild the cache", root_rc, "0")
U = shell()
U.uid = 1000
nonroot = out(U, "ldconfig 2>&1; echo rc=$?").strip().splitlines()
check("a normal user may not", nonroot,
      ["/usr/sbin/ldconfig: Can't create temporary cache file "
       "/etc/ld.so.cache~: Permission denied", "rc=1"],
      "the error names the temporary file, not the cache")

# ------------------------------------------------- the loader's own config
check("/etc/ld.so.conf exists", out(S, "cat /etc/ld.so.conf").strip(),
      "include /etc/ld.so.conf.d/*.conf")
confd = sorted(out(S, "ls /etc/ld.so.conf.d/").split())
check("...and the directory it includes", confd,
      ["libc.conf", "x86_64-linux-gnu.conf"])
conf_dirs = []
for f in confd:
    for line in out(S, "cat /etc/ld.so.conf.d/%s" % f).splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            conf_dirs.append(line)
check("the multiarch directory is on the search path",
      "/lib/x86_64-linux-gnu" in conf_dirs, True)
for path in sorted({v.rsplit("/", 1)[0] for v in cache.values()}):
    check("the cache only lists configured directories",
          path in conf_dirs, True,
          "the cache is built from ld.so.conf; a path in it that is not on "
          "the search path did not come from there")

cachef = out(S, "ls -l /etc/ld.so.cache").split()
check("/etc/ld.so.cache is on disk", len(cachef) > 4, True,
      "ldd resolves through a cache; the cache has to be a file")
check("...and is not text", out(S, "file /etc/ld.so.cache").strip(),
      "/etc/ld.so.cache: data")
check("...with glibc's magic",
      out(S, "head -c 20 /etc/ld.so.cache").strip(),
      "glibc-ld.so.cache1.1")

# ------------------------------------------------------------------- dpkg
for so in sorted(SHARED)[:8] + sorted(PRIVATE):
    fn = getattr(fakeshell, "lib_path", None)
    path = fn(so) if fn else None
    if path is None:
        continue
    # Only the leading /lib is the merged-/usr spelling. A private
    # library already under /usr/lib/x86_64-linux-gnu/systemd contains that
    # substring too, and rewriting it produced /usr/usr/lib.
    usr = ("/usr" + path) if path.startswith("/lib/") else path
    got = out(S, "dpkg -S %s" % usr).strip()
    check("dpkg owns %s" % so, bool(got) and "no path found" not in got, True,
          "a library on a Debian box belongs to a package; these belonged "
          "to none while ldd and ldconfig both pointed at them")
    if got:
        pkg = got.split(":")[0]
        want = pkg + (":amd64" if usr.startswith("/usr/lib/x86_64-linux-gnu/")
                      else "")
        check("...and qualifies %s correctly" % so, got.split(": ")[0], want,
              "Multi-Arch: same packages carry the architecture; that is "
              "every package shipping into the multiarch directory")
        listed = out(S, "dpkg -L %s" % pkg).splitlines()
        check("dpkg -L %s lists it back" % pkg, usr in listed, True,
              "-S and -L are two halves of one database")

check("dpkg does not follow the merged-/usr symlink",
      "no path found" in out(S, "dpkg -S /lib/x86_64-linux-gnu/libc.so.6 "
                                "2>&1"), True,
      "measured: real dpkg answers for the /usr spelling only")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
