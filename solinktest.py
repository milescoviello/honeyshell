#!/usr/bin/env python3
"""The library directory, and who owns the files in it.

`ls -l /usr/lib/x86_64-linux-gnu` on this box printed 115 regular files,
mode 0755, and not one symlink. Every real Debian box prints a forest of
symlinks at 0644:

    lrwxrwxrwx  libtinfo.so.6 -> libtinfo.so.6.4
    -rw-r--r--  libtinfo.so.6.4

That is one `ls` away, needs no privileges, and there is no configuration
under which a real box looks like the first one. Measured on a live
Debian host and against the shipping debs with dpkg-deb -c: the soname is
a link, the versioned file behind it is the library, and shared objects
are not executable. Only two files in that directory are 0755 -- libc.so.6
and the loader -- because those two can be run directly.

The same sweep found the package database disagreeing with itself about
who owns what. `dpkg -S /usr/sbin/fdisk` answered util-linux, whose own
deb does not contain the file; fdisk, mount, bsdextrautils and
uuid-runtime split out of util-linux years ago and were not installed at
all, while thirteen of their binaries sat on disk credited to a package
that does not ship them. And the four util-linux libraries claimed
2.41.5-0+deb13u1 -- a version Debian has never published -- while
util-linux, mount and bsdutils, built from that same source package, all
correctly said 2.41-5. Sibling binaries of one source package cannot
carry two upstream versions.

Ground truth for everything here is the shipping deb, then a real box,
then nothing.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell

CHECKS = []
FAILS = []
LIBDIR = "/usr/lib/x86_64-linux-gnu"


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.9",
                           peer_port=40111)


def out(sh, cmd):
    try:
        r = sh.run(cmd)
    except Exception as exc:                       # noqa: BLE001
        return "EXC %s" % exc
    return r if isinstance(r, str) else r[0]


S = shell()

# ------------------------------------------------ the directory reads right
listing = [l for l in out(S, "ls -l %s/" % LIBDIR).splitlines()
           if l[:1] in ("-", "l")]
links = [l for l in listing if l.startswith("l")]
check("the library directory has symlinks in it", bool(links), True,
      "115 regular files and no links is not a Linux library directory")
check("no shared library is executable",
      sorted(l.split()[-1] for l in listing
             if l.startswith("-rwxr-xr-x")),
      ["ld-linux-x86-64.so.2", "libc.so.6"],
      "shared objects are 0644; only these two can be run directly")
check("every regular library is 0644 or one of those two",
      [l.split()[0] for l in listing
       if l.startswith("-") and not l.startswith(("-rw-r--r--",
                                                  "-rwxr-xr-x"))],
      [], "dpkg-deb -c prints -rw-r--r-- for every one of these")

# ------------------------------------------------ each link points somewhere
present = set()
for l in listing:
    present.add(l.split()[-3] if l.startswith("l") else l.split()[-1])

bad_target, bad_kind = [], []
for so, target in sorted(fakeshell.SO_REAL.items()):
    if so not in fakeshell.SHARED_LIBS:
        continue
    got = out(S, "readlink %s/%s" % (LIBDIR, so)).strip()
    if got != target:
        bad_target.append((so, got, target))
    real = out(S, "readlink -f %s/%s" % (LIBDIR, so)).strip()
    if not real.startswith(LIBDIR + "/"):
        bad_kind.append((so, real))
check("every soname links to the file the deb ships", bad_target[:3], [])
check("every chain ends on a real file in the same directory",
      bad_kind[:3], [],
      "libcuda.so -> libcuda.so.1 -> libcuda.so.595.84 is two hops")

# the versioned file is the one with the bytes in it
sizes = []
for so, target in sorted(fakeshell.SO_REAL.items()):
    if so not in fakeshell.SHARED_LIBS or target in fakeshell.SHARED_LIBS:
        continue
    want = fakeshell.SHARED_LIBS[so][0]
    got = out(S, "stat -c %%s %s/%s" % (LIBDIR, target)).strip()
    if got != str(want):
        sizes.append((target, got, want))
check("the versioned file carries the size, not the link", sizes[:3], [])

# ------------------------------------------------ ldconfig agrees
cache = [l.split()[0] for l in out(S, "ldconfig -p").splitlines()
         if "=>" in l]
check("ldconfig lists no link target as a library of its own",
      sorted(set(cache) & fakeshell.SO_TARGETS)[:3], [],
      "the cache is keyed by soname; libcuda.so.595.84 is not one")
check("every soname is in the cache",
      sorted(so for so in fakeshell.SHARED_LIBS if so not in cache)[:3], [])

# ------------------------------------------------ dpkg knows both spellings
miss_s, miss_l = [], []
for so, target in sorted(fakeshell.SO_REAL.items()):
    pkg = fakeshell.SHARED_LIBS.get(so, (0, None))[1]
    if not pkg or target in fakeshell.SHARED_LIBS:
        continue
    for path in (so, target):
        got = out(S, "dpkg -S %s/%s" % (LIBDIR, path))
        if not got.startswith(pkg + ":"):
            miss_s.append((path, got.strip()[:50]))
    listed = out(S, "dpkg -L %s" % pkg)
    for path in (so, target):
        if LIBDIR + "/" + path not in listed:
            miss_l.append((pkg, path))
check("dpkg -S answers for the link and for the file", miss_s[:3], [],
      "dpkg's file list holds both names")
check("dpkg -L lists the link and the file", miss_l[:3], [])

# ------------------------------------------------ one source, one version
def ver(pkg):
    row = out(S, "dpkg -l %s 2>/dev/null" % pkg).splitlines()
    for l in row:
        if l.startswith("ii "):
            return l.split()[2]
    return "(not installed)"


# every binary package built from src:util-linux, epoch aside
UL = ("util-linux", "util-linux-extra", "mount", "fdisk", "bsdutils",
      "bsdextrautils", "uuid-runtime", "libblkid1", "libmount1",
      "libsmartcols1", "libuuid1", "libfdisk1")
check("every util-linux binary package carries one version",
      sorted({ver(p).split(":")[-1] for p in UL}), ["2.41-5"],
      "2.41.5-0+deb13u1 is not a version Debian ever published, and "
      "sibling packages of one source cannot disagree")

# ------------------------------------------------ ownership round-trips
inst = {n for n, _v, _a in S.PACKAGES}
check("every package with a file list is installed",
      sorted(p for p in fakeshell.Shell._PKG_FILES if p not in inst), [])

wrong = []
for pkg, names in sorted(fakeshell.Shell._PKG_FILES.items()):
    for n in names:
        where = out(S, "command -v %s 2>&1" % n).strip()
        if not where.startswith("/"):
            continue
        got = out(S, "dpkg -S %s 2>&1" % where).strip()
        if not got.startswith(pkg + ":"):
            wrong.append((n, pkg, got[:40]))
check("dpkg -S names the package whose file list holds the binary",
      wrong[:4], [],
      "fdisk, mount, umount, swapon, swapoff, logger, renice, script, "
      "wall, hexdump, ul, uuidgen and lsfd all answered util-linux")

# ------------------------------------------------ the split-out packages
for binary, pkg in (("/usr/sbin/fdisk", "fdisk"),
                    ("/usr/sbin/sfdisk", "fdisk"),
                    ("/usr/sbin/cfdisk", "fdisk"),
                    ("/usr/bin/mount", "mount"),
                    ("/usr/bin/umount", "mount"),
                    ("/usr/sbin/swapon", "mount"),
                    ("/usr/bin/logger", "bsdutils"),
                    ("/usr/bin/hexdump", "bsdextrautils"),
                    ("/usr/bin/uuidgen", "uuid-runtime"),
                    ("/usr/bin/lsfd", "util-linux-extra")):
    check("%s belongs to %s" % (binary, pkg),
          out(S, "dpkg -S %s" % binary).split(":")[0], pkg)

check("fdisk links the library its own package depends on",
      sorted(l.split("=>")[0].strip()
             for l in out(S, "ldd /usr/sbin/fdisk").splitlines()
             if "=>" in l),
      ["libc.so.6", "libfdisk.so.1", "libreadline.so.8",
       "libsmartcols.so.1", "libtinfo.so.6"],
      "objdump -p on the shipping binary lists exactly these")

# ------------------------------------------------ sizes come from the deb
for name, want in (("/usr/bin/mount", 72072), ("/usr/bin/umount", 55688),
                   ("/usr/bin/wall", 47496), ("/usr/bin/logger", 60392),
                   ("/usr/sbin/swapon", 59784), ("/usr/bin/lsblk", 248208),
                   ("/usr/bin/setsid", 14728), ("/usr/sbin/fdisk", 178616),
                   ("/usr/bin/hexdump", 63896),
                   ("%s/ld-linux-x86-64.so.2" % LIBDIR, 225672)):
    check("%s is the size the deb ships" % name,
          out(S, "stat -c %%s %s" % name).strip(), str(want))

check("the loader link in /usr/lib64 is the relative one",
      out(S, "readlink /usr/lib64/ld-linux-x86-64.so.2").strip(),
      "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
      "libc6 ships it relative; the absolute spelling is two bytes longer")

print("solinktest: %d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
