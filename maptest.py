#!/usr/bin/env python3
"""A process's address space: six readers, and how big is it really?

/proc/<pid>/maps, /proc/<pid>/smaps, smaps_rollup, statm, the Vm* lines of
status, `pmap`, and `ps -o vsz,rss` all describe one number. On a real box
they agree to the byte, because all seven sum the same VMA list -- measured
on the guest, where one shell reads 4488 kB in every one of them.

Here maps was six literal lines:

    55a1c0000000-55a1c0020000 r--p 00000000 08:01 <pid*13%800000> <exe>
    ... two more of the same binary ...
    7f9a40000000-7f9a40028000 r--p 00000000 08:01 700123   libc.so.6
    7ffd20000000-7ffd20021000 rw-p 00000000 00:00 0        [stack]
    ffffffffff600000-...      --xp 00000000 00:00 0        [vsyscall]

So every process on the box had the same address space at the same
addresses, mapped exactly one library whatever it linked against, had no
heap and no dynamic loader, and carried a [vsyscall] this kernel does not
have. /proc/self/maps is what an exploit reads to find where anything is,
and a bash with no heap is not a bash.

The inodes were arithmetic on the pid, so `stat -c %i` on a mapped file and
the map of it disagreed -- and the same library came back with a different
inode in every process, which means they are different files.

smaps was empty. pmap was three lines, the same three for every pid, and it
said pid 1 was running /bin/bash where `ps -p 1` and /proc/1/comm both say
systemd -- two commands about one process, and pmap's was the one that
cannot be true. It ignored -x entirely.

Measured on the guest:

    pmap $$          <pid>:   <cmdline>
                     0000562aafa2b000    188K r---- bash
                     0000562aafb68000     44K rw---   [ anon ]
                      total             4488K
    pmap -x $$       Address  Kbytes  RSS  Dirty Mode  Mapping
                     a dashed rule, then "total kB" and three columns
    pmap 1           1:   /sbin/init
    pmap 2           2:   [kthreadd], total 0K
    pmap 999999      nothing at all, rc 42
    maps path column starts at 73; anonymous rows end in a single space
    /proc/1/maps     names /usr/lib/systemd/systemd, not the /sbin/init
                     that argv[0] says -- what gets mapped is the file the
                     symlink lands on
    VmSize == statm[0]*4 == sum of smaps Size == pmap total == ps VSZ

Two crashes in awk turned up while summing those columns, and both are
here because `awk '{a+=$2}'` over a column of kilobytes is how you check
this by hand:

    awk 'BEGIN{x=1e9; x^=100}'   OverflowError out of Python
    awk '... print x'            OverflowError converting inf to int

The first was a dict of all six compound-assignment results built before
one was chosen, so every `+=` also evaluated `cur ** rhs`. gawk's answers
for those are "+inf", "-inf" and "-nan", with a sign.

Usage:  python3 maptest.py
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
    return fakeshell.Shell(vfs=fs, peer="198.51.100.11", peer_port=40222)


def out(sh, cmd):
    try:
        return sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def num(text):
    m = re.search(r"-?\d+", text or "")
    return int(m.group(0)) if m else None


S = shell()

# --------------------------------------------------------- the maps format
maps = [l for l in out(S, "cat /proc/self/maps").splitlines() if l.strip()]
check("maps is more than a handful of lines", len(maps) > 20, True,
      "it was six, for every process on the box")
bad = [l for l in maps
       if not re.match(r"^[0-9a-f]{12}-[0-9a-f]{12} [-rwxps]{4} "
                       r"[0-9a-f]{8} [0-9a-f]{2}:[0-9a-f]{2} \d+", l)]
check("every line has the kernel's field layout", bad[:2], [])
named = [l for l in maps if len(l) > 73 and l[73:].strip()]
check("the path column starts at 73",
      sorted({l.index(l[73:].strip()[0], 60) for l in named}) or [-1], [73],
      "the kernel pads the fields to a fixed width and then prints the name")
anon = [l for l in maps if len(l) <= 73]
check("anonymous rows end in a single space",
      sorted({repr(l[-2:]) for l in anon}) or ["<none>"], ["'0 '"],
      "five fields and a trailing space, not six")

# The things a process has to have.
def has(label):
    return any(l.rstrip().endswith(label) for l in maps)


for label in ("[heap]", "[stack]", "[vvar]", "[vdso]"):
    check("maps has %s" % label, has(label), True,
          "a process without a heap or a stack is not a process")
check("maps has no [vsyscall]", has("[vsyscall]"), False,
      "measured: this kernel does not map it, and we invented one")
check("the loader is mapped",
      any("ld-linux-x86-64.so.2" in l for l in maps), True,
      "something has to have resolved those libraries")

# --------------------------------------------- the inode is the file's inode
for path in ("/usr/bin/bash", "/usr/lib/x86_64-linux-gnu/libc.so.6"):
    rows = [l for l in maps if l.rstrip().endswith(path)]
    check("%s is mapped" % path, bool(rows), True)
    if rows:
        ino = rows[0].split()[4]
        check("...with the inode stat gives it", ino,
              out(S, "stat -c %%i %s" % path).strip(),
              "the inode was arithmetic on the pid, so the same library "
              "had a different inode in every process")
        check("...the same inode in every segment",
              sorted({l.split()[4] for l in rows}), [ino],
              "one file, one inode, however many times it is mapped")
filebacked = [l for l in named
              if not l.rstrip().endswith("]") and "00:00" in l]
check("no file-backed mapping has device 00:00", filebacked[:2], [],
      "dev 00:00 and inode 0 is how the kernel spells 'not a file'")
zero = [l for l in named if l.split()[4] == "0" and "/" in l[73:]]
check("no named file has inode 0", zero[:2], [])

# --------------------------------------------- maps agrees with ldd
def sonames_from(cmd):
    return sorted({l.split("=>")[0].strip()
                   for l in out(S, cmd).splitlines() if "=>" in l})


ldd = sonames_from("ldd /usr/bin/bash")
mapped = sorted({l.rsplit("/", 1)[-1] for l in maps
                 if ".so" in l and "ld-linux" not in l})
check("every library ldd names is mapped",
      [so for so in ldd if so not in mapped], [],
      "ldd and the loader are describing one act")
# ...but not by the same spelling, and that asymmetry is measured: the
# kernel records where the dentry is, ld.so reports where the cache sent
# it, and /lib is a symlink only one of them follows.
check("maps uses the /usr spelling",
      sorted({l[73:].rsplit("/", 1)[0] for l in maps
              if ".so" in l}) or ["<none>"],
      ["/usr/lib/x86_64-linux-gnu"])
check("ldd uses the /lib spelling",
      sorted({l.split("=>")[1].split("(")[0].strip().rsplit("/", 1)[0]
              for l in out(S, "ldd /usr/bin/bash").splitlines()
              if "=>" in l}) or ["<none>"],
      ["/lib/x86_64-linux-gnu"])

# ----------------------------------------------- the total, seven ways
vsz = num(out(S, "ps -p $$ -o vsz=").strip())
rss = num(out(S, "ps -p $$ -o rss=").strip())
status = {}
for line in out(S, "cat /proc/self/status").splitlines():
    if ":" in line:
        k, v = line.split(":", 1)
        status[k.strip()] = v.strip()
statm = out(S, "cat /proc/self/statm").split()
smaps_size = num(out(S, "awk -F: '/^Size:/{a+=$2} END{print a}' "
                        "/proc/self/smaps"))
smaps_rss = num(out(S, "awk -F: '/^Rss:/{a+=$2} END{print a}' "
                       "/proc/self/smaps"))
rollup = num(out(S, "awk -F: '/^Rss:/{print $2; exit}' "
                    "/proc/self/smaps_rollup"))
pmap_tot = num(out(S, "pmap $$ | tail -1"))
pmap_x = (out(S, "pmap -x $$ | tail -1").split() + ["", "", "", ""])

check("VmSize is ps VSZ", num(status.get("VmSize", "")), vsz)
check("statm's first field is VmSize in pages",
      int(statm[0]) * 4 if statm else -1, vsz)
check("the smaps Size column sums to VmSize", smaps_size, vsz,
      "the maps were an independent story: pmap totalled 4692K next to a "
      "VmSize of 9284 kB")
check("pmap's total is VmSize", pmap_tot, vsz)
check("pmap -x totals VmSize", num(pmap_x[2]) if len(pmap_x) > 2 else -1, vsz)
check("VmRSS is ps RSS", num(status.get("VmRSS", "")), rss)
check("statm's second field is VmRSS in pages",
      int(statm[1]) * 4 if len(statm) > 1 else -1, rss)
check("the smaps Rss column sums to VmRSS", smaps_rss, rss,
      "smaps and pmap -x each drew their own numbers")
check("smaps_rollup agrees", rollup, rss)
check("pmap -x totals VmRSS", num(pmap_x[3]) if len(pmap_x) > 3 else -1, rss)

# ------------------------------------------------ pmap agrees with ps
p1 = out(S, "pmap 1").splitlines()
check("pmap 1 has a header", bool(p1), True)
if p1:
    check("pmap 1 names what ps names", p1[0],
          "1:   %s" % out(S, "ps -p 1 -o args=").strip(),
          "it said /bin/bash on a box whose ps and /proc/1/comm both say "
          "systemd")
check("pmap's rows are 5-char modes",
      [l for l in p1[1:] if l.strip() and not l.startswith(" total")
       and not re.match(r"^[0-9a-f]{16} +\d+K [-rwxs]{5} ", l)][:2], [])
check("pmap labels anonymous mappings",
      any("[ anon ]" in l for l in p1), True)
check("pmap labels the stack", any("[ stack ]" in l for l in p1), True)
check("pmap on a missing pid is silent",
      out(S, "pmap 999999 2>&1").strip(), "",
      "measured: nothing at all, and rc 42")
check("...and exits 42", out(S, "pmap 999999 >/dev/null 2>&1; echo $?"
                             ).strip(), "42")
check("pmap -x prints the extended header",
      out(S, "pmap -x $$").splitlines()[1] if
      len(out(S, "pmap -x $$").splitlines()) > 1 else "",
      "Address           Kbytes     RSS   Dirty Mode  Mapping")
check("pmap -x has the dashed rule",
      any(l.startswith("---------------- ------- ")
          for l in out(S, "pmap -x $$").splitlines()), True)
check("two pids do not share an address space",
      out(S, "pmap 1 | sed -n 2p").split()[0]
      == out(S, "pmap $$ | sed -n 2p").split()[0], False,
      "every process was mapped at 55a1c0000000")

# The maps have to hold still within one process.
check("two reads of one process's maps agree",
      out(S, "cat /proc/self/maps") == out(S, "cat /proc/self/maps"), True,
      "it is the same address space both times")

# ------------------------------------------------------- smaps structure
sm = out(S, "cat /proc/self/smaps").splitlines()
check("smaps is not empty", len(sm) > 20, True,
      "it returned nothing on a box that lists the file in /proc/<pid>")
blocks = [i for i, l in enumerate(sm) if re.match(r"^[0-9a-f]{12}-", l)]
check("smaps has one block per mapping", len(blocks), len(maps))
if len(blocks) > 1:
    fields = [l.split(":")[0] for l in sm[blocks[0] + 1:blocks[1]]]
    check("the field list is the guest's", fields[:6],
          ["Size", "KernelPageSize", "MMUPageSize", "Rss", "Pss",
           "Pss_Dirty"])
    check("...and ends with VmFlags", fields[-1], "VmFlags")
check("no mapping is more resident than its size",
      [l for i, l in enumerate(sm)
       if l.startswith("Rss:") and i > 0
       and num(l) > num(sm[i - 3]) if sm[i - 3].startswith("Size:")][:2], [])

# -------------------------------------------------- the awk that found it
for prog, want in (
        ("BEGIN{x=1e9; x^=100; print x}", "+inf"),
        ("BEGIN{x=-1e9; x^=101; print x}", "-inf"),
        ("BEGIN{x=2; x^=10; print x}", "1024"),
        ("BEGIN{a=0; for(i=0;i<5;i++) a+=1e308; print a}", "+inf"),
        ("BEGIN{x=1e9; x^=100; printf \"%d|%s|%g\\n\", x, x, x}",
         "+inf|+inf|+inf")):
    check("awk %s" % prog[:34], out(S, "awk '%s'" % prog).strip(), want,
          "gawk signs its infinities, and += must not evaluate ** on the "
          "way past")
check("summing a big column does not raise",
      out(S, "awk '{a+=$1} END{print a}' /proc/self/statm").strip(), "2321",
      "a running total over a column of kilobytes is the whole reason "
      "anybody runs awk")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
