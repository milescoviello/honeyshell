#!/usr/bin/env python3
"""Eight axes that already agree, pinned so they cannot quietly stop.

This suite is the product of four sweeps that found no bug. Eight axes
nobody had asked were checked against each other and against a real
trixie, and all eight were right. That is worth keeping only if it is enforced --
every one of them is the kind of agreement that holds until somebody adds
a key, a device or a column and does not think to look at the other
reader.

What was checked, and why each is a place two readers could drift:

  * **sysctl against /proc/sys.** 629 keys, each one readable two ways.
    A tunable added to one and not the other is invisible until an
    attacker greps for it. Found agreeing on all 629; the single
    exception is kernel.random.uuid, which *must* differ between reads
    because the kernel mints a fresh UUID each time it is opened.
  * **the box's own name.** hostname, uname -n, /proc/sys/kernel/hostname,
    hostname -s/-f/-d/-i/-I/-A, dnsdomainname, hostnamectl and
    /etc/hostname. This is live state an attacker changes -- renaming a
    box is a way of marking it -- and the transient/static split is easy
    to get wrong in the direction that gives the game away.
  * **block-device identity.** lsblk, lsblk -f, blkid, /etc/fstab,
    /dev/disk/by-uuid, findmnt and df. A 28T /data that one of them does
    not know about would be a loud tell to anyone surveying storage.
  * **the process limits.** ulimit -a in kbytes and blocks against
    /proc/self/limits in bytes, plus prlimit. Unit conversions are where
    these drift.
  * **how a program gets its privilege.** find -perm -4000, find -perm
    -2000, getcap, capsh --print and /proc/self/status. The SUID survey
    is the first thing a privesc script runs, and the counterintuitive
    part is worth freezing: on trixie `getcap -r /` is *empty* and
    /usr/bin/ping is plain -rwxr-xr-x with no capabilities at all --
    verified on the guest and in a container with iputils-ping and
    libcap2-bin installed. ping works because
    net.ipv4.ping_group_range is `0 2147483647`, so it opens an
    unprivileged ICMP socket. Somebody reading an empty getcap as a bug
    and granting ping cap_net_raw would be making the box *less* like a
    real one, which is why the three facts are pinned together.
  * **the interface counters.** /proc/net/dev, ip -s link, ifconfig and
    netstat -i are four readers of one pair of numbers, and none of them
    had a suite. They advance per read, which a live box's do, so the
    invariant that matters is not equality but that no reader ever goes
    backwards relative to another -- four independent counters would
    look fine in isolation and regress the moment anyone interleaved
    them, which is exactly what a bot sampling a rate does.

  * **how bash refuses to run something.** A command containing a slash
    is a *path*, and bash says so differently: `nosuchcmd` is "command
    not found" at rc 127, `/usr/bin/nosuchbin` is "No such file or
    directory" at rc 127, `/etc` is "Is a directory" at rc 126 and
    `/etc/passwd` is "Permission denied" at rc 126. Four messages and two
    exit codes for one apparent question, and a refactor that flattened
    them into one "command not found" would be invisible to every other
    suite. Live traffic exercises it: the toolkit from 203.0.113.78 runs
    `/ip cloud print`, a MikroTik command, and what it gets back is
    `bash: /ip: No such file or directory`.
  * **locate.** Six readers agree it is not installed -- no binary,
    neither plocate nor mlocate as a package, no /var/lib/plocate or
    /var/lib/mlocate, rc 127 -- and the guest agrees. The same toolkit
    runs `locate D877F783D5D3EF8C`, a WhatsApp crypt-key signature, so
    this is a real answer to a real probe rather than a hypothetical.

Measured against the guest, a real Debian trixie, for the ones that needed
it: `lsblk` and `lsblk -f` there list exactly the same device set -- six
lines each, including sda14 which has no filesystem and sr0 -- so a
device without a filesystem still appears under -f with empty columns.

Usage:  python3 crossreadtest.py
"""

import re
import sys

import fakeshell as fs

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    sh = fs.Shell(fs.VFS(), peer="203.0.113.88")
    sh.exec_mode = True
    return sh


def run(sh, cmd):
    try:
        out = sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<%s>" % exc, "", None
    err = "".join(sh._err)
    sh._err = []
    return out, err, sh.last_rc


# ===================================== sysctl and /proc/sys are one table
# Read through the filesystem rather than 629 `cat` invocations, which is
# the same question and finishes in the gate's lifetime; a handful go
# through the command path below to prove that reader too.
sh = shell()
out, _e, _rc = run(sh, "sysctl -a")
pairs = [ln.partition("=") for ln in out.splitlines() if "=" in ln]
check("sysctl -a returns a substantial table", len(pairs) > 500, True,
      "if this collapses the comparison below proves nothing")

# The kernel mints a new UUID on every read of this one, so the two
# readers are *supposed* to disagree. Anything else that disagrees is a
# real divergence.
VOLATILE = {"kernel.random.uuid", "kernel.random.boot_id"}
missing, differ = [], []
for k, _, v in pairs:
    key, want = k.strip(), v.strip()
    if key in VOLATILE:
        continue
    path = "/proc/sys/" + key.replace(".", "/")
    raw = sh.fs.read(path)
    if raw is None:
        missing.append(key)
        continue
    got = "\t".join(raw.decode("utf-8", "replace").rstrip("\n").split("\n"))
    if got.split() != want.split():
        differ.append((key, want, got))
check("every sysctl key has a /proc/sys file", missing[:8], [],
      "a key readable one way and not the other")
check("and the two readers agree on all of them",
      [d[0] for d in differ][:8], [],
      "sysctl and the file it reads are one question")

# kernel.random.uuid must keep differing -- if it ever stops, it has been
# turned into a fixed string and the box has a fingerprint.
a, _e, _rc = run(sh, "cat /proc/sys/kernel/random/uuid")
b, _e, _rc = run(sh, "cat /proc/sys/kernel/random/uuid")
check("a fresh uuid on every read", a.strip() != b.strip(), True,
      "the kernel mints one per open; a constant here is a fingerprint")
check("...and it is shaped like a uuid",
      bool(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12}", a.strip())), True)

# And the command path agrees with the file for a few that matter.
for key in ("net.ipv4.ip_forward", "kernel.hostname", "fs.file-max",
            "kernel.pid_max", "net.ipv4.tcp_syncookies"):
    o1, _e, _rc = run(sh, "sysctl -n %s" % key)
    o2, _e, _rc = run(sh, "cat /proc/sys/%s" % key.replace(".", "/"))
    check("sysctl -n %s == its file" % key, o1.split(), o2.split())


# ============================================== the box's own name
sh = shell()
readers = ("hostname", "uname -n", "cat /proc/sys/kernel/hostname",
           "hostname -s", "hostnamectl hostname", "hostnamectl --static",
           "hostnamectl --transient", "cat /etc/hostname")
base = {}
for c in readers:
    o, _e, _rc = run(sh, c)
    base[c] = o.strip()
check("every name reader agrees before anything changes",
      sorted(set(base.values())), ["web01"],
      "eight readers, one answer")

o, _e, _rc = run(sh, "hostname -f")
check("the fqdn comes from /etc/hosts", o.strip(), "web01.example.net")
o, _e, _rc = run(sh, "hostname -d")
check("...and the domain half of it", o.strip(), "example.net")
o, _e, _rc = run(sh, "getent hosts web01")
check("...and getent resolves the short name to it",
      "web01.example.net" in o, True)
o, _e, _rc = run(sh, "hostname -i")
check("hostname -i is the /etc/hosts address", o.strip(), "127.0.1.1")

# `hostname NAME` sets the transient name only. /etc/hostname and the
# static name must not move: that split is what a careful operator looks
# at, and a box where the rename persisted into /etc/hostname without
# anyone editing it would be wrong.
sh2 = shell()
run(sh2, "hostname prod-db-07")
for c, want in (("hostname", "prod-db-07"),
                ("uname -n", "prod-db-07"),
                ("cat /proc/sys/kernel/hostname", "prod-db-07"),
                ("hostnamectl --transient", "prod-db-07"),
                ("hostnamectl --static", "web01"),
                ("cat /etc/hostname", "web01")):
    o, _e, _rc = run(sh2, c)
    check("after `hostname NAME`: %s" % c, o.strip(), want,
          "transient moves, static does not")
o, _e, _rc = run(sh2, "hostnamectl")
check("...and hostnamectl shows both names",
      "Static hostname: web01" in o and "Transient hostname: prod-db-07" in o,
      True, "systemd prints the transient line only when they differ")
o, err, _rc = run(sh2, "hostname -f")
check("...and the fqdn stops resolving, because /etc/hosts did not move",
      "Name or service not known" in (o + err), True)

# `hostnamectl set-hostname` sets both and writes the file.
sh3 = shell()
run(sh3, "hostnamectl set-hostname prod-db-07")
for c in ("hostname", "uname -n", "cat /etc/hostname",
          "hostnamectl --static", "hostnamectl --transient"):
    o, _e, _rc = run(sh3, c)
    check("after `hostnamectl set-hostname`: %s" % c, o.strip(), "prod-db-07",
          "this one persists, which is the difference between the two")


# ====================================== block devices, seven readers
sh = shell()


def devnames(text):
    out = []
    for ln in text.rstrip().splitlines()[1:]:
        if not ln.strip():
            continue
        out.append(re.sub(r"^[\s|`├─└]+", "", ln).split()[0])
    return out


plain, _e, _rc = run(sh, "lsblk")
withfs, _e, _rc = run(sh, "lsblk -f")
check("lsblk -f lists the same devices as lsblk",
      devnames(withfs), devnames(plain),
      "-f is a column set, not a filter; on the guest both list six "
      "lines including sda14, which has no filesystem")

blk, _e, _rc = run(sh, "blkid")
uuids = dict(re.findall(r'^(/dev/\S+):.*?\bUUID="([^"]+)"', blk, re.M))
check("blkid knows the root and the data filesystem",
      sorted(k for k in uuids if k in ("/dev/sda1", "/dev/nvme0n1p1")),
      ["/dev/nvme0n1p1", "/dev/sda1"])

fstab, _e, _rc = run(sh, "cat /etc/fstab")
for dev, mnt in (("/dev/sda1", "/"), ("/dev/nvme0n1p1", "/data")):
    u = uuids.get(dev, "")
    check("fstab mounts %s by the UUID blkid reports" % mnt,
          ("UUID=%s" % u) in fstab and u != "", True)
    o, _e, _rc = run(sh, "ls -l /dev/disk/by-uuid/%s" % u)
    check("...and /dev/disk/by-uuid points at %s" % dev,
          dev.rsplit("/", 1)[-1] in o, True)

o, _e, _rc = run(sh, "findmnt -no SOURCE,UUID /")
f = o.split()
check("findmnt agrees about the root device", f[:1], ["/dev/sda1"])
check("...and about its UUID", f[1:2], [uuids.get("/dev/sda1")])
o, _e, _rc = run(sh, "df -h /")
check("df agrees about the root device",
      o.splitlines()[1].split()[0], "/dev/sda1")


# ================================ the limits, in three units and two files
sh = shell()
ul, _e, _rc = run(sh, "ulimit -a")
lim, _e, _rc = run(sh, "cat /proc/self/limits")


def ulimit_val(flag):
    for ln in ul.splitlines():
        m = re.search(r"-%s\)\s+(\S+)" % re.escape(flag), ln)
        if m:
            return m.group(1)
    return None


def proc_soft(name):
    for ln in lim.splitlines():
        if ln.startswith(name):
            return ln[len(name):].split()[0]
    return None


# kbytes on one side, bytes on the other. This is the conversion that
# makes the two disagree when anybody edits one of them.
for flag, row, mult in (("s", "Max stack size", 1024),
                        ("l", "Max locked memory", 1024)):
    u, p = ulimit_val(flag), proc_soft(row)
    check("%s: ulimit kbytes * 1024 == /proc bytes" % row,
          (u, p), (u, str(int(u) * mult) if u and u.isdigit() else p))

for flag, row in (("u", "Max processes"), ("n", "Max open files"),
                  ("i", "Max pending signals"), ("q", "Max msgqueue size"),
                  ("r", "Max realtime priority"), ("e", "Max nice priority")):
    check("%s: ulimit and /proc agree" % row, ulimit_val(flag),
          proc_soft(row))

for flag, row in (("t", "Max cpu time"), ("d", "Max data size"),
                  ("v", "Max address space"), ("x", "Max file locks"),
                  ("m", "Max resident set"), ("f", "Max file size")):
    check("%s: both say unlimited" % row,
          (ulimit_val(flag), proc_soft(row)), ("unlimited", "unlimited"))

pr, _e, _rc = run(sh, "prlimit")
for res, row in (("CORE", "Max core file size"), ("CPU", "Max cpu time"),
                 ("AS", "Max address space")):
    m = re.search(r"^%s\s+.*?(\S+)\s+(\S+)\s+\S*$" % res, pr, re.M)
    check("prlimit's %s soft matches /proc" % res,
          m.group(1) if m else None, proc_soft(row))

# ============================ the interface counters, four readers, one source
sh = shell()


def c_proc():
    o, _e, _rc = run(sh, "cat /proc/net/dev")
    for ln in o.splitlines():
        if ln.strip().startswith("eth0:"):
            f = ln.split(":", 1)[1].split()
            return int(f[0]), int(f[1])
    return None, None


def c_iplink():
    o, _e, _rc = run(sh, "ip -s link show eth0")
    ls = o.splitlines()
    for i, ln in enumerate(ls):
        if "RX:" in ln and i + 1 < len(ls):
            f = ls[i + 1].split()
            return int(f[0]), int(f[1])
    return None, None


def c_ifconfig():
    o, _e, _rc = run(sh, "ifconfig eth0")
    m = re.search(r"RX packets (\d+)\s+bytes (\d+)", o)
    return (int(m.group(2)), int(m.group(1))) if m else (None, None)


def c_netstat():
    o, _e, _rc = run(sh, "netstat -i")
    for ln in o.splitlines():
        if ln.startswith("eth0"):
            return None, int(ln.split()[2])
    return None, None


READERS = (("/proc/net/dev", c_proc), ("ip -s link", c_iplink),
           ("ifconfig", c_ifconfig), ("netstat -i", c_netstat))

for name, fn in READERS:
    by, pk = fn()
    check("%s reports eth0 packets" % name, isinstance(pk, int) and pk > 0,
          True, "if a reader stops parsing, the ordering below is vacuous")

# Read every reader after every other, three times round. A per-reader
# counter would pass a single read of each and fail here.
last, regress = 0, []
for _round in range(3):
    for name, fn in READERS:
        v = fn()[1]
        if v is None:
            continue
        if v < last:
            regress.append((name, last, v))
        last = v
check("no reader ever goes backwards when interleaved", regress, [],
      "they have to be one counter, not four that happen to look alike")

# Reading one reader twice must not go backwards either.
for name, fn in READERS:
    a = fn()[1]
    b = fn()[1]
    check("%s does not go backwards on a second read" % name, b >= a, True)

# The byte and packet columns have to stay a plausible ratio: a counter
# advanced in one column and not the other shows up here and nowhere else.
by, pk = c_proc()
check("bytes per packet is a sane frame size", 40 <= by / pk <= 1600, True,
      "got %.0f" % (by / pk))

# ifconfig renders the same byte count as a human figure; the two halves
# of its own line have to agree.
o, _e, _rc = run(sh, "ifconfig eth0")
m = re.search(r"RX packets \d+\s+bytes (\d+) \(([\d.]+) ([KMGT])iB\)", o)
check("ifconfig's human-readable RX matches its own byte count",
      bool(m), True)
if m:
    raw = int(m.group(1))
    shown, unit = float(m.group(2)), m.group(3)
    mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4}[unit]
    check("...to within rounding", abs(raw / mult - shown) < 0.15, True,
          "%d bytes shown as %.1f %siB" % (raw, shown, unit))

# multicast is carried by two of them and must match.
o, _e, _rc = run(sh, "cat /proc/net/dev")
pm = [ln.split(":", 1)[1].split()[7] for ln in o.splitlines()
      if ln.strip().startswith("eth0:")]
o, _e, _rc = run(sh, "ip -s link show eth0")
ls = o.splitlines()
im = None
for i, ln in enumerate(ls):
    if "RX:" in ln and i + 1 < len(ls):
        f = ls[i + 1].split()
        im = f[5] if len(f) > 5 else None
check("multicast agrees between /proc/net/dev and ip -s link", im, pm[0]
      if pm else None)

# ================== how a program gets its privilege: suid, caps, sysctl
sh = shell()

o, _e, _rc = run(sh, "find / -perm -4000 -type f 2>/dev/null | sort")
suid = [ln for ln in o.split() if ln.startswith("/")]
check("the suid survey returns the expected set", suid, [
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/gpasswd", "/usr/bin/mount",
    "/usr/bin/newgrp", "/usr/bin/passwd", "/usr/bin/su", "/usr/bin/sudo",
    "/usr/bin/umount", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
    "/usr/lib/openssh/ssh-keysign"],
    "the guest's list is the same eleven plus polkit-agent-helper-1, and "
    "this persona does not install polkit -- dpkg -l polkitd finds no "
    "package and /usr/lib/polkit-1 does not exist, so its absence here is "
    "consistent rather than missing")

# Every file the survey names has to actually carry the bit, or the survey
# and ls disagree about the same file.
for f in suid:
    o, _e, _rc = run(sh, "ls -l %s" % f)
    check("ls confirms the setuid bit on %s" % f,
          o[:10].count("s"), 1, "got %r" % o[:10])

o, _e, _rc = run(sh, "find / -perm -2000 -type f 2>/dev/null | sort")
sgid = [ln for ln in o.split() if ln.startswith("/")]
check("and the setgid survey", sgid,
      ["/usr/bin/chage", "/usr/bin/crontab", "/usr/bin/expiry",
       "/usr/bin/ssh-agent", "/usr/sbin/unix_chkpwd"])
for f in sgid:
    o, _e, _rc = run(sh, "ls -l %s" % f)
    check("ls confirms the setgid bit on %s" % f,
          o[:10].count("s"), 1, "got %r" % o[:10])

# The counterintuitive trio. Checked on the guest (a real trixie) and in a
# debian:trixie container with iputils-ping and libcap2-bin: ping is not
# setuid, has no capabilities, and getcap finds nothing anywhere.
o, _e, _rc = run(sh, "ls -l /usr/bin/ping")
check("ping is not setuid", o[:10], "-rwxr-xr-x")
o, err, _rc = run(sh, "getcap /usr/bin/ping")
check("...and carries no file capabilities", (o + err).strip(), "")
o, err, _rc = run(sh, "getcap -r /usr/bin 2>/dev/null")
check("...and nothing under /usr/bin does either", (o + err).strip(), "",
      "an empty getcap is correct on trixie; granting ping cap_net_raw "
      "to 'fix' it would make the box less like a real one")
o, _e, _rc = run(sh, "sysctl -n net.ipv4.ping_group_range")
check("because the sysctl lets any group open an ICMP socket",
      o.split(), ["0", "2147483647"],
      "this is what makes ping work without privilege, and it is the "
      "reader that explains the two above")
o, _e, _rc = run(sh, "cat /proc/sys/net/ipv4/ping_group_range")
check("...and the file says the same", o.split(), ["0", "2147483647"])

# capsh and /proc/self/status are two spellings of one bitmask.
o, _e, _rc = run(sh, "capsh --print")
names = []
for ln in o.splitlines():
    if ln.startswith("Bounding set"):
        names = [n.strip() for n in ln.split("=", 1)[1].split(",")
                 if n.strip()]
o, _e, _rc = run(sh, "grep CapBnd /proc/self/status")
mask = int(o.split(":")[1].strip(), 16)
check("capsh names exactly as many caps as CapBnd has bits",
      len(names), bin(mask).count("1"),
      "the mask is the machine-readable spelling of that list")
check("...and the mask is a contiguous run from cap 0",
      mask + 1 == 1 << mask.bit_length(), True,
      "a full bounding set has no holes")
check("...ending at the last capability the list names",
      names[-1:], ["cap_checkpoint_restore"],
      "cap 40; if the kernel gains one, both readers move together")

# =============================== how bash refuses to run something
# All seven verified byte-for-byte against bash on the guest. The split
# that matters is rc 126 (found, not executable) against rc 127 (not
# found at all), and that a slash makes it a path rather than a name.
sh = shell()
for cmd, rc_want, msg in (
        ("nosuchcmd", 127, "bash: line 1: nosuchcmd: command not found"),
        ("/ip cloud print", 127,
         "bash: line 1: /ip: No such file or directory"),
        ("/usr/bin/nosuchbin", 127,
         "bash: line 1: /usr/bin/nosuchbin: No such file or directory"),
        ("./nosuchrel", 127,
         "bash: line 1: ./nosuchrel: No such file or directory"),
        ("/etc", 126, "bash: line 1: /etc: Is a directory"),
        ("/tmp", 126, "bash: line 1: /tmp: Is a directory"),
        ("/etc/passwd", 126, "bash: line 1: /etc/passwd: Permission denied"),
):
    o, err, rc = run(sh, cmd)
    check("%s exits %d" % (cmd, rc_want), rc, rc_want,
          "126 is found-but-not-executable, 127 is not found")
    check("...and says %r" % msg.split(": ", 2)[-1], (o + err).strip(), msg,
          "four messages for one apparent question; verified on the guest")

# ============================================================ locate
sh = shell()
o, _e, _rc = run(sh, "command -v locate plocate updatedb")
check("no locate binary of any kind", o.strip(), "",
      "plocate is not installed by default on trixie, and the guest "
      "agrees")
o, err, rc = run(sh, "locate D877F783D5D3EF8C")
check("locate exits 127", rc, 127)
check("...as a missing command, not a failed search",
      (o + err).strip(), "bash: line 1: locate: command not found",
      "the toolkit from 203.0.113.78 really runs this")
for pkg in ("plocate", "mlocate"):
    o, err, _rc = run(sh, "dpkg -l %s" % pkg)
    check("dpkg has no %s package" % pkg,
          "no packages found" in (o + err), True)
for d in ("/var/lib/plocate", "/var/lib/mlocate"):
    o, _e, rc = run(sh, "test -e %s" % d)
    check("%s does not exist" % d, rc, 1,
          "a database with no tool to read it would be the inconsistency")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
