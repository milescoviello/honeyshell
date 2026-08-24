#!/usr/bin/env python3
"""Does the box agree about how much of everything it has?

Fourth coherence sweep: when, who, where, and now how much. Memory, CPU,
filesystems and load are each reported by several commands that all read the
same few files on a real machine, so they cannot disagree there -- and the
recon probes we actually receive read CPUS and CPU_MODEL directly.

Found in one pass:

  * Three commands, three different load averages. /proc/loadavg, uptime and
    top each generated their own, and top's was the frozen literal
    "0.08, 0.03, 0.01" that matched nothing.
  * top's memory block was four hardcoded numbers: 148.3 MiB free against
    /proc/meminfo's 1103 and `free`'s 1102, 1426.1 buff/cache against 470,
    and 975 MB of swap on a box where both meminfo and free say there is
    none.
  * df listed /run/lock and /boot/efi; /proc/mounts, which df reads its
    filesystem list out of, had neither.
  * df -i was a second hand-maintained table and had lost /run/lock.
  * blkid gave /dev/sda1 and /dev/sda15 the same PARTUUID, "...-01".
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS = FAIL = 0
FAILURES = []


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
    s = fs.Shell(fs.VFS())

    # ---- memory: meminfo is the source, free and top are views of it
    mi = {k: int(v) for k, v in
          re.findall(r"^(\w+):\s+(\d+) kB", s.run("cat /proc/meminfo"), re.M)}
    for key in ("MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached",
                "SwapTotal", "SwapFree"):
        check("/proc/meminfo has %s" % key, key in mi, str(sorted(mi)[:6]))

    # one command, so all three are the same sample
    out = s.run("free -m; echo __S__; top -bn1 | head -5; echo __S__; "
                "cat /proc/loadavg; echo __S__; uptime")
    fm, tp, la_raw, up = out.split("__S__")
    fline = [l for l in fm.splitlines() if l.startswith("Mem:")][0].split()
    sline = [l for l in fm.splitlines() if l.startswith("Swap:")][0].split()
    check("free's total matches MemTotal",
          abs(int(fline[1]) - mi["MemTotal"] // 1024) <= 1,
          "%s vs %d" % (fline[1], mi["MemTotal"] // 1024))
    check("free's free matches MemFree",
          abs(int(fline[3]) - mi["MemFree"] // 1024) <= 1,
          "%s vs %d" % (fline[3], mi["MemFree"] // 1024))
    check("free's available matches MemAvailable",
          abs(int(fline[6]) - mi["MemAvailable"] // 1024) <= 1)
    check("free's swap total matches SwapTotal",
          abs(int(sline[1]) - mi["SwapTotal"] // 1024) <= 1,
          "%s vs %d" % (sline[1], mi["SwapTotal"] // 1024))

    tmem = re.search(r"MiB Mem :\s+([\d.]+) total,\s+([\d.]+) free,"
                     r"\s+([\d.]+) used,\s+([\d.]+) buff/cache", tp)
    tswp = re.search(r"MiB Swap:\s+([\d.]+) total,\s+([\d.]+) free,"
                     r"\s+([\d.]+) used\.\s+([\d.]+) avail Mem", tp)
    check("top prints a memory line", bool(tmem), tp[:80])
    check("top prints a swap line", bool(tswp))
    if tmem:
        check("top's total matches free's",
              abs(float(tmem.group(1)) - int(fline[1])) <= 1.5,
              "%s vs %s" % (tmem.group(1), fline[1]))
        check("top's free matches free's",
              abs(float(tmem.group(2)) - int(fline[3])) <= 1.5,
              "%s vs %s" % (tmem.group(2), fline[3]))
        check("top's buff/cache matches free's",
              abs(float(tmem.group(4)) - int(fline[5])) <= 1.5,
              "%s vs %s" % (tmem.group(4), fline[5]))
    if tswp:
        check("top's swap total matches free's",
              abs(float(tswp.group(1)) - int(sline[1])) <= 1.5,
              "%s vs %s" % (tswp.group(1), sline[1]))
        check("a box with no swap says so everywhere",
              (mi["SwapTotal"] == 0) == (float(tswp.group(1)) == 0.0)
              == (int(sline[1]) == 0),
              "meminfo %d, top %s, free %s"
              % (mi["SwapTotal"], tswp.group(1), sline[1]))
    check("/proc/swaps agrees about swap",
          (mi["SwapTotal"] == 0)
          == (len([l for l in s.run("cat /proc/swaps").splitlines()[1:]
                   if l.strip()]) == 0),
          s.run("cat /proc/swaps").replace("\n", " | ")[:70])

    # ---- load average: one number, three readers
    la = la_raw.split()[:3]
    upla = re.search(r"load average: ([\d.]+), ([\d.]+), ([\d.]+)", up)
    tpla = re.search(r"load average: ([\d.]+), ([\d.]+), ([\d.]+)", tp)
    check("uptime prints a load average", bool(upla), up.strip()[:70])
    check("top prints a load average", bool(tpla))
    if upla:
        check("uptime's load matches /proc/loadavg",
              [float(x) for x in upla.groups()] == [float(x) for x in la],
              "%s vs %s" % (list(upla.groups()), la))
    if tpla:
        check("top's load matches /proc/loadavg",
              [float(x) for x in tpla.groups()] == [float(x) for x in la],
              "%s vs %s" % (list(tpla.groups()), la))
    check("w's load matches too",
          re.search(r"load average: ([\d.]+)", s.run("w")) is not None)

    # ---- cpu count, four ways
    n = int(s.run("nproc").strip())
    check("nproc matches /proc/cpuinfo",
          n == int(s.run("grep -c ^processor /proc/cpuinfo").strip()))
    check("nproc matches lscpu",
          ("CPU(s):" in s.run("lscpu")
           and int(re.search(r"^CPU\(s\):\s+(\d+)", s.run("lscpu"),
                             re.M).group(1)) == n))
    check("nproc matches /sys/devices/system/cpu",
          len([x for x in s.run("ls /sys/devices/system/cpu").split()
               if re.fullmatch(r"cpu\d+", x)]) == n)
    check("nproc matches /proc/stat's per-cpu rows",
          len([l for l in s.run("cat /proc/stat").splitlines()
               if re.match(r"^cpu\d", l)]) == n)
    check("lscpu's model name matches /proc/cpuinfo",
          re.search(r"Model name:\s+(.+)", s.run("lscpu")).group(1).strip()
          == re.search(r"model name\s*:\s*(.+)",
                       s.run("cat /proc/cpuinfo")).group(1).strip())
    check("cores x sockets x threads equals the cpu count",
          int(re.search(r"Core\(s\) per socket:\s+(\d+)",
                        s.run("lscpu")).group(1))
          * int(re.search(r"Socket\(s\):\s+(\d+)", s.run("lscpu")).group(1))
          * int(re.search(r"Thread\(s\) per core:\s+(\d+)",
                          s.run("lscpu")).group(1)) == n)

    # ---- filesystems: df, df -i and /proc/mounts describe one set
    dfm = {l.split()[-1] for l in s.run("df -h").splitlines()[1:] if l.strip()}
    dfi = {l.split()[-1] for l in s.run("df -i").splitlines()[1:] if l.strip()}
    pm = {l.split()[1] for l in s.run("cat /proc/mounts").splitlines()
          if len(l.split()) > 1}
    check("df and df -i list the same filesystems", dfm == dfi,
          str(sorted(dfm ^ dfi)))
    check("every df filesystem is in /proc/mounts", not (dfm - pm),
          str(sorted(dfm - pm)))
    # The types GNU df skips without -a: everything that holds no blocks.
    # The list grew when /proc/mounts stopped being nine hand-written lines
    # and became the mount table a real trixie has.
    pseudo = {m for m in pm
              if any(m == x or m.startswith(x + "/")
                     for x in ("/proc", "/sys", "/dev/pts", "/dev/mqueue",
                               "/dev/hugepages"))}
    check("the only mounts df omits are pseudo filesystems",
          not (pm - dfm - pseudo), str(sorted(pm - dfm - pseudo)))
    check("df's used plus available does not exceed its total",
          all(int(f[2]) + int(f[3]) <= int(f[1]) * 1.02
              for f in (l.split() for l in
                        s.run("df").splitlines()[1:]) if len(f) > 3
              and f[1].isdigit()))

    # ---- block devices agree with the filesystems on them
    blk = s.run("blkid")
    parts = re.findall(r"^(/dev/\S+):", blk, re.M)
    puuids = re.findall(r'PARTUUID="([^"]+)"', blk)
    check("blkid gives every partition a distinct PARTUUID",
          len(set(puuids)) == len(puuids), str(puuids))
    check("blkid's PARTUUID suffix is the partition number",
          all(p.endswith("-%02d" % int(re.search(r"(\d+)$", d).group(1)))
              for d, p in zip(parts, puuids) if re.search(r"\d+$", d)),
          str(list(zip(parts, puuids))))
    root_uuid = re.search(r'/dev/sda1: UUID="([^"]+)"', blk)
    check("fstab's root UUID is the one blkid reports",
          root_uuid and root_uuid.group(1) in s.run("cat /etc/fstab"),
          root_uuid.group(1) if root_uuid else "")
    lsb = s.run("lsblk")
    for dev in parts:
        check("lsblk knows about %s" % dev,
              os.path.basename(dev) in lsb, lsb[:60])
    check("lsblk's mountpoints are ones df knows",
          all(m in dfm for m in re.findall(r"(/\S*)$", lsb, re.M)
              if m.startswith("/")),
          str([m for m in re.findall(r"(/\S*)$", lsb, re.M)
               if m.startswith("/") and m not in dfm]))

    # ---- ps, top and /proc agree on how many processes there are
    nps = len([l for l in s.run("ps -e").splitlines()[1:] if l.strip()])
    tasks = re.search(r"Tasks:\s+(\d+) total", s.run("top -bn1"))
    check("top's task count matches ps", tasks and int(tasks.group(1)) == nps,
          "%s vs %d" % (tasks.group(1) if tasks else "?", nps))

    # ---- statfs and df describe the same filesystem, before and after a
    # write. They were independent: statfs reported 4128760 blocks -- about
    # 16GB, left over from before the disk was resized -- while df said 63G,
    # and df's figure never moved when a file was written, so `du` saw the
    # write and `df` insisted nothing had changed.
    def fs_pair():
        d = s.run("df -k /").splitlines()[-1].split()
        f = s.run("stat -f -c '%b %a %S' /").strip().split()
        return (int(d[1]), int(d[3]),
                int(f[0]) * int(f[2]) // 1024, int(f[1]) * int(f[2]) // 1024)

    dt, da, st_, sa = fs_pair()
    check("stat -f -c honours its format",
          len(s.run("stat -f -c %b /").split()) == 1,
          s.run("stat -f -c %b /").strip()[:40])
    check("statfs and df agree on the filesystem size", dt == st_,
          "df %d vs statfs %d" % (dt, st_))
    check("statfs and df agree on free space", da == sa,
          "df %d vs statfs %d" % (da, sa))
    check("statfs block size is 4096",
          s.run("stat -f -c %S /").strip() == "4096")
    check("statfs names the same type df does",
          s.run("stat -f -c %T /").strip() in ("ext2/ext3", "ext4"),
          s.run("stat -f -c %T /").strip())

    # /tmp is a tmpfs of its own, so a file written there is charged to
    # that filesystem and not to /. This check is about the root one, so it
    # writes somewhere on it.
    before_used = int(s.run("df -k /").splitlines()[-1].split()[2])
    s.run("rm -f /root/growcheck; head -c 4194304 /dev/zero > /root/growcheck")
    after_used = int(s.run("df -k /").splitlines()[-1].split()[2])
    check("writing 4MiB moves df's used figure",
          after_used - before_used == 4096,
          "delta %d KB" % (after_used - before_used))
    check("du sees the same write",
          s.run("du -sk /root/growcheck").split()[0] == "4096",
          s.run("du -sk /root/growcheck").split()[0])
    # ...and the same write into /tmp lands on the tmpfs instead.
    tmp_before = int(s.run("df -k /tmp").splitlines()[-1].split()[2])
    root_before = int(s.run("df -k /").splitlines()[-1].split()[2])
    s.run("rm -f /tmp/growcheck; head -c 4194304 /dev/zero > /tmp/growcheck")
    check("writing to /tmp moves the tmpfs",
          int(s.run("df -k /tmp").splitlines()[-1].split()[2])
          - tmp_before == 4096,
          s.run("df -k /tmp").splitlines()[-1])
    check("and leaves the root filesystem alone",
          int(s.run("df -k /").splitlines()[-1].split()[2]) == root_before,
          s.run("df -k /").splitlines()[-1])
    dt2, da2, st2, sa2 = fs_pair()
    check("statfs still agrees with df after the write",
          dt2 == st2 and da2 == sa2,
          "df %d/%d vs statfs %d/%d" % (dt2, da2, st2, sa2))
    check("the total size did not change, only the usage", dt2 == dt)

    # A bounded, deliberate limit rather than a bug: a single command's
    # output is capped so a `yes`-style loop cannot exhaust the honeypot's
    # memory. Recorded here so the bound stays visible and intentional.
    # The bound is on output that grows without limit. This used to assert
    # it with `head -c 8388608`, which is the opposite case -- a command told
    # exactly how many bytes to produce -- and so pinned a silent short read
    # as if it were the policy. An explicit count is honoured now, up to the
    # hard ceiling; a generator is still cut.
    unbounded = len(s.run("seq 1 5000000"))
    check("output that grows without limit is bounded at 4MiB",
          unbounded <= 4 * 1024 * 1024, "%d bytes" % unbounded)
    s.run("rm -f /tmp/cap; head -c 8388608 /dev/zero > /tmp/cap")
    asked = int(s.run("wc -c < /tmp/cap").strip() or 0)
    check("...but an explicit byte count is honoured",
          asked == 8388608, "%d bytes" % asked)
    s.run("rm -f /tmp/cap2; head -c 134217728 /dev/zero > /tmp/cap2")
    ceil = int(s.run("wc -c < /tmp/cap2").strip() or 0)
    check("...and still ceilinged at 64MiB",
          ceil == 64 * 1024 * 1024, "%d bytes" % ceil)

    print()
    print("=" * 62)
    print("passed %d, failed %d" % (PASS, FAIL))
    for f in FAILURES:
        print("   FAILED: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
