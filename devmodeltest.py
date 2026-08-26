#!/usr/bin/env python3
"""The device model: which devices exist, and does every view agree?

/sys/devices is the tree the kernel builds. /sys/bus/<bus>/devices and
/sys/block are symlink views onto it, and lsblk, fdisk, /proc/partitions,
/proc/diskstats and lspci are commands that describe the same hardware
from the same place. On this box the views existed and the tree did not,
and the descriptions had drifted apart:

    ls /sys/block            sda  sda1  sda15  sr0
    lsblk -d                 the whole tree, partitions and all
    cat /proc/diskstats      sda  sda1  sda2  sr0  loop0
    cat /proc/partitions     sda  sda1  sda14  sda15  sr0
    ls /sys/bus              pci
    ls /sys/bus/virtio       No such file or directory
    cat /proc/interrupts     ... IO-APIC  10-fasteoi  virtio3

Five answers to "what block devices are on this machine" and no two of
them the same. /proc/diskstats was the worst of them: it still carried the
sda2 swap partition that fdisk's own docstring records as removed, on a
box where `swapon -s`, `free` and /proc/swaps all say there is no swap --
and a loop0 with no /dev/loop0 and no loop row in lsblk. /sys/block had
never heard of sda14, which the other four all report, and listed
partitions as though they were devices, which no Linux does.

The virtio side was the same shape one layer up. lspci lists three virtio
devices, lsmod loads seven virtio modules, dmesg binds them -- and
/sys/bus/virtio, which is where every "am I in a VM" check looks after
systemd-detect-virt, did not exist. /proc/interrupts meanwhile named a
virtio3 that appears nowhere else, on IO-APIC lines, which is not how a
KVM guest with virtio-pci wires interrupts at all.

Measured on the guest (Debian 13.6, KVM, i440FX) rather than assumed:

    ls /sys/block                sda  sr0            -- disks only
    ls -l /sys/block             both are symlinks into ../devices/...
    lsblk -d                     sda, sr0
    lsblk -l                     sda, sda1, sda14, sda15, sr0, no glyphs
    ls /sys/bus                  24 buses, virtio among them
    /sys/bus/virtio/devices      virtio0 virtio1 virtio2, all symlinks
    virtio0/device               0x0003   (vendor 0x1af4, status 0xf)
    /proc/interrupts             PCI-MSIX-0000:00:08.0  0-edge  virtio0-config
    ls -l on any sysfs symlink   size 0, dated at boot

What this suite does not do is pin the device list. It asks the readers to
agree with each other and with gpt_layout(), so adding a disk to the
persona moves every answer at once or fails here.

Usage:  python3 devmodeltest.py
"""

import re
import sys
import time

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
    return fakeshell.Shell(vfs=fs, peer="198.51.100.7", peer_port=41234)


def out(sh, cmd):
    try:
        return sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def lines(sh, cmd):
    return [l for l in out(sh, cmd).splitlines() if l.strip()]


def layout():
    """gpt_layout(), or a sentinel if the emulator has no such call."""
    fn = getattr(fakeshell, "gpt_layout", None)
    if fn is None:
        return []
    try:
        return list(fn())
    except Exception as exc:                                   # noqa: BLE001
        return [("<raised %s>" % type(exc).__name__, 0, 0, 0, 0, "")]


S = shell()
PARTS = layout()
PARTNAMES = sorted(p[0] for p in PARTS)

# ---------------------------------------------------------------- the set
# Whole disks, five ways. lsblk -d is the command for this question; the
# other four are the files it is supposed to be reading.
disks_lsblk = sorted(l.split()[0] for l in lines(S, "lsblk -dn -o NAME"))
disks_sys = sorted(out(S, "ls /sys/block").split())
disks_part = sorted(l.split()[3] for l in lines(S, "cat /proc/partitions")[1:]
                    if len(l.split()) == 4 and l.split()[1] == "0")
disks_stat = sorted(l.split()[2] for l in lines(S, "cat /proc/diskstats")
                    if len(l.split()) > 2 and l.split()[1] == "0")

# Compared against the persona's disk set rather than against each other,
# so a reader that is wrong fails on its own line instead of poisoning the
# baseline for the next three.
DISKS = ["sda", "sr0"]
check("lsblk -d lists whole disks only", disks_lsblk, DISKS,
      "-d means --nodeps: drop the partitions. It was an alias for -l, "
      "which keeps them.")
check("/sys/block holds whole disks only", disks_sys, DISKS,
      "partitions live under the disk directory, never beside it")
check("/proc/partitions minor-0 devices match", disks_part, DISKS)
check("/proc/diskstats minor-0 devices match", disks_stat, DISKS)

# Partitions, four ways.
parts_lsblk = sorted(l.split()[0] for l in lines(S, "lsblk -ln -o NAME,TYPE")
                     if l.split()[-1] == "part")
parts_sys = sorted(n for n in out(S, "ls /sys/block/sda").split()
                   if n.startswith("sda") and n != "sda")
parts_part = sorted(l.split()[3] for l in lines(S, "cat /proc/partitions")[1:]
                    if len(l.split()) == 4 and l.split()[3].startswith("sda")
                    and l.split()[3] != "sda")
parts_stat = sorted(l.split()[2] for l in lines(S, "cat /proc/diskstats")
                    if len(l.split()) > 2 and l.split()[2].startswith("sda")
                    and l.split()[2] != "sda")
parts_fdisk = sorted(l.split()[0].rsplit("/", 1)[-1]
                     for l in lines(S, "fdisk -l /dev/sda")
                     if l.startswith("/dev/sda"))

check("gpt_layout() is the partition list", PARTNAMES,
      ["sda1", "sda14", "sda15"],
      "if the persona's disk changes this line changes with it")
check("lsblk partitions match the layout", parts_lsblk, PARTNAMES)
check("/sys/block/sda partitions match", parts_sys, PARTNAMES,
      "sda14 was missing here and present in every other reader")
check("/proc/partitions matches", parts_part, PARTNAMES)
check("/proc/diskstats matches", parts_stat, PARTNAMES,
      "this file carried sda2 and no sda14")
check("fdisk -l matches", parts_fdisk, PARTNAMES)

# The devices that must not exist anywhere.
for ghost, why in (("sda2", "the invented swap partition fdisk dropped"),
                   ("loop0", "no /dev/loop0, no loop row in lsblk")):
    seen = []
    for cmd in ("cat /proc/diskstats", "cat /proc/partitions", "lsblk -l",
                "fdisk -l /dev/sda", "ls /dev", "ls /sys/block",
                "blkid", "cat /proc/swaps", "swapon -s"):
        if re.search(r"\b%s\b" % ghost, out(S, cmd)):
            seen.append(cmd)
    check("%s appears nowhere" % ghost, seen, [], why)

# ------------------------------------------------------- views are links
ls_block = {}
for l in lines(S, "ls -l /sys/block"):
    m = re.match(r"^(.)\S+\s+\d+\s+\S+\s+\S+\s+(\d+)\s+.*?(\S+) -> (\S+)$", l)
    if m:
        ls_block[m.group(3)] = (m.group(1), m.group(2), m.group(4))
check("both /sys/block entries are symlinks", sorted(ls_block), DISKS,
      "they were real directories, so nothing in /sys/devices backed them")
check("a sysfs symlink is size 0",
      sorted({v[1] for v in ls_block.values()}) or ["<none>"], ["0"],
      "sysfs pages are 4096; its symlinks are 0, and every one of these "
      "reported a page")
for dev, (_t, _sz, target) in sorted(ls_block.items()):
    check("/sys/block/%s points into /sys/devices" % dev,
          target.startswith("../devices/pci0000:00/"), True)
    check("/sys/block/%s target exists" % dev,
          out(S, "cat /sys/block/%s/dev" % dev).strip() != "", True,
          "a link is only a view if what it points at is there")

# The link is not a shortcut to a different answer.
check("size through the link matches /proc/partitions",
      out(S, "cat /sys/block/sda/size").strip(),
      str(int([l.split()[2] for l in lines(S, "cat /proc/partitions")
               if l.split()[-1] == "sda"][0]) * 2))
fdisk_rows = {l.split()[0].rsplit("/", 1)[-1]: l.split()
              for l in lines(S, "fdisk -l /dev/sda") if l.startswith("/dev/")}
for name, minor, start, sectors, _kb, _kind in PARTS:
    row = fdisk_rows.get(name, [])
    check("%s start agrees with fdisk" % name,
          out(S, "cat /sys/block/sda/%s/start" % name).strip(),
          row[1] if len(row) > 1 else "<no fdisk row>")
    check("%s size agrees with fdisk" % name,
          out(S, "cat /sys/block/sda/%s/size" % name).strip(),
          row[3] if len(row) > 3 else "<no fdisk row>")
    check("%s knows its partition number" % name,
          out(S, "cat /sys/block/sda/%s/partition" % name).strip(),
          str(minor))

# ------------------------------------------------------------- the buses
buses = out(S, "ls /sys/bus").split()
check("the pci bus is on /sys/bus", "pci" in buses, True)
check("the virtio bus is on /sys/bus", "virtio" in buses, True,
      "lspci lists three virtio devices and lsmod loads their drivers; "
      "the bus they hang off has to be there too")

lspci = lines(S, "lspci")
lspci_virtio = [l for l in lspci if "Virtio" in l]
vdevs = sorted(out(S, "ls /sys/bus/virtio/devices").split())
check("one virtio bus device per virtio PCI device",
      len(vdevs), len(lspci_virtio),
      "lspci: " + "; ".join(l.split(": ", 1)[-1] for l in lspci_virtio))
check("they are numbered from zero in probe order", vdevs,
      ["virtio%d" % i for i in range(len(lspci_virtio))])

for v in vdevs:
    b = "/sys/bus/virtio/devices/" + v
    check("%s vendor is Red Hat" % v, out(S, "cat %s/vendor" % b).strip(),
          "0x1af4")
    check("%s is running" % v, out(S, "cat %s/status" % b).strip(),
          "0x0000000f",
          "0xf is DRIVER_OK; anything else means it failed to come up, "
          "which dmesg would have said")
    dev = out(S, "cat %s/device" % b).strip()
    check("%s modalias is built from its own ids" % v,
          out(S, "cat %s/modalias" % b).strip(),
          "virtio:d%08Xv%08X" % (int(dev, 16) if re.match(r"^0x[0-9a-f]+$",
                                                          dev) else 0, 0x1AF4))
    feat = out(S, "cat %s/features" % b).strip()
    check("%s features is a 64-bit string" % v,
          (len(feat), set(feat) <= set("01")), (64, True),
          "the guest's kernel prints 64 bits; got %r" % feat[:20])
    drv = out(S, "readlink %s/driver" % b).strip()
    check("%s has a driver bound" % v, drv.startswith("../"), True)
    back = out(S, "ls /sys/bus/virtio/drivers/%s" % drv.rsplit("/", 1)[-1])
    check("%s driver links back to it" % v, v in back.split(), True,
          "a binding has two ends; /sys/bus/*/drivers was empty, so every "
          "driver link on the box dangled")

# lspci's own subsystem column is where the virtio device id comes from.
for line in lspci_virtio:
    slot = line.split()[0]
    kern = out(S, "lspci -nnk -s " + slot)
    check("lspci -s %s still resolves" % slot, kern.strip() != "", True)

# ---------------------------------------------------- pci devices are links
pci_ls = lines(S, "ls -l /sys/bus/pci/devices")
pci_links = [l for l in pci_ls if l.startswith("l")]
check("every /sys/bus/pci/devices entry is a link",
      len(pci_links), len([l for l in pci_ls if not l.startswith("total")]),
      "they were real directories, and /sys/devices/pci0000:00 did not "
      "exist at all")
slots = sorted(out(S, "ls /sys/devices/pci0000:00").split())
check("the tree holds every device lspci lists",
      len(slots), len(lspci),
      "lspci reads this bus; the bus has to hold what it prints")
ids = {}
for line in lines(S, "lspci -n"):
    m = re.match(r"^(\S+)\b.*\[([0-9a-f]{4}):([0-9a-f]{4})\]", line)
    if m:
        ids[m.group(1)] = (m.group(2), m.group(3))
check("lspci -n gives an id for every device", sorted(ids),
      sorted(l.split()[0] for l in lspci))
for slot, (vid, did) in sorted(ids.items()):
    base = "/sys/devices/pci0000:00/0000:" + slot
    check("0000:%s ids match lspci" % slot,
          (out(S, "cat %s/vendor" % base).strip(),
           out(S, "cat %s/device" % base).strip()),
          ("0x" + vid, "0x" + did),
          "lspci prints from this device; they cannot disagree")

# ------------------------------------------------------- /proc/interrupts
irq = out(S, "cat /proc/interrupts")
named = sorted({m.group(1) for m in re.finditer(r"\b(virtio\d+)-", irq)})
check("/proc/interrupts names only virtio devices that exist", named, vdevs,
      "it named virtio3 on a box with three virtio devices")
check("virtio interrupts are MSI-X, not IO-APIC",
      bool(re.search(r"PCI-MSIX-\S+\s+\d+-edge\s+virtio", irq))
      and not re.search(r"IO-APIC.*virtio", irq), True,
      "a KVM guest gets one PCI-MSIX vector per virtqueue")
for v in vdevs:
    slot = out(S, "readlink /sys/bus/virtio/devices/" + v).strip()
    slot = re.sub(r".*/(0000:[0-9a-f:.]+)/virtio\d+$", r"\1", slot)
    rows = [l for l in irq.splitlines() if re.search(r"\b%s-" % v, l)]
    check("%s interrupts cite its own PCI slot" % v,
          sorted({r.split()[NCOL] for r in rows for NCOL in
                  [next(i for i, t in enumerate(r.split())
                        if t.startswith("PCI-MSIX-"))]}) or ["<no rows>"],
          ["PCI-MSIX-" + slot])

# Summary counters may not be identical across every CPU; device vectors
# fire on one CPU, not spread evenly.
sums = [l for l in irq.splitlines() if re.match(r"^(LOC|RES|CAL|TLB):", l)]
for l in sums:
    vals = l.split()[1:1 + len(re.findall(r"CPU\d+", irq.splitlines()[0]))]
    check("%s is not the same number on every CPU" % l.split(":")[0],
          len(set(vals)) > 1, True,
          "per-CPU counters that match to the digit are not a thing")

# --------------------------------------------------------- diskstats sanity
stats = {l.split()[2]: [int(x) for x in l.split()[3:]]
         for l in lines(S, "cat /proc/diskstats") if len(l.split()) > 4}
if "sda" in stats and "sda1" in stats:
    check("no partition reads more than its disk",
          stats["sda1"][0] <= stats["sda"][0], True)
if "sda14" in stats:
    check("the BIOS boot partition has no writes", stats["sda14"][4], 0,
          "it has no filesystem; nothing can write to it")
    first = stats["sda14"][0]
    time.sleep(1.1)
    again = {l.split()[2]: [int(x) for x in l.split()[3:]]
             for l in lines(S, "cat /proc/diskstats") if len(l.split()) > 4}
    check("its counters do not climb with uptime", again["sda14"][0], first,
          "a partition nothing opens does not accumulate reads")

# ------------------------------------------------------------ lsblk shapes
plain = out(S, "lsblk")
listed = out(S, "lsblk -l")
nodeps = out(S, "lsblk -d")
check("-l is the default minus the tree glyphs",
      sorted(re.sub(r"[|`─│├└]", "", plain).split()),
      sorted(listed.split()))
check("-d is a subset of -l",
      set(nodeps.split()) <= set(listed.split()), True)
check("-d drops the glyphs too", "─" in nodeps, False)
check("bundled short flags are parsed",
      out(S, "lsblk -dn -o NAME").split(), ["sda", "sr0"],
      "-dn matched nothing and was silently ignored")
check("-l and the default agree on trailing whitespace",
      [l.rstrip() == l for l in listed.splitlines()],
      [l.rstrip() == l for l in plain.splitlines()][:len(listed.splitlines())],
      "lsblk pads every column but the last, so a row with an empty "
      "MOUNTPOINTS ends in a space")

# ------------------------------------------------------------- link dating
now = int(time.time())
boot = getattr(fakeshell, "BOOT_TS", now)
st = out(S, "stat -c %Y /sys/block/sda").strip()
check("sysfs links are dated at boot, not now",
      st.isdigit() and abs(int(st) - boot) < 90, True,
      "a driver binds at boot; a device link stamped this minute on a box "
      "claiming %d days of uptime is a contradiction on its own"
      % ((now - boot) // 86400))

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
