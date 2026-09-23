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
        # Every disk's layout, not just the default one -- gpt_layout()
        # takes a disk argument now, and calling it bare listed sda's
        # partitions while lsblk listed all of them.
        disks = getattr(fakeshell, "DISKS", None)
        if disks:
            rows = []
            for d in disks:
                rows += list(fn(d[0]))
            return rows
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
# From the emulator's own disk table plus the CD-ROM, which is not in it
# (no partition table). This was ["sda", "sr0"], which made adding a
# second drive look like a -dn parsing regression.
# Sorted, because every reader above is sorted -- `ls /sys/block` sorts
# and lsblk prints in table order, so comparing them to one *ordered*
# list could only ever have worked while there was a single disk.
DISKS = sorted([d[0] for d in getattr(fakeshell, "DISKS",
                                      [("sda",)])] + ["sr0"])
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
# Every partition on the box, not the ones whose names begin "sda".
# Filtering by that prefix pinned all five readers to a single disk, so a
# second drive's partition was invisible to the suite that exists to
# check that every reader lists the same partitions.
_wholedisks = set(DISKS)
parts_sys = sorted(n for d in DISKS
                   for n in out(S, "ls /sys/block/%s" % d).split()
                   if n.startswith(d) and n != d)
parts_part = sorted(l.split()[3] for l in lines(S, "cat /proc/partitions")[1:]
                    if len(l.split()) == 4
                    and l.split()[3] not in _wholedisks)
parts_stat = sorted(l.split()[2] for l in lines(S, "cat /proc/diskstats")
                    if len(l.split()) > 2
                    and l.split()[2] not in _wholedisks)
parts_fdisk = sorted(l.split()[0].rsplit("/", 1)[-1]
                     for l in lines(S, "fdisk -l")
                     if l.startswith("/dev/"))

check("gpt_layout() is the partition list", PARTNAMES,
      ["nvme0n1p1", "sda1", "sda14", "sda15"],
      "if the persona's disk changes this line changes with it")
check("lsblk partitions match the layout", parts_lsblk, PARTNAMES)
check("/sys/block partitions match", parts_sys, PARTNAMES,
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
              for l in lines(S, "fdisk -l") if l.startswith("/dev/")}
# A partition lives under its own disk in /sys/block. This read
# /sys/block/sda/<part> for every partition, which was fine while there
# was one disk and answered nothing at all once there were two.
_pdisk = getattr(fakeshell, "PART_DISK", {})
for name, minor, start, sectors, _kb, _kind in PARTS:
    row = fdisk_rows.get(name, [])
    disk = _pdisk.get(name, "sda")
    check("%s start agrees with fdisk" % name,
          out(S, "cat /sys/block/%s/%s/start" % (disk, name)).strip(),
          row[1] if len(row) > 1 else "<no fdisk row>")
    check("%s size agrees with fdisk" % name,
          out(S, "cat /sys/block/%s/%s/size" % (disk, name)).strip(),
          row[3] if len(row) > 3 else "<no fdisk row>")
    check("%s knows its partition number" % name,
          out(S, "cat /sys/block/%s/%s/partition" % (disk, name)).strip(),
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
# `lspci -n` prints unbracketed numbers -- "00:00.0 0600: 8086:29c0".
# The brackets belong to -nn, and this regex wanted them, which it only
# ever got because the two flags were treated as one and both printed the
# -nn form. Measured on the Debian 13 host: -n is slot, class, ids.
for line in lines(S, "lspci -n"):
    m = re.match(r"^(\S+)\s+[0-9a-f]{4}:\s+([0-9a-f]{4}):([0-9a-f]{4})",
                 line)
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
      sorted(out(S, "lsblk -dn -o NAME").split()), DISKS,
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

# ------------------------------------------- /sys/class is a view as well
# The docstring above is about /sys/bus and /sys/block; /sys/class obeys
# the same rule and had been left out of it. Every entry under
# /sys/class/<class>/ is a symlink into /sys/devices -- the real guest has
# 176 of them and not one plain directory -- and twenty of ours were plain
# directories: /sys/class/dmi/id, /sys/class/net/{eth0,lo} and all
# seventeen DRM nodes.
#
# The dmi one had both halves of the bug at once. /sys/class/dmi/id held
# all 21 files as a real directory while /sys/devices/virtual/dmi/id held
# product_name alone, so two paths to one SMBIOS table disagreed on
# sixteen of them:
#
#     cat /sys/class/dmi/id/sys_vendor             QEMU
#     cat /sys/devices/virtual/dmi/id/sys_vendor   No such file or directory
#
# and dmidecode, reading the same table, agreed with the path that worked.
_plain = out(S, 'for d in /sys/class/*/; do for e in "$d"*; do '
                '[ -d "$e" ] && [ ! -L "$e" ] && echo "$e"; done; done')
check("no entry under /sys/class is a plain directory",
      sorted(_plain.split()), [],
      "sysfs makes every /sys/class/<class>/<device> a symlink into "
      "/sys/devices; a real box has zero plain directories there")

check("/sys/class/dmi/id is the documented symlink",
      out(S, "readlink /sys/class/dmi/id").strip(),
      "../../devices/virtual/dmi/id")
check("...and it resolves into the devices tree",
      out(S, "readlink -f /sys/class/dmi/id").strip(),
      "/sys/devices/virtual/dmi/id")
# Regular files only. power/ is a directory and subsystem a symlink to
# one, and `cat` on either names the path it was given -- so comparing
# their error text reports a difference that a real box has too.
_dmi_diff = out(S, 'for f in $(ls /sys/class/dmi/id); do '
                   '[ -f /sys/class/dmi/id/$f ] || continue; '
                   'a=$(cat /sys/class/dmi/id/$f 2>&1); '
                   'b=$(cat /sys/devices/virtual/dmi/id/$f 2>&1); '
                   '[ "$a" = "$b" ] || echo "$f"; done')
check("both paths to the SMBIOS table read the same",
      sorted(_dmi_diff.split()), [],
      "one directory reached two ways cannot answer differently")
check("dmidecode agrees with sysfs on the vendor",
      out(S, "dmidecode -s system-manufacturer").strip(),
      out(S, "cat /sys/devices/virtual/dmi/id/sys_vendor").strip())

# `readlink /sys/class/net/eth0` is how you tell a physical NIC from a
# virtual one, and how you get its PCI address without lspci. It was empty.
check("lo points into devices/virtual",
      out(S, "readlink /sys/class/net/lo").strip(),
      "../../devices/virtual/net/lo")
_nic = out(S, "readlink /sys/class/net/eth0").strip()
_nic_slot = out(S, "lspci -D | awk '/Ethernet controller/{print $1}'").strip()
check("eth0 points at the PCI slot lspci gives for the NIC",
      _nic.startswith("../../devices/pci0000:00/%s/" % _nic_slot)
      and _nic.endswith("/net/eth0"), True,
      "got %r for slot %r -- the two readers of one NIC have to name the "
      "same device" % (_nic, _nic_slot))
check("eth0's attributes are readable through the link",
      out(S, "cat /sys/class/net/eth0/address").strip(),
      out(S, "cat $(readlink -f /sys/class/net/eth0)/address").strip())

# The DRM nodes, which is where fastfetch and btop look for GPUs.
_drm_bad = out(S, 'for e in /sys/class/drm/card* /sys/class/drm/renderD*; do '
                  '[ -L "$e" ] || echo "$e"; done')
check("every DRM node is a link", sorted(_drm_bad.split()), [])
check("/sys/class/drm/version is a file, not a node",
      out(S, "cat /sys/class/drm/version").strip(), "drm 1.1.0 20060810",
      "it is the one entry under /sys/class/drm that is not a device")
_gpu_slot = out(S, "lspci -D | awk '/NVIDIA/{print $1; exit}'").strip()
check("card1 hangs off the first NVIDIA slot lspci reports",
      out(S, "readlink /sys/class/drm/card1").strip(),
      "../../devices/pci0000:00/%s/drm/card1" % _gpu_slot)
check("its render node hangs off the same device",
      out(S, "readlink /sys/class/drm/renderD128").strip(),
      "../../devices/pci0000:00/%s/drm/renderD128" % _gpu_slot)
check("a DRM node holds what a real one holds",
      sorted(out(S, "ls /sys/class/drm/card1").split()),
      ["dev", "device", "power", "subsystem", "uevent"])
check("the node's device link points back at the card",
      out(S, "readlink /sys/class/drm/card1/device").strip(),
      "../../../%s" % _gpu_slot)
check("...and its subsystem link points back at the class",
      out(S, "readlink /sys/class/drm/card1/subsystem").strip(),
      "../../../../../class/drm")
check("the PCI device carries both nodes",
      sorted(out(S, "ls /sys/devices/pci0000:00/%s/drm" % _gpu_slot).split()),
      ["card1", "renderD128"])
# sysfs's dev file and the device node in /dev are the same question.
# `ls -l` prints them in decimal, stat -c %t:%T in hex, so the comparison
# goes through the listing rather than converting.
for _n, _min in (("card1", 1), ("renderD128", 128)):
    check("%s's dev file matches its node in /dev/dri" % _n,
          out(S, "cat /sys/class/drm/%s/dev" % _n).strip(),
          out(S, "ls -l /dev/dri/%s | awk '{print $5$6}'" % _n
              ).strip().replace(",", ":"))
    check("...and names minor %d" % _min,
          out(S, "cat /sys/class/drm/%s/dev" % _n).strip(), "226:%d" % _min)

# Making the class entry a symlink introduced a failure mode of its own,
# and the gate caught it: the runtime writers pushed live state through
# /sys/class/net/<if>/, which created nodes *behind* the link that no read
# reached. `ip link set eth0 mtu 9000` returned 0, ip reported 9000, and
# both spellings of the sysfs path still said 1500 -- while the interface
# counters stopped moving altogether, because the statistics sync looked
# its nodes up by the class path and got None. Three suites went red on it
# (ifacetest, nstattest, nettest). This checks the view and the tree agree
# after a change, not just at construction.
W = shell()
_ = out(W, "ip link set eth0 mtu 9000")
_dev = out(W, "readlink -f /sys/class/net/eth0").strip()
check("a runtime write reaches the tree through the view",
      [out(W, "cat /sys/class/net/eth0/mtu").strip(),
       out(W, "cat %s/mtu" % _dev).strip(),
       out(W, "ip -o link show eth0 | grep -o 'mtu [0-9]*'").strip()],
      ["9000", "9000", "mtu 9000"],
      "a write through a symlinked directory that lands behind the link "
      "is invisible to every reader")
_ = out(W, "ip link set eth0 down")
check("...and so does operstate",
      [out(W, "cat /sys/class/net/eth0/operstate").strip(),
       out(W, "cat %s/operstate" % _dev).strip()], ["down", "down"])
check("the counters are live, not seeded zeros",
      out(W, "cat /sys/class/net/eth0/statistics/rx_bytes").strip() not in
      ("", "0"), True,
      "sync_net_dev addressed these by the class path; after the link went "
      "in it found no nodes and every counter stayed at 0")

# ------------------------------------------------------- lspci -D and -s
# -D was accepted and ignored, so `lspci -D` was byte-identical to `lspci`
# -- and the domain-qualified form is the one that matches the directory
# names under /sys/bus/pci/devices, so the two readers of one bus could
# not produce each other's spelling.
_plain_l = out(S, "lspci | head -1").split()[0]
_dom_l = out(S, "lspci -D | head -1").split()[0]
check("lspci -D prefixes the domain", _dom_l, "0000:" + _plain_l)
check("...and combines with -nn",
      out(S, "lspci -nnD | head -1").split()[0], "0000:" + _plain_l)
check("-D changes every line, not just the first",
      out(S, "diff <(lspci) <(lspci -D) >/dev/null; echo $?").strip(), "1")
check("the device count is unchanged by -D",
      out(S, "lspci -D | grep -c .").strip(),
      out(S, "lspci | grep -c .").strip())
check("-s takes a slot with the domain, as real lspci does",
      out(S, "lspci -s 0000:%s" % _plain_l).strip(),
      out(S, "lspci -s %s" % _plain_l).strip(),
      "the spelling copied out of /sys/bus/pci/devices selected nothing")
check("sysfs uses the domain-qualified name -D produces",
      out(S, "ls /sys/bus/pci/devices/ | head -1").strip(), _dom_l)

# ------------------------------------------- a link that points nowhere
# The single check that would have caught every bug in this block. sysfs
# links are made by the kernel when a driver binds; one that resolves to
# nothing is not a state a running kernel is in. There were 37 of them,
# all the same shape -- a relative target counted one level too far, so it
# climbed past /sys and landed outside the tree:
#
#   /sys/devices/pci0000:00/<bdf>/driver   ../../../../bus/... (needs 3)
#   /sys/block/<dev>/bdi                   ../..x9/virtual/... (needs 8)
#   /sys/bus/virtio/drivers/<d>/virtio0    ../..x5/devices/... (needs 4)
#
# Each read correctly with readlink and resolved to nothing with
# readlink -f, which is exactly the pair of answers no real box gives. The
# bdi one is the instructive case: its text is byte-identical to the
# guest's, because the guest's disk hangs off a PCI bridge this persona
# does not have, so the real path carries one more component and the wrong
# formula produces the right string there.
D = shell()
_dangling = out(D, 'for l in $(find /sys -type l 2>/dev/null); do '
                   '[ -e "$l" ] || echo "$l"; done')
check("no symlink under /sys dangles", sorted(_dangling.split()), [],
      "readlink answering while readlink -f does not is a link into "
      "nowhere")
check("...and there are enough of them for that to mean something",
      int(out(D, "find /sys -type l 2>/dev/null | wc -l").strip()) > 200,
      True)

# /sys/class/block holds partitions as well as whole disks, and was empty.
# /sys/block holds whole devices only -- the two are different questions
# and `ls /sys/class/block` is how you enumerate drives without lsblk.
_parts = [l.split()[-1] for l in
          out(D, "cat /proc/partitions").splitlines()[2:] if l.split()]
check("/sys/class/block lists every device /proc/partitions does",
      sorted(out(D, "ls /sys/class/block").split()), sorted(_parts))
# A partition's name extends its disk's -- sda1 under sda, nvme0n1p1
# under nvme0n1 -- which beats guessing from trailing digits, since
# nvme0n1 is a whole disk whose name ends in one.
_whole = sorted(q for q in _parts
                if not any(q != r and q.startswith(r) for r in _parts))
check("/sys/block lists whole disks only",
      sorted(out(D, "ls /sys/block").split()), _whole,
      "partitions belong in /sys/class/block, not /sys/block")
for _b in ("sda", "sda1", "nvme0n1p1"):
    check("/sys/class/block/%s resolves into the devices tree" % _b,
          out(D, "readlink -f /sys/class/block/%s" % _b).strip().startswith(
              "/sys/devices/"), True)

# The bdi each block device points at, which did not exist.
_disks = [p for p in _parts if p in ("sda", "nvme0n1", "sr0")]
for _d in _disks:
    check("%s's bdi link resolves" % _d,
          out(D, "readlink -f /sys/block/%s/bdi" % _d).strip(),
          "/sys/devices/virtual/bdi/%s"
          % out(D, "cat /sys/block/%s/dev" % _d).strip())
check("/sys/class/bdi has one entry per whole disk",
      len(out(D, "ls /sys/class/bdi").split()), len(_disks))
check("a bdi carries the attributes a real one does",
      sorted(out(D, "ls /sys/devices/virtual/bdi/8:0").split()),
      ["max_bytes", "max_ratio", "max_ratio_fine", "min_bytes", "min_ratio",
       "min_ratio_fine", "power", "read_ahead_kb", "stable_pages_required",
       "strict_limit", "subsystem", "uevent"])
check("read_ahead_kb is the kernel default",
      out(D, "cat /sys/devices/virtual/bdi/8:0/read_ahead_kb").strip(), "128")
# The disk and the optical drive do not report the same max_bytes on the
# guest, so neither of ours is invented from the other.
check("the rom's max_bytes differs from the disk's",
      out(D, "cat /sys/devices/virtual/bdi/8:0/max_bytes").strip()
      != out(D, "cat /sys/devices/virtual/bdi/11:0/max_bytes").strip(), True)

# Every PCI device claims a driver; the link has to reach it, and the
# driver has to list the device back.
_pci = out(D, "ls /sys/bus/pci/devices").split()
check("the pci bus has devices to check", len(_pci) > 10, True)
_baddrv, _backref = [], []
for _slot in _pci:
    # A device with no driver bound has no link at all, which is normal --
    # the host bridge and the PCI bridges are like that. readlink -f on a
    # path that is not there echoes the path back, so the link has to be
    # tested for rather than inferred from the output being non-empty.
    if out(D, "test -L /sys/bus/pci/devices/%s/driver && echo y"
           % _slot).strip() != "y":
        continue
    _t = out(D, "readlink -f /sys/bus/pci/devices/%s/driver" % _slot).strip()
    if not _t.startswith("/sys/bus/pci/drivers/"):
        _baddrv.append("%s -> %r" % (_slot, _t))
        continue
    if _slot not in out(D, "ls " + _t).split():
        _backref.append("%s not listed under %s" % (_slot, _t))
check("every bound PCI device's driver link resolves", _baddrv, [],
      "all 37 of these pointed above /sys and resolved to nothing")
check("...and the driver lists the device back", _backref, [],
      "the bus view and the driver view are one relationship")

# ------------------------------- the character devices this box claims
# /sys/class/mem, /sys/class/tty and /sys/class/misc existed and listed
# nothing, on a machine that names these devices in three other places:
#
#   /proc/consoles   ttyS0 ... 4:64   and   tty0 ... 4:1
#   dmesg            00:00: ttyS0 at I/O 0x3f8 (irq = 4 ...) is a 16550A
#   ps               /sbin/agetty ... tty1 linux
#
# against a /dev that held /dev/tty and nothing else of the kind. Three
# assertions that a device exists and no device.
C = shell()

# The cross-check first, because it is the one that found this: anything
# the box says it has a console on has to be there.
_missing = []
for _line in out(C, "cat /proc/consoles").splitlines():
    _nm = _line.split()[0] if _line.split() else ""
    if not _nm:
        continue
    if out(C, "test -c /dev/%s && echo y" % _nm).strip() != "y":
        _missing.append("/dev/" + _nm)
    if out(C, "test -e /sys/class/tty/%s && echo y" % _nm).strip() != "y":
        _missing.append("/sys/class/tty/" + _nm)
check("every console /proc/consoles names exists", _missing, [],
      "a box cannot have a console on a device that is not there")
# ...and the tty agetty is sitting on. The name has to come from an
# argument: 'tty[0-9]*' matches the tty inside "agetty" itself, which on
# HEAD picked up /dev/tty -- a device that does exist -- and passed while
# /dev/tty1 was missing.
_gt = ""
for _tok in out(C, "ps -e -o args= | grep agetty").split():
    if _tok.startswith("tty") and _tok[3:].isdigit():
        _gt = _tok
        break
check("agetty is running on a virtual console", _gt.startswith("tty"), True,
      "found %r in agetty's arguments" % _gt)
check("...and that console exists as a device node",
      out(C, "test -c /dev/%s && echo y" % (_gt or "nonexistent")).strip(),
      "y", "agetty was on %r" % _gt)
# /proc/consoles prints the device numbers; they have to be the same ones.
for _line in out(C, "cat /proc/consoles").splitlines():
    _f = _line.split()
    if len(_f) < 2 or ":" not in _f[-1]:
        continue
    check("/proc/consoles and sysfs agree on %s's device number" % _f[0],
          out(C, "cat /sys/class/tty/%s/dev" % _f[0]).strip()
          if _f[0] != "tty0" else _f[-1], _f[-1],
          "tty0's entry reports 4:0 while /proc/consoles shows the active "
          "vc, so only the others are compared here")

# The three classes, against what the guest lists.
check("/sys/class/mem holds the seven memory devices",
      sorted(out(C, "ls /sys/class/mem").split()),
      ["full", "kmsg", "mem", "null", "random", "urandom", "zero"])
check("/sys/class/misc holds the twelve the guest does",
      sorted(out(C, "ls /sys/class/misc").split()),
      ["autofs", "cpu_dma_latency", "device-mapper", "fuse", "hpet",
       "hw_random", "snapshot", "udmabuf", "userfaultfd", "vga_arbiter",
       "vmci", "vsock"])
check("/sys/class/tty holds 71 entries", 
      len(out(C, "ls /sys/class/tty").split()), 71,
      "console, ptmx, tty, 64 virtual consoles and 4 8250 ports")
check("...including all 64 virtual consoles",
      sorted(int(x[3:]) for x in out(C, "ls /sys/class/tty").split()
             if x.startswith("tty") and x[3:].isdigit()), list(range(64)))

# Each class entry's dev file and its /dev node are the same device.
_devmismatch = []
for _cls, _names in (("mem", ["full", "kmsg", "mem", "null", "random",
                              "urandom", "zero"]),
                     ("tty", ["console", "ptmx", "tty", "tty0", "tty1",
                              "ttyS0", "ttyS3"])):
    for _nm in _names:
        _sysdev = out(C, "cat /sys/class/%s/%s/dev" % (_cls, _nm)).strip()
        _lsdev = out(C, "ls -l /dev/%s" % _nm).split()
        _got = ("%s:%s" % (_lsdev[4].rstrip(","), _lsdev[5])
                if len(_lsdev) > 5 else "?")
        if _got != _sysdev:
            _devmismatch.append("%s: sysfs %s, /dev %s" % (_nm, _sysdev, _got))
check("sysfs and /dev agree on every device number", _devmismatch, [])

# The two misc entries whose node is not named after the class entry.
check("device-mapper's node is /dev/mapper/control",
      out(C, "test -c /dev/mapper/control && echo y").strip(), "y")
check("hw_random's node is /dev/hwrng",
      out(C, "test -c /dev/hwrng && echo y").strip(), "y")

# active belongs to console and tty0 and to nothing else in the class.
_withactive = sorted(
    n for n in out(C, "ls /sys/class/tty").split()
    if out(C, "test -e /sys/class/tty/%s/active && echo y" % n).strip() == "y")
check("only console and tty0 carry an active file", _withactive,
      ["console", "tty0"])
check("console's active names the consoles in use",
      out(C, "cat /sys/class/tty/console/active").strip(), "tty0 ttyS0")

# Of the four 8250 ports only the one the firmware declares has a UART
# behind it -- which is what "4 ports" in dmesg means beside one console.
check("ttyS0 is the port dmesg describes",
      [out(C, "cat /sys/class/tty/ttyS0/port").strip(),
       out(C, "cat /sys/class/tty/ttyS0/irq").strip(),
       out(C, "cat /sys/class/tty/ttyS0/type").strip()],
      ["0x3F8", "4", "4"],
      "dmesg says ttyS0 at I/O 0x3f8 irq 4, a 16550A, and type 4 is that")
check("...and it is the only one with a detected UART",
      sorted(n for n in ("ttyS0", "ttyS1", "ttyS2", "ttyS3")
             if out(C, "test -e /sys/class/tty/%s/rx_trig_bytes && echo y"
                    % n).strip() == "y"), ["ttyS0"],
      "rx_trig_bytes appears only where a real UART was found")
def _bus_of(name):
    """The bus directory a tty's device link goes through, or "" if the
    link is not there -- indexing a missing link crashed the suite and
    took every check after it with it."""
    parts = out(C, "readlink /sys/class/tty/%s" % name).strip().split("/")
    return parts[3] if len(parts) > 3 else ""


check("ttyS0 hangs off pnp0, the others off the platform driver",
      [_bus_of("ttyS0"), _bus_of("ttyS1")], ["pnp0", "platform"])

# -- every device directory carries power/, subsystem and uevent ----------
# The builders had drifted apart: of the 186 device directories reachable
# through /sys/class, 73 had no subsystem link, 69 no power/ and 2 no
# uevent. thermal alone was 64 of each. On a real box all three are on
# every one of them, so `ls` was short by up to three entries and
# `readlink .../subsystem` -- how you ask a device what class it is in
# without trusting the path you reached it by -- answered nothing.
_sh = shell()
_devdirs = [x for x in out(_sh, "ls -d /sys/class/*/* 2>/dev/null").split()
            if x.startswith("/sys/")]
check("there are device directories to check", len(_devdirs) > 150, True,
      "if the glob stops matching this whole block silently checks nothing")

_missing = {"power": [], "subsystem": [], "uevent": []}
for _d in _devdirs:
    # /sys/class/drm/version is a plain attribute file, not a device.
    if "No such" not in out(_sh, "ls -d %s/ 2>&1" % _d) and \
            out(_sh, "readlink %s" % _d).strip() == "":
        continue
    for _e in _missing:
        if "No such" in out(_sh, "ls -d %s/%s 2>&1" % (_d, _e)):
            _missing[_e].append(_d)
for _e, _bad in _missing.items():
    check("every device dir has %s" % _e, _bad[:4], [],
          "%d of %d lack it" % (len(_bad), len(_devdirs)))

# The link is relative and its depth counts the device path, not the
# /sys/class path it was reached by. Both of these are four below /sys.
check("net/lo names its class",
      out(_sh, "readlink /sys/class/net/lo/subsystem").strip(),
      "../../../../class/net")
check("a cooling device names its class",
      out(_sh, "readlink /sys/class/thermal/cooling_device0/subsystem").strip(),
      "../../../../class/thermal")
check("dmi names its class",
      out(_sh, "readlink /sys/class/dmi/id/subsystem").strip(),
      "../../../../class/dmi")
# ...and it resolves to a directory that exists, rather than dangling --
# 37 links pointing above /sys and resolving to nothing is a bug this
# tree has had before.
for _p in ("/sys/class/net/lo", "/sys/class/thermal/cooling_device0",
           "/sys/class/dmi/id"):
    check("%s/subsystem resolves" % _p,
          out(_sh, "test -d %s/subsystem && echo yes" % _p).strip(), "yes")

check("power/ holds the five attributes a real one does",
      sorted(out(_sh, "ls /sys/class/thermal/cooling_device0/power/").split()),
      ["autosuspend_delay_ms", "control", "runtime_active_time",
       "runtime_status", "runtime_suspended_time"])
check("runtime_status is unsupported",
      out(_sh, "cat /sys/class/thermal/cooling_device0/power/runtime_status"
               " 2>&1").strip(), "unsupported")
check("control is auto",
      out(_sh, "cat /sys/class/net/lo/power/control 2>&1").strip(), "auto")

# -- the perf PMU roots, and the bus that lists them ----------------------
# `ls /sys/devices` answered with five entries against the guest's twelve
# and `ls /sys/bus` with two against twenty-five. The seven added here are
# on any x86_64 Linux regardless of hardware -- they are software event
# sources, not devices -- so their absence described no machine.
_P = shell()
_devroots = out(_P, "ls /sys/devices").split()
for _r in ("breakpoint", "isa", "kprobe", "msr", "software", "tracepoint",
           "uprobe"):
    check("/sys/devices has %s" % _r, _r in _devroots, True, str(_devroots))

# The bus and the tree list the same six, which is the point of adding
# only a closed set: they cannot drift apart.
check("event_source lists exactly the six PMUs",
      sorted(out(_P, "ls /sys/bus/event_source/devices").split()),
      ["breakpoint", "kprobe", "msr", "software", "tracepoint", "uprobe"])
for _pmu in ("breakpoint", "kprobe", "msr", "software", "tracepoint",
             "uprobe"):
    check("%s links back to its device" % _pmu,
          out(_P, "readlink /sys/bus/event_source/devices/%s" % _pmu).strip(),
          "../../../devices/" + _pmu)
    check("%s names its bus" % _pmu,
          out(_P, "readlink /sys/devices/%s/subsystem" % _pmu).strip(),
          "../../bus/event_source")
    check("...and that resolves" % (),
          out(_P, "test -d /sys/devices/%s/subsystem && echo yes" % _pmu
              ).strip(), "yes")
check("the PMU types are the kernel's own numbers",
      [out(_P, "cat /sys/devices/%s/type" % p).strip()
       for p in ("software", "tracepoint", "breakpoint", "kprobe", "uprobe",
                 "msr")],
      ["1", "2", "5", "8", "9", "10"])
check("msr carries its one event", out(_P, "cat /sys/devices/msr/events/tsc"
                                       ).strip(), "event=0x00")
check("uprobe carries both format fields",
      sorted(out(_P, "ls /sys/devices/uprobe/format").split()),
      ["ref_ctr_offset", "retprobe"])
# isa is the odd one out: power/ and uevent, and no subsystem at all.
check("isa has no subsystem link",
      out(_P, "readlink /sys/devices/isa/subsystem").strip(), "")
check("...but it does have power/ and uevent",
      sorted(out(_P, "ls /sys/devices/isa").split()), ["power", "uevent"])
check("the bus dir has its own furniture",
      sorted(out(_P, "ls /sys/bus/event_source").split()),
      ["devices", "drivers", "drivers_autoprobe", "drivers_probe", "uevent"])

# -- cooling devices have stats/ ------------------------------------------
check("a cooling device has stats/",
      sorted(out(_P, "ls /sys/class/thermal/cooling_device0/stats").split()),
      ["reset", "time_in_state_ms", "total_trans", "trans_table"])
check("trans_table is byte-exact, trailing spaces and all",
      out(_P, "cat /sys/class/thermal/cooling_device0/stats/trans_table"),
      " From  :    To\n       : state 0  \nstate 0:       0 \n")
check("total_trans is zero",
      out(_P, "cat /sys/class/thermal/cooling_device0/stats/total_trans"
          ).strip(), "0")
# The counter is milliseconds since boot. Frozen, it would contradict
# /proc/uptime the moment anyone divided one by the other.
_ms = out(_P, "cat /sys/class/thermal/cooling_device0/stats/time_in_state_ms")
_up = out(_P, "cat /proc/uptime").split()[0]
check("time_in_state_ms names state0", _ms.startswith("state0\t"), True, _ms)
try:
    _drift = abs(int(_ms.split("\t")[1].strip()) / 1000.0 - float(_up))
except (IndexError, ValueError):
    _drift = 1e9
check("...and it tracks /proc/uptime", _drift < 5.0, True,
      "%s vs %s" % (_ms.strip(), _up))
check("reset is write-only",
      out(_P, "stat -c %a /sys/class/thermal/cooling_device0/stats/reset"
          ).strip(), "200")

# -- the NUMA node, which lscpu was already describing -------------------
# lscpu printed "NUMA node(s): 1" and "NUMA node0 CPU(s): 0-63" and reads
# exactly /sys/devices/system/node to produce those lines -- and that
# directory did not exist. The box asserted a topology its own sysfs could
# not confirm.
_N = shell()
_nd = "/sys/devices/system/node"
check("the node tree exists",
      sorted(out(_N, "ls %s" % _nd).split()),
      ["has_cpu", "has_generic_initiator", "has_memory",
       "has_normal_memory", "node0", "online", "possible", "power",
       "uevent"])
# These are node lists, not booleans: "0" means node zero is in the set.
for _f in ("has_cpu", "has_memory", "has_normal_memory", "online",
           "possible"):
    check("%s is the node list" % _f,
          out(_N, "cat %s/%s" % (_nd, _f)).strip(), "0")
check("has_generic_initiator is empty",
      out(_N, "cat %s/has_generic_initiator" % _nd).strip(), "")

# The reader that was already talking about this must agree with it.
_lsnuma = [l for l in out(_N, "lscpu").split("\n") if "NUMA node0" in l]
check("lscpu names node0's CPUs", bool(_lsnuma), True)
if _lsnuma:
    check("...and node0/cpulist says the same",
          _lsnuma[0].split(":", 1)[1].strip(),
          out(_N, "cat %s/node0/cpulist" % _nd).strip())
check("there is a cpu link per CPU",
      len([x for x in out(_N, "ls %s/node0" % _nd).split()
           if x.startswith("cpu") and x[3:].isdigit()]),
      len([x for x in out(_N, "ls /sys/devices/system/cpu").split()
           if x.startswith("cpu") and x[3:].isdigit()]))
check("cpu0 points into the cpu tree",
      out(_N, "readlink %s/node0/cpu0" % _nd).strip(), "../../cpu/cpu0")
check("cpumap is the 32-bit-grouped mask",
      out(_N, "cat %s/node0/cpumap" % _nd).strip(), "ffffffff,ffffffff")
check("the only distance is the node to itself",
      out(_N, "cat %s/node0/distance" % _nd).strip(), "10")
check("node0 names its bus",
      out(_N, "readlink %s/node0/subsystem" % _nd).strip(),
      "../../../../bus/node")
check("...and it resolves",
      out(_N, "test -d %s/node0/subsystem && echo yes" % _nd).strip(), "yes")
check("the bus lists the node",
      out(_N, "readlink /sys/bus/node/devices/node0").strip(),
      "../../../devices/system/node/node0")

# meminfo: 35 of its 37 fields are the same number /proc/meminfo reports,
# and the other two are the node's own arithmetic. Generated from the same
# rows, so this cannot drift.
def _kv(text, strip=""):
    d = {}
    for _l in text.split("\n"):
        if strip:
            _l = _l.replace(strip, "", 1)
        _m = re.match(r"([^:]+):\s+(\d+)", _l)
        if _m:
            d[_m.group(1).strip()] = int(_m.group(2))
    return d


_nmi = _kv(out(_N, "cat %s/node0/meminfo" % _nd), "Node 0 ")
_pmi = _kv(out(_N, "cat /proc/meminfo"))
check("node meminfo has all 37 fields", len(_nmi), 37)
check("every shared field matches /proc/meminfo",
      [k for k, v in _nmi.items() if k in _pmi and _pmi[k] != v], [])
check("MemUsed is MemTotal minus MemFree",
      _nmi.get("MemUsed"), _nmi.get("MemTotal", 0) - _nmi.get("MemFree", 0))
check("FilePages is Cached plus Buffers",
      _nmi.get("FilePages"), _pmi.get("Cached", 0) + _pmi.get("Buffers", 0))
check("the HugePages lines carry no kB",
      "HugePages_Surp:" in out(_N, "cat %s/node0/meminfo" % _nd)
      and not any(l.endswith("kB") for l in
                  out(_N, "cat %s/node0/meminfo" % _nd).split("\n")
                  if "HugePages_" in l), True)

# vmstat is a filter over /proc/vmstat, never a second source. The
# monotonic counters advance between two reads -- /proc/vmstat does that
# against itself -- so the assertion is on the key set, not the values.
_nvm = dict(l.split() for l in
            out(_N, "cat %s/node0/vmstat" % _nd).strip().split("\n") if l.split())
_pvm = dict(l.split() for l in
            out(_N, "cat /proc/vmstat").strip().split("\n") if l.split())
check("every node vmstat key is a /proc/vmstat key",
      [k for k in _nvm if k not in _pvm], [])
check("node vmstat is not empty", len(_nvm) > 10, True, str(len(_nvm)))

# numastat reports the same six counters under other names. Within one
# read they are computed together, so these invariants hold exactly.
_ns = dict(l.split() for l in
           out(_N, "cat %s/node0/numastat" % _nd).strip().split("\n") if l.split())
check("numastat has its six counters", sorted(_ns),
      ["interleave_hit", "local_node", "numa_foreign", "numa_hit",
       "numa_miss", "other_node"])
check("on one node every hit is local", _ns.get("numa_hit"),
      _ns.get("local_node"))
check("and nothing is foreign, missed or remote",
      [_ns.get("numa_miss"), _ns.get("numa_foreign"), _ns.get("other_node")],
      ["0", "0", "0"])
check("compact is write-only",
      out(_N, "stat -c %a " + _nd + "/node0/compact").strip(), "200")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
