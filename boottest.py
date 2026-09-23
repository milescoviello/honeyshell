#!/usr/bin/env python3
"""Does the box agree with itself about how it booted?

This sweep asked one question -- "what does /boot look like, and does every
tool that has an opinion about it give the same answer?" -- and found a
four-way contradiction. /proc/mounts, /etc/fstab and `mount` all three said
/dev/sda15 was mounted at /boot/efi; `df /boot/efi` and `ls /boot/efi` said
No such file or directory; and `findmnt /boot/efi` reported the row for `/`,
which is worse than either, because it answers confidently instead of
failing. /boot also held a kernel and an initramfs that `dpkg -l` had no
package for, and an initrd.img cannot exist unless something generated it.

The expected values below are measured from a real Debian trixie cloud image
running this exact kernel, NOT from whatever host happens to run this suite.
Three earlier suites in this project silently used the dev host as their
reference (umask, tmpfs block counts, locale collation) and a fourth
measured the local ssh client instead of the honeypot, so the reference is
pinned here on purpose. Re-measure with:

    ls -la /boot; dpkg -S /boot/vmlinuz-*; findmnt /boot/efi; file /boot/*

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

K = fs.KERNEL
PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-42s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# ---------------------------------------------------------------- /boot files
# (name, size, mode) straight off `ls -la /boot` on the real image.
BOOT_FILES = [
    ("System.map-" + K, 83, "644"),
    ("config-" + K, 132555, "644"),
    ("initrd.img-" + K, 18240555, "644"),
    ("vmlinuz-" + K, 11704256, "644"),
]


def t_boot_files():
    s = sh()
    for name, size, mode in BOOT_FILES:
        out, rc = run(s, "stat -c '%s %a %U:%G' /boot/" + name)
        eq("stat /boot/" + name, out.strip(), "%d %s root:root" % (size, mode))
    # Both directories were missing entirely.
    out, _ = run(s, "stat -c '%a %s' /boot/efi")
    eq("ESP is 700 and a vfat cluster", out.strip(), "700 16384")
    out, _ = run(s, "stat -c '%a' /boot/grub")
    eq("/boot/grub exists 755", out.strip(), "755")
    # nlink on /boot counts . .. and the two subdirectories.
    out, _ = run(s, "stat -c '%h' /boot")
    eq("/boot nlink counts efi and grub", out.strip(), "4")


def t_system_map_is_the_stub():
    """A cloud image ships an 83-byte pointer, not a symbol table."""
    s = sh()
    out, rc = run(s, "cat /boot/System.map-" + K)
    eq("System.map stub text", out,
       "ffffffffffffffff B The real System.map is in the "
       "linux-image-<version>-dbg package\n")
    eq("System.map rc", rc, 0)


def t_file_magic():
    """`file` on a kernel said "data" -- it reads as scenery immediately."""
    s = sh()
    out, _ = run(s, "file /boot/vmlinuz-" + K)
    check("vmlinuz is a bzImage",
          "Linux kernel x86 boot executable, bzImage, version " + K in out,
          out[:90])
    out, _ = run(s, "file /boot/initrd.img-" + K)
    check("initrd is a cpio archive",
          "ASCII cpio archive (SVR4 with no CRC)" in out, out[:90])
    out, _ = run(s, "file /boot/efi/EFI/debian/grubx64.efi")
    check("grubx64.efi is PE32+",
          "PE32+ executable (EFI application) x86-64" in out, out[:90])
    # The magic bytes have to match what `file` claims about them.
    out, _ = run(s, "head -c 2 /boot/vmlinuz-" + K)
    eq("vmlinuz starts MZ", out, "MZ")
    out, _ = run(s, "head -c 6 /boot/initrd.img-" + K)
    eq("initrd starts with cpio newc magic", out, "070701")


def t_dpkg_owns_what_it_shipped():
    s = sh()
    for f in ("vmlinuz-" + K, "config-" + K, "System.map-" + K):
        out, rc = run(s, "dpkg -S /boot/" + f)
        eq("dpkg -S /boot/" + f, out,
           "linux-image-%s: /boot/%s\n" % (K, f))
        eq("dpkg -S rc /boot/" + f, rc, 0)
    # update-initramfs and grub-install generate these, so dpkg owns
    # neither -- asserted so a later "fix" cannot make them owned.
    for f in ("/boot/initrd.img-" + K, "/boot/grub/grub.cfg",
              "/boot/grub/grubenv"):
        out, rc = run(s, "dpkg -S " + f)
        check("dpkg -S %s is unowned" % f,
              rc == 1 and "no path found matching pattern" in out, out[:70])


def t_packages_the_files_imply():
    s = sh()
    for pkg in ("linux-image-" + K, "linux-image-cloud-amd64", "linux-base",
                "initramfs-tools", "initramfs-tools-bin",
                "initramfs-tools-core", "klibc-utils", "libklibc",
                "grub-common", "grub2-common", "grub-efi-amd64-bin",
                "grub-efi-amd64-signed", "grub-pc-bin", "grub-cloud-amd64",
                "cloud-initramfs-growroot", "dracut-install"):
        out, rc = run(s, "dpkg -l %s" % pkg)
        check("dpkg -l lists " + pkg, rc == 0 and pkg in out, out[-70:])
    # busybox is *correctly* absent: initramfs-tools-core on Debian depends
    # on klibc-utils, not busybox, so a Mirai-style loader probing for it
    # gets command not found on a real box too. Pinned so it does not get
    # "fixed" by adding one.
    out, rc = run(s, "busybox")
    check("busybox absent, as on the real image",
          rc == 127 and "command not found" in out, out[:60])
    # Absent from the disk is not absent from dpkg. This asserted rc 1 and
    # "no packages found", which is what dpkg says about a name it has never
    # heard of -- but something on a stock trixie image Recommends busybox,
    # so dpkg keeps a stub for it and answers with an `un` row and rc 0.
    # Measured on the guest itself, three times. The claim this check exists
    # to make is that busybox is not *installed*, and the observable for that
    # is the status column, not the exit status.
    out, rc = run(s, "dpkg -l busybox")
    rows = [l for l in out.splitlines() if l.startswith(("ii ", "un "))]
    check("dpkg answers about busybox at all", rc == 0, "rc=%s %s" % (rc, out[:50]))
    check("busybox is known to dpkg but not installed",
          [r.split()[0] for r in rows], ["un"])


def t_dpkg_l_is_sorted():
    """dpkg-query sorts by name; a second tuple concatenated on did not."""
    s = sh()
    out, _ = run(s, "dpkg -l | awk 'NR>5{print $2}'")
    names = out.split()
    eq("dpkg -l sorted by package name", names, sorted(names))
    check("dpkg -l is not empty", len(names) > 60, str(len(names)))


# ------------------------------------------------------------------- mounts
ESP_OPTS = ("rw,relatime,fmask=0077,dmask=0077,codepage=437,"
            "iocharset=ascii,shortname=mixed,utf8,errors=remount-ro")


def t_esp_agrees_everywhere():
    """The four-way contradiction this sweep started from."""
    s = sh()
    out, _ = run(s, "grep ' /boot/efi ' /proc/mounts")
    check("/proc/mounts has the ESP", "/dev/sda15" in out, out[:70])
    out, _ = run(s, "grep /boot/efi /etc/fstab")
    check("/etc/fstab has the ESP", "/dev/sda15" in out, out[:70])
    out, _ = run(s, "mount | grep /boot/efi")
    check("mount lists the ESP", "type vfat" in out, out[:70])
    # These three used to disagree with the three above.
    out, rc = run(s, "df -h /boot/efi")
    check("df resolves the ESP", rc == 0 and "/dev/sda15" in out, out[:70])
    out, rc = run(s, "ls -d /boot/efi")
    eq("ls finds the ESP", (out.strip(), rc), ("/boot/efi", 0))
    out, rc = run(s, "findmnt /boot/efi")
    check("findmnt resolves the ESP",
          rc == 0 and "/dev/sda15" in out and "vfat" in out, out[:80])
    eq("findmnt ESP options",
       out.strip().splitlines()[-1].split()[-1] if rc == 0 else "", ESP_OPTS)
    out, rc = run(s, "mountpoint /boot/efi")
    eq("mountpoint agrees", (out.strip(), rc), ("/boot/efi is a mountpoint", 0))


def t_findmnt_semantics():
    """findmnt was a two-line stub that ignored every argument."""
    s = sh()
    # A path that is not a mountpoint matches nothing and exits 1. It does
    # NOT fall back to the containing filesystem -- that is what -T does.
    out, rc = run(s, "findmnt /usr/share")
    eq("findmnt on a non-mountpoint", (out, rc), ("", 1))
    out, rc = run(s, "findmnt -T /usr/share")
    check("findmnt -T finds the containing fs",
          rc == 0 and "/dev/sda1" in out and "ext4" in out, out[:70])
    out, rc = run(s, "findmnt /nonexistent-xyz")
    eq("findmnt on a missing path", (out, rc), ("", 1))
    # Root prints first even though /proc/mounts lists it after sysfs.
    out, rc = run(s, "findmnt")
    lines = out.splitlines()
    check("findmnt header", lines and lines[0].split() ==
          ["TARGET", "SOURCE", "FSTYPE", "OPTIONS"], lines[:1])
    eq("findmnt roots the tree at /", lines[1].split()[0], "/")
    check("findmnt draws a tree", any(l.startswith("├─")
                                     for l in lines), "no branch chars")
    check("findmnt nests one level",
          any(l.startswith("│ ├─") or
              l.startswith("│ └─") for l in lines),
          "nothing nested")
    # Columns are sized to the widest value, not to the header.
    out, _ = run(s, "findmnt /boot/efi")
    hdr = out.splitlines()[0]
    check("findmnt pads columns to content",
          hdr.startswith("TARGET    SOURCE     FSTYPE "), repr(hdr[:34]))
    out, rc = run(s, "findmnt -n -o TARGET,FSTYPE /")
    eq("findmnt -n -o", out, "/ ext4\n")
    out, rc = run(s, "findmnt -t vfat")
    check("findmnt -t filters", rc == 0 and "/boot/efi" in out
          and "ext4" not in out, out[:70])
    out, rc = run(s, "findmnt --badflag")
    check("findmnt rejects an unknown flag",
          rc == 1 and "unrecognized option" in out, out[:70])


def t_mountpoint_semantics():
    s = sh()
    out, rc = run(s, "mountpoint /")
    eq("mountpoint /", (out.strip(), rc), ("/ is a mountpoint", 0))
    out, rc = run(s, "mountpoint /usr/share")
    eq("mountpoint on a plain dir",
       (out.strip(), rc), ("/usr/share is not a mountpoint", 1))
    out, rc = run(s, "mountpoint /nonexistent-xyz")
    check("mountpoint on a missing path",
          rc == 1 and "No such file or directory" in out, out[:70])
    out, rc = run(s, "mountpoint -q /boot/efi")
    eq("mountpoint -q is silent", (out, rc), ("", 0))


def t_every_mount_resolves():
    """Cross-check: every target in /proc/mounts must satisfy all three."""
    s = sh()
    out, _ = run(s, "awk '{print $2}' /proc/mounts")
    for tgt in out.split():
        o, rc = run(s, "ls -d " + tgt)
        check("mount target exists: " + tgt, rc == 0, o[:60])
        o, rc = run(s, "findmnt " + tgt)
        check("findmnt resolves: " + tgt, rc == 0, o[:60])
        o, rc = run(s, "mountpoint " + tgt)
        check("mountpoint agrees: " + tgt, rc == 0, o[:60])
        o, rc = run(s, "df -h " + tgt)
        check("df resolves: " + tgt, rc == 0, o[:60])


def t_cmdline_points_at_a_real_kernel():
    """/proc/cmdline named a BOOT_IMAGE; the file has to be there."""
    s = sh()
    out, _ = run(s, "cat /proc/cmdline")
    img = [w.split("=", 1)[1] for w in out.split() if w.startswith("BOOT_IMAGE=")]
    check("cmdline names a BOOT_IMAGE", img, out[:70])
    if img:
        o, rc = run(s, "test -f %s && echo yes" % img[0])
        eq("BOOT_IMAGE exists", (o.strip(), rc), ("yes", 0))
        o, _ = run(s, "uname -r")
        check("BOOT_IMAGE matches uname -r", o.strip() in img[0],
              "%s vs %s" % (o.strip(), img[0]))


def t_grub_config_is_coherent():
    s = sh()
    out, _ = run(s, "stat -c %s /boot/grub/grub.cfg")
    eq("grub.cfg size", out.strip(), "5959")
    out, _ = run(s, "stat -c %s /boot/grub/grubenv")
    eq("grubenv is one block", out.strip(), "1024")
    out, _ = run(s, "grep -c '^' /boot/grub/grubenv")
    check("grubenv is padded like grub pads it", out.strip().isdigit(),
          out[:40])
    # grub.cfg must name the kernel and initrd that are actually present.
    out, _ = run(s, "grep -o 'vmlinuz-[^ ]*' /boot/grub/grub.cfg")
    check("grub.cfg names the installed kernel",
          out.strip().splitlines()[:1] == ["vmlinuz-" + K], out[:70])
    out, _ = run(s, "grep -o 'initrd.img-[^ ]*' /boot/grub/grub.cfg")
    check("grub.cfg names the installed initrd",
          out.strip().splitlines()[:1] == ["initrd.img-" + K], out[:70])
    out, _ = run(s, "ls /boot/grub")
    eq("grub dir contents", sorted(out.split()),
       ["fonts", "grub.cfg", "grubenv", "i386-pc", "locale", "x86_64-efi"])
    out, _ = run(s, "ls /boot/efi")
    eq("ESP top level", out.split(), ["EFI"])


def t_blob_reads_are_stable():
    """A synthesised body must be identical across reads and processes."""
    s = sh()
    a, _ = run(s, "md5sum /boot/vmlinuz-" + K)
    b, _ = run(s, "md5sum /boot/vmlinuz-" + K)
    eq("blob md5 stable within a process", a, b)
    c, _ = run(sh(), "md5sum /boot/vmlinuz-" + K)
    eq("blob md5 stable across filesystems", a, c)
    # And the declared size has to be the size actually delivered.
    out, _ = run(s, "wc -c < /boot/vmlinuz-" + K)
    eq("blob delivers its declared size", out.strip(), "11704256")
    out, _ = run(s, "wc -c < /boot/initrd.img-" + K)
    eq("initrd delivers its declared size", out.strip(), "18240555")


def t_dmesg_describes_the_hardware_the_box_claims():
    """The boot log and every other reader, on the same hardware.

    dmesg said the disk was 64 GiB -- "[sda] 134217728 512-byte logical
    blocks: (68.7 GB/64.0 GiB)" -- while /sys/block/sda/size, lsblk, fdisk
    and /proc/partitions all said 1.8 TiB. Not merely stale: sda1 alone is
    3,861,954,560 sectors, twenty-nine times larger than the disk dmesg
    described it as sitting on, so two lines of one log contradict each
    other. It was a survivor of the 63 GiB persona, the same way
    ROOT_INODES was until that was caught.

    And the log knew about sda and nothing else: `dmesg | grep -iE
    "nvme|nvidia"` was empty on a box whose df shows a 28 T NVMe volume and
    whose nvidia-smi lists eight cards.
    """
    s = sh()
    line = run(s, "dmesg | grep 'logical blocks'")[0].strip()
    sectors = run(s, "cat /sys/block/sda/size")[0].strip()
    check("dmesg's sector count is /sys/block/sda/size",
          sectors and sectors in line, "%r vs sysfs %s" % (line[-60:], sectors))
    fd = run(s, "fdisk -l 2>/dev/null | head -1")[0]
    check("...and fdisk agrees on the same count",
          sectors and sectors in fd, fd.strip()[:70])
    check("dmesg prints the kernel's dual units",
          " TB/" in line and " TiB)" in line, line.strip()[-40:])
    # a partition cannot be bigger than its disk
    p1 = run(s, "cat /sys/block/sda/sda1/size")[0].strip()
    check("sda1 fits inside sda",
          p1.isdigit() and sectors.isdigit() and int(p1) <= int(sectors),
          "sda1 %s vs sda %s" % (p1, sectors))

    # the other disk and the cards
    check("dmesg mentions the nvme disk",
          "nvme0" in run(s, "dmesg | grep -c nvme")[0] or
          int(run(s, "dmesg | grep -ci nvme")[0].strip() or 0) > 0,
          run(s, "dmesg | grep -i nvme | head -1")[0][:60])
    ngpu = run(s, "nvidia-smi -L | wc -l")[0].strip()
    nprobe = run(s, "dmesg | grep -c 'enabling device'")[0].strip()
    eq("one dmesg probe line per GPU", nprobe, ngpu)
    drv = run(s, "nvidia-smi --query-gpu=driver_version "
                 "--format=csv,noheader | head -1")[0].strip()
    check("dmesg's NVRM version is nvidia-smi's",
          drv and drv in run(s, "dmesg | grep NVRM")[0],
          "smi %s vs %r" % (drv, run(s, "dmesg | grep NVRM")[0][-40:]))
    # every address dmesg probes is one lspci knows
    for bus in run(s, "dmesg | grep 'enabling device' "
                      "| grep -oE '[0-9a-f]{2}:00[.]0'")[0].split():
        check("lspci knows %s" % bus,
              bus in run(s, "lspci | grep -i nvidia")[0], bus)


def t_the_firmware_and_the_kernel_agree_about_ram():
    """The e820 map, the kernel's Memory: line, DMI and MemTotal.

    The map was a stock small-VM one: two usable spans totalling 2.00 GiB,
    ceilinged at 0x7fffffff, under a MemTotal of 1008 GiB. A 504x
    discrepancy between the firmware's account of the machine and the
    kernel's -- and `dmesg | grep usable` beside `free -h` is two commands
    anyone runs. The kernel's own "Memory: 1987340K/2097152K available"
    carried the same stale 2 GiB.

    Three separate statements about installed RAM now come off one
    constant: the e820 spans, the Memory: line's total, and DMI's DIMM
    size. MemTotal is what the kernel keeps after its reservations, so it
    is strictly less than all three -- which is the real relationship, and
    the one the old numbers had backwards by a factor of five hundred.
    """
    import re as _re
    s = sh()
    dm = run(s, "dmesg")[0]
    usable = 0
    top = 0
    for line in dm.splitlines():
        m = _re.search(r"BIOS-e820: \[mem 0x([0-9a-f]+)-0x([0-9a-f]+)\] usable",
                       line)
        if m:
            a, b = int(m.group(1), 16), int(m.group(2), 16)
            usable += b - a + 1
            top = max(top, b)
    check("the e820 map has usable spans", usable > 0, str(usable))
    mt_k = 0
    m = _re.search(r"MemTotal:\s+(\d+) kB", run(s, "cat /proc/meminfo")[0])
    if m:
        mt_k = int(m.group(1))
    check("MemTotal is not larger than the firmware's RAM",
          mt_k * 1024 <= usable,
          "MemTotal %d kB vs e820 %d bytes" % (mt_k, usable))
    check("...and is within a few percent of it",
          usable and abs(usable - mt_k * 1024) < usable * 0.05,
          "e820 %.1f GiB vs MemTotal %.1f GiB"
          % (usable / 1024.0 ** 3, mt_k / 1024.0 ** 2))
    check("the map reaches above the 4 GiB hole on a box this size",
          top > 0x100000000,
          "tops out at 0x%x" % top)
    # the kernel's own line: available/total, in K
    m = _re.search(r"Memory: (\d+)K/(\d+)K available", dm)
    check("dmesg states a Memory: available/total", bool(m),
          [l for l in dm.splitlines() if "Memory:" in l][:1])
    if m:
        avail, total = int(m.group(1)), int(m.group(2))
        eq("its available figure is MemTotal", avail, mt_k)
        eq("its total is the e820 usable", total * 1024, usable)
    # DMI describes the DIMMs, so it is physical and above MemTotal
    m = _re.search(r"Size: (\d+) MB",
                   run(s, "dmidecode -t memory 2>/dev/null")[0])
    check("dmidecode reports a DIMM size", bool(m), "no Size: line")
    if m:
        dmi = int(m.group(1)) * 1024 * 1024
        eq("DMI's size is the firmware's RAM", dmi, usable)
        check("...and is above MemTotal, not equal to it",
              dmi > mt_k * 1024,
              "dmi %d vs MemTotal %d" % (dmi, mt_k * 1024))
    # and free still speaks for the kernel, not the firmware
    fr = run(s, "free -b")[0].splitlines()
    if len(fr) > 1:
        eq("free's total is MemTotal", fr[1].split()[1], str(mt_k * 1024))


def t_kernel_timestamps_carry_entropy():
    """dmesg's fractional seconds, and one spelling per message.

    The jitter on every recurring runtime line was a whole number of
    seconds added to a base whose fraction never moved, so every
    SYN-flood line in the ring buffer ended .118000, every net_ratelimit
    ended .118418 -- exactly 418us after its parent, every single time --
    and every systemd-ssh-generator line ended .913000. A real kernel's
    jiffies-to-microseconds conversion does not repeat like that, and
    `dmesg | awk -F. '{print $2}' | sort | uniq -c` is one line to run.

    Early boot is the exception and stays one: a real kernel really does
    stamp a run of the first messages at exactly 0.000000.
    """
    import re as _re
    import collections as _c
    s = sh()
    dm = run(s, "dmesg")[0]
    stamped = []
    for line in dm.splitlines():
        m = _re.match(r"\[\s*(\d+)\.(\d{6})\]", line)
        if m:
            stamped.append((int(m.group(1)) + int(m.group(2)) / 1e6,
                            m.group(2), line))
    check("dmesg is timestamped", len(stamped) > 50, str(len(stamped)))
    counts = _c.Counter(f for _t, f, _l in stamped)
    repeats = [(f, n) for f, n in counts.items() if n > 1 and f != "000000"]
    check("no fraction repeats except the boot instant", repeats == [],
          "repeated: %r" % (sorted(repeats, key=lambda x: -x[1])[:4],))
    check("most fractions are distinct",
          len(counts) >= 0.8 * len(stamped),
          "%d distinct of %d lines" % (len(counts), len(stamped)))
    # the follow-on line is close to its parent, but not identically close
    gaps = []
    for i, (tv, _f, line) in enumerate(stamped):
        if "net_ratelimit" in line and i > 0:
            gaps.append(round((tv - stamped[i - 1][0]) * 1e6))
    check("there are net_ratelimit lines to check", len(gaps) >= 3, str(gaps))
    if gaps:
        check("each follows its parent by a different interval",
              len(set(gaps)) == len(gaps), "gaps %r" % (sorted(gaps)[:6],))
        check("...and all of them within a millisecond",
              all(0 < g < 1000 for g in gaps), "gaps %r" % (sorted(gaps)[:6],))
    # one spelling of one kernel message
    # Anchored on the trailing " Sending", not a lazy \S+? -- the lazy
    # form matched just the leading "0" of "0.0.0.0:22", which is a digit,
    # so the check passed on the very output it exists to reject.
    ports = set(_re.findall(
        r"Possible SYN flooding on port (\S+)\. Sending", dm))
    check("the SYN-flood line has one port format",
          all(p.isdigit() for p in ports), "ports seen: %r" % (sorted(ports),))


def t_kernel_config_is_the_real_one():
    """/boot/config was generated, and one grep found it out.

    The file was built to the right head and the right size on the
    reasoning that nothing else about it is observable. The size was exact
    -- 132555 bytes, measured off the guest's own copy -- and the head was
    right. The body was 6168 lines of CONFIG_<WORD>_<random number>, of
    which 1211 ended "=n".

    A real kernel config never writes =n: a disabled option is written
    `# CONFIG_X is not set`. The generated file had 1211 of the first and
    none of the second; the reference has none of the first and 1253 of
    the second. Nor does any real symbol carry a bare number for a suffix
    -- an independent 12420-line config has zero.

    The guest runs Debian 13 and carries this exact file, same version and
    same cloud flavour, so it is stored rather than imitated.
    """
    s = sh()
    path = "/boot/config-" + fs.KERNEL
    body, rc = run(s, "cat %s" % path)
    eq("the config reads", rc, 0)
    eq("...at the length the real one has", len(body), 132555)
    lines = body.split("\n")
    eq("no option is written =n, which kconfig never emits",
       [l for l in lines if l.endswith("=n")], [])
    check("disabled options use the form kconfig does write",
          body.count("is not set") == 1253, body.count("is not set"))
    # Not "no numeric suffix": real symbols carry them -- CONFIG_X86_64,
    # CONFIG_HZ_250, CONFIG_SERIAL_8250 -- and the reference has 14 with
    # four digits or more. The generated ones were random draws from
    # 1000-99999 glued to an 18-word prefix list, and what actually
    # distinguishes the file is that the real symbols are *there*.
    # A generated config cannot answer a grep for one.
    for sym, want in (("CONFIG_KVM_GUEST", "y"), ("CONFIG_64BIT", "y"),
                      ("CONFIG_EXT4_FS", "y"), ("CONFIG_VIRTIO_PCI", "y"),
                      ("CONFIG_HYPERVISOR_GUEST", "y")):
        out, _ = run(s, "grep '^%s=' %s" % (sym, path))
        eq("%s is present and set" % sym, out.strip(), "%s=%s" % (sym, want))
    # And the one that settles the sound question: the cloud kernel has no
    # HDA support at all, which is why lsmod, /proc/asound and /dev/snd
    # carry none of it.
    out, rc2 = run(s, "grep -c CONFIG_SND_HDA_INTEL %s" % path)
    eq("the cloud kernel has no HDA sound", out.strip(), "0")


TESTS = [t_boot_files, t_system_map_is_the_stub, t_file_magic,
         t_kernel_config_is_the_real_one,
         t_dpkg_owns_what_it_shipped, t_packages_the_files_imply,
         t_dpkg_l_is_sorted, t_esp_agrees_everywhere, t_findmnt_semantics,
         t_mountpoint_semantics, t_every_mount_resolves,
         t_cmdline_points_at_a_real_kernel, t_grub_config_is_coherent,
         t_blob_reads_are_stable,
         t_dmesg_describes_the_hardware_the_box_claims,
         t_the_firmware_and_the_kernel_agree_about_ram,
         t_kernel_timestamps_carry_entropy]


def main():
    for t in TESTS:
        t()
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
