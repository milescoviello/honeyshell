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
    out, rc = run(s, "dpkg -l busybox")
    check("no busybox package", rc == 1, out[:60])


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


TESTS = [t_boot_files, t_system_map_is_the_stub, t_file_magic,
         t_dpkg_owns_what_it_shipped, t_packages_the_files_imply,
         t_dpkg_l_is_sorted, t_esp_agrees_everywhere, t_findmnt_semantics,
         t_mountpoint_semantics, t_every_mount_resolves,
         t_cmdline_points_at_a_real_kernel, t_grub_config_is_coherent,
         t_blob_reads_are_stable]


def main():
    for t in TESTS:
        t()
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
