#!/usr/bin/env python3
"""Am I in a VM? The readers a loader consults before it deploys.

Seventy-second coherence sweep. The axis is virtualisation detection,
picked because it is the check that decides whether a payload runs at
all: miners and loaders routinely refuse to unpack inside a hypervisor or
a container, and a sandbox that answers inconsistently is a sandbox they
can spot.

The persona is a QEMU/KVM guest -- Q35 + ICH9 with OVMF firmware -- and
it should look like one from every angle. Most of it did. What did not:

  * **sysfs held dmidecode's wording.** `product_serial`,
    `product_family`, `product_sku` and `chassis_serial` all contained
    the string "Not Specified", so

        cat /sys/class/dmi/id/product_serial

    printed a serial number reading "Not Specified" where every real box
    prints nothing at all. sysfs exposes an unset DMI string as an *empty
    file*; "Not Specified" is dmidecode's rendering of the same absence,
    and it had been written into the table both readers share. A check
    that tests the file for emptiness -- which is how you ask "does this
    machine have a serial" -- got the wrong answer.

    The box's own modalias was the witness that already disagreed: it
    ends `:sku:` with nothing in it, beside a product_sku claiming to be
    "Not Specified".

  * **chassis_asset_tag was missing.** Present on every real box, 0444
    and empty on the guest.

One table feeds sysfs and dmidecode, so the rendering moved out of the
table and into dmidecode, where it belongs.

Reference values measured on the guest (a QEMU/KVM Debian 13 VM), as
root, because product_uuid and the serial files are 0400:

    product_serial     []          chassis_serial     []
    product_family     []          chassis_asset_tag  []
    product_sku        []          product_uuid       [b9baf...]
    -r--r--r--  everything except uuid and the serials, which are -r--------

Checked and found already right: systemd-detect-virt says kvm and -c says
none; lscpu prints "Hypervisor vendor: KVM" and "Virtualization type:
full"; /proc/cpuinfo carries the hypervisor flag; dmesg has
"Hypervisor detected: KVM"; /sys/hypervisor does not exist (that is Xen);
/.dockerenv does not exist; /proc/1/cgroup is 0::/init.scope.

Left for a measurement this box cannot take: real QEMU emits no DMI type
2 at all, so a real guest has no /sys/class/dmi/id/board_* files -- the
guest has none. This persona has the four files and a Base Board
Information block, which is at least self-consistent. Making it match
QEMU means knowing what dmidecode prints for a type that is absent, and
that needs root on a QEMU box with dmidecode installed; the guest has no
dmidecode. Guessing the string would be worse than the mismatch.

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user="root")
    s.exec_mode = True
    return s


def out(s, cmd):
    o = s.run(cmd)
    e = "".join(s._err)
    s._err.clear()
    return (o + e).rstrip("\n")


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-56s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


#: DMI strings QEMU leaves unset. sysfs shows an empty file for each.
UNSET = ("product_serial", "product_family", "product_sku",
         "chassis_serial", "chassis_asset_tag",
         "board_vendor", "board_name", "board_version", "board_serial")
#: ...and the ones it does set, with the value this persona uses.
SET = {"product_name": "Standard PC (Q35 + ICH9, 2009)",
       "product_version": "pc-q35-9.0",
       "sys_vendor": "QEMU",
       "chassis_vendor": "QEMU",
       "chassis_version": "pc-q35-9.0",
       "chassis_type": "1",
       "bios_vendor": "EFI Development Kit II / OVMF",
       "bios_version": "0.0.0",
       "bios_date": "02/06/2015",
       "bios_release": "0.0"}


def t_an_unset_dmi_string_is_an_empty_file():
    s = sh()
    for name in UNSET:
        eq("cat %s" % name, out(s, "cat /sys/class/dmi/id/%s" % name), "")
        eq("wc -c %s" % name,
           out(s, "wc -c < /sys/class/dmi/id/%s" % name).strip(), "1")


def t_the_set_strings_are_what_this_machine_is():
    s = sh()
    for name, want in SET.items():
        eq("cat %s" % name, out(s, "cat /sys/class/dmi/id/%s" % name), want)


def t_the_uuid_is_a_uuid():
    s = sh()
    u = out(s, "cat /sys/class/dmi/id/product_uuid")
    check("shaped like a uuid",
          len(u) == 36 and u.count("-") == 4 and
          all(c in "0123456789abcdef-" for c in u), repr(u))


def t_the_serials_are_root_only():
    s = sh()
    for name in ("product_uuid", "product_serial", "chassis_serial",
                 "board_serial"):
        eq("%s mode" % name,
           out(s, "stat -c %%a /sys/class/dmi/id/%s" % name), "400")
    for name in ("product_name", "sys_vendor", "chassis_asset_tag",
                 "modalias", "bios_vendor"):
        eq("%s mode" % name,
           out(s, "stat -c %%a /sys/class/dmi/id/%s" % name), "444")


def t_the_modalias_agrees_with_the_files():
    """It is one string built from the others, so it cannot drift."""
    s = sh()
    m = out(s, "cat /sys/class/dmi/id/modalias")
    check("starts with dmi:", m.startswith("dmi:"), m[:20])
    for tag, name in (("svn", "sys_vendor"), ("pn", "product_name"),
                      ("pvr", "product_version"), ("cvn", "chassis_vendor"),
                      ("bvn", "bios_vendor"), ("bvr", "bios_version")):
        want = out(s, "cat /sys/class/dmi/id/%s" % name).replace(" ", "")
        check("modalias %s carries %s" % (tag, name),
              (":%s%s:" % (tag, want)) in m + ":", "%s not in %s" % (want, m))
    check("the sku field is empty, like the file", m.endswith(":sku:"),
          m[-20:])
    eq("uevent is the modalias",
       out(s, "cat /sys/class/dmi/id/uevent"), "MODALIAS=%s" % m)


def t_dmidecode_says_not_specified_where_sysfs_is_empty():
    """Two renderings of one absence, and each has to use its own."""
    s = sh()
    for key, name in (("system-serial-number", "product_serial"),
                      ("system-family", "product_family"),
                      ("baseboard-manufacturer", "board_vendor"),
                      ("baseboard-product-name", "board_name")):
        eq("dmidecode -s %s" % key, out(s, "dmidecode -s %s" % key),
           "Not Specified")
        eq("sysfs %s stays empty" % name,
           out(s, "cat /sys/class/dmi/id/%s" % name), "")


def t_dmidecode_agrees_with_sysfs_where_the_value_exists():
    s = sh()
    for key, name in (("system-product-name", "product_name"),
                      ("system-manufacturer", "sys_vendor"),
                      ("system-version", "product_version"),
                      ("system-uuid", "product_uuid"),
                      ("bios-vendor", "bios_vendor"),
                      ("bios-version", "bios_version"),
                      ("bios-release-date", "bios_date"),
                      ("chassis-manufacturer", "chassis_vendor")):
        eq("dmidecode -s %s" % key, out(s, "dmidecode -s %s" % key),
           out(s, "cat /sys/class/dmi/id/%s" % name))


def t_the_dmidecode_tables_render_the_same_way():
    s = sh()
    body = out(s, "dmidecode -t system")
    check("System Information block", "System Information" in body, body[:80])
    check("Serial Number: Not Specified",
          "Serial Number: Not Specified" in body, body)
    check("SKU Number: Not Specified",
          "SKU Number: Not Specified" in body, body)
    check("Family: Not Specified", "Family: Not Specified" in body, body)
    check("and the product name is the real one",
          "Product Name: Standard PC (Q35 + ICH9, 2009)" in body, body)
    board = out(s, "dmidecode -t 2")
    check("no empty field is left blank in the baseboard block",
          board.count("Not Specified") == 4 and ": \n" not in board, board)


# -- the other ways to ask ------------------------------------------------

def t_systemd_detect_virt():
    s = sh()
    eq("plain", out(s, "systemd-detect-virt"), "kvm")
    eq("-v", out(s, "systemd-detect-virt -v"), "kvm")
    eq("-c says none: this is a VM, not a container",
       out(s, "systemd-detect-virt -c"), "none")


def t_lscpu_names_the_hypervisor():
    s = sh()
    body = out(s, "lscpu")
    check("Hypervisor vendor: KVM",
          any(l.startswith("Hypervisor vendor:") and l.endswith("KVM")
              for l in body.splitlines()), "no such line")
    check("Virtualization type: full",
          any(l.startswith("Virtualization type:") and l.endswith("full")
              for l in body.splitlines()), "no such line")


def t_the_cpu_carries_the_hypervisor_flag():
    s = sh()
    flags = out(s, "grep -m1 ^flags /proc/cpuinfo")
    check("hypervisor in /proc/cpuinfo flags", " hypervisor " in flags + " ",
          flags[:80])
    check("lscpu's flags line carries it too",
          "hypervisor" in out(s, "lscpu | grep -i ^flags"), "")


def t_the_kernel_said_so_at_boot():
    s = sh()
    check("dmesg has the KVM line",
          "Hypervisor detected: KVM" in out(s, "dmesg"), "")


def t_it_is_not_xen_and_not_a_container():
    s = sh()
    # The directory exists on any Linux; Xen is what puts anything in it.
    # Measured on the guest: /sys/hypervisor is an empty 0755 directory and
    # /sys/hypervisor/type is absent. The first version of this check
    # expected the directory to be missing, which is not what a KVM guest
    # looks like.
    eq("/sys/hypervisor is there",
       out(s, "[ -d /sys/hypervisor ] && echo present || echo absent"),
       "present")
    eq("but it is empty -- no type file, so not Xen",
       out(s, "[ -e /sys/hypervisor/type ] && echo present || echo absent"),
       "absent")
    eq("and nothing else in it",
       out(s, "ls -A /sys/hypervisor | wc -l").strip(), "0")
    eq("/.dockerenv does not exist",
       out(s, "[ -e /.dockerenv ] && echo present || echo absent"), "absent")
    eq("pid 1 is in the root cgroup",
       out(s, "cat /proc/1/cgroup"), "0::/init.scope")
    eq("no container marker in /proc/1/environ",
       out(s, "tr '\\0' '\\n' < /proc/1/environ | grep -c container").strip(),
       "0")


def t_virt_what_is_not_installed():
    """It is not in Debian's base install, and dpkg has to agree."""
    s = sh()
    eq("not found", out(s, "which virt-what"), "")
    check("dpkg does not claim it",
          "no packages found" in out(s, "dpkg -l virt-what 2>&1"),
          out(s, "dpkg -l virt-what 2>&1")[:80])


def t_dmidecode_is_installed_and_dpkg_agrees():
    s = sh()
    eq("which", out(s, "which dmidecode"), "/usr/sbin/dmidecode")
    check("dpkg -S resolves it",
          out(s, "dpkg -S /usr/sbin/dmidecode").startswith("dmidecode:"),
          out(s, "dpkg -S /usr/sbin/dmidecode"))
    check("dpkg -l lists it installed",
          out(s, "dpkg -l dmidecode").splitlines()[-1].startswith("ii"),
          out(s, "dpkg -l dmidecode")[-80:])
    check("and the banner version matches the package",
          out(s, "dmidecode -t system").splitlines()[0].split()[-1]
          in out(s, "dpkg -l dmidecode"), "")


TESTS = [t_an_unset_dmi_string_is_an_empty_file,
         t_the_set_strings_are_what_this_machine_is,
         t_the_uuid_is_a_uuid,
         t_the_serials_are_root_only,
         t_the_modalias_agrees_with_the_files,
         t_dmidecode_says_not_specified_where_sysfs_is_empty,
         t_dmidecode_agrees_with_sysfs_where_the_value_exists,
         t_the_dmidecode_tables_render_the_same_way,
         t_systemd_detect_virt,
         t_lscpu_names_the_hypervisor,
         t_the_cpu_carries_the_hypervisor_flag,
         t_the_kernel_said_so_at_boot,
         t_it_is_not_xen_and_not_a_container,
         t_virt_what_is_not_installed,
         t_dmidecode_is_installed_and_dpkg_agrees]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
