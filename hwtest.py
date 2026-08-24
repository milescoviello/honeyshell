#!/usr/bin/env python3
"""What hardware does this box say it has?

At 07:07 an actor logged in on the first try, ran five commands and left:
lscpu, nproc, MemTotal, nvidia-smi, rocm-smi, and `lspci | grep -i
'vga\\|3d\\|display'`. They were sizing the machine for a GPU. That is the
question this sweep asks back.

  - `lspci -nn` and `lspci -k` were accepted and ignored, so the two forms
    anyone actually uses -- IDs to parse, drivers to read -- returned the
    plain listing. `-k` is how you find out whether a display adapter has
    a driver bound.
  - /sys/bus/pci/devices did not exist. lspci reads that directory on a
    real box, so the command listed devices its own data source had never
    heard of.
  - /sys/class/drm and /dev/dri did not exist either, on a box whose lspci
    lists a VGA controller and whose kernel log binds bochs-drm to it.
    `ls /dev/dri` is the GPU question asked without lspci.
  - `dmidecode -t system` printed a two-line header and no data -- the
    standard "what am I running on" -- while /sys/class/dmi/id was fully
    populated. Every -t table is rendered from that same directory now, so
    dmidecode and sysfs cannot describe two different machines.

Shapes measured on the trixie guest (lspci -nn, -k, /sys/bus/pci/devices)
and on the hypervisor (dmidecode's table layout).

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
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
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# --- lspci and sysfs are one bus -------------------------------------------

def t_lspci_and_sysfs_list_the_same_devices():
    s = sh()
    o, _ = run(s, "lspci")
    slots = [l.split()[0] for l in o.splitlines() if l.strip()]
    o2, rc = run(s, "ls /sys/bus/pci/devices")
    eq("sysfs has a pci bus", rc, 0)
    sysfs = [d.replace("0000:", "") for d in o2.split()]
    eq("the same devices, in the same order", slots, sysfs)


def t_the_ids_match_between_them():
    s = sh()
    o, _ = run(s, "lspci -nn")
    for line in o.splitlines():
        m = re.search(r"^(\S+) .*\[([0-9a-f]{4}):([0-9a-f]{4})\]", line)
        check("every -nn line carries its ids", m is not None, line[:70])
        if not m:
            continue
        slot, vid, did = m.groups()
        v, _ = run(s, "cat /sys/bus/pci/devices/0000:%s/vendor" % slot)
        d, _ = run(s, "cat /sys/bus/pci/devices/0000:%s/device" % slot)
        eq("%s vendor matches sysfs" % slot, v.strip(), "0x" + vid)
        eq("%s device matches sysfs" % slot, d.strip(), "0x" + did)


def t_nn_also_prints_the_class_code():
    s = sh()
    o, _ = run(s, "lspci -nn | head -1")
    check("the class code is in brackets after the class",
          re.search(r"Host bridge \[0600\]", o), o[:80])
    o2, _ = run(s, "cat /sys/bus/pci/devices/0000:00:00.0/class")
    eq("and sysfs agrees", o2.strip(), "0x060000")


def t_k_shows_the_drivers():
    s = sh()
    o, _ = run(s, "lspci -k")
    check("subsystems are printed", "Subsystem: Red Hat, Inc." in o, o[:120])
    check("and a driver where one is bound",
          "Kernel driver in use: virtio-pci" in o, o[-200:])
    o2, _ = run(s, "lspci -s 00:02.0 -k")
    check("the display adapter has bochs-drm",
          "Kernel driver in use: bochs-drm" in o2, o2[:200])
    o3, _ = run(s, "readlink /sys/bus/pci/devices/0000:00:02.0/driver")
    check("which sysfs also names", o3.strip().endswith("bochs-drm"), o3)


def t_selecting_one_slot():
    s = sh()
    o, _ = run(s, "lspci -s 00:03.0")
    lines = [l for l in o.splitlines() if l.strip()]
    eq("one device", len(lines), 1)
    check("the one asked for", lines[0].startswith("00:03.0"), lines[0])


# --- the display device -----------------------------------------------------

def t_a_vga_controller_has_a_drm_device():
    s = sh()
    o, _ = run(s, "lspci | grep -i 'vga\\|3d\\|display'")
    check("there is a display adapter", "VGA compatible controller" in o,
          o[:80])
    o2, rc = run(s, "ls /dev/dri")
    eq("so /dev/dri exists", rc, 0)
    check("with a card node", "card0" in o2.split(), o2)
    o3, _ = run(s, "ls -l /dev/dri/card0")
    check("which is a character device", o3.startswith("c"), o3[:30])
    check("at the DRM major", "226," in o3, o3[:60])
    o4, _ = run(s, "cat /sys/class/drm/card0/dev")
    eq("and sysfs gives the same numbers", o4.strip(), "226:0")


def t_no_gpu_is_still_no_gpu():
    """The honest half: there is no accelerator here, and the tools that
    would report one are not installed."""
    s = sh()
    for c in ("nvidia-smi", "rocm-smi"):
        o, rc = run(s, c)
        eq("%s is not installed" % c, rc, 127)
        check("command not found", "command not found" in o, o[:60])
    o2, _ = run(s, "lspci | grep -ci nvidia")
    eq("no nvidia device on the bus", o2.strip(), "0")
    o3, _ = run(s, "ls /dev/nvidia0 2>/dev/null; echo rc=$?")
    check("and no device node", "rc=1" in o3 or "rc=2" in o3, o3[:40])


# --- dmidecode --------------------------------------------------------------

def t_dmidecode_t_prints_tables():
    s = sh()
    o, rc = run(s, "dmidecode -t system")
    eq("rc", rc, 0)
    check("it announces the SMBIOS version", "SMBIOS 2.8 present." in o,
          o[:80])
    check("with a handle line", re.search(r"Handle 0x\w+, DMI type 1,", o),
          o[:120])
    check("and the table title", "System Information" in o, o[:120])
    for field in ("Manufacturer:", "Product Name:", "UUID:",
                  "Wake-up Type:"):
        check("the table has %s" % field, field in o, o[:200])


def t_dmidecode_agrees_with_sysfs():
    s = sh()
    o, _ = run(s, "dmidecode -t system")
    fields = dict(re.findall(r"\t([\w ]+): (.*)", o))
    for key, path in (("Manufacturer", "sys_vendor"),
                      ("Product Name", "product_name"),
                      ("UUID", "product_uuid"),
                      ("Version", "product_version")):
        v, _ = run(s, "cat /sys/class/dmi/id/%s" % path)
        eq("%s matches /sys/class/dmi/id/%s" % (key, path),
           fields.get(key), v.strip())
    o2, _ = run(s, "dmidecode -s system-uuid")
    eq("and -s gives the same uuid", o2.strip(), fields.get("UUID"))


def t_dmidecode_types_and_errors():
    s = sh()
    o, _ = run(s, "dmidecode -t 1")
    check("a numeric type works too", "System Information" in o, o[:120])
    o2, _ = run(s, "dmidecode -t processor")
    check("the processor table names the model",
          fs.CPU_MODEL in o2, o2[:200])
    n, _ = run(s, "dmidecode -t processor | grep 'Core Count'")
    o3, _ = run(s, "nproc")
    eq("and its core count is nproc's", n.split(":")[1].strip(), o3.strip())
    o4, rc4 = run(s, "dmidecode -t nosuchtype")
    eq("an unknown type is rc 1", rc4, 1)
    check("named", "Invalid type keyword" in o4, o4[:60])
    o5, _ = run(s, "dmidecode | grep -c 'DMI type'")
    check("a bare dmidecode prints every table",
          int(o5.strip()) >= 6, o5)


def t_memory_table_matches_the_kernel():
    s = sh()
    o, _ = run(s, "dmidecode -t memory | grep Size")
    mb = int(re.search(r"(\d+) MB", o).group(1))
    o2, _ = run(s, "grep MemTotal /proc/meminfo")
    kb = int(re.search(r"(\d+)", o2).group(1))
    check("the DIMM is a little larger than MemTotal, as it always is",
          kb // 1024 <= mb <= kb // 1024 + 64, "%d MB vs %d kB" % (mb, kb))


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:10]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
