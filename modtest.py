#!/usr/bin/env python3
"""Do the views of "which kernel modules are loaded" agree with each other?

There were three answers and they shared nothing:

  - /proc/modules and lsmod named ext4, virtio_net, virtio_scsi and
    crc32c_intel.
  - /sys/module held exactly one entry, kvm_intel, which appears in neither
    -- and which only exists on a KVM *host*, on a box that tells DMI,
    lscpu, systemd-detect-virt and /sys/hypervisor/uuid it is a guest.
  - modules.builtin said ext4 was compiled in, which cannot be true of a
    module lsmod reports as loaded.

Underneath that:

  - modinfo, modprobe, insmod, rmmod and depmod were unimplemented, so all
    five fell through to the stock-binary stub and answered "missing
    operand" whatever you passed them. `insmod /tmp/rootkit.ko` -- the last
    step of the XorDDoS sample recovered from this box -- got "insmod:
    missing operand", which no real insmod has ever said.
  - /lib/modules/<ver>/kernel was an empty directory and modules.dep had one
    line, so nothing lsmod claimed was loaded could have been loaded.
  - /proc/kallsyms did not exist. It is one command for anyone deciding
    whether a rootkit is worth trying.
  - /proc/modules printed all-zero addresses to root while
    kernel.kptr_restrict, one directory away, said 1 -- which means root
    sees them.
  - lsmod's columns were %-22s %6s against kmod's %-19s %8s, and the "Used
    by" column dropped the holder names, which is the only place lsmod shows
    the dependency graph.
  - /proc/sys/kernel/tainted was missing.

Membership of the module list is pinned to the rest of the box: /boot/efi is
mounted vfat with codepage=437,iocharset=ascii, so vfat/fat/nls_cp437/
nls_ascii have to be loaded; the root disk is /dev/sda behind virtio_scsi.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh():
    s = fs.Shell(fs.VFS(), peer="203.0.113.77")
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


def procmods(s):
    """name -> (size, refcnt, holders, addr) straight out of /proc/modules."""
    out, _ = run(s, "cat /proc/modules")
    d = {}
    for line in out.splitlines():
        f = line.split()
        if len(f) >= 6:
            d[f[0]] = (int(f[1]), int(f[2]),
                       [] if f[3] == "-" else f[3].rstrip(",").split(","),
                       f[5])
    return d


def t_three_views_name_the_same_modules():
    """The contradiction this sweep started from."""
    s = sh()
    pm = procmods(s)
    check("/proc/modules is not empty", pm, "empty")
    lsm, _ = run(s, "lsmod")
    lsnames = [l.split()[0] for l in lsm.splitlines()[1:] if l.strip()]
    eq("lsmod lists exactly /proc/modules", sorted(lsnames), sorted(pm))
    sysm, _ = run(s, "ls /sys/module")
    sysnames = set(sysm.split())
    missing = sorted(set(pm) - sysnames)
    eq("every loaded module has a /sys/module entry", missing, [])
    # A /sys/module entry that is neither loaded nor built in is the
    # kvm_intel case: a claim nothing else on the box supports.
    builtin = set(n for n, _sub in fs.BUILTIN_MODULES)
    orphan = sorted(sysnames - set(pm) - builtin)
    eq("no /sys/module entry is unaccounted for", orphan, [])


def t_builtin_and_loaded_are_disjoint():
    s = sh()
    pm = procmods(s)
    out, _ = run(s, "cat /lib/modules/$(uname -r)/modules.builtin")
    names = [l.rsplit("/", 1)[-1][:-3] for l in out.split() if l.endswith(".ko")]
    check("modules.builtin is non-empty", names, out[:60])
    both = sorted(set(names) & set(pm))
    eq("nothing is both built in and loaded", both, [])
    for n in names[:4]:
        o, rc = run(s, "modinfo %s" % n)
        eq("modinfo finds builtin %s" % n, rc, 0)
        check("modinfo calls %s builtin" % n, "(builtin)" in o, o[:80])


def t_no_kvm_host_module_in_a_guest():
    s = sh()
    o, rc = run(s, "ls -d /sys/module/kvm_intel 2>&1")
    check("no /sys/module/kvm_intel on a guest", rc != 0, o[:80])
    v, _ = run(s, "systemd-detect-virt")
    eq("and the box still says it is a guest", v.strip(), "kvm")


def t_dependency_order_and_refcounts():
    s = sh()
    pm = procmods(s)
    order = list(pm)
    for name, (_sz, rc, holders, _a) in pm.items():
        check("%s refcnt >= holders" % name, rc >= len(holders),
              "rc=%d holders=%r" % (rc, holders))
        for h in holders:
            check("holder %s of %s is loaded" % (h, name), h in pm, sorted(pm))
            if h in pm:
                check("holder %s is newer than %s" % (h, name),
                      order.index(h) < order.index(name),
                      "%d vs %d" % (order.index(h), order.index(name)))


def t_holders_match_sysfs_and_lsmod():
    s = sh()
    pm = procmods(s)
    lsm, _ = run(s, "lsmod")
    lsused = {}
    for line in lsm.splitlines()[1:]:
        f = line.split()
        if len(f) >= 3:
            lsused[f[0]] = f[3].split(",") if len(f) > 3 else []
    for name, (_sz, _rc, holders, _a) in pm.items():
        o, _ = run(s, "ls /sys/module/%s/holders" % name)
        eq("sysfs holders of %s" % name, sorted(o.split()), sorted(holders))
        eq("lsmod used-by of %s" % name, sorted(lsused.get(name, [])),
           sorted(holders))
        o, _ = run(s, "cat /sys/module/%s/refcnt" % name)
        eq("sysfs refcnt of %s" % name, o.strip(), str(pm[name][1]))


def t_modinfo_agrees_with_proc_and_disk():
    s = sh()
    pm = procmods(s)
    for name in list(pm)[:6]:
        o, rc = run(s, "modinfo %s" % name)
        eq("modinfo %s succeeds" % name, rc, 0)
        d = dict(re.findall(r"^(\w+):[ \t]*(.*)$", o, re.M))
        eq("modinfo names %s" % name, d.get("name"), name)
        eq("modinfo vermagic starts with uname -r for %s" % name,
           (d.get("vermagic") or "").split()[0], fs.KERNEL)
        f = d.get("filename", "")
        check("modinfo filename is under /lib/modules/%s" % fs.KERNEL,
              f.startswith("/lib/modules/" + fs.KERNEL), f)
        o2, rc2 = run(s, "test -f %s && echo yes" % f)
        eq("the .ko modinfo names exists on disk (%s)" % name,
           (o2.strip(), rc2), ("yes", 0))
        sv, _ = run(s, "cat /sys/module/%s/srcversion" % name)
        eq("srcversion matches sysfs for %s" % name, sv.strip(),
           d.get("srcversion"))
        deps = [x for x in (d.get("depends") or "").split(",") if x]
        for dep in deps:
            check("dependency %s of %s is loaded" % (dep, name), dep in pm,
                  sorted(pm))


def t_modules_dep_covers_every_loaded_module():
    s = sh()
    pm = procmods(s)
    dep, _ = run(s, "cat /lib/modules/$(uname -r)/modules.dep")
    listed = set()
    for line in dep.splitlines():
        lhs = line.split(":")[0]
        listed.add(lhs.rsplit("/", 1)[-1].split(".")[0])
    eq("modules.dep lists every loaded module",
       sorted(set(pm) - listed), [])
    order, _ = run(s, "cat /lib/modules/$(uname -r)/modules.order")
    eq("modules.order lists every loaded module",
       sorted(set(pm) - set(l.rsplit("/", 1)[-1].split(".")[0]
                            for l in order.split())), [])


def t_modinfo_errors():
    s = sh()
    o, rc = run(s, "modinfo")
    eq("bare modinfo rc", rc, 1)
    check("bare modinfo message", "missing module or filename" in o, o[:80])
    o, rc = run(s, "modinfo definitelynotamodule")
    eq("unknown module rc", rc, 1)
    check("unknown module message",
          "ERROR: Module definitelynotamodule not found." in o, o[:90])
    o, rc = run(s, "modinfo -n ext4")
    eq("modinfo -n prints one line", len(o.strip().splitlines()), 1)
    check("modinfo -n prints the filename", o.strip().endswith("ext4.ko.xz"),
          o[:90])
    o, rc = run(s, "modinfo -F srcversion ext4")
    check("modinfo -F prints a bare value", re.fullmatch(r"[0-9A-F]{32}\n", o),
          repr(o))
    o, rc = run(s, "modinfo --version")
    check("modinfo --version says kmod", o.startswith("kmod version "), o[:40])
    ver, _ = run(s, "dpkg-query -W -f '${Version}' kmod")
    check("and agrees with the kmod package (%s)" % ver.strip(),
          o.split()[2] in ver, "%r vs %r" % (o.split()[2], ver))


def t_insmod_refuses_a_foreign_module_like_a_real_kernel():
    s = sh()
    o, rc = run(s, "insmod")
    eq("bare insmod rc", rc, 1)
    check("bare insmod message", "missing filename" in o, o[:80])
    o, rc = run(s, "insmod /tmp/nothing-here.ko")
    eq("absent file rc", rc, 1)
    check("absent file message", "No such file or directory" in o, o[:90])
    run(s, "printf '\\x7fELF fake module' > /tmp/rk.ko")
    o, rc = run(s, "insmod /tmp/rk.ko")
    eq("foreign module rc", rc, 1)
    check("foreign module message", "Invalid module format" in o, o[:100])
    d, _ = run(s, "dmesg")
    check("and the kernel logged the version magic mismatch",
          "version magic" in d and fs.KERNEL in d.split("version magic")[-1],
          d.splitlines()[-1] if d else "")
    o, rc = run(s, "lsmod | grep -c rk")
    eq("the module did not load", o.strip(), "0")


def t_rmmod_and_modprobe_change_every_view_together():
    s = sh()
    o, rc = run(s, "rmmod")
    eq("bare rmmod rc", rc, 1)
    check("bare rmmod message", "missing module name" in o, o[:80])
    o, rc = run(s, "rmmod notloaded")
    eq("unloaded module rc", rc, 1)
    check("unloaded module message", "is not currently loaded" in o, o[:90])
    o, rc = run(s, "rmmod ext4")
    eq("in-use module rc", rc, 1)
    check("in-use module message", "is in use" in o, o[:90])
    o, rc = run(s, "rmmod jbd2")
    check("a module with a named holder says who", "in use by: ext4" in o,
          o[:90])
    # evdev has refcnt 0 and no holders, so it can actually go.
    o, rc = run(s, "rmmod evdev")
    eq("removing an idle module succeeds", rc, 0)
    for probe, want in (("grep -c '^evdev ' /proc/modules", "0"),
                        ("lsmod | grep -c '^evdev '", "0"),
                        ("ls -d /sys/module/evdev 2>/dev/null | wc -l", "0")):
        o, _ = run(s, probe)
        eq("after rmmod: %s" % probe, o.strip(), want)
    d, _ = run(s, "dmesg | tail -1")
    check("rmmod left a dmesg line", "evdev" in d, d[:80])
    o, rc = run(s, "modprobe evdev")
    eq("modprobe brings it back", rc, 0)
    for probe, want in (("grep -c '^evdev ' /proc/modules", "1"),
                        ("lsmod | grep -c '^evdev '", "1"),
                        ("ls -d /sys/module/evdev 2>/dev/null | wc -l", "1")):
        o, _ = run(s, probe)
        eq("after modprobe: %s" % probe, o.strip(), want)


def t_modprobe_errors():
    s = sh()
    o, rc = run(s, "modprobe")
    eq("bare modprobe rc", rc, 1)
    check("bare modprobe message", "missing parameters" in o, o[:80])
    o, rc = run(s, "modprobe definitelynotamodule")
    eq("unknown module rc", rc, 1)
    check("unknown module message",
          "not found in directory /lib/modules/" + fs.KERNEL in o, o[:120])
    o, rc = run(s, "modprobe -r notloaded")
    eq("modprobe -r of an unloaded module rc", rc, 1)
    check("modprobe -r message", "is not currently loaded" in o, o[:90])
    o, rc = run(s, "modprobe ext4")
    eq("modprobe of a loaded module is a silent no-op", (o, rc), ("", 0))
    o, rc = run(s, "depmod -a")
    eq("depmod -a is silent for root", (o, rc), ("", 0))


def t_kallsyms_exists_and_honours_kptr_restrict():
    s = sh()
    o, rc = run(s, "cat /proc/sys/kernel/kptr_restrict")
    eq("kptr_restrict is 1", o.strip(), "1")
    o, rc = run(s, "head -3 /proc/kallsyms")
    eq("kallsyms is readable", rc, 0)
    for line in o.splitlines():
        check("kallsyms line shape", re.fullmatch(r"[0-9a-f]{16} \w \S+", line),
              repr(line))
    n, _ = run(s, "wc -l < /proc/kallsyms")
    check("kallsyms has a plausible symbol count", int(n) > 50000, n.strip())
    o, _ = run(s, "grep -c ' 0000000000000000 ' /proc/kallsyms")
    # root has CAP_SYSLOG, so kptr_restrict=1 shows it real addresses.
    o, _ = run(s, "head -1 /proc/kallsyms")
    check("root sees real addresses", not o.startswith("0000000000000000"),
          o[:40])
    for sym in ("commit_creds", "prepare_kernel_cred", "kallsyms_lookup_name",
                "sys_call_table", "modprobe_path"):
        o, rc = run(s, "grep -c ' %s$' /proc/kallsyms" % sym)
        eq("kallsyms has %s" % sym, o.strip(), "1")


def t_kallsyms_module_addresses_match_proc_modules():
    s = sh()
    pm = procmods(s)
    for name in list(pm)[:5]:
        base = int(pm[name][3], 16)
        o, rc = run(s, "grep '\\[%s\\]' /proc/kallsyms | head -1" % name)
        eq("kallsyms has symbols for %s" % name, rc, 0)
        check("%s symbol line shape" % name, o.strip(), o[:60])
        if not o.strip():
            continue
        addr = int(o.split()[0], 16)
        check("%s symbols sit at its /proc/modules base" % name,
              base <= addr < base + 0x100000,
              "%016x vs base %016x" % (addr, base))


def t_module_addresses_are_64_bit_and_in_range():
    s = sh()
    pm = procmods(s)
    for name, (_sz, _rc, _h, addr) in pm.items():
        check("%s address is 16 hex digits" % name,
              re.fullmatch(r"0x[0-9a-f]{16}", addr), addr)
        v = int(addr, 16)
        check("%s address is in the module vmalloc range" % name,
              0xFFFFFFFFC0000000 <= v < 0xFFFFFFFFFFF00000, addr)


def t_taint_and_module_tooling_present():
    s = sh()
    o, rc = run(s, "cat /proc/sys/kernel/tainted")
    eq("tainted exists and is clean", (o.strip(), rc), ("0", 0))
    o, _ = run(s, "grep -c '(O)\\|(E)\\|(P)' /proc/modules")
    eq("no module claims to be out-of-tree while tainted is 0", o.strip(), "0")
    o, rc = run(s, "cat /proc/sys/kernel/modules_disabled")
    eq("modules_disabled is 0, matching modprobe working", o.strip(), "0")


def t_mounted_filesystems_have_their_modules():
    """/boot/efi is vfat, so the vfat stack has to be loaded."""
    s = sh()
    pm = procmods(s)
    mnt, _ = run(s, "cat /proc/mounts")
    if " vfat " in mnt:
        for need in ("vfat", "fat"):
            check("vfat is mounted so %s is loaded" % need, need in pm,
                  sorted(pm))
        if "codepage=437" in mnt:
            check("codepage=437 implies nls_cp437", "nls_cp437" in pm,
                  sorted(pm))
        if "iocharset=ascii" in mnt:
            check("iocharset=ascii implies nls_ascii", "nls_ascii" in pm,
                  sorted(pm))
    if re.search(r"^\S+ / ext4 ", mnt, re.M):
        for need in ("ext4", "jbd2", "mbcache"):
            check("ext4 root so %s is loaded" % need, need in pm, sorted(pm))
    fsl, _ = run(s, "cat /proc/filesystems")
    for name in ("ext4", "vfat"):
        check("/proc/filesystems registers %s" % name, name in fsl, fsl[:80])


def t_module_files_are_readable_and_typed():
    s = sh()
    pm = procmods(s)
    for name in list(pm)[:4]:
        f, _ = run(s, "modinfo -n %s" % name)
        f = f.strip()
        o, rc = run(s, "stat -c '%F %s' " + f)
        check("%s .ko is a regular file with a size" % name,
              o.startswith("regular file") and int(o.split()[-1]) > 0, o[:60])
    o, rc = run(s, "ls -d /lib/modules/$(uname -r)/kernel/fs/ext4")
    eq("the kernel/ tree has real subdirectories", rc, 0)


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


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
