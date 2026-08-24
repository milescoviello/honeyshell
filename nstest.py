#!/usr/bin/env python3
"""Am I really root, and am I really on the metal?

Both questions get asked in the first minute of every privilege-escalation
script, and the box was answering the second one two ways at once.

  - `systemd-detect-virt -c` printed "kvm" and exited 0. -c asks *only*
    about containers; on a KVM guest it prints "none" and exits 1. So the
    box claimed to be a container and a virtual machine in the same breath,
    and the standard "am I in a container" test got a yes.
  - /proc/<pid>/ns was an empty directory while `lsns` printed three
    namespaces out of a literal -- a command disagreeing with the files it
    is implemented on top of. Comparing /proc/self/ns/mnt with
    /proc/1/ns/mnt is how every container check ever written asks whether
    it is boxed in, and both readlinks came back empty.
  - `lsns -t mnt` ignored the type and listed everything.
  - /proc/<pid>/attr was empty, so `cat /proc/self/attr/current` -- how a
    process asks what confines it -- said no such file, on a box whose
    /sys/kernel/security/lsm lists apparmor and whose boot log says the
    AppArmor filesystem is enabled. /sys/kernel/security/apparmor did not
    exist either: the module was named in one file and had nowhere to live.

Namespace inode numbers, the private-mount set, the attr directory and
every detect-virt status here were measured on the real Debian 13 cloud
guest this box imitates.

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


# --- the container question -------------------------------------------------

def t_detect_virt_answers_each_question_separately():
    s = sh()
    o, rc = run(s, "systemd-detect-virt")
    eq("plain says kvm", (o.strip(), rc), ("kvm", 0))
    o2, rc2 = run(s, "systemd-detect-virt -c")
    eq("-c says none", o2.strip(), "none")
    eq("...and exits 1, which is what the shell idiom tests", rc2, 1)
    o3, rc3 = run(s, "systemd-detect-virt -v")
    eq("-v says kvm", (o3.strip(), rc3), ("kvm", 0))
    o4, rc4 = run(s, "systemd-detect-virt -q")
    eq("-q prints nothing and keeps the status", (o4.strip(), rc4), ("", 0))
    o5, rc5 = run(s, "systemd-detect-virt -c -q")
    eq("...both ways", (o5.strip(), rc5), ("", 1))


def t_the_container_markers_are_absent_together():
    s = sh()
    for f in ("/.dockerenv", "/run/.containerenv"):
        o, rc = run(s, "test -e %s; echo $?" % f)
        eq("%s is not there" % f, o.strip(), "1")
    o2, _ = run(s, "cat /proc/1/cgroup")
    eq("pid 1 is in the init scope, not a container's cgroup",
       o2.strip(), "0::/init.scope")
    o3, rc3 = run(s, "systemd-detect-virt -c")
    eq("and detect-virt agrees", o3.strip(), "none")


# --- namespaces -------------------------------------------------------------

NS_TYPES = ("cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts")


def t_every_process_has_its_namespace_links():
    s = sh()
    o, _ = run(s, "ls /proc/self/ns/")
    have = set(o.split())
    for t in NS_TYPES:
        check("/proc/self/ns/%s exists" % t, t in have, sorted(have))
    check("and the _for_children pair", "pid_for_children" in have
          and "time_for_children" in have, sorted(have))
    o2, _ = run(s, "ls -l /proc/self/ns/mnt")
    check("they are symlinks", o2.startswith("l"), o2[:20])
    check("into the namespace's own inode",
          re.search(r"-> mnt:\[40265\d+\]", o2), o2[-30:])


def t_the_box_is_in_one_namespace_set():
    """The check every container escape starts with."""
    s = sh()
    for t in NS_TYPES:
        if t == "mnt":
            continue
        a, _ = run(s, "readlink /proc/self/ns/%s" % t)
        b, _ = run(s, "readlink /proc/1/ns/%s" % t)
        eq("this shell shares pid 1's %s namespace" % t,
           a.strip(), b.strip())
    a, _ = run(s, "readlink /proc/self/ns/mnt")
    b, _ = run(s, "readlink /proc/1/ns/mnt")
    eq("and its mount namespace", a.strip(), b.strip())


def t_a_hardened_service_has_its_own_mount_namespace():
    s = sh()
    a, _ = run(s, "readlink /proc/221/ns/mnt")
    b, _ = run(s, "readlink /proc/1/ns/mnt")
    check("systemd-udevd is in a private mount namespace",
          a.strip() != b.strip(), "%s vs %s" % (a.strip(), b.strip()))
    c, _ = run(s, "readlink /proc/221/ns/net")
    d, _ = run(s, "readlink /proc/1/ns/net")
    eq("but shares the network namespace", c.strip(), d.strip())


def t_lsns_and_the_links_are_the_same_source():
    s = sh()
    o, rc = run(s, "lsns")
    eq("rc", rc, 0)
    rows = [l.split() for l in o.splitlines()[1:] if l.strip()]
    listed = {(r[0], r[1]) for r in rows}
    for t in NS_TYPES:
        link, _ = run(s, "readlink /proc/1/ns/%s" % t)
        ino = link.strip().split("[")[1].rstrip("]")
        check("lsns lists the %s namespace pid 1 is in" % t,
              (ino, t) in listed, sorted(listed)[:3])
    o2, _ = run(s, "ps -eo pid --no-headers | wc -l")
    nprocs = [r[2] for r in rows if r[1] == "uts"]
    eq("and counts every process in it", nprocs, [o2.strip()])


def t_lsns_filters():
    s = sh()
    o, _ = run(s, "lsns -t mnt")
    kinds = {l.split()[1] for l in o.splitlines()[1:] if l.strip()}
    eq("-t mnt lists only mount namespaces", kinds, {"mnt"})
    check("including the private ones",
          len([l for l in o.splitlines()[1:] if l.strip()]) > 1, o[:80])
    o2, _ = run(s, "lsns -t net")
    eq("-t net lists only the network one",
       {l.split()[1] for l in o2.splitlines()[1:] if l.strip()}, {"net"})
    o3, _ = run(s, "lsns -p 1")
    pids = {l.split()[3] for l in o3.splitlines()[1:] if l.strip()}
    eq("-p 1 is pid 1's namespaces", pids, {"1"})
    o4, _ = run(s, "lsns -n -t uts | wc -l")
    eq("-n drops the header", o4.strip(), "1")


# --- what confines a process ------------------------------------------------

def t_the_lsm_is_readable_where_a_process_looks():
    s = sh()
    o, _ = run(s, "cat /sys/kernel/security/lsm")
    check("apparmor is in the lsm list", "apparmor" in o, o.strip())
    o2, rc = run(s, "cat /proc/self/attr/current")
    eq("rc", rc, 0)
    eq("and the process is unconfined", o2.strip(), "unconfined")
    o3, _ = run(s, "cat /proc/self/attr/apparmor/current")
    eq("the apparmor-specific file says the same", o3.strip(), "unconfined")
    o4, _ = run(s, "ls /proc/self/attr/")
    for f in ("current", "exec", "fscreate", "keycreate", "prev",
              "sockcreate", "apparmor"):
        check("attr/%s exists" % f, f in o4.split(), o4.split())


def t_the_module_named_in_lsm_has_a_home():
    s = sh()
    o, rc = run(s, "ls /sys/kernel/security/apparmor/")
    eq("rc", rc, 0)
    for f in ("features", "policy", "profiles"):
        check("securityfs has apparmor/%s" % f, f in o.split(), o.split())
    o2, rc2 = run(s, "cat /sys/kernel/security/apparmor/profiles")
    eq("no profiles are loaded, which is why we are unconfined",
       (o2.strip(), rc2), ("", 0))


def t_capabilities_match_the_uid():
    s = sh()
    o, _ = run(s, "grep -E '^Cap(Eff|Prm|Bnd|Amb|Inh)' /proc/self/status")
    caps = dict(l.split() for l in o.splitlines())
    eq("root has the full effective set", caps.get("CapEff:"),
       "000001ffffffffff")
    eq("and nothing ambient", caps.get("CapAmb:"), "0000000000000000")
    d = sh(user="deploy")
    o2, _ = run(d, "grep -E '^Cap(Eff|Bnd)' /proc/self/status")
    caps2 = dict(l.split() for l in o2.splitlines())
    eq("a normal user has none", caps2.get("CapEff:"), "0000000000000000")
    eq("but the bounding set is still the kernel's",
       caps2.get("CapBnd:"), "000001ffffffffff")
    o3, _ = run(d, "id -u")
    eq("...and that user is not root", o3.strip(), "1000")


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
