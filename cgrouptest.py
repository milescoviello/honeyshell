#!/usr/bin/env python3
"""cgroup v2: the tree, and the numbers systemd quotes from it.

The axis: every process on a cgroup2 box is in a cgroup, and three
things say which one -- /proc/<pid>/cgroup, the directory tree under
/sys/fs/cgroup, and systemd. None of them agreed.

    /proc/self/cgroup   0::/user.slice/user-0.slice/session-21.scope
    /sys/fs/cgroup      one file, cgroup.controllers, and no directories
                        at all -- so the path the process claims to be in
                        did not exist
    systemctl show ssh -p MemoryCurrent
                        13001728, quoted from
                        /sys/fs/cgroup/system.slice/ssh.service/memory.current,
                        a file that was equally absent -- and the same
                        13001728 for nginx and mariadb, next to a ps that
                        gave each of them a different RSS
    systemd-cgls        command not found, on a box running systemd

"Which cgroup am I in" is the first question a container-detection script
asks, and "one the kernel has never heard of" is not a state Linux can be
in.

Reference tree and layout measured on the guest (Debian 13, cgroup2).
"""
import re
import sys

import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.150")
    s.exec_mode = True
    return v, s


def main():
    v, s = sh()

    # -- the root of the tree -------------------------------------------------
    root = s.run("ls /sys/fs/cgroup").split()
    check("the root has more than the controllers file", len(root) > 20, True)
    for name in ("cgroup.procs", "cgroup.stat", "cgroup.subtree_control",
                 "cpu.stat", "memory.stat", "io.stat", "cpu.pressure",
                 "memory.pressure", "cpuset.cpus.effective", "misc.capacity"):
        check("root has %s" % name, name in root, True)
    for name in ("init.scope", "system.slice", "user.slice",
                 "dev-hugepages.mount", "sys-kernel-debug.mount"):
        check("root has %s/" % name,
              s.run("test -d /sys/fs/cgroup/%s && echo y" % name).strip(), "y")
    check("the controllers are the guest's",
          s.run("cat /sys/fs/cgroup/cgroup.controllers").strip(),
          "cpuset cpu io memory hugetlb pids rdma misc")
    check("cgroup.stat has the descendant counts",
          s.run("cat /sys/fs/cgroup/cgroup.stat").splitlines()[0].split()[0],
          "nr_descendants")

    # -- the path /proc claims exists -----------------------------------------
    path = s.run("cat /proc/self/cgroup").strip()
    check("/proc/self/cgroup is a v2 line", path.startswith("0::/"), True)
    scope = path.split("::", 1)[1]
    check("the scope directory exists",
          s.run("test -d /sys/fs/cgroup%s && echo y" % scope).strip(), "y")
    check("...and has the interface files",
          "memory.current" in s.run("ls /sys/fs/cgroup%s" % scope).split(),
          True)
    check("its parent slices exist too",
          s.run("test -d /sys/fs/cgroup/user.slice/user-0.slice "
                "&& echo y").strip(), "y")
    # A daemon's own line has to name a directory too.
    dpath = s.run("cat /proc/412/cgroup").strip().split("::", 1)[1]
    check("a daemon is in system.slice", dpath, "/system.slice/ssh.service")
    check("and that directory exists",
          s.run("test -d /sys/fs/cgroup%s && echo y" % dpath).strip(), "y")
    check("pid 1 is in init.scope",
          s.run("cat /proc/1/cgroup").strip(), "0::/init.scope")

    # -- systemd's numbers come from the files --------------------------------
    for unit in ("ssh", "nginx", "mariadb", "cron"):
        base = "/sys/fs/cgroup/system.slice/%s.service" % unit
        prop = s.run("systemctl show %s -p MemoryCurrent" % unit).strip()
        check("%s: MemoryCurrent matches memory.current" % unit,
              prop.split("=")[1],
              s.run("cat %s/memory.current" % base).strip())
        check("%s: TasksCurrent matches pids.current" % unit,
              s.run("systemctl show %s -p TasksCurrent" % unit
                    ).strip().split("=")[1],
              s.run("cat %s/pids.current" % base).strip())
        check("%s: ControlGroup names a real directory" % unit,
              s.run("test -d /sys/fs/cgroup$(systemctl show %s -p "
                    "ControlGroup | cut -d= -f2) && echo y" % unit).strip(),
              "y")
    # Different daemons must not report identical memory: they were all a
    # single hardcoded constant.
    mems = [s.run("systemctl show %s -p MemoryCurrent" % u).strip()
            for u in ("ssh", "nginx", "mariadb", "cron")]
    check("four daemons, four different figures", len(set(mems)), 4)
    check("and none of them is the old constant",
          any("13001728" in m for m in mems), False)
    # The figure has to be a multiple of the page size, as the kernel
    # counts pages.
    cur = int(s.run("cat /sys/fs/cgroup/system.slice/ssh.service/"
                    "memory.current").strip())
    check("memory.current is a whole number of pages", cur % 4096, 0)
    check("...and is in the region ps reports for that unit's RSS",
          cur > 1024 * 1024, True)

    # -- cgroup.procs lists the unit's processes ------------------------------
    procs = s.run("cat /sys/fs/cgroup/system.slice/ssh.service/"
                  "cgroup.procs").split()
    check("ssh.service has processes", bool(procs), True)
    check("...and its main pid is one of them",
          s.run("systemctl show ssh -p MainPID").strip().split("=")[1]
          in procs, True)
    check("pids.current counts them",
          s.run("cat /sys/fs/cgroup/system.slice/ssh.service/"
                "pids.current").strip(), str(len(procs)))
    check("cgroup.events says it is populated",
          "populated 1" in s.run("cat /sys/fs/cgroup/system.slice/"
                                 "ssh.service/cgroup.events"), True)
    # Every pid listed there must agree with /proc about its cgroup.
    bad = [p for p in procs
           if s.run("cat /proc/%s/cgroup" % p).strip()
           != "0::/system.slice/ssh.service"]
    check("every pid in the file agrees with /proc", bad, [])

    # -- a unit that is stopped loses its directory ---------------------------
    v2, s2 = sh()
    check("nginx is there to start with",
          s2.run("test -d /sys/fs/cgroup/system.slice/nginx.service "
                 "&& echo y").strip(), "y")
    s2.run("systemctl stop nginx")
    check("systemctl agrees it stopped",
          s2.run("systemctl is-active nginx").strip(), "inactive")
    check("and the cgroup directory is gone",
          s2.run("test -d /sys/fs/cgroup/system.slice/nginx.service "
                 "&& echo y || echo gone").strip(), "gone")
    check("while the others are untouched",
          s2.run("test -d /sys/fs/cgroup/system.slice/cron.service "
                 "&& echo y").strip(), "y")

    # -- the two commands that show the tree ----------------------------------
    v3, s3 = sh()
    check("systemd-cgls exists",
          s3.run("command -v systemd-cgls").strip(), "/usr/bin/systemd-cgls")
    check("systemd-cgtop exists",
          s3.run("command -v systemd-cgtop").strip(),
          "/usr/bin/systemd-cgtop")
    check("dpkg says systemd owns them",
          s3.run("dpkg -S /usr/bin/systemd-cgls").strip(),
          "systemd: /usr/bin/systemd-cgls")
    cgls = s3.run("systemd-cgls")
    check("cgls starts the way the guest's does",
          cgls.splitlines()[:2], ["CGroup /:", "-.slice"])
    check("it shows both slices",
          ("user.slice" in cgls and "system.slice" in cgls), True)
    check("it lists a unit that is running", "cron.service" in cgls, True)
    check("with the pid ps gives it",
          re.search(r"─498 /usr/sbin/cron", cgls) is not None, True)
    top = s3.run("systemd-cgtop -n1 -b")
    check("cgtop has the header",
          top.splitlines()[0].split()[:2], ["Control", "Group"])
    check("cgtop totals the root", top.splitlines()[1].split()[0], "/")
    check("cgtop lists the units",
          any(l.startswith("system.slice/ssh.service")
              for l in top.splitlines()), True)
    # cgtop's memory column has to be the same number, differently rendered.
    line = [l for l in top.splitlines()
            if l.startswith("system.slice/ssh.service")][0]
    shown = line.split()[3]
    raw = int(s3.run("cat /sys/fs/cgroup/system.slice/ssh.service/"
                     "memory.current").strip())
    val = float(shown[:-1]) * {"K": 1 << 10, "M": 1 << 20,
                               "G": 1 << 30}[shown[-1]]
    check("cgtop's figure is the file's, rounded",
          abs(val - raw) < raw * 0.05 + 1024, True)

    # -- nothing here says container ------------------------------------------
    # The tree is the first thing a detection script reads, so it has to
    # look like a plain host: no docker/lxc scopes, no /docker path.
    check("no container path in /proc/self/cgroup",
          any(k in path for k in ("docker", "lxc", "kubepods")), False)
    check("no container directory in the tree",
          any(k in s.run("ls /sys/fs/cgroup")
              for k in ("docker", "lxc")), False)
    check("systemd-detect-virt still says kvm",
          s.run("systemd-detect-virt").strip(), "kvm")

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("cgrouptest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
