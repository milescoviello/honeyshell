#!/usr/bin/env python3
"""What does this box say about the processes running on it?

`ps eww` and /proc/<pid>/environ are where an attacker goes looking for
credentials in other people's environments, and /proc is where every
enumeration script starts. Both were answering out of thin air.

  - Every process had the same eight variables, differing only in HOME. A
    kernel thread carried a systemd service's environment -- kernel threads
    have no mm at all, so the real kernel answers ESRCH. pid 1 carried
    INVOCATION_ID and JOURNAL_STREAM, which belong to a unit, and it is the
    manager. And two different services shared one INVOCATION_ID.
  - That INVOCATION_ID did not even match the one `systemctl show -p
    InvocationID` printed for the same unit: two formulas, one pid, two
    answers about which start this is.
  - `ps eww 1` printed the whole process table and no environment: BSD `e`
    was being read as "every process" (that is `-e`) and the environment
    was never appended. So the command an attacker runs to harvest secrets
    from other processes answered with a process list.
  - `ps 1234` -- how anyone asks whether a pid is alive -- ignored the
    operand and printed this shell, so the answer was yes whatever pid you
    named.
  - `systemctl show-environment` printed nothing, on a box where every
    service's environ starts with the two variables it is supposed to list.
  - Everything under /proc reported a size: `ls -l /proc/1/cwd` said 1, the
    length of "/", next to a cmdline of 0. Real procfs reports 0 for all of
    it, files and links alike, and `ls -l /proc/1` prints "total 0".
    sysfs is the other way round -- directories are 0 and every attribute
    file is one page -- and we printed the length of the string. `du -sh
    /sys` said 892K where every Linux says 0.
  - /proc and /sys were mounted rwxr-xr-x, which says root can create files
    in them, and every sysfs attribute was 0644, which says every one of
    them is writable.

Environments, modes and sizes here were measured on the real Debian 13
cloud guest this box imitates.

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


def envof(s, pid):
    o, rc = run(s, "cat /proc/%d/environ | tr '\\0' '\\n'" % pid)
    return dict(l.split("=", 1) for l in o.splitlines() if "=" in l), rc


# --- whose environment is whose --------------------------------------------

def t_a_kernel_thread_has_no_environment():
    s = sh()
    o, rc = run(s, "cat /proc/2/environ")
    eq("rc", rc, 1)
    check("the kernel answers ESRCH, not an empty file",
          "No such process" in o, o[:70])
    o2, rc2 = run(s, "wc -c /proc/2/environ")
    check("every reader says the same", "No such process" in o2, o2[:70])
    o3, _ = run(s, "cat /proc/2/cmdline | wc -c")
    eq("and its cmdline is empty, which is not the same thing",
       o3.strip(), "0")
    o4, _ = run(s, "ps -o comm -p 2 --no-headers")
    eq("it is still a process", o4.strip(), "kthreadd")


def t_pid_one_has_the_boot_environment():
    s = sh()
    env, rc = envof(s, 1)
    eq("rc", rc, 0)
    eq("init inherited the initramfs environment", env.get("init"),
       "/sbin/init")
    eq("HOME is / for pid 1", env.get("HOME"), "/")
    eq("TERM is the console", env.get("TERM"), "linux")
    check("the manager is not a unit: no INVOCATION_ID",
          "INVOCATION_ID" not in env, sorted(env))
    check("and no JOURNAL_STREAM", "JOURNAL_STREAM" not in env, sorted(env))


def t_a_service_has_a_service_environment():
    s = sh()
    env, _ = envof(s, 701)
    eq("LANG comes from the manager", env.get("LANG"), "C.UTF-8")
    eq("so does PATH", env.get("PATH"), fs.MANAGER_PATH)
    eq("SYSTEMD_EXEC_PID is its own pid", env.get("SYSTEMD_EXEC_PID"), "701")
    check("it has an invocation id",
          re.fullmatch(r"[0-9a-f]{32}", env.get("INVOCATION_ID", "")),
          env.get("INVOCATION_ID"))
    check("and a journal stream",
          env.get("JOURNAL_STREAM", "").startswith("9:"),
          env.get("JOURNAL_STREAM"))
    eq("the pressure watch names its own cgroup",
       env.get("MEMORY_PRESSURE_WATCH"),
       "/sys/fs/cgroup/system.slice/nginx.service/memory.pressure")


def t_the_invocation_id_has_one_source():
    s = sh()
    env, _ = envof(s, 701)
    o, _ = run(s, "systemctl show -p InvocationID nginx")
    eq("systemctl and the process agree",
       o.strip(), "InvocationID=" + env.get("INVOCATION_ID", "?"))
    o2, _ = run(s, "systemctl show -p MainPID nginx")
    eq("...about the same pid", o2.strip(), "MainPID=701")


def t_two_services_are_two_invocations():
    s = sh()
    a, _ = envof(s, 701)
    b, _ = envof(s, 884)
    check("nginx and mariadb do not share an invocation id",
          a.get("INVOCATION_ID") != b.get("INVOCATION_ID"),
          a.get("INVOCATION_ID"))
    check("nor a journal stream",
          a.get("JOURNAL_STREAM") != b.get("JOURNAL_STREAM"),
          a.get("JOURNAL_STREAM"))


def t_the_cgroup_and_the_environment_agree():
    s = sh()
    for pid in (701, 884, 194):
        env, _ = envof(s, pid)
        o, _ = run(s, "cat /proc/%d/cgroup" % pid)
        cg = o.strip().split("::")[-1]
        watch = env.get("MEMORY_PRESSURE_WATCH", "")
        check("pid %d: the pressure path is under its own cgroup" % pid,
              watch == "/sys/fs/cgroup%s/memory.pressure" % cg,
              "%s vs %s" % (watch, cg))


def t_every_cgroup_names_a_unit_that_exists():
    """comm is 15 characters; the unit name often is not."""
    s = sh()
    o, _ = run(s, "systemctl list-units --type=service --no-legend")
    units = {l.split()[0] for l in o.splitlines() if l.strip()}
    check("systemctl knows some units", len(units) > 5, len(units))
    o2, _ = run(s, "ps -eo pid --no-headers")
    bad = []
    for pid in (int(x) for x in o2.split()):
        cg, _ = run(s, "cat /proc/%d/cgroup" % pid)
        path = cg.strip().split("::")[-1]
        if not path.startswith("/system.slice/"):
            continue
        unit = path.split("/")[-1]
        if unit not in units:
            bad.append((pid, unit))
    eq("every service cgroup names a unit systemctl has", bad, [])


def t_the_session_shell_environment_is_the_shells():
    s = sh()
    o, _ = run(s, "cat /proc/$$/environ | tr '\\0' '\\n' | sort")
    o2, _ = run(s, "env | sort")
    have = [l for l in o.splitlines() if l.strip()]
    want = [l for l in o2.splitlines() if "=" in l and not l.startswith("_=")]
    missing = [l for l in want if l not in have]
    eq("env and /proc/self/environ describe the same process", missing, [])
    check("and it carries the connection, which is what people grep for",
          any(l.startswith("SSH_CLIENT=") for l in have), have[:4])


def t_the_manager_environment_is_published():
    s = sh()
    o, rc = run(s, "systemctl show-environment")
    eq("rc", rc, 0)
    eq("it is the two variables every unit inherits",
       o.split(), ["LANG=C.UTF-8", "PATH=" + fs.MANAGER_PATH])
    env, _ = envof(s, 701)
    eq("a service's PATH is that PATH", env.get("PATH"), fs.MANAGER_PATH)


# --- ps agrees with /proc ---------------------------------------------------

def t_ps_e_prints_the_environment():
    s = sh()
    o, rc = run(s, "ps eww -p 701")
    eq("rc", rc, 0)
    check("the BSD header carries STAT",
          o.splitlines()[0].split() == ["PID", "TTY", "STAT", "TIME",
                                        "COMMAND"], o.splitlines()[0])
    env, _ = envof(s, 701)
    row = o.splitlines()[1]
    for k, v in env.items():
        check("ps prints %s from the process's own environ" % k,
              "%s=%s" % (k, v) in row, row[-80:])


def t_ps_e_respects_permissions():
    d = sh(user="deploy")
    o, _ = run(d, "ps eww -p 1")
    check("a user who cannot read the environ gets no environ",
          "init=/sbin/init" not in o, o[:120])
    check("but still gets the row", "/sbin/init" in o, o[:80])
    o2, rc2 = run(d, "cat /proc/1/environ")
    eq("and the file says why", rc2, 1)
    check("permission denied", "Permission denied" in o2, o2[:60])


def t_ps_selects_by_bare_pid():
    s = sh()
    o, rc = run(s, "ps 1")
    eq("rc", rc, 0)
    rows = [l for l in o.splitlines()[1:] if l.strip()]
    eq("one row", len(rows), 1)
    check("and it is pid 1", rows[0].split()[0] == "1", rows[0])
    o2, rc2 = run(s, "ps 99999")
    eq("an absent pid is rc 1", rc2, 1)
    eq("with no rows", [l for l in o2.splitlines()[1:] if l.strip()], [])
    o3, _ = run(s, "ps 701,884")
    eq("a list selects both",
       sorted(l.split()[0] for l in o3.splitlines()[1:] if l.strip()),
       ["701", "884"])


def t_ps_and_proc_agree_on_the_process_list():
    s = sh()
    o, _ = run(s, "ps -eo pid --no-headers")
    ps_pids = sorted(int(x) for x in o.split())
    o2, _ = run(s, "ls /proc | grep -E '^[0-9]+$'")
    proc_pids = sorted(int(x) for x in o2.split())
    eq("every pid in ps has a /proc entry and vice versa",
       ps_pids, proc_pids)


# --- procfs and sysfs report themselves the way the kernel does -------------

def t_everything_under_proc_is_size_zero():
    s = sh()
    o, _ = run(s, "ls -l /proc/1/")
    check("the listing totals zero", o.startswith("total 0\n"),
          o.split("\n")[0])
    sizes = set(l.split()[4] for l in o.splitlines()[1:] if l.strip())
    eq("and every entry is 0", sizes, {"0"})
    o2, _ = run(s, "stat -c %s /proc/1/exe /proc/1/cwd /proc/1/environ")
    eq("stat says the same", set(o2.split()), {"0"})
    o3, _ = run(s, "ls -ld /proc")
    check("procfs is mounted read-only to everyone",
          o3.startswith("dr-xr-xr-x"), o3[:20])
    check("and reports no size itself", o3.split()[4] == "0", o3[:40])


def t_sysfs_reports_a_page_per_attribute():
    s = sh()
    o, _ = run(s, "ls -l /sys/class/net/eth0/address")
    eq("an attribute is one page", o.split()[4], "4096")
    check("and read-only", o.startswith("-r--r--r--"), o[:20])
    o2, _ = run(s, "ls -ld /sys/class/net")
    eq("a sysfs directory is 0", o2.split()[4], "0")
    o3, _ = run(s, "wc -c < /sys/class/net/eth0/address")
    eq("but reading it gives the bytes, not the page", o3.strip(), "18")
    o4, _ = run(s, "ls -l /sys/class/net/eth0/mtu")
    check("an attribute the kernel accepts a write on is 644",
          o4.startswith("-rw-r--r--"), o4[:20])


def t_the_virtual_filesystems_occupy_nothing():
    s = sh()
    for p in ("/proc", "/sys"):
        o, _ = run(s, "du -s %s" % p)
        eq("du %s is zero" % p, o.split()[0], "0")
    o2, _ = run(s, "du -s /etc")
    check("a real directory still costs something",
          int(o2.split()[0]) > 100, o2[:30])


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
