#!/usr/bin/env python3
"""Does the box agree with itself about what is running?

`ps aux` is the first thing almost every attacker types, and /proc is what
their scripts read. This sweep asked whether the two tell the same story,
and whether the things derived from them -- loadavg, /proc/stat, kill,
pgrep, systemctl -- agree with both.

What it found, in order of how loudly it gives the game away:

  - /proc/<kthread>/cmdline returned "[kthreadd]". A kernel thread's cmdline
    is *empty*; that emptiness is the only reason ps draws the brackets in
    the first place, and it is the standard kernel-thread test.
  - readlink /proc/<kthread>/exe returned /usr/bin/[kthreadd]. A kernel
    thread has no exe at all, and one that does is a textbook sandbox tell.
    exe was built as "/usr/bin/" + the first token of the ps listing, which
    also gave sshd /usr/bin/sshd: -- with the colon.
  - ls /proc/<kthread>/fd listed 0, 1 and 2. Kernel threads hold no fds.
  - readlink /proc/1/exe said /sbin/init. Real systemd resolves to
    /usr/lib/systemd/systemd; /sbin/init is only what its cmdline says.
  - cwd was /root for every root process, including pid 1 and the kernel
    threads. On a real box every daemon and kernel thread has cwd=/ and only
    an interactive shell sits in a home directory.
  - /proc/loadavg claimed 1/128 tasks while ps listed 27, its running count
    said 1 while /proc/stat said 2 or 3 in the same instant, and its last-pid
    was a random 20000-35000 on a box whose highest pid is 4100.
  - kill -0 on a live pid returned EPERM as root, so a live pid and a dead
    pid both came back rc=1 and the canonical liveness probe could not tell
    them apart.

Reference values are measured on a real Debian trixie guest, not read off
whatever host runs this suite -- that mistake has been made four times in
this project. Re-measure with:

    od -c /proc/2/cmdline; readlink /proc/1/exe; cat /proc/loadavg

Run from `honeypot/`, or on the guest.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

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
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def pids(s):
    out, _ = run(s, "ps -eo pid --no-headers")
    return [int(x) for x in out.split()]


def kthread_pid(s):
    out, _ = run(s, "ps -eo pid,args --no-headers")
    for line in out.splitlines():
        f = line.split(None, 1)
        if len(f) == 2 and f[1].strip().startswith("["):
            return int(f[0])
    return None


def daemon_pid(s, name):
    out, _ = run(s, "pgrep -x %s" % name)
    return int(out.split()[0]) if out.split() else None


# ------------------------------------------------------- ps <-> /proc
def t_ps_and_proc_list_the_same_pids():
    s = sh()
    ps = set(pids(s))
    out, _ = run(s, "ls /proc")
    pr = {int(x) for x in out.split() if x.isdigit()}
    eq("every ps pid is in /proc", sorted(ps - pr), [])
    eq("every /proc pid is in ps", sorted(pr - ps), [])
    check("the table is not trivially small", len(ps) > 10, str(len(ps)))


def t_every_pid_has_the_expected_proc_files():
    s = sh()
    for pid in pids(s)[:8]:
        for f in ("stat", "status", "comm", "cmdline"):
            out, rc = run(s, "test -f /proc/%d/%s && echo ok" % (pid, f))
            eq("/proc/%d/%s exists" % (pid, f), (out.strip(), rc), ("ok", 0))


# ------------------------------------------------------- kernel threads
def t_kernel_thread_cmdline_is_empty():
    s = sh()
    k = kthread_pid(s)
    check("found a kernel thread in ps", k is not None, "none")
    if k is None:
        return
    out, rc = run(s, "wc -c < /proc/%d/cmdline" % k)
    eq("kernel thread cmdline is zero bytes", out.strip(), "0")
    eq("reading it still succeeds", rc, 0)
    # ...while a userspace process has a non-empty one.
    out, _ = run(s, "wc -c < /proc/1/cmdline")
    check("pid 1 cmdline is not empty", int(out.strip() or 0) > 0, out)


def t_kernel_thread_has_no_exe():
    s = sh()
    k = kthread_pid(s)
    if k is None:
        return
    out, rc = run(s, "readlink /proc/%d/exe" % k)
    eq("kernel thread exe is absent", (out.strip(), rc), ("", 1))
    out, rc = run(s, "test -e /proc/%d/exe && echo yes" % k)
    check("test -e agrees there is no exe", rc != 0, out[:40])


def t_kernel_thread_holds_no_fds():
    s = sh()
    k = kthread_pid(s)
    if k is None:
        return
    out, _ = run(s, "ls /proc/%d/fd | wc -l" % k)
    eq("kernel thread fd dir is empty", out.strip(), "0")


def t_kernel_thread_cwd_is_root():
    s = sh()
    k = kthread_pid(s)
    if k is None:
        return
    out, _ = run(s, "readlink /proc/%d/cwd" % k)
    eq("kernel thread cwd is /", out.strip(), "/")


# ------------------------------------------------------------- exe paths
def t_exe_paths_are_real_binaries():
    s = sh()
    # Measured: systemd's exe is the real binary, not the /sbin/init symlink
    # that appears in its cmdline.
    out, _ = run(s, "readlink /proc/1/exe")
    eq("pid 1 exe", out.strip(), "/usr/lib/systemd/systemd")
    out, _ = run(s, "cat /proc/1/cmdline")
    check("pid 1 cmdline still says /sbin/init",
          out.strip("\0\n") == "/sbin/init", repr(out[:40]))
    for name, want in (("sshd", "/usr/sbin/sshd"),
                       ("nginx", "/usr/sbin/nginx")):
        pid = daemon_pid(s, name)
        if pid is None:
            continue
        out, _ = run(s, "readlink /proc/%d/exe" % pid)
        eq("%s exe" % name, out.strip(), want)
    # No exe may contain a character a path cannot hold.
    for pid in pids(s):
        out, rc = run(s, "readlink /proc/%d/exe" % pid)
        if rc != 0:
            continue
        t = out.strip()
        check("exe of %d is a plausible path" % pid,
              t.startswith("/") and "[" not in t and ":" not in t
              and " " not in t, repr(t))


def t_exe_targets_exist():
    """A dangling exe is as visible as a missing one."""
    s = sh()
    for pid in pids(s):
        out, rc = run(s, "readlink /proc/%d/exe" % pid)
        if rc != 0:
            continue
        o, rc2 = run(s, "test -e %s && echo ok" % out.strip())
        eq("exe target exists for %d (%s)" % (pid, out.strip()),
           (o.strip(), rc2), ("ok", 0))


# ------------------------------------------------------------- cmdline
def t_rewritten_argv_is_one_string():
    """sshd and nginx put their whole banner in argv[0], spaces included."""
    s = sh()
    pid = daemon_pid(s, "sshd")
    if pid is None:
        return
    out, _ = run(s, "cat /proc/%d/cmdline" % pid)
    body = out.rstrip("\n")
    check("sshd cmdline is a single NUL-terminated string",
          body.count("\0") == 1 and body.endswith("\0"),
          "%d NULs in %r" % (body.count("\0"), body[:60]))
    check("and it keeps its spaces", " " in body, repr(body[:60]))


def t_ordinary_argv_is_nul_separated():
    s = sh()
    out, _ = run(s, "ps -eo pid,args --no-headers")
    for line in out.splitlines():
        f = line.split(None, 1)
        if len(f) != 2:
            continue
        pid, args = f[0], f[1].strip()
        if args.startswith("[") or ": " in args or " " not in args:
            continue
        body, _ = run(s, "cat /proc/%s/cmdline" % pid)
        body = body.rstrip("\n")
        check("multi-arg cmdline for %s is NUL-separated" % pid,
              body.count("\0") == len(args.split()),
              "%r vs args %r" % (body[:50], args[:40]))
        break


# ----------------------------------------------------------------- cwd
def t_daemons_have_cwd_root():
    s = sh()
    out, _ = run(s, "ps -eo pid,tty --no-headers")
    for line in out.splitlines():
        f = line.split()
        if len(f) < 2 or f[1] != "?":
            continue
        o, _ = run(s, "readlink /proc/%s/cwd" % f[0])
        eq("cwd of ttyless pid %s is /" % f[0], o.strip(), "/")


# --------------------------------------------------------------- fd shape
def t_service_fd_shape():
    """A journald-managed service shares one socket inode on 1 and 2."""
    s = sh()
    pid = daemon_pid(s, "sshd")
    if pid is None:
        return
    out, _ = run(s, "readlink /proc/%d/fd/0" % pid)
    eq("service stdin is /dev/null", out.strip(), "/dev/null")
    a, _ = run(s, "readlink /proc/%d/fd/1" % pid)
    b, _ = run(s, "readlink /proc/%d/fd/2" % pid)
    check("stdout is a socket", a.strip().startswith("socket:["), a[:30])
    eq("stderr shares stdout's inode", b.strip(), a.strip())
    out, _ = run(s, "ls /proc/%d/fd | wc -l" % pid)
    check("a listener holds more than three fds",
          int(out.strip() or 0) > 3, out.strip())


# ------------------------------------------------------- derived counters
def t_loadavg_matches_the_process_table():
    s = sh()
    n = len(pids(s))
    out, _ = run(s, "cat /proc/loadavg")
    f = out.split()
    check("loadavg has five fields", len(f) == 5, out[:50])
    if len(f) != 5:
        return
    running, total = f[3].split("/")
    eq("loadavg task total equals the ps count", int(total), n)
    o, _ = run(s, "awk '/^procs_running/{print $2}' /proc/stat")
    eq("loadavg running agrees with /proc/stat", running, o.strip())
    check("procs_running is at least 1", int(o.strip() or 0) >= 1, o.strip())
    eq("last pid is above the highest live pid",
       int(f[4]) >= max(pids(s)), True)


def t_stat_and_uptime_agree():
    s = sh()
    out, _ = run(s, "cat /proc/uptime")
    up = float(out.split()[0])
    o, _ = run(s, "awk '/^btime/{print $2}' /proc/stat")
    import time as _t
    drift = abs((_t.time() - float(o.strip())) - up)
    check("btime + uptime lands on now", drift < 120, "drift %.0fs" % drift)


def t_nproc_matches_cpuinfo():
    s = sh()
    a, _ = run(s, "nproc")
    b, _ = run(s, "grep -c ^processor /proc/cpuinfo")
    eq("nproc matches /proc/cpuinfo", a.strip(), b.strip())
    c, _ = run(s, "awk '/^cpu[0-9]/{n++} END{print n}' /proc/stat")
    eq("/proc/stat has one line per cpu", c.strip(), a.strip())


# ------------------------------------------------- status / stat coherence
def t_status_matches_stat_and_ps():
    s = sh()
    for pid in pids(s)[:8]:
        st, _ = run(s, "cat /proc/%d/stat" % pid)
        f = st.split()
        ppid_stat = f[3] if len(f) > 3 else "?"
        o, _ = run(s, "awk '/^PPid:/{print $2}' /proc/%d/status" % pid)
        eq("status PPid == stat ppid for %d" % pid, o.strip(), ppid_stat)
        o2, _ = run(s, "ps -o ppid= -p %d" % pid)
        eq("ps ppid == status PPid for %d" % pid, o2.strip(), o.strip())
        # comm appears in both, and the kernel truncates it to 15 bytes.
        c, _ = run(s, "cat /proc/%d/comm" % pid)
        eq("stat's (comm) matches comm for %d" % pid,
           "(%s)" % c.strip(), f[1] if len(f) > 1 else "?")
        check("comm is at most 15 bytes for %d" % pid,
              len(c.strip()) <= 15, c.strip())


def t_threads_match_task_dir():
    s = sh()
    for pid in pids(s)[:6]:
        o, _ = run(s, "awk '/^Threads:/{print $2}' /proc/%d/status" % pid)
        t, _ = run(s, "ls /proc/%d/task | wc -l" % pid)
        eq("Threads == entries in task/ for %d" % pid, o.strip(), t.strip())


def t_status_uid_matches_ps_user():
    s = sh()
    out, _ = run(s, "ps -eo pid,user --no-headers")
    for line in out.splitlines()[:8]:
        f = line.split()
        if len(f) < 2:
            continue
        o, _ = run(s, "awk '/^Uid:/{print $2}' /proc/%s/status" % f[0])
        n, _ = run(s, "id -u %s" % f[1])
        if not n.strip().isdigit():
            continue
        eq("status Uid matches ps USER for %s" % f[0], o.strip(), n.strip())


# ------------------------------------------------------------- pid lookup
def t_pgrep_pidof_agree_with_ps():
    s = sh()
    for name in ("sshd", "nginx", "cron"):
        out, _ = run(s, "ps -eo pid,comm --no-headers")
        want = sorted(int(l.split()[0]) for l in out.splitlines()
                      if l.split()[1:2] == [name])
        if not want:
            continue
        g, _ = run(s, "pgrep -x %s" % name)
        eq("pgrep -x %s matches ps" % name,
           sorted(int(x) for x in g.split()), want)
        d, _ = run(s, "pidof %s" % name)
        eq("pidof %s matches ps" % name,
           sorted(int(x) for x in d.split()), want)
        # pidof prints newest first, pgrep oldest first.
        if len(want) > 1:
            check("pidof is newest-first",
                  [int(x) for x in d.split()] == sorted(want, reverse=True),
                  d.strip())


def t_proc_self_points_at_our_shell():
    s = sh()
    a, _ = run(s, "readlink /proc/self")
    b, _ = run(s, "echo $$")
    eq("/proc/self resolves to our own pid", a.strip(), b.strip())
    c, _ = run(s, "cat /proc/self/comm")
    check("/proc/self/comm is a shell", c.strip() in ("bash", "sh"), c.strip())


# ---------------------------------------------------------------- signals
def t_kill_zero_distinguishes_live_from_dead():
    s = sh()
    out, rc = run(s, "kill -0 1")
    eq("kill -0 on pid 1 succeeds as root", (out, rc), ("", 0))
    out, rc = run(s, "kill -0 $$")
    eq("kill -0 on our own shell succeeds", (out, rc), ("", 0))
    for pid in pids(s)[:6]:
        o, rc = run(s, "kill -0 %d" % pid)
        eq("kill -0 on live pid %d" % pid, (o, rc), ("", 0))
    out, rc = run(s, "kill -0 31337")
    check("kill -0 on a dead pid fails",
          rc == 1 and "No such process" in out, out[:60])


def t_kernel_threads_survive_signals():
    s = sh()
    k = kthread_pid(s)
    if k is None:
        return
    out, rc = run(s, "kill -9 %d" % k)
    eq("signalling a kernel thread succeeds silently", (out, rc), ("", 0))
    check("the kernel thread is still there", k in pids(s), "gone")
    out, rc = run(s, "kill -9 1")
    eq("signalling pid 1 succeeds silently", (out, rc), ("", 0))
    check("pid 1 is still there", 1 in pids(s), "gone")


def t_killing_a_service_agrees_with_systemctl():
    """kill and systemctl stop must not disagree about a daemon."""
    s = sh()
    pid = daemon_pid(s, "nginx")
    if pid is None:
        return
    before, _ = run(s, "systemctl is-active nginx")
    eq("nginx starts active", before.strip(), "active")
    out, rc = run(s, "kill %d" % pid)
    eq("killing nginx succeeds", (out, rc), ("", 0))
    check("nginx leaves the process table", pid not in pids(s), "still listed")
    after, _ = run(s, "systemctl is-active nginx")
    eq("systemctl agrees nginx is down", after.strip(), "inactive")
    o, rc = run(s, "kill -0 %d" % pid)
    check("kill -0 on the dead pid now fails",
          rc == 1 and "No such process" in o, o[:50])
    o, _ = run(s, "ls /proc/%d 2>&1" % pid)
    check("/proc entry is gone too",
          "No such file or directory" in o, o[:60])


TESTS = [t_ps_and_proc_list_the_same_pids,
         t_every_pid_has_the_expected_proc_files,
         t_kernel_thread_cmdline_is_empty, t_kernel_thread_has_no_exe,
         t_kernel_thread_holds_no_fds, t_kernel_thread_cwd_is_root,
         t_exe_paths_are_real_binaries, t_exe_targets_exist,
         t_rewritten_argv_is_one_string, t_ordinary_argv_is_nul_separated,
         t_daemons_have_cwd_root, t_service_fd_shape,
         t_loadavg_matches_the_process_table, t_stat_and_uptime_agree,
         t_nproc_matches_cpuinfo, t_status_matches_stat_and_ps,
         t_threads_match_task_dir, t_status_uid_matches_ps_user,
         t_pgrep_pidof_agree_with_ps, t_proc_self_points_at_our_shell,
         t_kill_zero_distinguishes_live_from_dead,
         t_kernel_threads_survive_signals,
         t_killing_a_service_agrees_with_systemctl]


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
