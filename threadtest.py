"""A process cannot use more CPU than its threads allow.

Three readers of one fact, and they have to agree:

    ps -o pcpu     how much CPU the process is using
    ps -o stat     `l` if the kernel sees more than one thread
    /proc/<pid>/status  Threads: N

/proc/<pid>/status reported `Threads: 1` for every process on the box. That
was harmless while nothing used more than one core, and became a physical
impossibility the moment the persona started running work: a training job
at 388% on a single thread. Nothing can do that.

It also caught three daemons that were already wrong -- systemd-timesyncd,
rsyslogd and mariadbd all carried `l` in STAT, which means multi-threaded,
beside a Threads count of 1. That predates the workload.

Measured on the guest: systemd-timesyncd runs Threads 2 with STAT Ssl, and
dbus-daemon, journald, logind, resolved, networkd and udevd all run a
single thread with no `l`. A real multi-threaded process on another box
reads 165% CPU, STAT Rl, Threads 2 -- which is where the rule below comes
from rather than from reasoning about it.

Usage:  python3 threadtest.py
"""

import math
import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def sh():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.88")


def run(s, cmd):
    try:
        return s.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def threads_of(s, pid):
    """Threads: from /proc, or None."""
    for line in run(s, "cat /proc/%s/status" % pid).splitlines():
        if line.startswith("Threads:"):
            parts = line.split()
            if len(parts) > 1 and parts[1].isdigit():
                return int(parts[1])
    return None


s = sh()
rows = []
for line in run(s, "ps -eo pid,pcpu,stat,comm --no-headers").splitlines():
    f = line.split(None, 3)
    if len(f) < 4 or not f[0].isdigit():
        continue
    try:
        rows.append((int(f[0]), float(f[1]), f[2], f[3]))
    except ValueError:
        continue

check("there are processes to check", len(rows) > 10, True)

# ------------------------------------------------ the physical constraint
impossible = []
for pid, cpu, stat, comm in rows:
    n = threads_of(s, pid)
    if n is None:
        continue
    if cpu > 100.0 * n:
        impossible.append((pid, cpu, n, comm))
check("no process uses more CPU than its threads allow", impossible, [],
      "one thread is one core at most; a job at 388% needs at least four")

# ------------------------------------------- the l flag means what it says
mismatched = []
for pid, cpu, stat, comm in rows:
    n = threads_of(s, pid)
    if n is None:
        continue
    if ("l" in stat) != (n > 1):
        mismatched.append((pid, stat, n, comm))
check("ps's multi-threaded flag agrees with the thread count", mismatched, [],
      "`l` in STAT is how ps says a process has more than one thread, so it "
      "and /proc/<pid>/status are two spellings of the same fact")

# ------------------------------------------------- every process has one
missing = [pid for pid, _c, _s, _m in rows if threads_of(s, pid) is None]
check("every process in ps reports a thread count", missing, [])
nonpositive = [(pid, threads_of(s, pid)) for pid, _c, _s, _m in rows
               if (threads_of(s, pid) or 0) < 1]
check("...and it is at least one", nonpositive, [])

# --------------------------------------------- kernel threads are single
kthreads = [(pid, threads_of(s, pid)) for pid, _c, _s, comm in rows
            if comm.startswith("[")]
check("kernel threads run exactly one thread",
      [p for p, n in kthreads if n != 1], [],
      "a kthread is one task by construction")

# ----------------------------------- the daemons measured on a real box
# systemd-timesyncd: Threads 2, STAT Ssl. dbus, journald, logind, resolved,
# networkd and udevd: one thread, no l. Read off the guest.
for comm, want_threads, want_l in (("systemd-timesyn", 2, True),
                                   ("dbus-daemon", 1, False),
                                   ("systemd-journal", 1, False),
                                   ("systemd-logind", 1, False),
                                   ("systemd-resolve", 1, False),
                                   ("systemd-network", 1, False),
                                   ("systemd-udevd", 1, False)):
    hit = [(p, c, st) for p, c, st, m in rows if m.startswith(comm[:14])]
    if not hit:
        continue
    pid, _cpu, stat = hit[0]
    check("%s runs %d thread%s, as the guest does"
          % (comm, want_threads, "" if want_threads == 1 else "s"),
          threads_of(s, pid), want_threads)
    check("...and ps flags it accordingly", "l" in stat, want_l)

# ----------------------------------------- the workload declares its own
try:
    import workload
except ImportError:
    workload = None
if workload is None:
    check("the workload module is importable", False, True)
else:
    for j in workload.active():
        # .get, because a tree without the thread count is exactly the tree
        # this suite exists to fail against -- it has to report that, not
        # raise KeyError and take the run down with it.
        declared = j.get("threads")
        n = threads_of(s, j["pid"])
        check("workload job %s declares a thread count" % j["name"],
              declared is not None, True,
              "a job at %.1f%% CPU has to say how many threads it spreads "
              "that over" % j.get("cpu", 0.0))
        if declared is None:
            continue
        check("workload job %s reports its declared threads" % j["name"],
              n, declared)
        check("...enough of them for the CPU it claims",
              declared * 100 >= j["cpu"], True,
              "%s asks for %.1f%% on %d threads"
              % (j["name"], j["cpu"], declared))

# --------------------------------- a process this session starts is single
run(s, "mkdir -p /root/.x; echo x > /root/.x/p; chmod 755 /root/.x/p")
run(s, "nohup /root/.x/p >/dev/null 2>&1 &")
started = [(p, st) for p, _c, st, m in
           [(int(x.split()[0]), 0, x.split()[1], x.split(None, 2)[2])
            for x in run(s, "ps -eo pid,stat,comm --no-headers").splitlines()
            if x.split() and x.split()[0].isdigit()]
           if m.startswith("p")]
for pid, stat in started[:1]:
    n = threads_of(s, pid)
    if n is not None:
        check("a freshly launched payload is single-threaded", n, 1)
        check("...and is not flagged multi-threaded", "l" in stat, False)

# ------------------------------------- a thread has to exist everywhere
# Four readers of "does TID 21440 exist", and they gave three answers:
# htop drew it as a row, /proc/884/task listed it, ps -eL printed it, and
# /proc/21440 said No such file or directory. Inside the one path that did
# work the split went further -- `cat /proc/884/task/21440/status` returned
# 58 lines while `test -f` on it said no, `ls` of the directory came back
# empty, and grep and head, which stat before reading, both failed. A real
# kernel answers /proc/<tid> for every thread and keeps it out of readdir,
# which is what leaves ps -e and ls /proc counting processes only.
T = sh()
_pid = "884"
_tids = [x for x in run(T, "ls /proc/%s/task" % _pid).split() if x != _pid]
check("the process has threads to test with", len(_tids) > 4, True,
      "everything below is vacuous without them")
_tid = sorted(_tids, key=int)[0]

# The two spellings of one thread.
for _label, _p in (("task path", "/proc/%s/task/%s" % (_pid, _tid)),
                   ("bare tid", "/proc/%s" % _tid)):
    check("%s: the directory is there" % _label,
          run(T, "test -d %s && echo dir || echo nodir" % _p).strip(), "dir")
    check("%s: its status is a file" % _label,
          run(T, "test -f %s/status && echo file || echo nofile" % _p).strip(),
          "file", "cat answered this path while test -f denied it")
    check("%s: stat calls it a regular file" % _label,
          run(T, "stat -c '%%F' %s/status" % _p).strip(),
          "regular empty file",
          "a /proc file reports size 0, so this is what real stat says")
    check("%s: ls -l shows a file, not a directory" % _label,
          run(T, "ls -l %s/status | cut -c1-10" % _p).strip(), "-r--r--r--",
          "with no node to read, ls rendered it drwxr-xr-x")
    check("%s: grep can read it" % _label,
          run(T, "grep -c . %s/status" % _p).strip() not in ("", "0"), True,
          "grep and head stat before reading, so they failed where cat did not")
    check("%s: find sees it" % _label,
          run(T, "find %s -maxdepth 1 -name status" % _p).strip(),
          "%s/status" % _p,
          "find walks the node table, and a thread's files have no nodes")
    # The identity: Tgid is the process, Pid is the thread. This reported
    # the process for both, so every one of mariadbd's 32 threads called
    # itself 884 while ps -eL and htop called them 21440..21470.
    check("%s: status names the thread and its process" % _label,
          [l for l in run(T, "cat %s/status" % _p).splitlines()
           if l.startswith(("Tgid:", "Pid:", "NSpid:"))],
          ["Tgid:\t%s" % _pid, "Pid:\t%s" % _tid, "NSpid:\t%s" % _tid])
    check("%s: stat field 1 is the thread id" % _label,
          run(T, "awk '{print $1}' %s/stat" % _p).strip(), _tid)
    # ...and the fields that must NOT change: a thread shares its
    # process's parent, group and session.
    check("%s: ppid, pgrp and session stay the process's" % _label,
          run(T, "awk '{print $4,$5,$6}' %s/stat" % _p).strip(),
          run(T, "awk '{print $4,$5,$6}' /proc/%s/stat" % _pid).strip())

# A thread directory is not a process directory: it has no task/ of its
# own, which also stops find descending task -> tids -> task without end.
check("a thread has no task directory",
      run(T, "test -d /proc/%s/task/%s/task && echo yes || echo no"
          % (_pid, _tid)).strip(), "no")
check("...nor the seven other process-only entries",
      sorted(n for n in ("autogroup", "coredump_filter", "map_files",
                         "mountstats", "timens_offsets", "timers",
                         "timerslack_ns")
             if run(T, "test -e /proc/%s/task/%s/%s && echo y"
                    % (_pid, _tid, n)).strip() == "y"), [],
      "measured against a real thread directory")
check("...and it does have children, which a process lacks",
      run(T, "test -e /proc/%s/task/%s/children && echo yes || echo no"
          % (_pid, _tid)).strip(), "yes")

# The bare TID stays out of readdir, which is what keeps the process
# counts right -- three readers that must not move.
check("the tid is not in ls /proc",
      run(T, "ls /proc | grep -c '^%s$'" % _tid).strip(), "0")
_nproc = run(T, "ls -d /proc/[0-9]* | wc -l").strip()
check("ls /proc, ps -e and /proc/loadavg agree on the process count",
      [run(T, "ps -e --no-headers | wc -l").strip(), _nproc],
      [_nproc, _nproc])
check("ps -eL counts thread rows, and it is more than the processes",
      int(run(T, "ps -eL --no-headers | wc -l").strip()) > int(_nproc), True)
check("a pid that does not exist is still absent",
      run(T, "test -e /proc/99999/status && echo yes || echo no").strip(),
      "no", "the fallback must not invent threads")

# ps -T is the other spelling of ps -L. It printed the process row alone.
_nthr = run(T, "ls /proc/%s/task | wc -l" % _pid).strip()
check("ps -T lists every thread",
      run(T, "ps -T -p %s --no-headers | wc -l" % _pid).strip(), _nthr)
check("...and ps -L agrees with it",
      run(T, "ps -L -p %s --no-headers | wc -l" % _pid).strip(), _nthr)
check("ps -T names the column SPID",
      run(T, "ps -T -p %s" % _pid).splitlines()[0],
      "    PID    SPID TTY          TIME CMD")
check("...where ps -L names it LWP",
      run(T, "ps -L -p %s" % _pid).splitlines()[0],
      "    PID     LWP TTY          TIME CMD")
check("ps -T's second column is the thread id",
      run(T, "ps -o pid,spid --no-headers -T -p %s" % _pid).split()[1], _pid)
# ...and the process views stay process views.
check("ps -e still counts processes, not threads",
      run(T, "ps -e --no-headers | wc -l").strip(), _nproc)
check("ps aux too", run(T, "ps aux --no-headers | wc -l").strip(), _nproc)
check("ps -ejH is a hierarchy, not a thread list",
      run(T, "ps -ejH --no-headers | wc -l").strip(), _nproc,
      "-H is hierarchy and bare H is threads; they are different options")

for f in FAILS:
    print(" ", f)
print("   thread: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
