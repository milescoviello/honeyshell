#!/usr/bin/env python3
"""Which threads does this box have, and do its readers name the same ones?

Four commands answer questions about threads and processes, and they had
drifted into four different answers.

`ps -eL` printed one row per *process* -- 33, on a box whose own
/proc/<pid>/task held 102 thread directories. The thread ids existed only
inside the exporter, allocated while walking the VFS in whatever order it
happened to yield, so `ps -L` could not have named the same threads even
if it had tried. The exporter's own comment claimed they were allocated
"so `ps -L` and htop's thread view agree", which was never true.

`ps -eo nlwp` was the literal "1" for every process -- the same shape as
psr beside it -- while /proc/<pid>/status Threads, stat field 20 and
htop's Threads column all said mariadbd had 32 and the training run 12.

htop reported "0 kthr" on a box listing kthreadd, rcu_gp, ksoftirqd,
kswapd0, jbd2 and kworker, because stat field 9 was one literal, 4194560,
for every process alike -- so PF_KTHREAD (0x00200000), the bit htop reads
to tell a kernel thread from a process, was set on nothing. Measured on a
real box: kthreadd carries 2129984, ordinary processes 4194560.

And the exporter only ever wrote. Every session left its sshd, bash and
children behind for good, so /proc grew a permanent record of everything
that had ever run here -- 108 pid directories against a process table of
33, and htop counting all 108 while ps counted 33.

The invariant is one number per question, from one allocator:

    ps -eL rows == sum of nlwp == /proc/<pid>/task directories

and every LWP ps prints must be a directory that actually exists.
"""

import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                           peer_port=40333)


def out(sh, cmd):
    try:
        return sh.run(cmd) or ""
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def main():
    # ---- the allocator itself -------------------------------------------
    table = [(884, 32), (1, 1), (21400, 12), (2, 1)]
    m = fakeshell.tid_map(table)
    check("tid_map is order-independent",
          fakeshell.tid_map(list(reversed(table))), m,
          "two callers must get the same ids or ps and /proc diverge")
    check("the main thread's tid is the pid",
          [m[p][0] for p, _ in table], [p for p, _ in table])
    check("it hands out exactly the requested counts",
          [len(m[p]) for p, n in table], [n for p, n in table])
    flat = [t for v in m.values() for t in v]
    check("no tid is handed out twice", len(flat), len(set(flat)))
    pids = {p for p, _ in table}
    check("no extra tid collides with a pid",
          sorted(t for t in flat if t in pids), sorted(pids),
          "only the main threads may equal a pid")

    sh = shell()

    # ---- ps agrees with itself ------------------------------------------
    per_pid = {}
    for line in out(sh, "ps -eo pid,nlwp --no-headers").splitlines():
        f = line.split()
        if len(f) == 2 and f[0].isdigit() and f[1].isdigit():
            per_pid[int(f[0])] = int(f[1])
    check("ps reports processes at all", bool(per_pid), True)
    check("nlwp is not the literal 1 for everything",
          any(v > 1 for v in per_pid.values()), True,
          "a 32-thread database reporting one thread is the old bug")

    lrows = [l for l in out(sh, "ps -eL --no-headers").splitlines() if l.strip()]
    check("ps -eL expands to one row per thread",
          len(lrows), sum(per_pid.values()),
          "-L printing one row per process is the old bug")

    # ---- ps agrees with /proc -------------------------------------------
    for pid in sorted(per_pid)[:6]:
        st = out(sh, "cat /proc/%d/status" % pid)
        thr = None
        for line in st.splitlines():
            if line.startswith("Threads:"):
                thr = int(line.split()[1])
                break
        check("status Threads == ps nlwp for pid %d" % pid, thr, per_pid[pid])
        f = out(sh, "cat /proc/%d/stat" % pid).split()
        if len(f) > 19:
            check("stat field 20 == ps nlwp for pid %d" % pid,
                  int(f[19]), per_pid[pid])

    # ---- kernel threads are marked ---------------------------------------
    PF_KTHREAD = 0x00200000
    kt, ut = [], []
    for line in out(sh, "ps -eo pid,comm,args --no-headers").splitlines():
        f = line.split(None, 2)
        if len(f) < 2 or not f[0].isdigit():
            continue
        st = out(sh, "cat /proc/%s/stat" % f[0]).split()
        if len(st) < 9:
            continue
        (kt if (len(f) > 2 and f[2].strip().startswith("[")) else ut).append(
            (f[0], int(st[8])))
    check("the box has kernel threads to mark", bool(kt), True)
    check("every kernel thread carries PF_KTHREAD",
          [p for p, fl in kt if not fl & PF_KTHREAD], [])
    check("and no ordinary process does",
          [p for p, fl in ut if fl & PF_KTHREAD], [])

    # ---- the export: same ids, and dead pids removed ---------------------
    import procexport
    root = tempfile.mkdtemp(prefix="threadid-")
    try:
        procexport.export(sh, root)
        mismatched, total = [], 0
        for pid, n in per_pid.items():
            d = os.path.join(root, "proc", str(pid), "task")
            got = sorted(int(x) for x in os.listdir(d)) \
                if os.path.isdir(d) else []
            total += len(got)
            if len(got) != n:
                mismatched.append((pid, n, len(got)))
        check("every process's task dirs == its nlwp", mismatched, [])
        check("task dirs total == ps -eL rows", total, len(lrows))

        lwps = {}
        for line in out(sh, "ps -eLo pid,lwp --no-headers").splitlines():
            f = line.split()
            if len(f) == 2 and f[0].isdigit() and f[1].isdigit():
                lwps.setdefault(int(f[0]), []).append(int(f[1]))
        missing = []
        for pid, tids in lwps.items():
            d = os.path.join(root, "proc", str(pid), "task")
            have = set(os.listdir(d)) if os.path.isdir(d) else set()
            missing += [(pid, t) for t in tids if str(t) not in have]
        check("every LWP ps prints exists in /proc/<pid>/task", missing, [])

        # A process that has gone must stop being in /proc.
        for stale in ("99001", "99002"):
            os.makedirs(os.path.join(root, "proc", stale), exist_ok=True)
            with open(os.path.join(root, "proc", stale, "stat"), "w") as fh:
                fh.write("stale\n")
        procexport.refresh(sh, root, full=True)
        left = [d for d in os.listdir(os.path.join(root, "proc"))
                if d.isdigit()]
        # The exact pids planted, not a prefix. "99" also matches the real
        # 99, 990..999 the box now has, so the prefix form failed the moment
        # the process table grew past a hundred entries -- the test was
        # wrong, not the exporter.
        check("the exporter removes pids the box no longer has",
              sorted(d for d in left if d in ("99001", "99002")), [],
              "without this /proc keeps every process that ever ran")
        check("and keeps the ones it does", "1" in left, True)
    finally:
        shutil.rmtree(root, ignore_errors=True)

    # -- ls /proc/<pid>/task, which is how you count threads without ps --
    # Four commands answered "how many threads does mariadbd have" and
    # three agreed:
    #     ps -o nlwp -p 884          32
    #     /proc/884/status Threads   32
    #     ps -eL -p 884              32 rows
    #     ls /proc/884/task           1
    # The exporter had it right -- it builds these from tid_map, so htop
    # read 32 -- but the VFS, which is what the attacker's own shell walks,
    # held only the main thread. The directories now come from the same
    # tid_map, so a thread has one id wherever it is read from.
    shx = shell()
    rows = []
    for line in (shx.run("ps -eo pid,nlwp,args --no-headers") or "").splitlines():
        f = line.split(None, 2)
        if len(f) >= 3 and f[0].isdigit():
            rows.append((int(f[0]), int(f[1]), f[2]))
    check("the process table is populated", len(rows) > 400, True, len(rows))
    mismatched = []
    total_dirs = 0
    for pid, nlwp, args in rows:
        ents = shx.fs.listdir("/proc/%d/task" % pid) or []
        total_dirs += len(ents)
        if len(ents) != nlwp:
            mismatched.append((pid, nlwp, len(ents), args[:20]))
    check("every process has one task directory per thread",
          mismatched, [], mismatched[:5])
    check("the box's task directories total its thread count",
          total_dirs,
          len((shx.run("ps -eL --no-headers") or "").splitlines()))
    for pid in (884, 21400):
        ents = sorted(shx.fs.listdir("/proc/%d/task" % pid) or [], key=int)
        check("pid %d lists its main thread first, with tid == pid" % pid,
              ents[:1], [str(pid)], ents[:4])
        st = (shx.run("grep Threads /proc/%d/status" % pid) or "").split()
        check("...and status agrees for %d" % pid,
              st[-1] if st else "?", str(len(ents)))

    # -- and the exported tree must not carry threads that are gone -------
    # _export_tasks only ever created task directories. When a thread count
    # changed -- or the allocation shifted because another process's did --
    # the old ones stayed. Measured on the live guest: 584 exported task
    # directories against the VFS's 565, a strict superset, with pid 21428
    # offering 16 where ps, /proc/<pid>/status and ls /proc/<pid>/task all
    # said 9. htop reads the export, so htop listed threads that existed
    # nowhere else on the box. Same shape as the stale cpuN directories in
    # sweep 223: a writer with no matching remover.
    import os as _os
    import shutil as _sh
    import tempfile as _tf
    import procexport as _px
    shy = shell()
    _root = _tf.mkdtemp(prefix="tidprune-")
    try:
        _px.export(shy, _root)

        def _totals():
            v = e = 0
            for line in (shy.run("ps -eo pid --no-headers") or "").splitlines():
                if not line.strip():
                    continue
                pid = int(line.split()[0])
                v += len(shy.fs.listdir("/proc/%d/task" % pid) or [])
                try:
                    e += len(_os.listdir("%s/proc/%d/task" % (_root, pid)))
                except OSError:
                    pass
            return v, e

        v0, e0 = _totals()
        check("the export lists exactly the threads the VFS does", e0, v0)

        # Plant what a shifted allocation would leave behind.
        for _pid, _ghosts in ((884, (90001, 90002, 90003)), (21400, (90010,))):
            for _g in _ghosts:
                _os.makedirs("%s/proc/%d/task/%d" % (_root, _pid, _g),
                             exist_ok=True)
        v1, e1 = _totals()
        check("planted threads are visible before the next export",
              e1 > v1, True, "%d vs %d" % (e1, v1))
        _px.export(shy, _root)
        v2, e2 = _totals()
        check("a re-export removes threads the box no longer claims", e2, v2)
        for _pid in (884, 21400):
            _vs = set(shy.fs.listdir("/proc/%d/task" % _pid) or [])
            _es = set(_os.listdir("%s/proc/%d/task" % (_root, _pid)))
            check("pid %d: nothing in the export the VFS does not have"
                  % _pid, sorted(_es - _vs), [])
            check("pid %d: nothing in the VFS the export does not have"
                  % _pid, sorted(_vs - _es), [])
    finally:
        _sh.rmtree(_root, ignore_errors=True)

    # ---- a filtered ps must name the same threads as an unfiltered one.
    # tid_map allocates the extra ids from a counter above the highest pid
    # it is shown, so it answers correctly only when every caller hands it
    # the whole process table. `ps -eL -p 884` narrowed rows to one
    # process first, which started that counter at 885 and produced
    # 884 885 886 887 -- while /proc/884/task, built from every process,
    # held 21440 upwards. Both said 32 threads and agreed on nothing else,
    # which is the shape sweep 232 was supposed to have ended: it made the
    # counts agree and left the identities free to diverge.
    _s2 = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                          peer_port=40333)
    _s2.run("true")

    def _out(c):
        o = _s2.run(c)
        return ((o[0] if isinstance(o, tuple) else o) or "")

    def _lwps(cmd):
        # Per line, not a flat split stepped by five: the CMD column holds
        # spaces ("/lib/systemd/systemd-networkd --address=systemd:"), so
        # a flat split walks off the end of the row.
        out = []
        for line in _out(cmd).splitlines():
            f = line.split()
            if len(f) > 1 and f[0].isdigit() and f[1].isdigit():
                out.append(f[1])
        return sorted(out, key=int)

    for _p in (884,):
        _task = sorted(_out("ls /proc/%d/task" % _p).split(), key=int)
        _filt = _lwps("ps -eL -p %d --no-headers" % _p)
        check("pid %d: ps -eL -p names the threads /proc has" % _p,
              _filt, _task,
              "a filtered ps built its own tid map from the filtered table")
        _all = _lwps("ps -eL --no-headers")
        check("pid %d: and an unfiltered ps names them too" % _p,
              [t for t in _task if t in _all], _task)
        check("pid %d: the main thread's tid is the pid" % _p,
              _task[0], str(_p), "as the kernel does")
        _n = _out("grep Threads /proc/%d/status" % _p).split()[-1]
        check("pid %d: and the count still agrees everywhere" % _p,
              {len(_task), len(_filt), int(_n),
               int(_out("ps -o nlwp= -p %d" % _p).strip())},
              {len(_task)})

    # ---- and the flags that were not asked: -Lf and -m
    # Four readers agreed on 606 tasks -- `ps -eL`, `ps -eT`,
    # `ps -eLo pid,tid`, and the fourth field of /proc/loadavg (1/606),
    # which is also what htop's own header sums to (31 + 113 thr +
    # 462 kthr). Two more disagreed. `ps -eLf` returned the *process*
    # count, 493: the -ef branch iterated the process rows and never
    # reached the thread expansion, so -L was accepted and ignored, and
    # its header carried neither LWP nor NLWP. `ps -em` was not parsed at
    # all and returned 493 too.
    #
    # Measured against procps 4.0.4: -eL and -eLf return identical counts
    # there, -f adds LWP and NLWP to the full format, and -m returns
    # processes plus threads.
    _s3 = shell()

    def _o(c):
        o = _s3.run(c)
        return ((o[0] if isinstance(o, tuple) else o) or "")

    def _n(c):
        t = _o(c).strip()
        return len(t.split("\n")) if t else 0

    _procs = _n("ps -e --no-headers")
    _tasks = _n("ps -eL --no-headers")
    _load = _o("cat /proc/loadavg").split()
    check("loadavg's task total is the thread count",
          int(_load[3].split("/")[1]), _tasks,
          "field four is running/total, and total counts threads")
    check("-eT agrees with -eL", _n("ps -eT --no-headers"), _tasks)
    check("-eLf lists threads, not processes",
          _n("ps -eLf --no-headers"), _tasks,
          "the -ef branch iterated processes and ignored -L entirely")
    check("...and is not merely the process count",
          _n("ps -eLf --no-headers") == _procs, False)
    check("-eLf's header carries LWP and NLWP",
          _o("ps -eLf").split("\n")[0],
          "UID          PID    PPID     LWP  C NLWP STIME TTY          TIME CMD",
          "measured byte-exact against procps 4.0.4")
    check("-em lists each process and then its threads",
          _n("ps -em --no-headers"), _procs + _tasks,
          "procps prints the process row, then one '-' row per thread")
    # The same process, counted six ways.
    _pid = None
    for _ln in _o("ps -eLf").split("\n")[1:]:
        _f = _ln.split()
        if len(_f) > 5 and _f[5].isdigit() and int(_f[5]) > 4:
            _pid = _f[1]
            break
    if _pid:
        _lf = [l for l in _o("ps -eLf").split("\n")
               if l.split() and l.split()[1] == _pid]
        _nlwp = {l.split()[5] for l in _lf}
        _tids_lf = {l.split()[3] for l in _lf}
        _tids_L = {l.split()[1] for l in _o("ps -eL").split("\n")[1:]
                   if l.split() and l.split()[0] == _pid}
        check("-eLf names the same tids as -eL", _tids_lf, _tids_L,
              "pid %s" % _pid)
        check("...one row per thread", len(_lf), len(_tids_L))
        check("...and NLWP is that count, on every row", _nlwp,
              {str(len(_tids_L))})
        check("...matching /proc/<pid>/status",
              _o("grep ^Threads: /proc/%s/status" % _pid).split()[-1],
              str(len(_tids_L)))
        check("...and /proc/<pid>/task",
              len(_o("ls /proc/%s/task" % _pid).split()), len(_tids_L))

    # A format name is not an option. `flags` joins every argv token with
    # its dashes stripped -- arguments included -- so `ps -p N -o etime=`
    # reads as "pNoetime=", and keying -m off that turned every format
    # carrying an m into a thread listing: etime, comm, %mem. Caught by
    # procstarttest, which compares 493 processes' ages and found 206 of
    # them answering with the wrong shape entirely. The L/T/H tests get
    # away with `flags` only because they are uppercase.
    for _spec, _want_digits in (("etime", False), ("comm", False),
                                ("%mem", False), ("times", False)):
        _v = _o("ps -p 884 -o %s=" % _spec).strip()
        check("-o %s is a column, not the -m format" % _spec,
              "\n" in _v or _v.startswith("-"), False,
              "got %r -- a '-' row or several lines means -m fired" % _v[:40])

    print("%d/%d assertions pass" % (sum(CHECKS), len(CHECKS)))
    for f in FAILS:
        print(f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
