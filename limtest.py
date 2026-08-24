#!/usr/bin/env python3
"""Do the four things that report resource limits report the same limits?

A process has one set of rlimits. The box offers four views of them and
every pair disagreed:

  - `ulimit -a` printed 8 rows. bash prints 17. The nine it left out --
    scheduling priority, pending signals, max memory size, pipe size,
    POSIX message queues, real-time priority, cpu time, virtual memory,
    file locks -- were not absent from the kernel's view: /proc/self/limits
    had real numbers for them the whole time.
  - Asking for one by flag went through a catch-all that returned
    "unlimited", so `ulimit -l` said unlimited for the same limit
    `ulimit -a` printed as 8192.
  - `prlimit` listed two resources out of sixteen, and its numbers agreed
    with nothing: NPROC 7772 where every other view said 7628, NOFILE hard
    524288 where /proc said 1048576.
  - Bare `ulimit` dumped the whole table; in bash it is `ulimit -f` and
    prints one word.

All four now render from one table, so a limit cannot be a matter of
opinion. Values are the persona's; the *formats* are checked against real
bash on this host and against util-linux's prlimit on trixie.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                        # noqa: E402

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
        print("  FAIL %-54s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# bash's own row set, in bash's own order.
BASH_FLAGS = "Rcdefilmnpqrstuvx"


def ulimit_a(s, hard=False):
    """{flag: printed value} from ulimit -a."""
    out, _ = run(s, "ulimit %s-a" % ("-H " if hard else ""))
    got = {}
    for line in out.strip().splitlines():
        m = re.search(r"\(-?([A-Za-z0-9 ,]*?)-([A-Za-z])\)\s+(\S+)$", line)
        if m:
            got[m.group(2)] = m.group(3)
    return got


def proc_limits(s):
    """{proc label: (soft, hard)} from /proc/self/limits."""
    out, _ = run(s, "cat /proc/self/limits")
    rows = {}
    for line in out.splitlines()[1:]:
        if not line.strip():
            continue
        m = re.match(r"^(.{0,25}?)\s{2,}(\S+)\s+(\S+)", line)
        if m:
            rows[m.group(1).strip()] = (m.group(2), m.group(3))
    return rows


def prlimit_rows(s):
    out, _ = run(s, "prlimit")
    rows = {}
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3:
            rows[parts[0]] = (parts[-3], parts[-2]) if len(parts) > 3 \
                else (parts[1], parts[2])
    # Re-parse properly on the fixed columns rather than by splitting, since
    # the descriptions contain spaces and the units column can be empty.
    rows = {}
    for line in out.splitlines()[1:]:
        if len(line) < 65:
            continue
        rows[line[:10].strip()] = (line[46:55].strip(), line[56:65].strip())
    return rows


def t_ulimit_a_has_bashs_row_set():
    """It printed 8 of 17, and the missing ones were not unlimited."""
    got = ulimit_a(sh())
    eq("ulimit -a covers every bash flag", "".join(sorted(got)),
       "".join(sorted(BASH_FLAGS)))
    eq("and prints 17 rows", len(got), 17)


def t_ulimit_a_matches_real_bash_formatting():
    """Labels, units and padding are bash's, so only the values differ."""
    try:
        real = subprocess.run(["bash", "-c", "ulimit -a"],
                              capture_output=True, text=True,
                              timeout=15).stdout
    except (OSError, subprocess.TimeoutExpired):        # pragma: no cover
        return
    ours, _ = run(sh(), "ulimit -a")

    def shape(t):
        return [l.rsplit(" ", 1)[0] for l in t.strip().splitlines()]
    rs, os_ = shape(real), shape(ours)
    eq("same number of rows as real bash", len(os_), len(rs))
    for a, b in zip(rs, os_):
        eq("row layout %r" % a[:28].strip(), b, a)


def t_every_flag_agrees_with_the_table():
    """`ulimit -l` went through a catch-all default and said unlimited for
    a limit `ulimit -a` printed as 8192."""
    s = sh()
    got = ulimit_a(s)
    for flag, shown in sorted(got.items()):
        direct, rc = run(s, "ulimit -%s" % flag)
        eq("ulimit -%s rc" % flag, rc, 0)
        eq("ulimit -%s agrees with -a" % flag, direct.strip(), shown)


def t_soft_and_hard_are_distinct_where_they_should_be():
    s = sh()
    eq("-S -n is the soft limit", run(s, "ulimit -S -n")[0].strip(), "1024")
    eq("-H -n is the hard limit", run(s, "ulimit -H -n")[0].strip(),
       "1048576")
    eq("-n defaults to soft", run(s, "ulimit -n")[0].strip(), "1024")
    eq("-H -s is unlimited", run(s, "ulimit -H -s")[0].strip(), "unlimited")
    eq("-s soft is 8192", run(s, "ulimit -s")[0].strip(), "8192")


def t_bare_ulimit_is_the_file_size_limit():
    """bash prints one word; this dumped the whole table."""
    s = sh()
    bare, rc = run(s, "ulimit")
    eq("bare ulimit rc", rc, 0)
    eq("bare ulimit is one line", len(bare.strip().splitlines()), 1)
    eq("and equals ulimit -f", bare.strip(), run(s, "ulimit -f")[0].strip())


def t_proc_agrees_with_ulimit():
    """The kernel's view and the shell's view of one process, in the units
    each of them uses."""
    s = sh()
    shown = ulimit_a(s)
    hard = ulimit_a(s, hard=True)
    rows = proc_limits(s)
    for (plabel, _pn, _pd, _pu, _pru, flag, _bd, _bu, div,
         soft, hardv) in fs.RLIMITS:
        check("/proc lists %r" % plabel, plabel in rows, sorted(rows)[:4])
        if plabel not in rows:
            continue
        psoft, phard = rows[plabel]
        eq("%s soft: proc vs ulimit -%s" % (plabel, flag), psoft,
           "unlimited" if soft is None else str(soft))
        eq("%s hard: proc vs ulimit -H -%s" % (plabel, flag), phard,
           "unlimited" if hardv is None else str(hardv))
        want_soft = "unlimited" if soft is None else str(soft // div)
        eq("%s: ulimit -%s in its own units" % (plabel, flag),
           shown[flag], want_soft)
        want_hard = "unlimited" if hardv is None else str(hardv // div)
        eq("%s: ulimit -H -%s in its own units" % (plabel, flag),
           hard[flag], want_hard)


def t_prlimit_agrees_with_proc():
    """prlimit had NPROC 7772 and NOFILE hard 524288 -- numbers no other
    view of the same process produced."""
    s = sh()
    rows = prlimit_rows(s)
    eq("prlimit lists all sixteen", len(rows), 16)
    for (_pl, pn, _pd, _pu, _pru, _f, _bd, _bu, _dv,
         soft, hardv) in fs.RLIMITS:
        check("prlimit lists %s" % pn, pn in rows, sorted(rows))
        if pn not in rows:
            continue
        eq("prlimit %s soft" % pn, rows[pn][0],
           "unlimited" if soft is None else str(soft))
        eq("prlimit %s hard" % pn, rows[pn][1],
           "unlimited" if hardv is None else str(hardv))


def t_prlimit_is_alphabetical_like_util_linux():
    out, rc = run(sh(), "prlimit")
    eq("prlimit rc", rc, 0)
    names = [l[:10].strip() for l in out.splitlines()[1:] if l.strip()]
    eq("sorted by resource name", names, sorted(names))
    check("header is util-linux's",
          out.splitlines()[0].startswith("RESOURCE   DESCRIPTION"),
          out.splitlines()[0][:40])


def t_the_numbers_that_disagreed():
    """Named explicitly so a regression is legible."""
    s = sh()
    eq("locked memory is 8192 kbytes to bash",
       run(s, "ulimit -l")[0].strip(), "8192")
    eq("and 8388608 bytes to the kernel",
       proc_limits(s)["Max locked memory"], ("8388608", "8388608"))
    eq("nproc is 7628 to bash", run(s, "ulimit -u")[0].strip(), "7628")
    eq("nproc is 7628 to prlimit", prlimit_rows(s)["NPROC"],
       ("7628", "7628"))
    eq("nofile hard is 1048576 to prlimit", prlimit_rows(s)["NOFILE"][1],
       "1048576")
    eq("and to bash", run(s, "ulimit -H -n")[0].strip(), "1048576")
    eq("pending signals is not unlimited",
       run(s, "ulimit -i")[0].strip(), "7628")
    eq("msgqueue is not unlimited", run(s, "ulimit -q")[0].strip(),
       "819200")
    eq("pipe size is bash's constant", run(s, "ulimit -p")[0].strip(), "8")


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:6]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
