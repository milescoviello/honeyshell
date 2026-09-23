"""What ps prints at the top of a column, and where it draws the tree.

Four findings, all from one question: does the narrowed form of a command
agree with the broad one? `ps -eL` unfiltered was right while `ps -eL -p N`
was wrong; `ps -e --forest` drew a tree while `ps -e --forest -o ...` did
not; `ps aux` titled a column %CPU while `ps -o pcpu` titled it PCPU. The
broad form is the one a suite reaches for and the narrow one is what an
attacker actually types, so checking only the broad form passes forever.

Every expected value here was measured against procps on a real Debian
box, field by field, rather than derived from the field name.

Usage:  python3 pscolumntest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


sh = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                     peer_port=40333)
sh.run("true")


def out(c):
    o = sh.run(c)
    return ((o[0] if isinstance(o, tuple) else o) or "")


# ------------------------------------------------- the column titles
# procps does not title a column by upper-casing the field name, and for
# twenty fields the two differ. `ps aux` prints %CPU from its own format
# table while `ps -o pcpu` printed PCPU, which is one box with two names
# for one column.
HEADERS = {
    "pid": "PID", "ppid": "PPID", "pgid": "PGID", "sid": "SID",
    "lwp": "LWP", "nlwp": "NLWP", "thcount": "THCNT",
    "user": "USER", "ruser": "RUSER", "group": "GROUP",
    "uid": "UID", "gid": "GID",
    "comm": "COMMAND", "args": "COMMAND", "cmd": "CMD", "ucmd": "CMD",
    "pcpu": "%CPU", "pmem": "%MEM",
    "rss": "RSS", "vsz": "VSZ", "sz": "SZ", "size": "SIZE",
    "stat": "STAT", "state": "S", "s": "S",
    "pri": "PRI", "ni": "NI", "nice": "NI",
    "etime": "ELAPSED", "etimes": "ELAPSED",
    "time": "TIME", "cputime": "TIME", "bsdtime": "TIME",
    "start": "STARTED", "lstart": "STARTED", "start_time": "START",
    "tty": "TT", "tt": "TT",
    "psr": "PSR", "wchan": "WCHAN", "flags": "F",
    "policy": "POL", "cls": "CLS",
}
for _f, _want in sorted(HEADERS.items()):
    _got = (out("ps -o %s -p 1" % _f).splitlines() or [""])[0].strip()
    check("ps -o %s is titled %s" % (_f, _want), _got, _want)

check("a trailing = still suppresses the header entirely",
      out("ps -o pcpu= -p 1").splitlines()[0].strip().replace(".", "").isdigit(),
      True, "`ps -o x=` is how a script gets a bare value")

# ------------------------------------------ USER truncation by position
# procps pads every column but the last to its declared width, and USER's
# is eight -- so a longer name is cut to seven and marked '+' only when
# something follows it. Measured on a real box, one process whose user is
# twenty characters:
#     ps -o user,pid   gnome-r+
#     ps -o pid,user   gnome-remote-desktop
#     ps -o user       gnome-remote-desktop
_long = None
for _line in out("ps -eo pid,user --no-headers").splitlines():
    _f = _line.split()
    if len(_f) > 1 and len(_f[1]) > 8:
        _long = _f
        break
check("the persona has a username longer than eight", bool(_long), True,
      "without one this suite proves nothing about truncation")
if _long:
    _pid, _name = _long[0], _long[1]
    check("USER is cut when a column follows it",
          out("ps -o user,pid -p %s" % _pid).splitlines()[-1].split()[0],
          _name[:7] + "+")
    check("USER is whole when it is the last column",
          out("ps -o pid,user -p %s" % _pid).splitlines()[-1].split()[-1],
          _name)
    check("USER is whole when it is the only column",
          out("ps -o user= -p %s" % _pid).strip(), _name,
          "asking for the column on its own is how you get a name that "
          "can be looked up in passwd")

# ----------------------------------------------- the tree under -o
# The forest was drawn in the no-columns branch and not in the -o branch,
# so the same request answered differently depending on whether columns
# were named. procps hangs the connector off the command column and draws
# nothing when no command column was asked for.
_f_comm = out("ps -eo pid,ppid,comm --forest")
check("--forest draws the tree when columns are named",
      "\\_" in _f_comm, True,
      "`ps -e --forest` drew it and `ps -e --forest -o ...` did not")
check("the connector sits on the command column",
      any(l.split()[2:3] == ["\\_"] for l in _f_comm.splitlines()[1:]), True)
check("--forest draws nothing when no command column is asked for",
      "\\_" in out("ps -eo pid,ppid --forest"), False)
check("the connector follows comm when comm is not last",
      "\\_" in out("ps -eo pid,comm,ppid --forest"), True)
check("and the no-columns form still draws it",
      "\\_" in out("ps -e --forest"), True,
      "the branch that already worked must not have been broken")

# -------------------------------------- one number, two files, one answer
# /proc/loadavg's fifth field and /proc/sys/kernel/ns_last_pid are the
# same quantity. On a real box they track within a couple of allocations
# (measured 3917092 against 3917094); here one was a literal 284746 while
# the other derived 21438, and 284746 is above every pid on the box.
_la = out("cut -d' ' -f5 /proc/loadavg").strip()
_ns = out("cat /proc/sys/kernel/ns_last_pid").strip()
check("loadavg and ns_last_pid report the same last pid", _ns, _la)
_max = max(int(x) for x in out("ls /proc").split() if x.isdigit())
check("and it is not below a pid that exists", int(_ns) >= _max, True,
      "the last pid allocated cannot precede a running process")
check("nor absurdly above the table", int(_ns) - _max < 10000, True,
      "284746 against a highest pid of 21435 was the tell")

for f in FAILS:
    print(" ", f)
print("   pscolumn: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
