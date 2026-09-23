#!/usr/bin/env python3
"""ps has two personalities, and this box had implemented one of them.

procps' ps answers to two option languages at once. `ps -e` is the Unix
one; `ps ax` is the BSD one, and the difference is not cosmetic -- the two
select different processes and print different columns. Measured on the
guest, one process under both spellings:

    ps -e     1 ?        00:01:23 systemd
    ps ax     1 ?        Ss     0:41 /sbin/init

Three columns differ in that one line. STAT exists in BSD and not in Unix,
TIME is M:SS against HH:MM:SS, and the last column is comm against argv.
This box printed the Unix row for both, so every BSD invocation produced a
table procps does not print.

## What that cost, in the order anyone would hit it

`ps aux` is the single most-typed spelling of this command, and its TIME
column was wrong on every row -- HH:MM:SS where the guest prints M:SS.

`ps -e` printed /sbin/init for pid 1. `ps -o comm`, pgrep and /proc/1/comm
all said systemd. Four readers of one process's name and only the default
table disagreed, which is the cheapest possible way to catch this box:
run ps twice.

Selection was wrong in both directions at once. BSD `a` drops the "only my
processes" restriction and keeps the "must have a terminal" one; `x` is
the mirror image. Both were folded into "show everything":

                guest   here (before)
    ps a          6         493
    ps x         12         493

## The one that reads as a broken command

An exec channel has no controlling terminal, and the BSD default selects
the current terminal's processes -- so on the guest `ps u` over ssh prints
its header, no rows, and exits 1. `ps h` is that same empty selection with
the header suppressed, which is why it looks like a command that failed
silently. It is not a failure and it is not about -h: with `x` or `-A` in
front of it the same command works.

    ps h        rc 1, nothing        ps xh    rc 0, 12 rows
    ps ho pid   rc 1, nothing        ps axh   rc 0, 109 rows

That rc 1 was the finding this suite started from, recorded as "ps -h
prints nothing and exits 1" -- which named the wrong option as the cause.

## Parsing

`o` inside a BSD bundle takes the format as its argument, glued on or as
the next word. Unconsumed, that next word was rescanned as another bundle:
`ps ho user` read "user" as the BSD options u, s, e and r and answered in
the user format, having also filtered to running processes and turned on
the environment dump.

Every expectation below was measured on the Debian 13 guest running
procps-ng 4.0.4, over both an exec channel and a pty.

Usage:  python3 psbsdtest.py
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


def _shell(pty):
    s = fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.12",
                        peer_port=45120)
    s.exec_mode = True
    # The channel has to be declared, not assumed: has_pty alone is not
    # what tty(1) and ps read -- set_channel_pty is what moves tty_name,
    # and a shell that never declares its channel keeps the default pts.
    s.set_channel_pty(pty, "xterm" if pty else None,
                      (200, 50) if pty else None)
    return s


TTY, NOTTY = _shell(True), _shell(False)


def r(cmd, sh=None):
    try:
        return (sh or TTY).run(cmd + " 2>&1")
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def rc_of(cmd, sh=None):
    return ((sh or TTY).run(cmd + " >/dev/null 2>&1; echo $?") or "").strip()


def rows(cmd, sh=None):
    return [l for l in r(cmd, sh).split("\n") if l.strip()]


def pid1(cmd, sh=None, col=0):
    """pid 1's row. `col` because the aux and -ef formats lead with a user
    name, so the pid is not always the first field."""
    for line in rows(cmd, sh):
        f = line.split()
        if len(f) > col and f[col] == "1":
            return line
    return "<no pid 1 row>"


# ---------------------------------------------------------------- columns
# The Unix default prints comm. This is the check that fails loudest on
# HEAD, because pid 1 is the process everyone looks at first.
check("ps -e prints comm for pid 1", pid1("ps -e").split()[-1], "systemd")
check("ps -p 1 agrees with it", pid1("ps -p 1").split()[-1], "systemd")
check("ps -e --forest agrees", pid1("ps -e --forest").split()[-1], "systemd")
check("ps -eH agrees", pid1("ps -eH").split()[-1], "systemd")
check("ps -eL agrees", pid1("ps -eL").split()[-1], "systemd")
check("...and -o comm has always said so",
      r("ps -p 1 -o comm --no-headers").strip(), "systemd")

# -f is the exception: it prints the command line.
check("ps -ef prints argv for pid 1",
      pid1("ps -ef", col=1).split()[-1], "/sbin/init")
check("BSD ps ax prints argv too", pid1("ps ax").split()[-1], "/sbin/init")

# Kernel threads: bracketed under argv, bare under comm.
def _pid2(cmd):
    for line in rows(cmd):
        if line.split()[:1] == ["2"]:
            return line.split()[-1]
    return "<none>"


check("kthread is bare in the Unix default", _pid2("ps -e"), "kthreadd")
check("...and bracketed in BSD", _pid2("ps ax"), "[kthreadd]")
check("...and bare again under BSD c", _pid2("ps cax"), "kthreadd")

# ------------------------------------------------------------------- STAT
check("BSD default carries a STAT column",
      rows("ps ax")[0], "    PID TTY      STAT   TIME COMMAND")
check("the Unix default does not",
      rows("ps -e")[0], "    PID TTY          TIME CMD")
check("ps h uses the BSD format", len(rows("ps h")[0].split()) >= 5, True,
      "PID TTY STAT TIME COMMAND -- five fields before the argv")

# ------------------------------------------------------------------- TIME
check("BSD TIME is M:SS", pid1("ps ax").split()[3], "0:41")
check("Unix TIME is HH:MM:SS", pid1("ps -e").split()[2], "00:00:41")
check("ps aux uses the BSD form", pid1("ps aux", col=1).split()[9], "0:41",
      "the most-typed spelling of this command")
check("ps -ef keeps the Unix form",
      pid1("ps -ef", col=1).split()[6], "00:00:41")
# Fetched rather than called: on a tree without it this has to read as a
# failed check, not as a suite that crashed.
_bt = getattr(fakeshell.Shell, "_bsd_time", None)
check("_bsd_time carries hours into minutes",
      _bt("02:03:04") if _bt else "<no _bsd_time>", "123:04")
check("...and leaves a malformed value alone",
      _bt("?") if _bt else "<no _bsd_time>", "?")

# --------------------------------------------------------------- selection
# a and x are not the same option and neither means "everything".
n_all = len(rows("ps ax")) - 1
check("ps a keeps only processes with a terminal",
      all(" ? " not in l for l in rows("ps a")[1:]), True)
check("...so it is far short of the whole table",
      len(rows("ps a")) - 1 < n_all, True)
check("ps x keeps only this user's processes",
      {l.split()[0] for l in rows("ps x -o user --no-headers")}, {"root"})
check("ps ax is everything", len(rows("ps ax")) - 1, n_all)
check("ps -e is the same count", len(rows("ps -e")) - 1, n_all)

# BSD r selects running processes only.
check("ps r selects on state",
      all(l.split()[2].startswith("R") for l in rows("ps r")[1:]), True)

# ---------------------------------------------------- the no-terminal case
check("no pty means no tty name", NOTTY.tty_name, None)
check("tty(1) agrees", r("tty", NOTTY), "not a tty\n")
check("ps h there selects nothing", r("ps h", NOTTY), "")
check("...and exits 1", rc_of("ps h", NOTTY), "1")
check("ps u there prints its header and no rows",
      rows("ps u", NOTTY),
      ["USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   "
       "TIME COMMAND"])
check("...and exits 1 as well", rc_of("ps u", NOTTY), "1")
check("ps ho pid is the same empty selection", rc_of("ps ho pid", NOTTY), "1")
# ...and the same command with a selector in front of it works.
check("ps xh works there", len(rows("ps xh", NOTTY)) > 1, True)
check("...rc 0", rc_of("ps xh", NOTTY), "0")
check("ps axh works there", len(rows("ps axh", NOTTY)), n_all,
      "h means no header, so every line is a process")
check("ps -A h works there", len(rows("ps -A h", NOTTY)), n_all)

# The Unix default is not empty there: it still matches on euid, and every
# one of this user's processes reads as "?".
check("the Unix default still lists processes with no terminal",
      len(rows("ps", NOTTY)) > 1, True)
check("...all of them ttyless",
      all(l.split()[1] == "?" for l in rows("ps", NOTTY)[1:]), True)
# With a pty it narrows to that pty.
check("with a pty it narrows to the pty",
      {l.split()[1] for l in rows("ps", TTY)[1:]}, {"pts/0"})

# ----------------------------------------------------------------- parsing
check("ps ho pid prints bare pids",
      rows("ps ho pid")[0].strip().isdigit(), True)
check("...with no header", any(l.strip() == "PID" for l in rows("ps ho pid")),
      False)
check("ps ho user takes 'user' as the format, not as options",
      {l.strip() for l in rows("ps ho user")}, {"root"},
      "u,s,e,r as BSD options would give the user format instead")
check("ps hopid glues its argument on",
      rows("ps hopid")[0].strip().isdigit(), True)
check("-h suppresses the header too",
      any("PID" in l and "TTY" in l for l in rows("ps -h -o pid,comm")), False)
check("...and -h carries the BSD personality like bare h",
      len(rows("ps -h")[0].split()) >= 5, True)
check("--no-headers is not the same option: it keeps the Unix format",
      len(rows("ps --no-headers")[0].split()), 4,
      "PID TTY TIME CMD, no STAT")

# BSD e still means "show the environment", not "every process".
# A dashed -h or -x reparses the whole line as BSD, which changes what
# the options beside it mean.
check("ps -e -h is BSD e: the environment, not every process",
      "HOME=" in r("ps -e -h"), True)
check("...while ps -e h keeps the Unix -e", len(rows("ps -e h")), n_all)
check("ps -x is BSD x", {l.split()[0] for l in
                         rows("ps -x -o user --no-headers")}, {"root"})
check("ps -aux is how most people spell ps aux",
      rows("ps -aux")[0], rows("ps aux")[0])
check("...same rows", len(rows("ps -aux")), len(rows("ps aux")))

check("ps e is the environment, not -e",
      "HOME=" in r("ps e"), True)
check("...and does not widen the selection",
      len(rows("ps e")) - 1 < n_all, True)

for f in FAILS:
    print(" ", f)
print("   ps BSD: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
