#!/usr/bin/env python3
"""A message goes where the box's own rsyslog config says it goes.

/etc/rsyslog.conf is on this box and readable, and it says:

    auth,authpriv.*                 /var/log/auth.log
    *.*;auth,authpriv.none          -/var/log/syslog
    kern.*                          -/var/log/kern.log

Every message went to /var/log/syslog whatever its facility. So one
command contradicted the file next to it in three ways at once:

    $ logger -p auth.info 'probe line'
    $ grep -c 'probe line' /var/log/auth.log /var/log/syslog
    /var/log/auth.log:0
    /var/log/syslog:1

auth in the file the config excludes it from by name, absent from the one
the config sends it to, and kern messages never reaching kern.log at all.
`logger` is what somebody runs to check logging works before they wipe it,
and auth.log is the file they read to find their own login.

Measured against a real rsyslog 8.2504 in a debian:trixie container,
since the reference guest runs journald only and has no rsyslog at all:

    auth.info, authpriv.notice        -> auth.log, and NOT syslog
    cron, daemon, kern, local0, user  -> syslog
    user.debug                        -> syslog (`*.*` means all
                                         priorities, debug included)
    mail.err                          -> syslog AND mail.log

That last one is the shape worth keeping: a message can match more than
one rule and be written to both files. Here the same is true of kern,
which matches `*.*` and `kern.*`.

Routing is read out of the config rather than restated here, so a rule
appended to /etc/rsyslog.conf changes where messages go -- which is the
only reason that file is on the box.

Usage:  python3 syslogtest.py
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


def shell():
    fs = fakeshell.VFS()
    return fakeshell.Shell(vfs=fs, peer="198.51.100.23", peer_port=40888)


def out(sh, cmd):
    try:
        return sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def where(sh, mark):
    """Which log files contain this marker."""
    hits = []
    for name in ("syslog", "auth.log", "kern.log", "messages"):
        path = "/var/log/" + name
        if out(sh, "test -e %s && echo y" % path).strip() != "y":
            continue
        if out(sh, "grep -c %s %s 2>/dev/null" % (mark, path)).strip() \
                not in ("0", ""):
            hits.append(name)
    return sorted(hits)


S = shell()

# ------------------------------------------------- the config is on the box
conf = out(S, "cat /etc/rsyslog.conf")
check("the config names auth.log",
      "auth,authpriv.*" in conf and "/var/log/auth.log" in conf, True)
check("...and excludes auth from syslog",
      "auth,authpriv.none" in conf, True,
      "this is the clause the routing was ignoring")
check("...and sends kern to kern.log", "kern.*" in conf, True)

# --------------------------------------------------------------- routing
out(S, "logger -p auth.info MARKauth")
check("auth goes to auth.log", where(S, "MARKauth"), ["auth.log"],
      "it went to syslog, which the config excludes it from by name")

out(S, "logger -p authpriv.notice MARKpriv")
check("authpriv goes with it", where(S, "MARKpriv"), ["auth.log"])

out(S, "logger -p kern.info MARKkern")
check("kern goes to both", where(S, "MARKkern"), ["kern.log", "syslog"],
      "it matches *.* and kern.*, and a message written by two rules "
      "lands in two files -- measured with a real rsyslog, where a "
      "mail.err appears in syslog and mail.log")

for fac in ("cron", "daemon", "local0", "user", "mail", "lpr", "news"):
    out(S, "logger -p %s.info MARK%s" % (fac, fac))
    check("%s goes to syslog" % fac, where(S, "MARK" + fac), ["syslog"])

out(S, "logger -p user.debug MARKdebug")
check("debug is not filtered out", where(S, "MARKdebug"), ["syslog"],
      "`*.*` means every priority, and debug is the one that gets "
      "dropped by a rule written as *.info")

out(S, "logger MARKdefault")
check("no -p means user.notice", where(S, "MARKdefault"), ["syslog"])

# ------------------------------------------------------- and the journal
check("journald gets it too",
      out(S, "journalctl --no-pager 2>/dev/null | grep -c MARKauth").strip(),
      "1",
      "rsyslog and journald both read /dev/log; a line in one and not the "
      "other is one of them not listening")

# -------------------------------------------------- the config decides it
E = shell()
out(E, "touch /var/log/errs.log")
out(E, "printf 'user.err\\t\\t/var/log/errs.log\\n' >> /etc/rsyslog.conf")
out(E, "logger -p user.err MARKerr")
out(E, "logger -p user.info MARKinfo")
check("a rule appended to the config takes effect",
      out(E, "grep -c MARKerr /var/log/errs.log").strip(), "1",
      "the routing is read from the file, not written down in the "
      "emulator -- that is the whole reason the file is there")
check("...and its severity threshold is honoured",
      out(E, "grep -c MARKinfo /var/log/errs.log").strip(), "0",
      "`user.err` means err and anything more severe, and info is less")
check("...while the old rules still apply",
      "syslog" in where(E, "MARKerr"), True)

W = shell()
out(W, "printf 'user.warning\\t\\t/var/log/warn.log\\n' >> /etc/rsyslog.conf")
out(W, "touch /var/log/warn.log")
for sev, want in (("emerg", "1"), ("crit", "1"), ("warning", "1"),
                  ("notice", "0"), ("debug", "0")):
    out(W, "logger -p user.%s SEV%s" % (sev, sev))
    check("user.warning catches %s" % sev,
          out(W, "grep -c SEV%s /var/log/warn.log" % sev).strip(), want,
          "a bare priority is a floor: that severity and everything worse")

# ------------------------------------------------------------ the wording
L = shell()
out(L, "logger -t mytag MARKtag")
line = [l for l in out(L, "cat /var/log/syslog").splitlines()
        if "MARKtag" in l]
check("the line carries the tag", bool(line) and " mytag: " in line[0],
      True, line[0] if line else "<no line>")
check("...and the hostname",
      bool(line) and out(L, "hostname").strip() in line[0], True)
check("-s also writes the file, not only stderr",
      out(L, "logger -s -t t2 MARKboth 2>/dev/null; "
             "grep -c MARKboth /var/log/syslog").strip(), "1")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
