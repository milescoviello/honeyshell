#!/usr/bin/env python3
"""journald and rsyslog are two stores, not one.

The reason anyone checks `journalctl` after `> /var/log/syslog` is that
truncating rsyslog's copy does not touch journald's. That check is the
whole point of the journal to someone clearing their tracks, and this box
answered it backwards in both directions at once:

    > /var/log/syslog             journalctl lost 178 lines
    rm -rf /var/log/journal/*     journalctl lost nothing

The second half got sharper in the sweep before this one. Once
`--disk-usage` was summed from the files that are actually there, the box
would say the journal took **0B** on disk and then print three thousand
lines out of it.

journald's store is snapshotted at session start now -- before anyone can
truncate rsyslog's copy -- and it is append-only rather than frozen, because
freezing it outright broke the other direction: a kernel message emitted
during the session reaches dmesg, kern.log and syslog, and has to reach the
journal too. On a real box the event goes into journald *first* and rsyslog
copies it out. So anything newer than the snapshot is a new event and
belongs in the store; anything missing from the files is a truncation and
does not.

And when the files the journal claims to come from are gone, it says
`-- No entries --`, which is what `journalctl` prints on a box with an empty
store.

Usage:  python3 journalsplittest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh():
    return fakeshell.Shell(fakeshell.VFS(), peer="203.0.113.9",
                           peer_port=44321)


def jlines(s, args="--no-pager"):
    out = s.run("journalctl %s" % args)
    if "No entries" in out:
        return 0
    return len([l for l in out.splitlines() if l.strip()])


def main():
    # -- the baseline the rest depends on -----------------------------------
    s = sh()
    base = jlines(s)
    check("the journal has entries to begin with", base > 500, True)
    check("syslog does too",
          int(s.run("wc -l < /var/log/syslog").strip() or 0) > 20, True)

    # -- truncating rsyslog's copy leaves journald alone ---------------------
    s.run("> /var/log/syslog")
    check("syslog is empty afterwards",
          s.run("wc -l < /var/log/syslog").strip(), "0")
    check("the journal is untouched", jlines(s), base)
    check("...including the unit views", jlines(s, "-u cron --no-pager") > 0,
          True)

    # The other text logs are copies too.
    s = sh()
    base = jlines(s)
    s.run("> /var/log/auth.log; > /var/log/kern.log")
    check("truncating auth.log and kern.log changes nothing either",
          jlines(s), base)

    # rm is not truncation, and neither is shredding the rotated copies.
    s = sh()
    base = jlines(s)
    s.run("rm -f /var/log/syslog /var/log/syslog.1 /var/log/auth.log")
    check("deleting the text logs changes nothing", jlines(s), base)

    # -- but deleting journald's own store does -----------------------------
    s = sh()
    check("the store has files", bool(s.run("ls /var/log/journal/*/").split()),
          True)
    s.run("rm -rf /var/log/journal/*")
    check("journalctl says there are no entries",
          "No entries" in s.run("journalctl --no-pager"), True)
    check("...and --disk-usage agrees there is nothing there",
          "0B" in s.run("journalctl --disk-usage"), True)
    check("...while syslog is still on disk, untouched",
          int(s.run("wc -l < /var/log/syslog").strip() or 0) > 20, True)

    # -- a new event still reaches the journal ------------------------------
    # Freezing the store outright breaks this: the message goes into
    # journald first on a real box, and rsyslog copies it out.
    s = sh()
    s.run("rmmod evdev")
    check("dmesg has the new kernel message",
          "evdev" in s.run("dmesg | tail -1"), True)
    check("kern.log has it", "evdev" in s.run("tail -1 /var/log/kern.log"),
          True)
    check("syslog has it",
          s.run("grep -c evdev /var/log/syslog").strip(), "1")
    check("and so does the journal",
          "evdev" in s.run("journalctl -k --no-pager | tail -1"), True)

    # ...even after the text copy has been wiped, which is the case that
    # matters: the event is in journald whether or not rsyslog kept it.
    s = sh()
    s.run("rmmod evdev")
    s.run("> /var/log/syslog; > /var/log/kern.log")
    check("the journal keeps an event whose text copy was destroyed",
          "evdev" in s.run("journalctl -k --no-pager | tail -1"), True)

    # -- an event in the same second as the login still lands ---------------
    # Merging by "newer than the newest entry" silently dropped anything
    # that happened in the same second as the session's own login line,
    # which is most of what a session does in its first moments.
    s = sh()
    s.run("systemctl restart nginx")
    tail = s.run("journalctl --no-pager | tail -12")
    check("a unit restarted this second reaches the journal",
          "Started nginx.service" in tail, True)
    # Not "the last line": several events land in the same second as the
    # login and their order within it is not something journalctl promises.
    check("...among the newest entries, not buried in history",
          "Started nginx.service" in s.run("journalctl --no-pager | tail -5"),
          True)

    # -- and the two stores do not drift on an untouched box ----------------
    s = sh()
    for unit in ("cron", "nginx", "ssh"):
        j = jlines(s, "-u %s --no-pager" % unit)
        check("journalctl -u %s has entries" % unit, j > 0, True)
    check("the journal is a superset of syslog",
          jlines(s) > int(s.run("wc -l < /var/log/syslog").strip() or 0), True)

    # Reading it twice gives the same thing; a store that changes when you
    # look at it is the one thing a log never does.
    a = s.run("journalctl --no-pager | wc -l").strip()
    b = s.run("journalctl --no-pager | wc -l").strip()
    check("reading the journal twice gives the same count", a, b)

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("journalsplittest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
