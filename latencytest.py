#!/usr/bin/env python3
"""How long does this box take to answer? A stopwatch is a fingerprint too.

Every fidelity sweep so far has asked what the box *says*. This one asks how
long it takes to say it, which needs no filesystem knowledge at all.

Measured before the fix: `true` took **67.8 ms**. So did everything else --
`id` 72.4, `echo hi` 68.5, `cat /etc/hostname` 66.2 -- a fixed floor that
had nothing to do with the command. A real Debian box runs

    for i in $(seq 100); do true; done

in a few milliseconds. This one took **seven seconds**, and an attacker
holding a stopwatch does not have to know why.

## Where it went

`_cron_snapshot` builds the persistence picture that `cron_install` and
`persistence_write` alerts are derived from, and it runs *before and after*
every command line. It called `listdir()` once per persistence directory,
and `listdir()` walks the entire node table:

    12 directories x 49,470 nodes x 2 snapshots = 1.19 million
    startswith calls to answer `true`

which the profiler confirmed exactly: 12,386,525 startswith over 10
commands.

Two changes, neither of which touches what is detected:

  * `listdir_many()` answers for all twelve directories in one pass
    instead of one pass each -- 24 walks per command became 2.
  * that pass rejects whole subtrees on their second character.
    39,000 of the 49,470 nodes are /proc/<pid>/* -- one set per process
    for 488 processes -- and none of them can be a persistence directory.
    `str.startswith` takes a tuple and does it in C.

`true` went 67.8 ms -> 7.7 ms, and the hundred-command loop 7 s -> 0.83 s.

## What this suite actually pins

Wall-clock in a test is a machine-dependent number, so the assertion here is
on the **work**, not the time: how many times a single command walks the
node table. That is deterministic, and it is the thing that regressed. A
generous wall-clock ceiling is checked as well, but only to catch an order
of magnitude, and it is measured against a baseline taken in the same
process on the same machine.

The detection itself is pinned too, because a faster snapshot that misses a
write would be the worst possible outcome -- including the case that
motivates it: a rename *inside* a persistence directory, which leaves the
file count unchanged and so defeats any cache keyed on counting.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want,
                        ("\n  -- " + str(note)) if note else ""))


def shell():
    return fakeshell.Shell(vfs=fakeshell.VFS(), peer="198.51.100.13",
                           peer_port=40333)


def main():
    sh = shell()
    sh.run("true")                       # warm every lazy path

    # -- the work, which is deterministic --------------------------------
    walks = {"n": 0}
    real_paths = type(sh.fs).node_paths

    def counting(self):
        walks["n"] += 1
        return real_paths(self)

    type(sh.fs).node_paths = counting
    try:
        walks["n"] = 0
        sh.run("true")
        per_true = walks["n"]
        walks["n"] = 0
        sh.run("echo hi > /tmp/lat")
        per_write = walks["n"]
    finally:
        type(sh.fs).node_paths = real_paths

    check("`true` does not walk the node table more than a handful of times",
          per_true <= 6, True,
          "%d walks; it was 24 before listdir_many, and each walk is "
          "%d nodes" % (per_true, len(sh.fs.nodes)))
    check("nor does a write", per_write <= 12, True, per_write)

    # -- one pass for many directories, not one each ---------------------
    check("the VFS can list several directories in one pass",
          callable(getattr(sh.fs, "listdir_many", None)), True)
    dirs = [d for d, _e, _k in fakeshell.Shell._PERSIST_DIRS]
    walks["n"] = 0
    type(sh.fs).node_paths = counting
    try:
        many = sh.fs.listdir_many(dirs)
    finally:
        type(sh.fs).node_paths = real_paths
    check("listing %d directories costs one walk" % len(dirs), walks["n"], 1)
    for d in dirs:
        check("listdir_many agrees with listdir for %s" % d,
              many.get(d.rstrip("/"), []), sh.fs.listdir(d) or [])

    # -- the ceiling, generously, against a same-process baseline --------
    def timed(cmd, n):
        t0 = time.time()
        for _ in range(n):
            sh.run(cmd)
        return (time.time() - t0) / n

    t_true = timed("true", 25)
    check("`true` answers in well under the 67.8 ms it used to take",
          t_true < 0.030, True, "%.1f ms" % (t_true * 1000))
    t_cat = timed("cat /etc/hostname", 15)
    check("...and reading a file is not an order of magnitude worse",
          t_cat < t_true * 4 + 0.020, True,
          "true %.1f ms, cat %.1f ms" % (t_true * 1000, t_cat * 1000))

    # -- and it still sees everything ------------------------------------
    sh2 = shell()
    seen = []
    orig = sh2.log

    def cap(**kw):
        seen.append(kw)
        return orig(**kw)

    sh2.log = cap
    for label, cmd, want in (
            ("a file dropped into /etc/cron.d",
             "echo '* * * * * root /tmp/.x' > /etc/cron.d/zz", "cron_install"),
            ("the root crontab written directly",
             "mkdir -p /var/spool/cron/crontabs; "
             "echo '@reboot /tmp/.y' > /var/spool/cron/crontabs/root",
             "cron_install"),
            ("a rename inside cron.d, which keeps the file count",
             "mv /etc/cron.d/zz /etc/cron.d/yy", "cron_install"),
            ("a systemd unit dropped in",
             "printf '[Service]\\nExecStart=/tmp/.z\\n' "
             "> /etc/systemd/system/evil.service", "persistence_write"),
            ("a cron file removed",
             "rm -f /etc/cron.d/yy", "cron_removed"),
    ):
        n = len(seen)
        sh2.run(cmd)
        events = {str(e.get("event")) for e in seen[n:]}
        check("still detected: %s" % label, want in events, True, sorted(events))

    # -- `time` is a keyword, and it has to actually time something ------
    # It was not implemented at all: `time sleep 0.5` answered
    #     bash: time: command not found
    # which bash never says about a keyword -- and the sleep never ran, so
    # the shell returned in 10 ms. Anyone benchmarking the box gets a
    # different answer from `time` than from their own stopwatch, and
    # benchmarking is the first thing someone deploying a miner does.
    sh3 = shell()
    sh3.run("true")
    sh3._err = []
    t0 = time.time()
    sh3.run("time sleep 0.25")
    wall = time.time() - t0
    err = "".join(sh3._err)
    check("`time sleep 0.25` actually sleeps", 0.2 < wall < 0.6, True,
          "%.3f s" % wall)
    check("...and says nothing on stdout", "real" in err, True, err[:60])
    check("...in bash's shape: leading newline, tabs, 0m0.000s",
          bool(re.match(r"\nreal\t\dm\d+\.\d{3}s\nuser\t\dm\d+\.\d{3}s\n"
                        r"sys\t\dm\d+\.\d{3}s\n$", err)), True, repr(err))
    m = re.search(r"real\t\dm([\d.]+)s", err)
    check("...and the real it reports is the time it took",
          bool(m) and abs(float(m.group(1)) - wall) < 0.15, True,
          "reported %s, wall %.3f" % (m.group(1) if m else "?", wall))
    m2 = re.search(r"user\t\dm([\d.]+)s", err)
    check("sleeping burns no user CPU, as on a real box",
          bool(m2) and float(m2.group(1)) < 0.05, True,
          "user %s for a sleep" % (m2.group(1) if m2 else "?"))

    sh3._err = []
    sh3.run("time -p sleep 0.1")
    errp = "".join(sh3._err)
    check("`time -p` uses the POSIX form",
          bool(re.match(r"real \d+\.\d{2}\nuser \d+\.\d{2}\n"
                        r"sys \d+\.\d{2}\n$", errp)), True, repr(errp))

    for cmd, want_rc in (("time false", 1), ("time ls /nonexistent", 2)):
        sh3._err = []
        sh3.run(cmd)
        check("%s passes the command's rc through" % cmd,
              getattr(sh3, "last_rc", None), want_rc)
    sh3._err = []
    out = sh3.run("time echo hi") or ""
    check("`time echo hi` still prints hi on stdout", out.strip(), "hi")

    # -- dd takes about as long as it says it took -----------------------
    # It reported "200 MiB copied, 0.0446203 s, 4.7 GB/s" and returned in
    # 10 ms, so dd's own answer and `time dd` disagreed by a factor of
    # four, and a stopwatch made the box a 21 GB/s device.
    sh3._err = []
    t0 = time.time()
    sh3.run("dd if=/dev/zero of=/root/ddprobe bs=1M count=200")
    wall = time.time() - t0
    err = "".join(sh3._err)
    sh3.run("rm -f /root/ddprobe")
    m = re.search(r"copied, ([\d.]+) s,", err)
    check("dd reports how long it took", bool(m), True, err[-70:])
    if m:
        check("...and takes about that long",
              abs(wall - float(m.group(1))) < 0.15, True,
              "dd said %s s, wall %.3f s" % (m.group(1), wall))

    print("%d/%d assertions pass" % (sum(CHECKS), len(CHECKS)))
    for f in FAILS:
        print(f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
