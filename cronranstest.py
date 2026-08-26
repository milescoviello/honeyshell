#!/usr/bin/env python3
"""A cron job the attacker installed has to appear in cron's own log.

Installing a crontab is the most common persistence there is, and the check
that follows it is always the same: come back, and

    grep CRON /var/log/syslog

The box showed them the hourly `run-parts --report /etc/cron.hourly` entries
and nothing of theirs, on a box where `crontab -l` and
/var/spool/cron/crontabs/root both said the job was scheduled. Two readers
of "is this job running": the crontab said yes and cron's log had never
heard of it.

Nothing is executed to fix this, and nothing can be. The lines are worked
out from the schedule and the clock -- when cron *would have written a
line* -- which is a different thing from running the payload. The payload is
never run, here or anywhere else in this emulator.

The firings are written at session start, after the replay journal has been
loaded, because the pass that seeds syslog runs before any attacker-installed
crontab exists. So a job installed and immediately grepped for shows
nothing, which is correct -- it has not fired yet -- and the same job on the
next login shows every minute it has been up.

Schedules are matched properly rather than assumed to be `* * * * *`:
`*/5`, a fixed minute, `0 */2`, ranges and lists, and cron's rule that
day-of-month and day-of-week are ORed unless both are `*`.

Usage:  python3 cronranstest.py
"""

import sys
import time

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def install(spec, cmd="/root/.x/miner", age=None, user="root"):
    """Install a job, then reconnect with it `age` seconds old."""
    fs = fakeshell.VFS()
    sh = fakeshell.Shell(vfs=fs, peer="203.0.113.9", peer_port=44321)
    sh.run("(crontab -l 2>/dev/null; echo '%s %s') | crontab -" % (spec, cmd))
    first = sh
    if age is None:
        return fs, sh, first
    fs2 = fakeshell.VFS()
    fs2.load_journal(fs.dump_journal())
    node = fs2.nodes.get("/var/spool/cron/crontabs/%s" % user)
    if node is not None:
        node.mtime = time.time() - age
    return fs2, fakeshell.Shell(vfs=fs2, peer="203.0.113.9",
                                peer_port=44322), first


def count(sh, needle="/root/.x/miner"):
    return int(sh.run("grep -c '%s' /var/log/syslog" % needle).strip() or 0)


def stamps(sh):
    return [l[:15] for l in sh.run("cat /var/log/syslog").splitlines()
            if l.strip()]


def main():
    # -- the job is scheduled but has not fired yet -------------------------
    fs, sh, _ = install("* * * * *")
    check("crontab -l shows it",
          "/root/.x/miner" in sh.run("crontab -l"), True)
    check("the spool file has it",
          "/root/.x/miner" in
          sh.run("cat /var/spool/cron/crontabs/root"), True)
    check("nothing has fired in the session that installed it",
          count(sh), 0)

    # -- and on the next login, it has ---------------------------------------
    fs, sh, _ = install("* * * * *", age=3600)
    n = count(sh)
    check("an hour of a per-minute job is about sixty lines",
          55 <= n <= 62, True)
    check("the lines name the command",
          "CMD (/root/.x/miner)" in sh.run("grep miner /var/log/syslog"), True)
    check("...and the user", "(root) CMD" in
          sh.run("grep miner /var/log/syslog"), True)
    check("journalctl -u cron shows them too",
          int(sh.run("journalctl -u cron --no-pager | grep -c miner").strip()
              or 0), n)

    # -- the stock entries are untouched -------------------------------------
    check("the hourly run-parts lines are still there",
          int(sh.run("grep -c 'run-parts --report /etc/cron.hourly' "
                     "/var/log/syslog").strip() or 0) > 0, True)

    # -- the log stays a log -------------------------------------------------
    # Appending them put an hour of cron history after tonight's nginx
    # errors, and `tail -1` then answered with a two-hour-old line.
    ts = stamps(sh)
    check("syslog is still in time order", ts, sorted(ts))
    check("tail -1 is one of the newest lines",
          sh.run("tail -1 /var/log/syslog")[:15], ts[-1])
    check("head -1 is still the rotation that started the file",
          "logrotate" in sh.run("head -1 /var/log/syslog"), True)

    # A second channel on the same connection must not double them.
    second = fakeshell.Shell(vfs=fs, peer="203.0.113.9", peer_port=44323)
    check("a second shell does not double the lines", count(second), n)

    # -- schedules are read, not assumed -------------------------------------
    for spec, age, lo, hi in (
            ("*/5 * * * *", 7200, 22, 26),
            ("*/15 * * * *", 7200, 6, 10),
            ("0 * * * *", 7200, 1, 3),
    ):
        _, s2, _ = install(spec, age=age)
        got = count(s2)
        check("%s over %dh fires %d-%d times" % (spec, age // 3600, lo, hi),
              lo <= got <= hi, True)

    # A job scheduled for a time that has not come round since it was
    # installed has not fired. Picked relative to now so the check does not
    # depend on the hour the suite runs at.
    far = time.localtime(time.time() + 6 * 3600)
    _, s3, _ = install("%d %d * * *" % (far.tm_min, far.tm_hour), age=3600)
    check("a job whose time has not come has not fired", count(s3), 0)

    # -- a job cannot have fired before it was installed ---------------------
    _, s4, _ = install("* * * * *", age=120)
    check("a two-minute-old job has a couple of lines, not an hour of them",
          count(s4) <= 4, True)

    # -- comments and environment lines are not schedules ---------------------
    fs5 = fakeshell.VFS()
    sh5 = fakeshell.Shell(vfs=fs5, peer="203.0.113.9", peer_port=44321)
    sh5.run("printf '# a comment\\nMAILTO=\\\"\\\"\\n"
            "* * * * * /root/.x/two\\n' | crontab -")
    fs6 = fakeshell.VFS()
    fs6.load_journal(fs5.dump_journal())
    n6 = fs6.nodes.get("/var/spool/cron/crontabs/root")
    if n6 is not None:
        n6.mtime = time.time() - 600
    sh6 = fakeshell.Shell(vfs=fs6, peer="203.0.113.9", peer_port=44322)
    check("the real schedule fired", count(sh6, "/root/.x/two") > 0, True)
    check("the comment did not become a job",
          "a comment" in sh6.run("grep CRON /var/log/syslog"), False)
    check("nor did MAILTO",
          "MAILTO" in sh6.run("grep CRON /var/log/syslog"), False)

    # -- and nothing was executed --------------------------------------------
    # The whole point: the log says the job ran; the box did not run it.
    fs7 = fakeshell.VFS()
    sh7 = fakeshell.Shell(vfs=fs7, peer="203.0.113.9", peer_port=44321)
    sh7.run("(crontab -l 2>/dev/null; echo '* * * * * touch /tmp/i-ran') "
            "| crontab -")
    fs8 = fakeshell.VFS()
    fs8.load_journal(fs7.dump_journal())
    n8 = fs8.nodes.get("/var/spool/cron/crontabs/root")
    if n8 is not None:
        n8.mtime = time.time() - 1800
    sh8 = fakeshell.Shell(vfs=fs8, peer="203.0.113.9", peer_port=44322)
    check("the log says it ran",
          count(sh8, "touch /tmp/i-ran") > 0, True)
    check("...and the command was not actually run",
          fs8.exists("/tmp/i-ran"), False)
    check("...nor did a process appear for it",
          "i-ran" in sh8.run("ps -ef"), False)

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("cronranstest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
