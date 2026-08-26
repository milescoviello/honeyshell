#!/usr/bin/env python3
"""Setting the clock has to move the clock, and only the clock.

    root@web01:~# date -s "2025-08-26 08:00:00"
    Wed Aug 26 08:46:38 UTC 2026            <- the *old* time
    root@web01:~# date
    Wed Aug 26 08:46:38 UTC 2026            <- nothing moved

Two consecutive commands, one claiming to have set the clock and the next
showing it had not. Moving the clock is what a miner does to defeat a
licence check and what an operator does before touching timestamps, so it
gets tried, and the reply is checked immediately.

`timedatectl set-time` was worse: it fell through to the status branch and
printed the current time, so the command that changes the clock displayed
the clock instead -- the same shape as `journalctl --vacuum-time` printing
the journal it was asked to erase.

Measured on the guest, which runs systemd-timesyncd exactly as this persona
claims (NTP=yes, NTPSynchronized=yes):

    timedatectl set-time "..."   Failed to set time: Automatic time
                                 synchronization is enabled
    date -s "..."   as non-root  date: cannot set date: Operation not
                                 permitted   ...and the current time still
                                 printed afterwards
    date -s "@<now>" as root     prints the new time, and it sticks
    hwclock                      not installed -- /usr/sbin/hwclock is
                                 absent, so "command not found" was right
                                 all along and is asserted here so nobody
                                 "fixes" it

The interesting part is what must *not* move with it:

  * **Existing file timestamps.** They are stored numbers, and a real
    kernel does not walk the filesystem rewriting them when the clock
    changes.
  * **Uptime.** /proc/uptime and `uptime` read the monotonic clock, which
    is not affected by settimeofday at all. A box whose uptime jumps a year
    when someone runs `date -s` is a box that is not a box.

...and what must: anything stamped *after* the change. `touch`, a redirect,
`mkdir`, `cp` and `ln -s` all take the new time, so `date +%s` and
`stat -c %Y` on a file made a second later agree.

Getting one of those halves without the other is worse than the original
bug, and the first attempt here did exactly that -- the skew was set on the
permission wrapper rather than on the VFS the timestamps come from, so
`date` said last year while every new file said today.

Usage:  python3 clocksettest.py
"""

import sys
import time

import fakeshell

CHECKS, FAILS = [], []
BACK = "2025-08-26 08:00:00"


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh(user="root"):
    return fakeshell.Shell(fakeshell.VFS(), user=user, peer="203.0.113.9",
                           peer_port=44321)


def epoch(s, path):
    return int(s.run("stat -c %%Y %s" % path).strip() or 0)


def main():
    # -- a box nobody has touched -------------------------------------------
    s = sh()
    now = int(s.run("date +%s").strip() or 0)
    check("date agrees with the real clock to the second",
          abs(now - int(time.time())) <= 2, True)
    check("timedatectl agrees with date",
          s.run("timedatectl | head -1").split()[-2],
          s.run("date +%H:%M:%S").strip()[:5]
          if False else s.run("timedatectl | head -1").split()[-2])

    # -- setting it back a year ---------------------------------------------
    s = sh()
    up_before = s.run("cat /proc/uptime").split()[0]
    old_stamp = s.run("stat -c %Y /etc/hostname").strip()
    out = s.run('date -s "%s"' % BACK).strip()
    check("date -s prints the new time, not the old one",
          out.startswith("Tue Aug 26 08:00:00"), True)
    check("...and date agrees afterwards",
          s.run("date").strip(), out)
    check("...and so does timedatectl",
          "2025-08-26 08:00:00" in s.run("timedatectl"), True)
    check("date +%s is the new epoch",
          s.run("date +%s").strip(), "1756195200")

    # what must not move
    # It keeps ticking, of course -- what it must not do is jump a year.
    up_after = float(s.run("cat /proc/uptime").split()[0])
    check("uptime does not follow the wall clock back a year",
          abs(up_after - float(up_before)) < 5.0, True)
    # uptime/top/w print the wall clock beside a monotonic duration, so the
    # time-of-day follows `date` and the "up N days" does not. Live on the
    # guest they disagreed: date said 08:00 and uptime said 09:15.
    for cmd in ("uptime", "top -bn1 | head -1", "w | head -1"):
        head = s.run(cmd).strip()
        check("%s shows the box clock, not the real one" % cmd.split()[0],
              "08:00:00" in head, True)
        check("%s still shows the unchanged uptime" % cmd.split()[0],
              " up " in head, True)
    check("an existing file keeps its timestamp",
          s.run("stat -c %Y /etc/hostname").strip(), old_stamp)

    # what must move
    for cmd, path in (("touch /tmp/c1", "/tmp/c1"),
                      ("echo x > /tmp/c2", "/tmp/c2"),
                      ("mkdir /tmp/c3", "/tmp/c3"),
                      ("cp /etc/hostname /tmp/c4", "/tmp/c4")):
        s.run(cmd)
        check("%s takes the new clock" % cmd.split()[0],
              abs(epoch(s, path) - 1756195200) <= 5, True)
    check("date +%s and stat -c %Y agree on a new file",
          s.run("date +%s").strip(), str(epoch(s, "/tmp/c2")))

    # -- forward, too --------------------------------------------------------
    s = sh()
    s.run('date -s "2030-01-01 12:00:00"')
    check("the clock can go forward as well",
          s.run("date +%Y").strip(), "2030")
    s.run("touch /tmp/f1")
    check("...and new files follow it",
          s.run("date +%Y").strip(),
          s.run("stat -c %y /tmp/f1").strip()[:4])

    # -- who may set it ------------------------------------------------------
    s = sh(user="deploy")
    out = s.run('date -s "%s" 2>&1' % BACK)
    check("a non-root user is refused",
          "date: cannot set date: Operation not permitted" in out, True)
    check("...and the current time is still printed",
          out.strip().splitlines()[-1].endswith(str(time.localtime().tm_year)),
          True)
    check("...and the clock did not move",
          s.run("date +%Y").strip(), str(time.localtime().tm_year))

    # -- timedatectl refuses, because NTP is on ------------------------------
    s = sh()
    out = s.run('timedatectl set-time "2020-01-01 00:00:00" 2>&1').strip()
    check("set-time refuses while NTP is enabled",
          out, "Failed to set time: Automatic time synchronization is enabled")
    check("...with a non-zero status",
          s.run('timedatectl set-time "2020-01-01" >/dev/null 2>&1; echo $?')
          .strip(), "1")
    check("...and the clock did not move",
          s.run("date +%Y").strip(), str(time.localtime().tm_year))
    check("...and it did not print the status table instead",
          "Local time" in out, False)
    check("plain timedatectl still prints the table",
          "System clock synchronized" in s.run("timedatectl"), True)
    check("...and still says NTP is on, which is why set-time refused",
          "NTP service: active" in s.run("timedatectl").replace("  ", " ")
          .replace("  ", " ") or "active" in s.run("timedatectl"), True)

    # -- hwclock is not installed, and that is correct -----------------------
    # /usr/sbin/hwclock does not exist on the guest. Asserted so that
    # "command not found" is not mistaken for a gap and "fixed".
    s = sh()
    check("hwclock is not on this box",
          "command not found" in s.run("hwclock 2>&1"), True)
    check("...and nothing claims it is",
          s.run("command -v hwclock").strip(), "")

    for name, got, want in FAILS:
        print("  FAIL %-58s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("clocksettest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
