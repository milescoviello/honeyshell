#!/usr/bin/env python3
"""When did the logs rotate, and does everything that records it agree?

Five things on this box claim to know when /var/log/syslog last rotated:

  * /etc/logrotate.d/rsyslog       -- how often it happens
  * /etc/crontab                   -- when the job that does it runs
  * /var/lib/logrotate/status      -- when it last happened
  * the rotated files' own mtimes  -- when each copy was closed
  * the content spans              -- what period each file covers

They disagreed three ways. The state file said local midnight, a moment at
which this box does nothing at all. The rotated mtimes said 05:08, which was
BOOT_TS's time of day rather than any scheduled event. And /etc/crontab did
not mention cron.daily, cron.weekly or cron.monthly at all -- the file that
says when logrotate runs never mentioned running it, because it was a
three-line sketch instead of the real 1042-byte file.

The content was worse than the metadata:

  * /var/log/syslog held Aug 23 -> Aug 25 in a file its own config rotates
    *daily*, because it was built from a sliding `now - 47h`.
  * syslog.1 was literally three fifths of the live file's lines, so the two
    shared every one of them and `zgrep` across syslog* reported each CRON
    run twice.
  * syslog.2.gz carried content from Aug 15 under an mtime of Aug 23 --
    eight days out -- because _rotated_syslog() used _rotation_start(),
    which counts in weeks and belongs to auth.log.
  * an nginx line inside syslog embedded the date "2026/08/18" next to a
    syslog stamp of now-38h, so the message and the line carrying it
    disagreed about when it was written.

And it moved. Timer entries emitted only each timer's most recent firing,
recomputed on every read, so a past event relocated as the clock crossed a
period boundary and `head -1 /var/log/syslog` returned a different line six
hours later. A log that edits its own history is a worse tell than a missing
one, and this is the sweep timelinetest had been reporting for two days.

Everything now derives from /etc/crontab: cron.daily at 06:25 and
cron.weekly at 06:47 on Sunday, measured from a real trixie.

Usage:  python3 rotwindowtest.py
"""

import calendar
import re
import sys
import time

import fakeshell as F

CHECKS, FAILS = [], []


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh():
    return F.Shell()


MON = {m: i for i, m in enumerate(calendar.month_abbr) if m}


def stamp(line):
    """Epoch of a syslog line's 'Mon DD HH:MM:SS' prefix, or None."""
    m = re.match(r"^([A-Z][a-z]{2})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)", line or "")
    if not m:
        return None
    now = time.localtime()
    mon, day, hh, mm, ss = (MON[m.group(1)], int(m.group(2)),
                            int(m.group(3)), int(m.group(4)), int(m.group(5)))
    year = now.tm_year
    # A month ahead of today is last year's, syslog carrying no year.
    if mon > now.tm_mon + 1:
        year -= 1
    return time.mktime((year, mon, day, hh, mm, ss, 0, 0, -1))


def crontab_time(s, which):
    """(hour, minute) /etc/crontab runs cron.<which> at, read off the file.

    Returns None when the file does not schedule it -- which is the defect
    under test, so every caller has to cope. The first version unpacked the
    result directly and the suite died on the third test against the broken
    build, taking the other five with it. A suite has to survive the thing
    it is testing for.
    """
    for line in s.run("cat /etc/crontab").splitlines():
        if "cron." + which in line and not line.lstrip().startswith("#"):
            f = line.split()
            if len(f) >= 2 and f[0].isdigit() and f[1].isdigit():
                return int(f[1]), int(f[0])
    return None


def state_times(s):
    out = {}
    for line in s.run("cat /var/lib/logrotate/status").splitlines():
        m = re.match(r'^"([^"]+)"\s+(\S+)', line)
        if m:
            try:
                out[m.group(1)] = time.strptime(m.group(2), "%Y-%m-%d-%H:%M:%S")
            except ValueError:
                pass
    return out


def t_crontab_is_the_real_file():
    s = sh()
    body = s.run("cat /etc/crontab")
    check("/etc/crontab size", len(body), 1042)
    for which in ("hourly", "daily", "weekly", "monthly"):
        check("/etc/crontab schedules cron.%s" % which,
              "cron." + which in body, True)
    check("cron.daily time", crontab_time(s, "daily"), (6, 25))
    check("cron.weekly time", crontab_time(s, "weekly"), (6, 47))
    # The PATH was in the wrong order, which `grep PATH /etc/crontab` shows.
    check("crontab PATH is Debian's",
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
          in body, True)
    check("stat agrees with cat", s.run("stat -c %s /etc/crontab").strip(),
          str(len(body)))


def t_state_file_matches_the_schedule():
    """logrotate runs inside cron.daily, so the times it records are cron's."""
    s = sh()
    st = state_times(s)
    daily = crontab_time(s, "daily")
    weekly = crontab_time(s, "weekly")
    check("crontab schedules cron.daily at all", daily is not None, True)
    check("crontab schedules cron.weekly at all", weekly is not None, True)
    check("state file names syslog", "/var/log/syslog" in st, True)
    if daily and "/var/log/syslog" in st:
        t = st["/var/log/syslog"]
        check("syslog rotated at the cron.daily time", (t.tm_hour, t.tm_min),
              daily)
    for f in ("/var/log/auth.log", "/var/log/kern.log"):
        if f in st:
            t = st[f]
            if weekly:
                check("%s rotated at the cron.weekly time" % f,
                      (t.tm_hour, t.tm_min), weekly)
            check("%s rotated on a Sunday" % f, t.tm_wday, 6)


def t_the_live_file_starts_at_its_rotation():
    s = sh()
    st = state_times(s)
    first = stamp(s.run("head -1 /var/log/syslog"))
    check("syslog's first line parses", first is not None, True)
    if first and "/var/log/syslog" in st:
        rot = time.mktime(st["/var/log/syslog"])
        check("no syslog entry predates the rotation", first >= rot - 1, True)
    last = stamp(s.run("tail -1 /var/log/syslog"))
    if first and last:
        # A daily-rotated file cannot hold more than a day.
        check("syslog spans less than 24h", (last - first) < 86400, True)


def t_rotations_do_not_overlap():
    """A rotated file ends where the next one begins. syslog.1 used to be a
    slice of the live file, so both contained the same lines."""
    s = sh()
    live_first = stamp(s.run("head -1 /var/log/syslog"))
    one_first = stamp(s.run("head -1 /var/log/syslog.1"))
    one_last = stamp(s.run("tail -1 /var/log/syslog.1"))
    check("syslog.1 ends before syslog begins",
          bool(live_first and one_last and one_last < live_first), True)
    # Each file's span is measured against its OWN bounds. The first version
    # of this compared a file's first stamp to the *previous* file's last
    # stamp and called the difference a span, which is two windows wide.
    if one_first and one_last:
        check("syslog.1 covers about a day",
              82800 <= (one_last - one_first) <= 90000, True)
    prev_first = one_first
    for n in range(2, 8):
        last = stamp(s.run("zcat /var/log/syslog.%d.gz | tail -1" % n))
        first = stamp(s.run("zcat /var/log/syslog.%d.gz | head -1" % n))
        check("syslog.%d.gz decompresses to dated lines" % n,
              bool(first and last), True)
        if first and last:
            check("syslog.%d.gz covers about a day" % n,
                  82800 <= (last - first) <= 90000, True)
            if prev_first:
                check("syslog.%d.gz ends before syslog.%d begins"
                      % (n, n - 1), last <= prev_first, True)
        prev_first = first


def t_rotated_mtimes_are_the_rotation_times():
    """`ls -l` and the content have to tell the same story."""
    s = sh()
    st = state_times(s)
    if "/var/log/syslog" not in st:
        return
    rot = time.mktime(st["/var/log/syslog"])
    for n in range(2, 8):
        got = s.run("stat -c %%Y /var/log/syslog.%d.gz" % n).strip()
        if got.isdigit():
            want = rot - (n - 1) * 86400
            check("syslog.%d.gz mtime is its rotation" % n,
                  abs(int(got) - want) <= 1, True)
    # And the count matches what the config promises.
    cfg = s.run("cat /etc/logrotate.d/rsyslog")
    m = re.search(r"/var/log/syslog\s*\{[^}]*?rotate\s+(\d+)", cfg, re.S)
    if m:
        keep = int(m.group(1))
        n = int(s.run("ls /var/log/syslog.* | wc -l").strip() or 0)
        check("as many rotated copies as `rotate` promises", n, keep)


def t_auth_log_seam():
    s = sh()
    live_first = stamp(s.run("head -1 /var/log/auth.log"))
    one_last = stamp(s.run("tail -1 /var/log/auth.log.1"))
    check("auth.log.1 ends before auth.log begins",
          bool(live_first and one_last and one_last < live_first), True)


def t_history_does_not_move():
    """The bug timelinetest kept reporting: read it twice, get two pasts."""
    # Absent on a build with no rotation authority, which is the point --
    # so ask for it rather than assuming it, and fall back to "no rotation
    # ever happened" so the comparison below still runs and still fails.
    daily = getattr(F, "cron_daily_last", None)
    check("there is one authority for the rotation time",
          daily is not None, True)
    real = time.time
    seen = {}
    for off in (0, 3600, 6 * 3600):
        if off:
            time.time = (lambda o: (lambda: real() + o))(off)
        try:
            s = sh()
            rot = daily() if daily else 0
            seen[off] = (s.run("head -1 /var/log/syslog").strip(), rot)
        finally:
            time.time = real
    base_line, base_rot = seen[0]
    for off in (3600, 6 * 3600):
        line, rot = seen[off]
        if rot == base_rot:
            # No rotation in between, so the first line cannot have changed.
            check("head -1 syslog holds still over %dh (no rotation)"
                  % (off // 3600), line, base_line)
        else:
            # A rotation *should* change it -- that is not drift, that is
            # logrotate. Assert it changed rather than skipping.
            check("head -1 syslog changes across a rotation (%dh)"
                  % (off // 3600), line != base_line, True)


def t_embedded_dates_match_their_line():
    """A message that carries its own timestamp must agree with the line."""
    s = sh()
    for line in s.run("cat /var/log/syslog").splitlines():
        m = re.search(r"(\d{4})/(\d\d)/(\d\d) (\d\d):(\d\d):(\d\d)", line)
        if not m:
            continue
        outer = stamp(line)
        inner = time.mktime((int(m.group(1)), int(m.group(2)), int(m.group(3)),
                             int(m.group(4)), int(m.group(5)), int(m.group(6)),
                             0, 0, -1))
        check("embedded date matches its syslog stamp",
              abs(outer - inner) <= 1 if outer else False, True)


def main():
    for fn in (t_crontab_is_the_real_file,
               t_state_file_matches_the_schedule,
               t_the_live_file_starts_at_its_rotation,
               t_rotations_do_not_overlap,
               t_rotated_mtimes_are_the_rotation_times,
               t_auth_log_seam,
               t_history_does_not_move,
               t_embedded_dates_match_their_line):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-56s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("rotwindowtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
