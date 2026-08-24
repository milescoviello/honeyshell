#!/usr/bin/env python3
"""The box's own history: does it hold still, and does it hold together?

Two questions nothing had asked. First, does any date on the box move because
we looked later -- a file whose mtime is an hour newer every hour, with nobody
having touched it. Second, do the dates that must be ordered actually order:
a filesystem cannot be mounted before it was created, and a log cannot be
rotated away after the live one starts.

The first question needed care to ask. BOOT_TS and FS_EPOCH are persisted to
disk precisely so ages stop being measured from now, and a naive harness that
runs without those files makes the module fall back to time.time() for both --
so shifting the clock moves the anchors and 17 of 22 answers appear to drift
when nothing is wrong. With the anchors pinned the way the deployed service
has them, exactly one thing was really moving.

What it found:

  * /var/log/auth.log was a sliding 47-hour window. Every read moved its
    earliest line and the CRON pid with it, which is the one thing a log file
    never does -- a real one is appended to and `head -1` is fixed until
    logrotate runs. The rotated copies already anchored to a midnight
    boundary; the live file did not.
  * its cron sessions landed at whatever second of the hour it happened to
    be, while /etc/crontab says cron.hourly runs at 17 past. The box
    disagreed with its own crontab about when its own cron ran. There is one
    schedule now, cron_hourly_runs, and the crontab line is generated from
    the same constant.
  * auth.log.1 was seeded with the *live* log rather than the previous
    window, so it held the same lines as auth.log -- same first line, last
    lines half an hour apart. A rotated file ends where the live one begins.
  * and the weekly windows were seven weeks apart, because _rotation_start
    already counts in weeks and the caller multiplied by seven again, leaving
    a six-week hole between auth.log.1 and auth.log.2.gz.
  * `Filesystem created` was FS_EPOCH minus 13 days. FS_EPOCH is when this
    honeypot first ran, which is *after* the boot the box claims, so the
    superblock said the filesystem was created a month after it was last
    mounted. A filesystem mounted before it existed is the one thing a
    superblock can never say.
  * tune2fs prints its version banner on stdout and dumpe2fs on stderr --
    measured on the guest with the streams split. Ours had tune2fs on stderr,
    so `tune2fs -l dev 2>/dev/null | head -1` gave a filesystem field where
    the guest gives the version. disktest.py had the wrong one pinned as
    expected behaviour and is corrected with it.

Run from ~/opsec/honeypot:  python3 -W ignore timelinetest.py
"""
import calendar
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# The anchors have to be in place *before* fakeshell is imported, because
# BOOT_TS and FS_EPOCH are module-level and read their files at import. On the
# guest they are already on disk; anywhere else this suite provides its own,
# fixed, so shifting the clock cannot move them. Without that the module falls
# back to time.time() for both and every date appears to drift -- which
# measures the harness rather than the box, and is exactly the trap that made
# a first pass at this report 17 false positives.
_DEFAULTS = {"HONEY_BOOT_TS": "/var/lib/honeypot/boot_ts",
             "HONEY_FS_EPOCH": "/var/lib/honeypot/fs_epoch"}
_FIXED = {"HONEY_BOOT_TS": "1783512697.18",   # 2026-07-08 12:11:37 UTC
          "HONEY_FS_EPOCH": "1787266200.32"}  # 2026-08-20 22:50:00 UTC
_tmp = None
for _var, _default in _DEFAULTS.items():
    if os.environ.get(_var) or os.path.exists(_default):
        continue
    if _tmp is None:
        _tmp = tempfile.mkdtemp(prefix="timelinetest-")
    _path = os.path.join(_tmp, _var.lower())
    with open(_path, "w") as _fh:
        _fh.write(_FIXED[_var])
    os.environ[_var] = _path

import fakeshell as fs                                          # noqa: E402

# Every answer that carries a date. Nothing here may move between two reads.
DATED = [
    "tune2fs -l /dev/sda1 2>/dev/null | grep -i created",
    "tune2fs -l /dev/sda1 2>/dev/null | grep -i 'last mount'",
    "tune2fs -l /dev/sda1 2>/dev/null | grep -i 'last checked'",
    "head -1 /var/log/dpkg.log",
    "uptime -s",
    "who -b",
    "stat -c %y /etc/ssh/ssh_host_ed25519_key",
    "stat -c %y /etc/machine-id",
    "stat -c %y /etc/passwd",
    "stat -c %y /etc/shadow",
    "stat -c %y /var/www/.env",
    "stat -c %y /root/.bash_history",
    "stat -c %y /",
    "stat -c %y /etc/crontab",
    "stat -c %y /var/lib/dpkg/status",
    "head -1 /var/log/syslog",
    "head -1 /var/log/auth.log",
    "last | tail -1",
    "head -1 /var/log/nginx/access.log",
    "lastlog -u root",
]


def shell():
    sh = fs.Shell(fs.VFS())
    sh.exec_mode = True
    return sh


def snapshot(offset, queries):
    """Answers as seen `offset` seconds from now, anchors held fixed.

    The anchors are the point: without pinning them the module recomputes
    BOOT_TS and FS_EPOCH from the shifted clock and everything appears to
    move, which measures the harness and not the box.
    """
    real = time.time
    if offset:
        time.time = lambda: real() + offset
    try:
        sh = shell()
        return {q: " ".join(sh.run(q).split()) for q in queries}
    finally:
        time.time = real


def main():
    verbose = "-v" in sys.argv
    ok = bad = 0

    def check(label, cond, detail=""):
        nonlocal ok, bad
        if cond:
            ok += 1
            if verbose:
                print("  ok    %s" % label)
        else:
            bad += 1
            print("  FAIL  %s  %s" % (label, detail))

    def eq(label, got, want):
        check(label, got == want, "want %r got %r" % (want, got))

    # The anchors have to be on disk for this to mean anything.
    have_anchors = (os.path.exists(fs._BOOT_TS_FILE)
                    and os.path.exists(fs._FS_EPOCH_FILE))
    check("the persisted anchors exist (else drift cannot be measured)",
          have_anchors,
          "set HONEY_BOOT_TS and HONEY_FS_EPOCH to fixed files")

    # ---- nothing moves because we looked later ---------------------------
    if have_anchors:
        a = snapshot(0, DATED)
        b = snapshot(6 * 3600, DATED)
        for q in DATED:
            check("holds still over six hours: %s" % q, a[q] == b[q],
                  "\n        now %r\n        +6h %r" % (a[q][:90], b[q][:90]))

    sh = shell()

    # ---- the superblock's own ordering -----------------------------------
    def sb():
        out = {}
        for line in sh.run("tune2fs -l /dev/sda1 2>/dev/null").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip()] = v.strip()
        return out

    d = sb()
    fmt = "%a %b %d %H:%M:%S %Y"

    def ts(key):
        return calendar.timegm(time.strptime(d[key], fmt))

    for k in ("Filesystem created", "Last mount time", "Last write time",
              "Last checked"):
        check("the superblock reports %s" % k, k in d, str(sorted(d)[:2]))
    if all(k in d for k in ("Filesystem created", "Last mount time",
                            "Last write time", "Last checked")):
        created = ts("Filesystem created")
        check("created before it was last mounted",
              created <= ts("Last mount time"),
              "created %s, mounted %s" % (d["Filesystem created"],
                                          d["Last mount time"]))
        check("mounted before it was last written",
              ts("Last mount time") <= ts("Last write time"))
        check("last checked no earlier than created",
              ts("Last checked") >= created)
        check("created before the boot it is running",
              created <= int(sh.run("stat -c %Y /proc/1/stat").strip() or 0)
              or created <= fs.BOOT_TS, "created after BOOT_TS")
        check("created before the oldest file on it",
              created <= int(sh.run("stat -c %Y /").strip()),
              "the root directory predates its own filesystem")

    # ---- the version banners, per the guest ------------------------------
    eq("tune2fs names itself on stdout",
       sh.run("tune2fs -l /dev/sda1 2>/dev/null | head -1").strip(),
       "tune2fs 1.47.2 (1-Jan-2025)")
    eq("...and puts nothing on stderr",
       sh.run("tune2fs -l /dev/sda1 2>&1 >/dev/null").strip(), "")
    eq("dumpe2fs names itself on stderr instead",
       sh.run("dumpe2fs -h /dev/sda1 2>/dev/null | head -1").strip(),
       "Filesystem volume name:   <none>")

    # ---- cron says one thing, once --------------------------------------
    minute = getattr(fs, "CRON_HOURLY_MINUTE", 17)
    check("the module has one constant for the cron minute",
          hasattr(fs, "CRON_HOURLY_MINUTE"), "it is a literal somewhere")
    crontab = sh.run("grep cron.hourly /etc/crontab").strip()
    eq("the crontab minute is the module's constant",
       crontab.split()[0], str(minute))
    for path in ("/var/log/auth.log", "/var/log/syslog"):
        mins = {l.split()[2].split(":")[1]
                for l in sh.run("grep -h 'CRON\\[' %s" % path).splitlines()
                if len(l.split()) > 2 and ":" in l.split()[2]}
        check("%s runs cron only at :%02d" % (path, minute),
              mins in ({"%02d" % minute}, set()),
              "minutes seen: %s" % sorted(mins)[:6])

    # ---- the rotation chain is contiguous and in order -------------------
    def span(path):
        cat = "zcat" if path.endswith(".gz") else "cat"
        first = sh.run("%s %s 2>/dev/null | head -1" % (cat, path)).strip()
        last = sh.run("%s %s 2>/dev/null | tail -1" % (cat, path)).strip()
        return first, last

    def stamp(line):
        if not line:
            return None
        try:
            t = time.strptime(" ".join(line.split()[:3]), "%b %d %H:%M:%S")
        except ValueError:
            return None
        now = time.localtime()
        year = now.tm_year - (1 if t.tm_mon > now.tm_mon else 0)
        return calendar.timegm(t[:1] and (year,) + t[1:6] + (0, 1, -1))

    chain = ["/var/log/auth.log.4.gz", "/var/log/auth.log.3.gz",
             "/var/log/auth.log.2.gz", "/var/log/auth.log.1",
             "/var/log/auth.log"]
    spans = []
    for p in chain:
        f, l = span(p)
        check("%s is not empty" % p, bool(f), "empty")
        spans.append((p, stamp(f), stamp(l)))
    for (p1, _f1, l1), (p2, f2, _l2) in zip(spans, spans[1:]):
        if l1 is None or f2 is None:
            continue
        check("%s ends before %s begins" % (p1, p2), l1 <= f2,
              "%s ends after %s starts" % (p1, p2))
    for p, f, l in spans:
        if f is not None and l is not None:
            check("%s runs forwards" % p, f <= l)

    print("\ntimelinetest: passed %d, failed %d" % (ok, bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
