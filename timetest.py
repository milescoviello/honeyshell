#!/usr/bin/env python3
"""Does every clock on the box agree, and does nothing move that shouldn't?

The other suites ask whether a command's output looks right. This one asks a
question no single command can answer: the box states the time in about
thirty places -- `date`, uptime, btime, wtmp, file mtimes, log lines, package
install dates, the kernel build stamp -- and they have to be mutually
consistent, and the ones describing the past have to stay put.

It was written after finding, in one pass:

  * `uname -v` said the kernel was built 2026-08-05 on a box that booted
    2026-07-10 and never rebooted. An attacker ran `uname -s -v -n -r -m`
    forty seconds after this was found.
  * /etc/passwd, /etc/shadow, /var/www/.env and /root/.bash_history -- the
    files people actually open -- had mtimes measured from time.time() when
    the session started, so listing /etc twice an hour apart showed every one
    of them an hour newer with nobody having touched them.
  * The per-path mtime jitter used hash(), which Python salts per process, so
    every one of those files also jumped up to +-9.5 hours on each restart.
    The comment above it said "deterministically per path".
  * /var/log/syslog's mtime was six weeks older than its own newest line.
  * /etc/shadow was 179 days older than /etc/passwd, and /etc/gshadow 51 days
    from /etc/group -- files useradd always writes in the same instant.
  * `stat -c %y` printed "?" for every file while plain `stat` printed the
    timestamp, and %W was 0 while `stat` reported a Birth time.
  * Every seeded file had exactly .000000000 nanoseconds.
  * `last -3` printed six entries.

Run with HONEY_BOOT_TS and HONEY_FS_EPOCH pointed at scratch files so the
anchors are pinned, exactly as they are on the guest.
"""

import os
import re
import subprocess
import sys
import tempfile
import time

TMP = tempfile.mkdtemp(prefix="timetest-")
os.environ.setdefault("HONEY_BOOT_TS", os.path.join(TMP, "boot_ts"))
os.environ.setdefault("HONEY_FS_EPOCH", os.path.join(TMP, "fs_epoch"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS = FAIL = 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  ok   %s" % name)
    else:
        FAIL += 1
        FAILURES.append(name)
        print("  FAIL %s %s" % (name, detail))


def sh():
    return fs.Shell(fs.VFS())


def run(s, cmd):
    return s.run(cmd)


MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()


def parse_ls_time(tok_month, tok_day, tok_last, now=None):
    """ls prints HH:MM within six months and a year outside it."""
    now = now or time.time()
    mon = MONTHS.index(tok_month) + 1
    if ":" in tok_last:
        hh, mm = (int(x) for x in tok_last.split(":"))
        year = time.localtime(now).tm_year
        cand = time.mktime((year, mon, int(tok_day), hh, mm, 0, 0, 1, -1))
        if cand > now + 86400:
            cand = time.mktime((year - 1, mon, int(tok_day), hh, mm, 0, 0, 1, -1))
        return cand
    return time.mktime((int(tok_last), mon, int(tok_day), 0, 0, 0, 0, 1, -1))


def main():
    s = sh()

    # ---- the box's own idea of now
    now_s = run(s, "date +%s").strip()
    check("date +%s is the real clock", abs(int(now_s) - time.time()) < 5, now_s)

    # ---- uptime, boot time and btime are three statements of one fact
    up = float(run(s, "cat /proc/uptime").split()[0])
    btime = int(re.search(r"btime (\d+)", run(s, "grep btime /proc/stat")).group(1))
    check("btime + uptime == now", abs((btime + up) - int(now_s)) < 5,
          "btime %d up %.0f now %s" % (btime, up, now_s))

    who_b = run(s, "who -b").strip()
    m = re.search(r"(\d{4}-\d\d-\d\d \d\d:\d\d)", who_b)
    check("who -b names a boot time", bool(m), who_b)
    if m:
        wb = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M"))
        check("who -b agrees with btime", abs(wb - btime) < 120,
              "who %s btime %s" % (m.group(1), btime))

    lr = run(s, "last reboot")
    m = re.search(r"([A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d\d:\d\d)", lr)
    check("last reboot names a boot time", bool(m), lr[:80])
    if m:
        lb = time.mktime(time.strptime(
            "%d %s" % (time.localtime(btime).tm_year, m.group(1)),
            "%Y %a %b %d %H:%M"))
        check("last reboot agrees with btime", abs(lb - btime) < 120,
              "last %s btime %s" % (m.group(1), btime))

    updays = re.search(r"up (\d+) day", run(s, "uptime"))
    check("uptime's day count matches /proc/uptime",
          updays and int(updays.group(1)) == int(up // 86400),
          "%s vs %d" % (updays and updays.group(1), up // 86400))

    # ---- the kernel cannot have been built after the boot it is running
    kv = run(s, "uname -v")
    m = re.search(r"\((\d{4}-\d\d-\d\d)\)", kv)
    check("uname -v carries a build date", bool(m), kv.strip())
    if m:
        built = time.mktime(time.strptime(m.group(1), "%Y-%m-%d"))
        check("kernel was built before the box booted", built < btime,
              "built %s, booted %s" % (m.group(1),
                                       time.strftime("%Y-%m-%d",
                                                     time.localtime(btime))))
    check("/proc/version carries the same build date",
          m and m.group(1) in run(s, "cat /proc/version"))

    # ---- nothing describing the past may move
    watched = ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
               "/var/www/.env", "/root/.bash_history", "/bin/bash",
               "/usr/sbin/nginx", "/etc/hostname", "/etc/machine-id")
    cmd = "stat -c '%n %Y' " + " ".join(watched)
    first = run(sh(), cmd)
    real = time.time
    try:
        time.time = lambda: real() + 6 * 3600
        import importlib
        importlib.reload(fs)
        later = run(fs.Shell(fs.VFS()), cmd)
    finally:
        time.time = real
        import importlib
        importlib.reload(fs)
    check("seeded mtimes do not move with the wall clock", first == later,
          "\n    was: %s\n    now: %s" % (first.replace("\n", " | ")[:120],
                                          later.replace("\n", " | ")[:120]))

    # a second process must agree too: hash() is salted, crc32 is not
    script = ("import os,sys;sys.path.insert(0,%r);import fakeshell as f;"
              "print(f.Shell(f.VFS()).run(%r),end='')"
              % (os.path.dirname(os.path.abspath(__file__)), cmd))
    outs = set()
    for _ in range(2):
        outs.add(subprocess.run([sys.executable, "-c", script],
                                capture_output=True, text=True,
                                env=dict(os.environ)).stdout)
    check("seeded mtimes are identical in a fresh process", len(outs) == 1,
          " || ".join(sorted(outs))[:200])

    s = sh()

    # ---- files a single command writes together share an instant
    def mtime(path):
        return float(run(s, "stat -c %%Y %s" % path).strip())

    check("passwd and shadow share an mtime",
          abs(mtime("/etc/passwd") - mtime("/etc/shadow")) < 2,
          "%s vs %s" % (mtime("/etc/passwd"), mtime("/etc/shadow")))
    check("group and gshadow share an mtime",
          abs(mtime("/etc/group") - mtime("/etc/gshadow")) < 2)
    ns = set()
    for f in ("/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow"):
        ns.add(run(s, "stat -c %%y %s" % f).strip().split(".")[1])
    check("the account files differ in the sub-second", len(ns) == 4, str(ns))
    check("shadow is not older than passwd by weeks",
          abs(mtime("/etc/passwd") - mtime("/etc/shadow")) < 86400)

    # ---- nothing is dated in the future
    now = time.time()
    listing = run(s, "find / -type f 2>/dev/null")
    paths = [p for p in listing.split() if p.startswith("/")][:400]
    future = []
    for p in paths:
        try:
            if float(run(s, "stat -c %%Y %s" % p).strip()) > now + 60:
                future.append(p)
        except ValueError:
            continue
    check("no file is dated in the future", not future, str(future[:5]))

    # ---- a log's mtime is when its last line was written
    for log, pat, fmt in (
            ("/var/log/syslog", r"^([A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d)",
             "%b %d %H:%M:%S"),
            ("/var/log/auth.log", r"^([A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d)",
             "%b %d %H:%M:%S"),
            ("/var/log/nginx/access.log",
             r"\[(\d\d/[A-Z][a-z]{2}/\d{4}:\d\d:\d\d:\d\d) ", "%d/%b/%Y:%H:%M:%S"),
            ("/var/log/dpkg.log", r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)",
             "%Y-%m-%d %H:%M:%S")):
        line = run(s, "tail -1 %s" % log).strip()
        m = re.search(pat, line)
        if not m:
            check("%s last line has a timestamp" % log, False, line[:70])
            continue
        tm = time.strptime(m.group(1), fmt)
        if tm.tm_year == 1900:
            tm = time.struct_time((time.localtime(now).tm_year,) + tuple(tm)[1:])
        last = time.mktime(tm)
        mt = mtime(log)
        check("%s mtime matches its newest line" % log, abs(mt - last) < 120,
              "mtime %s, last line %s"
              % (time.strftime("%F %T", time.localtime(mt)), m.group(1)))

    # ---- a live log's advertised size must match what reading it returns.
    # ls said 227 bytes on a file cat returned megabytes of.
    for log in ("/var/log/nginx/access.log", "/var/log/nginx/error.log",
                "/var/log/syslog", "/var/log/auth.log"):
        shown = int(run(s, "stat -c %%s %s" % log).strip() or -1)
        actual = int(run(s, "wc -c < %s" % log).strip() or -2)
        check("%s size matches its contents" % log, shown == actual,
              "stat %d, wc -c %d" % (shown, actual))
        lsz = run(s, "ls -l %s" % log).split()
        check("%s ls size matches stat" % log,
              lsz and lsz[4] == str(shown), " ".join(lsz[:6]))

    # ---- and find agrees with those mtimes
    recent = run(s, "find /var/log -mmin -180 2>/dev/null")
    check("find -mmin sees the freshly written logs",
          "/var/log/syslog" in recent, recent.replace("\n", " ")[:90])

    # ---- stat's two ways of printing a time must both work and agree
    out = run(s, "stat -c '%X|%Y|%Z|%W|%x|%y|%z|%w' /etc/passwd").strip()
    epochs, human = out.split("|")[:4], out.split("|")[4:]
    check("stat -c epoch specifiers all answer",
          all(e.isdigit() for e in epochs), str(epochs))
    check("stat -c human specifiers all answer",
          all(h and h != "?" for h in human), str(human))
    for e, h in zip(epochs, human):
        want = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(e)))
        check("stat %s matches its epoch form" % h[:19], h.startswith(want),
              "%s vs %s" % (h, want))
    plain = run(s, "stat /etc/passwd")
    check("plain stat and -c report the same Modify time",
          human[1].split(".")[0] in plain, human[1])
    check("plain stat reports a Birth time", "Birth: 2" in plain)

    # ---- nanoseconds
    zero = 0
    for p in ("/etc/passwd", "/etc/hosts", "/bin/bash", "/var/log/syslog",
              "/etc/crontab", "/root/.bash_history"):
        if run(s, "stat -c %%y %s" % p).split(".")[1].startswith("000000000"):
            zero += 1
    check("seeded files have real sub-second mtimes", zero == 0,
          "%d of 6 are exactly .000000000" % zero)

    # ---- ls's six-month rule, against the epoch stat reports
    for p in ("/bin/bash", "/etc/passwd", "/var/log/syslog"):
        cols = run(s, "ls -l %s" % p).split()
        shown = parse_ls_time(cols[5], cols[6], cols[7])
        check("ls and stat agree on %s" % p, abs(shown - mtime(p)) < 90,
              "ls %s %s %s vs %s" % (cols[5], cols[6], cols[7],
                                     time.strftime("%b %e %H:%M",
                                                   time.localtime(mtime(p)))))

    # ---- login records
    check("last -3 prints three entries",
          len([ln for ln in run(s, "last -3").splitlines()
               if ln.strip() and not ln.startswith("wtmp")]) == 3,
          run(s, "last -3").replace("\n", " | ")[:110])
    check("last -1 prints one entry",
          len([ln for ln in run(s, "last -1").splitlines()
               if ln.strip() and not ln.startswith("wtmp")]) == 1)

    login = run(s, "who").strip()
    m = re.search(r"(\d{4}-\d\d-\d\d \d\d:\d\d)", login)
    check("who reports our login time", bool(m), login[:70])
    if m:
        wt = time.mktime(time.strptime(m.group(1), "%Y-%m-%d %H:%M"))
        # lastlog was cross-checked here until Debian 13 was found to have
        # dropped the command; `last` is the surviving view of the same
        # question and it has to agree with who.
        lt_line = run(s, "last -1").splitlines()[0]
        m2 = re.search(r"(\w{3} \w{3} ?\d+ \d\d:\d\d)", lt_line)
        check("last reports our login too", bool(m2), lt_line[:80])
        if m2:
            check("last names the user who is logged in",
                  lt_line.split()[0] == s.user, lt_line[:40])
            check("last shows it still open", "still logged in" in lt_line,
                  lt_line[:80])
        check("our login is not before boot", wt >= btime - 60)

    # ---- systemd's timestamps
    since = run(s, "systemctl show nginx -p ActiveEnterTimestamp").strip()
    check("ActiveEnterTimestamp is populated",
          since.startswith("ActiveEnterTimestamp=") and len(since) > 22, since)
    stamp = since.split("=", 1)[1] if "=" in since else ""
    check("systemctl status prints the same instant",
          stamp and stamp in run(s, "systemctl status nginx"), stamp)
    check("ExecMainStartTimestamp matches ActiveEnterTimestamp",
          stamp and stamp in run(s, "systemctl show nginx -p "
                                    "ExecMainStartTimestamp"))
    check("systemctl show omits properties it does not know",
          run(s, "systemctl show nginx -p NoSuchProperty").strip() == "")
    if stamp:
        st = time.mktime(time.strptime(stamp, "%a %Y-%m-%d %H:%M:%S %Z"))
        check("nginx did not start before the box booted", st >= btime - 120,
              "%s vs boot" % stamp)

    # ---- package install dates sit between the kernel build and now
    dp = run(s, "tail -1 /var/log/dpkg.log")
    m = re.search(r"^(\d{4}-\d\d-\d\d)", dp)
    check("dpkg.log's last entry predates now",
          m and time.mktime(time.strptime(m.group(1), "%Y-%m-%d")) < now, dp[:60])

    # ---- ps start times cannot precede the boot
    bad = []
    for line in run(s, "ps -eo pid,lstart,cmd").splitlines()[1:]:
        m = re.match(r"\s*\d+ ([A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ "
                     r"\d\d:\d\d:\d\d \d{4})", line)
        if m and time.mktime(time.strptime(m.group(1),
                                           "%a %b %d %H:%M:%S %Y")) < btime - 60:
            bad.append(line.split()[0])
    check("no process started before the boot", not bad, str(bad[:5]))

    print()
    print("=" * 62)
    print("passed %d, failed %d" % (PASS, FAIL))
    for f in FAILURES:
        print("   FAILED: %s" % f)
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
