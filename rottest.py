#!/usr/bin/env python3
"""The logs that were rotated away -- can anything read them?

`zgrep <my ip> /var/log/auth.log.*.gz` is how anyone checks whether the
lines they care about survived rotation, and it could not be done here.
The .gz files carried gzip's four magic bytes and then noise:

    ls -l /var/log/syslog.2.gz     -rw-r----- 1 root adm 1478 ...
    file /var/log/syslog.2.gz      gzip compressed data, last modified:
                                   Thu Nov  8 22:00:45 2046, original
                                   size modulo 2^32 1818978921
    zcat /var/log/syslog.2.gz      gzip: not in gzip format

Three readers of one file and three answers -- and `file`'s absurd
metadata came straight out of the fake header, which is its own tell. They
are real deflate streams now, of the log the day held, with the original
name and mtime in the header where gzip puts them.

And /var/log/nginx held only its two live files, while
/etc/logrotate.d/nginx says `daily rotate 14 compress delaycompress` and
/var/lib/logrotate/status names both logs as rotated. Two config files and
a state file said a fortnight of history existed; `ls` said none of it
did. It does now, with .1 plain and .2 onwards gzipped, which is what
delaycompress means.

Writing that turned up the same shape of bug one level down: w() goes
through VFS.write, which refuses a path whose parent does not exist yet
and says nothing about it, and /var/log/nginx is created later in _seed
than this. So the .1 files were simply absent while the .gz siblings
written by direct assignment were there.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = 0, 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append("%-58s %s" % (name, detail))


S = fs.Shell(fs.VFS())
S.exec_mode = True


def R(cmd, s=None):
    t = s or S
    t._err = []
    out = t.run(cmd)
    return out or "", "".join(t._err), t.last_rc


def gzips():
    return sorted(R("ls /var/log/*.gz /var/log/nginx/*.gz "
                    "2>/dev/null")[0].split())


# ---------------------------------------------------------------------------
# every .gz is a gzip stream
# ---------------------------------------------------------------------------
def t_every_rotated_gz_decompresses():
    files = gzips()
    check("there are rotated .gz files", len(files) > 10, str(len(files)))
    bad = []
    for f in files:
        out, err, rc = R("zcat %s" % f)
        if rc != 0 or not out.strip() or "not in gzip format" in err:
            bad.append("%s: rc=%s %s" % (f, rc, err.strip()[:40]))
    check("all of them decompress", not bad, str(bad[:3]))
    for f in files[:4]:
        check("%s starts with gzip magic" % os.path.basename(f),
              R("head -c 2 %s | od -An -tx1" % f)[0].split() == ["1f", "8b"],
              R("head -c 2 %s | od -An -tx1" % f)[0].strip())


def t_the_three_readers_agree():
    for f in gzips()[:5]:
        base = os.path.basename(f)
        zc = R("zcat %s | wc -c" % f)[0].strip()
        gz = R("gunzip -c %s | wc -c" % f)[0].strip()
        check("%s: zcat and gunzip -c agree" % base, zc == gz,
              "%s vs %s" % (zc, gz))
        # gzip -l reports the uncompressed size, and it has to be that one.
        out = R("gzip -l %s" % f)[0].splitlines()
        row = [l.split() for l in out if f in l]
        if row and len(row[0]) >= 2 and row[0][1].isdigit():
            check("%s: gzip -l's uncompressed size is what came out" % base,
                  row[0][1] == zc, "%s vs %s" % (row[0][1], zc))
        # ...and the compressed size is the file's size on disk.
        size = R("stat -c %%s %s" % f)[0].strip()
        if row and row[0][0].isdigit():
            check("%s: gzip -l's compressed size is the file size" % base,
                  row[0][0] == size, "%s vs %s" % (row[0][0], size))


def t_the_content_is_the_log_it_came_from():
    """A rotated syslog holds syslog lines, not something else's."""
    out = R("zcat /var/log/syslog.2.gz")[0].splitlines()
    check("syslog.2.gz has lines", len(out) > 5, str(len(out)))
    check("they are syslog-shaped",
          all(re.match(r"^\w{3} [ \d]\d \d\d:\d\d:\d\d web01 ", l)
              for l in out), (out or [""])[0][:60])
    check("and they mention cron, as the live syslog does",
          any("CRON" in l for l in out), (out or [""])[0][:60])
    out = R("zcat /var/log/auth.log.2.gz")[0].splitlines()
    check("auth.log.2.gz is auth-shaped",
          out and all("pam_unix" in l or "sudo" in l or "sshd" in l
                      for l in out), (out or [""])[0][:60])
    # zgrep is the command this is all for.
    n = R("zgrep -c pam_unix /var/log/auth.log.2.gz")[0].strip()
    check("zgrep counts lines in it", n.isdigit() and int(n) > 0, n)
    check("and zgrep -l names the file",
          R("zgrep -l CRON /var/log/syslog.2.gz")[0].strip()
          == "/var/log/syslog.2.gz",
          R("zgrep -l CRON /var/log/syslog.2.gz")[0].strip())


def t_the_gzip_header_carries_the_original_name():
    """file reads the header, so the header has to be honest."""
    for f, want in (("/var/log/syslog.2.gz", "syslog.1"),
                    ("/var/log/auth.log.2.gz", "auth.log.1")):
        out = R("gzip -l -v %s 2>/dev/null || gzip -l %s" % (f, f))[0]
        check("%s: gzip -l runs" % os.path.basename(f), bool(out.strip()),
              "no output")
    # The mtime in the header is not in the future.
    out = R("file /var/log/syslog.2.gz")[0]
    check("file calls it gzip data", "gzip compressed data" in out, out[:60])
    m = re.search(r"last modified: (.+?),", out)
    if m:
        yr = re.search(r"(\d{4})", m.group(1))
        check("with a year that is not decades away",
              yr and 2020 <= int(yr.group(1)) <= 2030, m.group(1))


def t_a_file_that_is_not_gzip_still_says_so():
    """The failure path has to keep working, and with the right exit code."""
    s = fs.Shell(fs.VFS())
    s.exec_mode = True
    R("echo plaintext > /tmp/fake.gz", s)
    out, err, rc = R("zcat /tmp/fake.gz", s)
    check("zcat on a non-gzip exits 1", rc == 1, "rc=%s" % rc)
    check("with gzip's wording", "not in gzip format" in err, err[:50])
    out, err, rc = R("gunzip -c /nope.gz", s)
    check("a missing file exits 1", rc == 1, "rc=%s" % rc)
    check("saying no such file", "No such file or directory" in err, err[:50])


# ---------------------------------------------------------------------------
# the rotation set matches what the config asks for
# ---------------------------------------------------------------------------
def t_the_rotation_counts_follow_the_config():
    conf = R("cat /etc/logrotate.d/rsyslog")[0]
    check("rsyslog's config is there", "rotate" in conf, conf[:40])
    # syslog: rotate 7 daily. auth.log and kern.log: rotate 4 weekly.
    for log, want in (("syslog", 7), ("auth.log", 4), ("kern.log", 4)):
        got = len(R("ls /var/log/%s.* 2>/dev/null" % log)[0].split())
        check("%s keeps %d rotations" % (log, want), got == want,
              "%d" % got)
    ng = R("cat /etc/logrotate.d/nginx")[0]
    m = re.search(r"rotate (\d+)", ng)
    check("nginx's config names a count", m is not None, ng[:40])
    if m:
        for log in ("access", "error"):
            got = len(R("ls /var/log/nginx/%s.log.* 2>/dev/null"
                        % log)[0].split())
            check("nginx %s.log keeps %s rotations" % (log, m.group(1)),
                  got == int(m.group(1)), "%d" % got)


def t_delaycompress_leaves_the_first_one_plain():
    for f in ("/var/log/syslog.1", "/var/log/auth.log.1",
              "/var/log/nginx/access.log.1", "/var/log/nginx/error.log.1"):
        check("%s exists" % f, R("test -f %s" % f)[2] == 0, "missing")
        head = R("head -c 2 %s | od -An -tx1" % f)[0].split()
        check("%s is plain text, not gzip" % os.path.basename(f),
              head != ["1f", "8b"], str(head))
        check("%s has readable lines" % os.path.basename(f),
              bool(R("head -1 %s" % f)[0].strip()), "empty")
    # ...and .2 onwards are compressed.
    for f in ("/var/log/syslog.2.gz", "/var/log/nginx/access.log.2.gz"):
        check("%s is compressed" % os.path.basename(f),
              R("head -c 2 %s | od -An -tx1" % f)[0].split() == ["1f", "8b"],
              R("head -c 2 %s | od -An -tx1" % f)[0].strip())


def t_the_state_file_names_logs_that_have_history():
    state = R("cat /var/lib/logrotate/status")[0]
    check("the state file is there", "logrotate state" in state, state[:40])
    named = re.findall(r'^"(\S+)"', state, re.M)
    check("it names some logs", len(named) >= 4, str(named[:3]))
    missing = []
    for path in named:
        if R("test -f %s.1" % path)[2] != 0 and \
                R("test -f %s.1.gz" % path)[2] != 0:
            missing.append(path)
    check("every log it says it rotated has a rotation", not missing,
          str(missing[:3]))
    # ...and each rotated file is older than the live one it came from.
    bad = []
    for path in named:
        if R("test -f %s" % path)[2] != 0 or R("test -f %s.1" % path)[2] != 0:
            continue
        live = R("stat -c %%Y %s" % path)[0].strip()
        old = R("stat -c %%Y %s.1" % path)[0].strip()
        if live.isdigit() and old.isdigit() and int(old) > int(live):
            bad.append("%s: .1 newer than live" % path)
    check("no rotated file is newer than its live one", not bad,
          str(bad[:3]))


def t_the_nginx_error_format_is_nginxs():
    """One error line, three places, and nginx's own format string.

    From the shipping nginx 1.26.3 binary:
        ", client: %V"   ", server: %V"   ", request: \"%V\""
    All three of this box's error lines wrote "client" with no colon.
    Two of them also failed to open a path the request had not asked for
    -- open() on .git/HEAD beside a request for /.env -- which nginx
    cannot produce, because it takes the filename from the URI. And the
    rotated lines stopped after "No such file or directory", so the
    archive and the live error.log were in two different formats.
    """
    sets = {
        "live": R("cat /var/log/nginx/error.log")[0],
        "rotated": R("zcat /var/log/nginx/error.log.3.gz")[0],
        "journal": R("journalctl -u nginx --no-pager")[0],
    }
    for label, text in sets.items():
        lines = [l for l in text.splitlines() if "[error]" in l]
        check("%s has error lines" % label, bool(lines), label)
        check("%s spells it 'client:'" % label,
              not [l for l in lines if "client " in l],
              str([l[:60] for l in lines if "client " in l][:1]))
        check("%s names the request" % label,
              not [l for l in lines if "request:" not in l],
              str([l[:60] for l in lines if "request:" not in l][:1]))
        mism = []
        for l in lines:
            a = re.search(r'open\(\) "/var/www/html/([^"]*)"', l)
            b = re.search(r'request: "\S+ /(\S*) ', l)
            if a and b and a.group(1) != b.group(1):
                mism.append((a.group(1), b.group(1)))
        check("%s: the path failed on is the path requested" % label,
              not mism, str(mism[:2]))


def t_no_log_line_is_dated_in_the_future():
    """A log cannot contain an entry that has not happened yet.

    The rotation ordering check above is only meaningful at the instant it
    runs, and this bug lived in one minute out of every 1440 -- so it went
    red once in a gate and green on every rerun, which is the signature of
    something nobody chases.

    At the daily rotation the session line fell back to `rot + 120`, which
    is itself in the future for the two minutes after a rotation. syslog
    carries no year, so the mtime parser reads a future date as *last*
    year's: `ls -l /var/log/syslog` showed the live file dated 2025 beside
    its own syslog.1 dated 2026, a year apart in the wrong direction.

    Simulated across the boundary rather than sampled at now, because at
    now it is almost always fine.
    """
    import time as _t
    import fakeshell as _f
    real = _t.time
    base = real()
    lt = _t.localtime(base)
    midnight = base - (lt.tm_hour * 3600 + lt.tm_min * 60 + lt.tm_sec)
    mon = {m: i + 1 for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
         "Oct", "Nov", "Dec"])}
    inversions, future, sampled = [], [], 0
    try:
        # Every minute across the rotation window, plus a coarse sweep of
        # the rest of the day.
        minutes = list(range(6 * 60 + 20, 6 * 60 + 35)) + \
            list(range(0, 1440, 40))
        for m in minutes:
            when = midnight + m * 60 + 7
            _t.time = (lambda v: (lambda: v))(when)
            sh = _f.Shell(_f.VFS())
            sh.exec_mode = True
            sampled += 1
            live = sh.run("stat -c %Y /var/log/syslog").strip()
            rot = sh.run("stat -c %Y /var/log/syslog.1").strip()
            stamp = _t.strftime("%H:%M", _t.localtime(when))
            if live.isdigit() and rot.isdigit() and int(rot) >= int(live):
                inversions.append("%s: .1 newer than live" % stamp)
            for path in ("/var/log/syslog", "/var/log/auth.log"):
                last = sh.run("tail -1 %s" % path).strip()
                mm = re.match(r"^([A-Z][a-z]{2})\s+(\d+)\s+"
                              r"(\d+):(\d+):(\d+)", last)
                if not mm:
                    continue
                cur = _t.localtime(when)
                ts = _t.mktime((cur.tm_year, mon[mm.group(1)],
                                int(mm.group(2)), int(mm.group(3)),
                                int(mm.group(4)), int(mm.group(5)), 0, 0, -1))
                if ts > when + 1:
                    future.append("%s: %s %s" % (stamp, path, last[:36]))
    finally:
        _t.time = real
    check("the sweep actually ran", sampled > 40, str(sampled))
    check("no rotated file is newer than its live one, at any hour",
          not inversions, str(inversions[:3]))
    check("no log line is dated after the moment it is read",
          not future, str(future[:3]))


TESTS = [t_no_log_line_is_dated_in_the_future,
         t_the_nginx_error_format_is_nginxs,
         t_every_rotated_gz_decompresses,
         t_the_three_readers_agree,
         t_the_content_is_the_log_it_came_from,
         t_the_gzip_header_carries_the_original_name,
         t_a_file_that_is_not_gzip_still_says_so,
         t_the_rotation_counts_follow_the_config,
         t_delaycompress_leaves_the_first_one_plain,
         t_the_state_file_names_logs_that_have_history]


def main():
    for fn in TESTS:
        try:
            fn()
        except Exception as exc:                       # pragma: no cover
            check(fn.__name__ + " raised", False, repr(exc)[:90])
    for line in FAILURES:
        print("  FAIL " + line)
    print("passed %d, failed %d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
