#!/usr/bin/env python3
"""Do the log surfaces agree with each other and with the rest of the box?

An attacker's first commands after getting in are `w`, `last` and
`cat /var/log/auth.log`, and their last one is clearing them. This sweep
asked whether those surfaces tell one story.

What it found:

  - /var/log/auth.log, syslog and kern.log existed with no rsyslog package,
    no rsyslogd process and no rsyslog unit. Debian trixie itself ships none
    of those files, because it logs to the journal -- only rsyslog writes
    them. Files that nothing on the box could have produced, which is the
    same shape as the postfix listener a previous sweep closed, inverted.
  - auth.log had no record of the live session. Anyone grepping the file for
    their own address -- the obvious thing to do before deciding what to
    clean -- found nothing, on a box whose who, w and last all showed them
    logged in.
  - `last` claimed root was still logged in on tty1 while `who` showed only
    pts/0 and `w` said "1 user". agetty is alive on tty1 in ps, so nobody
    can be logged in there at all.
  - `lastlog` put deploy's most recent login 26 hours ago while `last`
    listed a deploy session five hours ago. lastlog reports the *latest*
    login per user; it cannot be older than one last is still showing.
  - wtmp, btmp, lastlog and faillog were all root:root 660 and all exactly
    384 bytes -- one utmp record -- on a box where `last` prints six
    sessions. Measured on the guest: group utmp, modes 664/660/664/664,
    wtmp a multiple of the 384-byte record, btmp and lastlog empty.
  - "1 user" in uptime/w was a literal and could not follow utmp.

/run/utmp WAS deliberately absent here, because it does not exist on real
trixie either -- systemd dropped utmp for logind. That was measured, not
guessed. It was reversed by the session sweep for a reason worth recording:
the box was only half a trixie. It kept a wtmp login history and answered
`last`, which a real trixie does not, while who/w/users all read a
/run/utmp that was not there. Half of one story and half of the other is
detectable by comparing two commands; a complete story is not. The box now
commits to the utmp-era half, because that is the half carrying the bait
attackers have actually been seen chasing.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(peer="203.0.113.77", user="root"):
    s = fs.Shell(fs.VFS(), peer=peer, user=user)
    s.exec_mode = True
    return s


def run(s, cmd):
    out = s.run(cmd)
    err = "".join(s._err)
    s._err.clear()
    return (out + err), s.last_rc


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-46s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


# ------------------------------------------------- rsyslog must exist
def t_rsyslog_backs_its_own_log_files():
    s = sh()
    for f in ("/var/log/auth.log", "/var/log/syslog"):
        o, rc = run(s, "test -s %s && echo ok" % f)
        eq("%s exists and is non-empty" % f, (o.strip(), rc), ("ok", 0))
    # kern.log is allowed to be empty: it rotates weekly, the kernel on an
    # idle VM says something every few days, and just after a rotation
    # there is genuinely nothing in it. What has to hold is that the file
    # exists and that the copy from last week is not empty -- something
    # wrote kernel messages, which is what this test is really asking.
    o, rc = run(s, "test -f /var/log/kern.log && echo ok")
    eq("/var/log/kern.log exists", (o.strip(), rc), ("ok", 0))
    o, rc = run(s, "test -s /var/log/kern.log.1 && echo ok")
    eq("last week's kern.log is not empty", (o.strip(), rc), ("ok", 0))
    # ...so the daemon that writes them has to be here, in all four places.
    o, rc = run(s, "dpkg -l rsyslog")
    check("rsyslog is installed", rc == 0 and "rsyslog" in o, o[-60:])
    o, _ = run(s, "ps -eo comm --no-headers")
    check("rsyslogd is running", "rsyslogd" in o.split(), "not in ps")
    o, _ = run(s, "systemctl is-active rsyslog")
    eq("the unit is active", o.strip(), "active")
    o, _ = run(s, "systemctl is-enabled rsyslog")
    eq("the unit is enabled", o.strip(), "enabled")
    o, rc = run(s, "test -f /etc/rsyslog.conf && echo ok")
    eq("it has a config", (o.strip(), rc), ("ok", 0))
    # And the config has to name the files that exist.
    o, _ = run(s, "cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf")
    for f in ("auth.log", "syslog", "kern.log"):
        check("rsyslog.conf routes to %s" % f, f in o, "not routed")


def t_rsyslogd_process_is_coherent():
    s = sh()
    o, _ = run(s, "pgrep -x rsyslogd")
    check("pgrep finds it", o.strip().isdigit(), o[:40])
    if not o.strip().isdigit():
        return
    pid = o.strip()
    o, _ = run(s, "readlink /proc/%s/exe" % pid)
    eq("its exe is the real path", o.strip(), "/usr/sbin/rsyslogd")
    o, rc = run(s, "test -e /usr/sbin/rsyslogd && echo ok")
    eq("and that binary exists", (o.strip(), rc), ("ok", 0))
    o, _ = run(s, "dpkg -S /usr/sbin/rsyslogd")
    check("dpkg can be asked about it", "rsyslog" in o or "no path" in o,
          o[:60])
    o, _ = run(s, "systemctl show rsyslog -p MainPID --value")
    if o.strip().isdigit() and o.strip() != "0":
        eq("systemd's MainPID matches ps", o.strip(), pid)


# ------------------------------------------- the session commands agree
def t_who_w_users_agree():
    s = sh()
    who, _ = run(s, "who")
    users, _ = run(s, "users")
    w, _ = run(s, "w")
    names_who = sorted(l.split()[0] for l in who.splitlines() if l.strip())
    eq("users matches who", sorted(users.split()), names_who)
    names_w = sorted(l.split()[0] for l in w.splitlines()[2:] if l.strip())
    eq("w matches who", names_w, names_who)
    # The count in the uptime line is the number of utmp entries.
    m = re.search(r"(\d+) users?,", w)
    check("w states a user count", m, w.splitlines()[0] if w else "")
    if m:
        eq("the count matches the rows", int(m.group(1)), len(names_who))
    o, _ = run(s, "uptime")
    m2 = re.search(r"(\d+) users?,", o)
    if m and m2:
        eq("uptime agrees with w", m2.group(1), m.group(1))


def t_still_logged_in_means_a_utmp_entry():
    """`last` said root was on tty1 since boot; who showed only pts/0."""
    s = sh()
    last, _ = run(s, "last")
    who, _ = run(s, "who")
    live = [l for l in last.splitlines() if "still logged in" in l]
    ttys_last = sorted(l.split()[1] for l in live)
    ttys_who = sorted(l.split()[1] for l in who.splitlines() if l.strip())
    eq("every 'still logged in' has a who entry", ttys_last, ttys_who)


def t_agetty_owns_tty1():
    """If agetty is on tty1, nobody is logged in there."""
    s = sh()
    o, _ = run(s, "ps -eo args --no-headers")
    if "agetty" not in o:
        return
    check("agetty holds tty1", "tty1" in o, "agetty not on tty1")
    who, _ = run(s, "who")
    check("so who shows no tty1 session",
          not any(l.split()[1:2] == ["tty1"]
                  for l in who.splitlines() if l.strip()), who[:70])


def t_lastlog_is_sized_by_who_has_logged_in():
    """It was 0 bytes on a box whose own `last` lists deploy sessions.

    lastlog is indexed by uid: the record for uid N sits at offset N*292,
    so logging in as uid N extends the file to (N+1)*292 and leaves a hole
    in front of it. An empty lastlog means nobody has ever logged in, and
    `last` says otherwise -- one file and one command disagreeing about
    whether this box has ever had a user on it.

    The reference reads 292584, which is exactly 1002*292 for a box whose
    highest uid to have logged in is 1001, and it occupies 4096 bytes on
    disk. Ours is derived from the same wtmp seed `last` reads.
    """
    s = sh()
    size = int(run(s, "stat -c %s /var/log/lastlog")[0].strip())
    check("lastlog is not empty", size > 0, size)
    eq("...and is a whole number of 292-byte records", size % 292, 0)
    # The highest uid with a login record, from the command that reads the
    # same seed.
    last_out, _ = run(s, "last")
    pw = dict((l.split(":")[0], int(l.split(":")[2]))
              for l in run(s, "cat /etc/passwd")[0].split("\n")
              if l.count(":") == 6 and l.split(":")[2].isdigit())
    users = {l.split()[0] for l in last_out.split("\n")
             if l.split() and l.split()[0] in pw}
    hi = max(pw[u] for u in users) if users else 0
    eq("lastlog covers exactly the uids that have logged in",
       size, (hi + 1) * 292)
    # Sparse: length is not occupancy, and the whole file must not sit in
    # RSS just because it is 292 KB long.
    blocks = int(run(s, "stat -c %b /var/log/lastlog")[0].strip())
    check("...and it is sparse", blocks * 512 <= 8192,
          "%d blocks" % blocks)
    eq("ownership is root:utmp",
       run(s, 'stat -c "%U:%G %a" /var/log/lastlog')[0].strip(),
       "root:utmp 664")
    # btmp stays empty -- the reference's is 0 too, and a failed-login log
    # that fills itself would be its own kind of wrong.
    eq("btmp is still empty",
       run(s, "stat -c %s /var/log/btmp")[0].strip(), "0")


def t_lastlog_is_not_older_than_last():
    s = sh()
    last, _ = run(s, "last")
    lastlog, _ = run(s, "lastlog")
    # Most recent session per user, out of `last`.
    newest = {}
    for line in last.splitlines():
        f = line.split()
        if len(f) < 5 or f[0] in ("reboot", "wtmp"):
            continue
        user = f[0]
        newest.setdefault(user, line)          # last lists newest first
    for line in lastlog.splitlines()[1:]:
        f = line.split()
        if len(f) < 4 or "Never" in line:
            continue
        user = f[0]
        if user not in newest:
            continue
        # Compare on the date+time text `last` prints; both come from the
        # same table now, so the day and HH:MM must match.
        m = re.search(r"(\w{3}) (\w{3})\s+(\d+) (\d\d:\d\d)", newest[user])
        check("lastlog for %s matches last" % user,
              m and m.group(4) in line and m.group(2) in line,
              "last=%r lastlog=%r" % (newest[user][:50], line[:70]))


def t_our_own_session_is_in_auth_log():
    """The check an attacker makes before deciding what to clean."""
    s = sh(peer="198.51.100.23")
    o, rc = run(s, "grep 198.51.100.23 /var/log/auth.log")
    check("auth.log records the live session", rc == 0 and o.strip(),
          "nothing for our address")
    check("it says Accepted", "Accepted" in o, o[:80])
    check("it names the user", "root" in o, o[:80])
    o2, _ = run(s, "grep 'session opened for user root' /var/log/auth.log")
    check("a pam session-opened line too", o2.strip(), "missing")
    # The sshd pid in auth.log has to be the sshd in ps. The tag is
    # sshd-session: OpenSSH 9.8 split the per-connection process out, and
    # this box advertises 10.0p2. And the comment above was the whole test
    # -- it matched a pid and never looked for it in ps.
    m = re.search(r"sshd-session\[(\d+)\]: Accepted", o)
    check("the Accepted line names an sshd-session pid", m, o[:60])
    if m:
        ps, _ = run(s, "ps -eo pid,args")
        row = [l for l in ps.splitlines()
               if l.split(None, 1)[0] == m.group(1)]
        check("that pid is the sshd-session in ps",
              row and "sshd-session:" in row[0], (row or [""])[0][:60])
    if m:
        ps, _ = run(s, "ps -eo pid --no-headers")
        check("that pid is in ps", m.group(1) in ps.split(),
              "pid %s absent" % m.group(1))


def t_auth_log_grows_with_the_session():
    """Two different peers must not produce identical auth.log tails."""
    a, _ = run(sh(peer="198.51.100.1"), "tail -3 /var/log/auth.log")
    b, _ = run(sh(peer="198.51.100.2"), "tail -3 /var/log/auth.log")
    check("the tail reflects who is connected", a != b, "identical")
    check("each names its own peer",
          "198.51.100.1" in a and "198.51.100.2" in b, "peer missing")


# ------------------------------------------------------- the utmp family
def t_utmp_family_ownership_and_size():
    s = sh()
    # Measured on the guest: group utmp, and the modes differ per file.
    for f, mode in (("wtmp", "664"), ("btmp", "660"),
                    ("lastlog", "664"), ("faillog", "664")):
        o, _ = run(s, "stat -c '%U %G %a' /var/log/" + f)
        eq("/var/log/%s ownership and mode" % f, o.strip(),
           "root utmp " + mode)
    # wtmp holds whole 384-byte utmp records and must be able to hold what
    # `last` claims to read out of it.
    o, _ = run(s, "stat -c %s /var/log/wtmp")
    size = int(o.strip())
    eq("wtmp is a whole number of utmp records", size % 384, 0)
    last, _ = run(s, "last")
    sessions = [l for l in last.splitlines()
                if l.strip() and not l.startswith("wtmp begins")]
    check("wtmp is big enough for what last prints",
          size // 384 >= len(sessions),
          "%d records for %d lines" % (size // 384, len(sessions)))
    # btmp is empty -- the reference box's is 0 bytes too, and a
    # failed-login log that fills itself would be its own kind of wrong.
    # lastlog is NOT: it was measured on a fresh install, where nobody had
    # logged in yet, and this box has a login history. It is sized by uid
    # in t_lastlog_is_sized_by_who_has_logged_in above.
    for f in ("btmp",):
        o, _ = run(s, "stat -c %s /var/log/" + f)
        eq("/var/log/%s is empty" % f, o.strip(), "0")


def t_run_utmp_backs_the_commands_that_read_it():
    """who, w and users all source /run/utmp, so it has to be there."""
    s = sh()
    o, rc = run(s, "ls -l /run/utmp")
    check("/run/utmp exists", rc == 0, o[:60])
    check("owned by group utmp like the rest of the family", " utmp " in o,
          o[:60])
    o, rc = run(s, "who")
    check("who reports a session", rc == 0 and o.strip(),
          "who produced nothing")
    size, _ = run(s, "wc -c < /run/utmp")
    n = int(size.strip())
    check("utmp is a whole number of 384-byte records", n % 384 == 0, size)
    users, _ = run(s, "who | wc -l")
    # Boot and run-level records, plus one per live session.
    check("utmp holds the sessions who reports", n // 384 == 2 + int(users),
          "%d records vs %s sessions" % (n // 384, users.strip()))


def t_syslog_trio_ownership():
    s = sh()
    for f in ("auth.log", "syslog", "kern.log"):
        o, _ = run(s, "stat -c '%U %G %a' /var/log/" + f)
        eq("/var/log/%s is root:adm 640" % f, o.strip(), "root adm 640")


def t_log_timestamps_are_not_in_the_future():
    s = sh()
    now = time.time()
    for f in ("auth.log", "syslog", "wtmp", "kern.log"):
        o, _ = run(s, "stat -c %Y /var/log/" + f)
        ts = int(o.strip() or 0)
        check("%s mtime is not in the future" % f, ts <= now + 5,
              "%d vs %d" % (ts, now))
        check("%s mtime is after boot" % f, ts >= fs.BOOT_TS - 86400,
              "%d before boot" % ts)


def t_logrotate_knows_about_these_files():
    """A log with no rotation config on a 41-day-old box grows forever."""
    s = sh()
    o, rc = run(s, "ls /etc/logrotate.d")
    if rc != 0:
        return
    conf, _ = run(s, "cat /etc/logrotate.conf /etc/logrotate.d/* 2>/dev/null")
    for f in ("syslog", "auth.log"):
        check("logrotate mentions %s" % f, f in conf,
              "no rotation configured")



def t_boot_records_agree():
    """`last reboot`, `who -b`, uptime and /proc/uptime name one boot."""
    s = sh()
    o, _ = run(s, "last reboot")
    m = re.search(r"still running", o)
    check("last reboot shows the running boot", m, o[:80])
    o2, _ = run(s, "who -b")
    check("who -b reports a boot time", "system boot" in o2, o2[:60])
    o3, _ = run(s, "cut -d. -f1 /proc/uptime")
    up = int(o3.strip() or 0)
    o4, _ = run(s, "uptime")
    m2 = re.search(r"up (\d+) days?,\s+(\d+):(\d+)", o4)
    check("uptime states days and hours", m2, o4[:70])
    if m2:
        stated = (int(m2.group(1)) * 86400 + int(m2.group(2)) * 3600
                  + int(m2.group(3)) * 60)
        check("uptime matches /proc/uptime within a minute",
              abs(stated - up) < 120, "%d vs %d" % (stated, up))
    # who -b's timestamp must be now minus uptime.
    m3 = re.search(r"(\d{4}-\d\d-\d\d \d\d:\d\d)", o2)
    if m3:
        boot = time.mktime(time.strptime(m3.group(1), "%Y-%m-%d %H:%M"))
        check("who -b lands on now minus uptime",
              abs((time.time() - up) - boot) < 120,
              "%s vs %d" % (m3.group(1), int(time.time() - up)))

def _render(s, records):
    """Render the nginx access log from a list of capture records, the way
    the shell renders it from the live HTTP capture."""
    import json as _json
    import tempfile
    import os as _os
    fd, path = tempfile.mkstemp(prefix="acclog-")
    with _os.fdopen(fd, "w") as fh:
        for rec in records:
            fh.write(_json.dumps(rec) + "\n")
    old = fs._HTTP_LOG
    try:
        fs._HTTP_LOG = path
        v = fs.VFS()
        acc, _err = v._nginx_logs()
        return acc
    finally:
        fs._HTTP_LOG = old
        _os.unlink(path)


def t_the_access_log_records_the_whole_request_line():
    """nginx logs $request -- method, full URI, protocol. This logged the
    path without its query string, so 459 captured requests appeared in
    the log stripped of the part that says what they were doing:

        capture:  POST /index.php?rest_route=/batch/v1
        log line: "POST /index.php HTTP/1.1"

    Found by asking whether the web half and the shell half of this
    honeypot agree about the same request. An actor who lands on the box
    and reads access.log to see what else has been probing it -- or to
    find their own traffic -- was being shown something different from
    what arrived.
    """
    s = sh()
    body = _render(s, [
        {"ts": "2026-08-22T04:08:40+00:00", "real_ip": "203.0.113.9",
         "method": "POST", "path": "/index.php",
         "query": "rest_route=/batch/v1", "status": 207, "sent": 33},
        {"ts": "2026-08-22T04:08:41+00:00", "real_ip": "203.0.113.9",
         "method": "GET", "path": "/wp-login.php", "status": 200,
         "sent": 2660},
    ])
    lines = [l for l in body.splitlines() if l.strip()]
    check("the query string survives",
          '"POST /index.php?rest_route=/batch/v1 HTTP/1.1"' in body,
          lines[0] if lines else "")
    check("a request without one is unchanged",
          '"GET /wp-login.php HTTP/1.1"' in body,
          lines[-1] if lines else "")
    check("and no stray ? is added",
          "/wp-login.php?" not in body, body[:80])


def t_rotated_logs_are_fourteen_different_days():
    """Two weeks of nginx history, and no two days the same.

    `body` was computed once and written to access.log.1 and to all
    thirteen .gz files behind it, so `zcat access.log.5.gz | md5sum`
    equalled `md5sum access.log.1`: fourteen days of history in which
    every day was a byte-for-byte copy, on a box whose logrotate config
    says it keeps two weeks.

    And each of those days was sixty copies of `GET / HTTP/1.1 200` with
    sizes marching 180, 183, 186 and one client per line out of a 40-wide
    block, so `awk '{print $1}' | sort | uniq -c` gave a dozen clients on
    exactly 28 hits and three distinct counts in the whole file. Real
    traffic is Pareto, and this box has its own numbers to shape it: its
    HTTP log carries 43,003 hits on /xmlrpc.php against 4,278 on
    /wp-login.php and a long tail below.
    """
    z = sh()
    digests = {}
    for name in ["access.log.1"] + ["access.log.%d.gz" % n
                                    for n in range(2, 15)]:
        if name.endswith(".gz"):
            d = run(z, "zcat /var/log/nginx/%s | md5sum" % name)[0].split()
        else:
            d = run(z, "md5sum /var/log/nginx/%s" % name)[0].split()
        if d:
            digests[name] = d[0]
    check("all fourteen rotated files are present", len(digests) == 14,
          "%d found" % len(digests))
    check("no two rotated days are identical",
          len(set(digests.values())) == len(digests),
          "%d distinct of %d" % (len(set(digests.values())), len(digests)))
    counts = set()
    for name in digests:
        cat = "zcat" if name.endswith(".gz") else "cat"
        counts.add(run(z, "%s /var/log/nginx/%s | wc -l" % (cat, name))[0].strip())
    check("their line counts differ", len(counts) > 3,
          "counts seen: %r" % sorted(counts)[:6])

    body = run(z, "cat /var/log/nginx/access.log.1")[0]
    lines = [l for l in body.splitlines() if '"' in l]
    check("the day has enough lines to judge", len(lines) > 40, str(len(lines)))
    import collections as _c
    hits = _c.Counter(l.split()[0] for l in lines)
    check("more than a handful of clients", len(hits) > 10,
          "%d clients" % len(hits))
    check("client hits are not all the same number",
          len(set(hits.values())) > 3,
          "counts: %r" % sorted(set(hits.values()))[:8])
    top = hits.most_common(1)[0][1]
    check("a heavy client is heavier than the tail",
          top >= 3 * min(hits.values()),
          "top %d vs min %d" % (top, min(hits.values())))
    # Clients read as real addresses. They were all inside 203.0.113.0/24
    # -- RFC 5737 TEST-NET-3 -- so fourteen days of logs came from a range
    # reserved for documentation, which anyone who knows the RFCs spots at
    # a glance. Miles chose real-looking addresses over that, with the
    # tradeoff understood; the invariant is that none of them can be an
    # address a real client could never have.
    import ipaddress as _ip
    bad = []
    for a in set(l.split()[0] for l in lines):
        try:
            addr = _ip.ip_address(a)
        except ValueError:
            bad.append(a)
            continue
        if (addr.is_private or addr.is_reserved or addr.is_multicast
                or addr.is_loopback or addr.is_link_local
                or a.startswith(("192.0.2.", "198.51.100.", "203.0.113."))):
            bad.append(a)
    check("no client is a reserved or documentation address", bad == [],
          "%d bad: %r" % (len(bad), bad[:4]))
    check("clients are spread across many networks",
          len(set(a.split(".")[0] for a in
                  set(l.split()[0] for l in lines))) > 8,
          "%d distinct first octets"
          % len(set(a.split(".")[0] for a in
                    set(l.split()[0] for l in lines))))
    paths = set(l.split('"')[1] for l in lines)
    check("more than one request line", len(paths) > 3,
          "paths: %r" % sorted(paths)[:5])
    check("the heaviest path is the one the box actually gets",
          any("xmlrpc" in p for p in paths), sorted(paths)[:4])
    agents = set(l.rsplit('"', 2)[-2] for l in lines if l.count('"') >= 4)
    check("more than one user agent", len(agents) > 2,
          "%d agents" % len(agents))
    sizes = [int(l.split('" ')[1].split()[1]) for l in lines if '" ' in l]
    check("response sizes are not an arithmetic run",
          len(set(sizes)) > 10 and
          len(set(sizes[i + 1] - sizes[i] for i in range(len(sizes) - 1))) > 3,
          "%d distinct sizes" % len(set(sizes)))
    # ordered oldest first, as a log written by appending must be
    stamps = [l.split("[")[1].split("]")[0] for l in lines if "[" in l]
    check("the file is in chronological order",
          stamps == sorted(stamps, key=lambda x: (x[7:11], x[3:6], x[0:2],
                                                  x[12:])),
          "first %r last %r" % (stamps[:1], stamps[-1:]))


TESTS = [t_rsyslog_backs_its_own_log_files, t_boot_records_agree, t_rsyslogd_process_is_coherent,
         t_who_w_users_agree, t_still_logged_in_means_a_utmp_entry,
         t_agetty_owns_tty1, t_lastlog_is_not_older_than_last,
         t_lastlog_is_sized_by_who_has_logged_in,
         t_our_own_session_is_in_auth_log, t_auth_log_grows_with_the_session,
         t_utmp_family_ownership_and_size, t_run_utmp_backs_the_commands_that_read_it,
         t_syslog_trio_ownership, t_log_timestamps_are_not_in_the_future,
         t_logrotate_knows_about_these_files,
         t_the_access_log_records_the_whole_request_line,
         t_rotated_logs_are_fourteen_different_days]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
