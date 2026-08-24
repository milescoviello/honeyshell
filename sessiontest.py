#!/usr/bin/env python3
"""Does the box agree with itself about who is logged in, and when?

`w`, `who` and `last` are what an attacker runs to find out whether an
admin is watching, so the answers have to hold still and agree.

  - The login history moved. `last` built its past sessions as offsets from
    time.time(), so a session it reported at 11:38 was reported at 12:38 an
    hour later, and again at 13:38 an hour after that. Records in wtmp do
    not change once written. Anchored to the boot time, which is fixed.
  - /var/log/wtmp was a flat 10 records while `last` printed a history of
    its own, unrelated length: the file could not have held what the
    command read out of it. The size is derived from the history now.
  - `lastlog` printed login records out of a /var/log/lastlog that is zero
    bytes, while `command -v lastlog` said the binary did not exist. Debian
    13 dropped lastlog from shadow -- the real trixie guest this box is
    modelled on has neither the command nor a non-empty file -- so the
    command is gone and the empty file is right.
  - `command -v last` found /usr/bin/last while `dpkg -S /usr/bin/last`
    found no owner and no installed package shipped it. trixie moved
    last/lastb/mesg/utmpdump out of util-linux into util-linux-extra when
    utmp went away; that package is installed here now and owns them.
    lastb and utmpdump did not exist at all.
  - who, w and users all read /run/utmp and all reported a live session, on
    a box where /run/utmp did not exist. Stock trixie really has no
    /run/utmp, and an earlier sweep left it absent for that reason -- but
    the same box kept a wtmp history and answered `last`, which that trixie
    would not. It was half one story and half the other, and the mix is
    what two commands can catch. It commits to the utmp-era half now.
  - `loginctl` reported session 4201 while the journal said "New session 41
    of user root" for the same login, and printed five columns where the
    systemd 257 this box claims prints nine. Every subcommand fell through
    to the session table, so `loginctl show-session N` printed the list.
  - `w`'s header had one space before WHAT where procps prints two.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def sh(user="root"):
    s = fs.Shell(fs.VFS(), peer="203.0.113.77", user=user)
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
        print("  FAIL %-52s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def with_clock(offset, fn):
    """Run fn with the shell's clock advanced by `offset` seconds."""
    real = time.time
    fs.time.time = lambda: real() + offset
    try:
        return fn()
    finally:
        fs.time.time = real


def t_the_login_history_does_not_move():
    """The contradiction this sweep started from."""
    s = sh()
    now, _ = run(s, "last")
    later = with_clock(7200, lambda: run(s, "last")[0])
    a = [l for l in now.splitlines() if "still logged in" not in l]
    b = [l for l in later.splitlines() if "still logged in" not in l]
    eq("last prints the same past two hours later", a, b)
    if a != b:
        for x, y in zip(a, b):
            if x != y:
                print("      was: %s\n      now: %s" % (x, y))
    # And a day later, for good measure.
    c = with_clock(86400, lambda: run(s, "last")[0])
    eq("and the same a day later",
       [l for l in c.splitlines() if "still logged in" not in l], a)


def t_wtmp_size_matches_the_history_last_prints():
    s = sh()
    size, _ = run(s, "wc -c < /var/log/wtmp")
    n = int(size.strip())
    check("wtmp is a whole number of 384-byte records", n % 384 == 0, size)
    out, _ = run(s, "last")
    body = out.split("\nwtmp begins")[0]
    lines = [l for l in body.splitlines() if l.strip()]
    closed = [l for l in lines if re.search(r"\(\d\d:\d\d\)", l)]
    open_ = [l for l in lines if "still logged in" in l]
    boots = [l for l in lines if l.startswith("reboot")]
    # A boot record and a run-level record, a login and a logout for each
    # finished session, and one login for each session still open.
    want = 2 + 2 * len(closed) + len(open_)
    eq("wtmp holds exactly the records last accounts for", n // 384, want)
    eq("exactly one boot in the history", len(boots), 1)


def t_last_and_who_and_w_agree_on_the_live_session():
    s = sh()
    w_out, _ = run(s, "w")
    who_out, _ = run(s, "who")
    last_out, _ = run(s, "last -1")
    users_out, _ = run(s, "users")
    eq("users names us", users_out.strip(), s.user)
    check("who names us", who_out.split()[0] == s.user, who_out[:60])
    check("last names us first", last_out.split()[0] == s.user,
          last_out[:60])
    check("last shows the session open", "still logged in" in last_out,
          last_out[:80])
    check("who reports the peer", s.peer in who_out, who_out[:80])
    check("w reports the peer", s.peer in w_out, w_out[:120])
    check("last reports the peer", s.peer in last_out, last_out[:80])
    # The times all come from one login.
    tw = re.search(r"(\d\d:\d\d)", who_out.split("(")[0])
    tl = re.search(r"(\d\d:\d\d)\s+still", last_out)
    check("who and last agree on the login minute",
          tw and tl and tw.group(1) == tl.group(1),
          "%s vs %s" % (tw and tw.group(1), tl and tl.group(1)))
    n_users = re.search(r"(\d+) users?,", w_out)
    check("w's user count matches who", n_users and
          int(n_users.group(1)) == len(who_out.strip().splitlines()),
          w_out.splitlines()[0] if w_out else "")


def t_w_header_matches_procps():
    s = sh()
    o, _ = run(s, "w")
    hdr = o.splitlines()[1]
    eq("w header", hdr,
       "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU  WHAT")
    o, _ = run(s, "w -h")
    check("w -h drops the header", "USER" not in o, o[:60])


def t_lastlog_is_gone_and_its_file_is_empty():
    s = sh()
    o, rc = run(s, "lastlog")
    eq("lastlog is not a command", rc, 127)
    o, rc = run(s, "command -v lastlog")
    eq("and command -v agrees", rc, 1)
    o, rc = run(s, "wc -c < /var/log/lastlog")
    eq("the legacy file is still there and empty", o.strip(), "0")
    o, rc = run(s, "dpkg -S /usr/bin/lastlog")
    eq("no package claims it", rc, 1)


def t_every_utmp_tool_that_runs_has_an_owning_package():
    s = sh()
    for tool in ("last", "lastb", "mesg", "utmpdump", "who", "w", "users"):
        path, rc = run(s, "command -v %s" % tool)
        eq("%s is on PATH" % tool, rc, 0)
        o, rc2 = run(s, "dpkg -S %s" % path.strip())
        eq("dpkg -S knows %s" % tool, rc2, 0)
        pkg = o.split(":")[0].strip()
        v, rc3 = run(s, "dpkg-query -W -f '${Version}' %s" % pkg)
        eq("and %s is an installed package" % pkg, rc3, 0)
    # trixie moved `last` and `lastb` out of util-linux-extra and into
    # wtmpdb. Checked on a real trixie: installing util-linux-extra alone
    # leaves no /usr/bin/last at all, and `dpkg -S /usr/bin/last` there
    # answers wtmpdb. This suite used to assert the opposite, so dpkg here
    # named a package that does not provide the file.
    o, _ = run(s, "dpkg -L util-linux-extra")
    for tool in ("mesg", "utmpdump"):
        check("util-linux-extra ships %s" % tool, "/usr/bin/" + tool in o,
              o[:100])
    for tool in ("last", "lastb"):
        check("util-linux-extra does not ship %s" % tool,
              "/usr/bin/" + tool not in o, o[:100])
    o, _ = run(s, "dpkg -L wtmpdb")
    for tool in ("last", "lastb"):
        check("wtmpdb ships %s" % tool, "/usr/bin/" + tool in o, o[:100])
        o2, _ = run(s, "dpkg -S /usr/bin/%s" % tool)
        eq("dpkg -S /usr/bin/%s" % tool, o2.strip(),
           "wtmpdb: /usr/bin/%s" % tool)
    for pkg in ("util-linux-extra", "wtmpdb"):
        o, _ = run(s, "for f in $(dpkg -L %s); do test -e $f || "
                      "echo MISSING $f; done" % pkg)
        eq("every file %s lists exists" % pkg, o.strip(), "")

    # wtmpdb documents the limit three ways and only the bare -N form was
    # parsed, so `last -n 5` -- the spelling in its own help text -- printed
    # every entry there was. Anyone running it is counting lines.
    full, _ = run(s, "last")
    total = len([l for l in full.splitlines()
                 if l.strip() and not l.startswith("wtmp begins")])
    for form in ("-n 1", "--limit 1", "-1"):
        o, _ = run(s, "last %s" % form)
        n = len([l for l in o.splitlines()
                 if l.strip() and not l.startswith("wtmp begins")])
        eq("last %s returns one entry" % form, n, 1)
    check("and the unlimited form still returns more", total > 1,
          "only %d entries" % total)
    # Take the host from the plain output rather than hard-coding one: the
    # live session's peer is whatever this shell was built with.
    plain, _ = run(s, "last -n 1")
    host = plain.split()[2]
    o, _ = run(s, "last -R -n 1")
    check("-R drops the hostname column", host not in o, o[:60])
    o, _ = run(s, "last -a -n 1")
    check("-a moves the hostname to the end",
          o.splitlines()[0].rstrip().endswith(host), o[:70])
    check("-a keeps it out of the third column",
          o.split()[2] != host, o[:70])


def t_lastb_reads_the_empty_btmp():
    s = sh()
    o, rc = run(s, "lastb")
    eq("lastb rc", rc, 0)
    body = [l for l in o.splitlines()
            if l.strip() and not l.startswith("btmp begins")]
    eq("lastb reports no failed logins", body, [])
    check("lastb prints the btmp footer", "btmp begins" in o, o[:80])
    m = re.search(r"btmp begins (.+)", o)
    if m:
        t = time.mktime(time.strptime(m.group(1).strip(),
                                      "%a %b %d %H:%M:%S %Y"))
        # Measured, not guessed: `last -f empty` on util-linux 2.40 prints
        # "begins" with the current time, because "begins" is the first
        # record read and there is no record to read. This suite used to
        # require the file's mtime instead, which no real lastb prints.
        check("an empty btmp begins now, as util-linux prints it",
              abs(t - time.time()) < 300, m.group(1))
    size, _ = run(s, "wc -c < /var/log/btmp")
    eq("btmp is empty, matching what lastb printed", size.strip(), "0")


def t_utmpdump_matches_last():
    s = sh()
    o, rc = run(s, "utmpdump /var/log/wtmp")
    eq("utmpdump rc", rc, 0)
    check("utmpdump announces the file", "Utmp dump of /var/log/wtmp" in o,
          o[:60])
    rows = [l for l in o.splitlines() if l.startswith("[")]
    check("utmpdump produced records", rows, o[:80])
    last_out, _ = run(s, "last")
    for user in set(l.split()[0] for l in last_out.splitlines()
                    if l.strip() and not l.startswith("wtmp")):
        if user == "reboot":
            continue
        check("utmpdump shows %s like last does" % user,
              any(user in r for r in rows), rows[:2])
    o, rc = run(s, "utmpdump /var/log/nope")
    eq("a missing file is an error", rc, 1)


def t_run_utmp_exists_and_matches_who():
    s = sh()
    o, rc = run(s, "ls -l /run/utmp")
    eq("/run/utmp exists", rc, 0)
    check("it belongs to group utmp", " utmp " in o, o[:70])
    size, _ = run(s, "wc -c < /run/utmp")
    n = int(size.strip())
    check("whole records", n % 384 == 0, size)
    who, _ = run(s, "who")
    eq("boot, run-level, and one record per session in who",
       n // 384, 2 + len(who.strip().splitlines()))
    # who -b and who -r are the two extra records, and both come from boot.
    b, _ = run(s, "who -b")
    r, _ = run(s, "who -r")
    check("who -b names the boot", "system boot" in b, b[:60])
    check("who -r names a run level", "run-level" in r, r[:60])
    bt = re.search(r"(\d{4}-\d\d-\d\d \d\d:\d\d)", b)
    check("who -b agrees with uptime", bt, b[:60])
    if bt:
        t = time.mktime(time.strptime(bt.group(1), "%Y-%m-%d %H:%M"))
        check("boot time within a minute of BOOT_TS",
              abs(t - fs.BOOT_TS) < 90, bt.group(1))


def t_loginctl_session_is_the_one_the_journal_logged():
    """One login cannot have two session numbers."""
    s = sh()
    o, rc = run(s, "loginctl")
    eq("loginctl rc", rc, 0)
    m = re.search(r"^\s*(\d+)\s+(\d+)\s+(\S+)", o.splitlines()[1])
    check("loginctl lists a session", m, o[:80])
    if not m:
        return
    sid, uid, user = m.group(1), m.group(2), m.group(3)
    eq("the session belongs to us", user, s.user)
    eq("with our uid", uid, "0")
    j, _ = run(s, "journalctl | grep 'New session' | tail -1")
    check("the journal logged a session for us", "New session" in j, j[:80])
    jm = re.search(r"New session (\d+) of user (\S+)\.", j)
    check("journal session line parses", jm, j[:80])
    if jm:
        eq("loginctl and the journal agree on the session number",
           sid, jm.group(1))
        eq("and on the user", jm.group(2), s.user)


def t_loginctl_columns_and_subcommands():
    s = sh()
    o, _ = run(s, "loginctl")
    hdr = o.splitlines()[0]
    for col in ("SESSION", "UID", "USER", "SEAT", "LEADER", "CLASS", "TTY",
                "IDLE", "SINCE"):
        check("loginctl header has %s" % col, col in hdr, hdr)
    o, rc = run(s, "loginctl list-sessions --no-legend")
    eq("--no-legend rc", rc, 0)
    check("--no-legend drops the header", "SESSION" not in o, o[:60])
    check("--no-legend drops the footer", "listed" not in o, o[:60])
    sid = o.split()[0]
    o, rc = run(s, "loginctl show-session %s" % sid)
    eq("show-session rc", rc, 0)
    d = dict(l.split("=", 1) for l in o.splitlines() if "=" in l)
    eq("show-session Id matches the list", d.get("Id"), sid)
    eq("show-session Name matches the user", d.get("Name"), s.user)
    eq("show-session says it is remote", d.get("Remote"), "yes")
    eq("show-session RemoteHost is the peer", d.get("RemoteHost"), s.peer)
    eq("show-session Service is sshd", d.get("Service"), "sshd")
    eq("show-session Scope names the session", d.get("Scope"),
       "session-%s.scope" % sid)
    check("show-session is not the session table", "SESSION" not in o, o[:60])
    o, rc = run(s, "loginctl show-session 99999")
    eq("an unknown session is an error", rc, 1)
    check("with logind's wording", "No session" in o, o[:70])
    o, rc = run(s, "loginctl session-status %s" % sid)
    eq("session-status rc", rc, 0)
    check("session-status leads with the id and user",
          o.startswith("%s - %s" % (sid, s.user)), o[:40])


def t_tty_and_the_process_table_agree():
    s = sh()
    t, rc = run(s, "tty")
    eq("tty rc", rc, 0)
    eq("tty names a pts device", t.strip(), "/dev/pts/0")
    o, rc = run(s, "test -c %s && echo yes" % t.strip())
    eq("and it is a character device", (o.strip(), rc), ("yes", 0))
    o, _ = run(s, "stat -c %F " + t.strip())
    eq("stat agrees", o.strip(), "character special file")
    o, _ = run(s, "ps -o tty= -p $$")
    eq("ps reports the same tty", "/dev/" + o.strip(), t.strip())
    o, _ = run(s, "echo $SSH_TTY")
    eq("SSH_TTY is the same device", o.strip(), t.strip())
    who, _ = run(s, "who")
    check("who names the same line", t.strip().split("/dev/")[1] in who,
          who[:60])
    o, _ = run(s, "readlink /proc/self/fd/0")
    eq("stdin is that device", o.strip(), t.strip())
    o, _ = run(s, "ls /dev/pts")
    check("the device is in /dev/pts", "0" in o.split(), o[:40])


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("t_")]


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
