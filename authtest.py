#!/usr/bin/env python3
"""What does the box know about how the attacker got in?

The first thing anyone does after landing on a machine is find out what it
recorded about them, and the second is decide what to wipe. Both questions
are answered by the utmp family -- wtmp, btmp, /run/utmp -- and by
auth.log, and every one of them was scenery.

  - `lastb` printed nothing and `grep "Failed password" /var/log/auth.log`
    found two lines, both from an unrelated address, on a box that had just
    refused this caller a few hundred times before letting them in. One
    address made 320 attempts against the real honeypot before landing as
    deploy; on the box it landed on, its own campaign had left no trace.
    The SSH layer now hands the shell what it rejected from this source,
    and auth.log, btmp and lastb all show it. Only this caller's own: what
    another actor failed at is not this actor's business.
  - wtmp, btmp and /run/utmp were runs of NUL bytes sized to the right
    number of records. The size was right and the contents were not, so
    `strings /var/log/wtmp` found no usernames in a file `last` read eight
    sessions out of, `utmpdump /var/log/btmp` printed nothing whatever the
    file held, and `> /var/log/wtmp` -- the first line of every log-wiping
    script there is -- changed nothing that any command printed. The files
    hold real 384-byte records now, written by the same packer real
    util-linux parses: last, lastb, utmpdump, who, w, users and uptime are
    readers of those bytes, so clearing a file clears its commands.
  - `last` printed the full date for the logout time ("Aug 22 18:32 - Sat
    Aug 22 18:50"); real last prints the login date and the logout clock
    ("Aug 22 18:35 - 18:53"). It also printed the untruncated 25-character
    kernel version in a column real last cuts to 16 without -w, and had no
    -x, no -f and no username filter -- `last root` printed everyone.
  - `users` asserted the login name while who, w and uptime read /run/utmp,
    so after `> /run/utmp` three of the four said the box was empty and the
    fourth still named the attacker.
  - `wc -c a b` concatenated every operand into one count and labelled it
    with the *first* filename. `wc -c /var/log/wtmp /run/utmp` reported the
    sum of the two under the name of one: a wrong number that looks like a
    right one, on two files an attacker checks the size of.

Reference for every format here is util-linux 2.40 (last, lastb, utmpdump)
and coreutils 9.4 (wc), measured by feeding the real binaries the very
records this file's packer produces.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []
NOW = time.time()
# (ts, username, invalid_user, client_port), oldest first -- the shape the
# SSH layer hands over.
FAILS = [(NOW - 900, "root", False, 44120),
         (NOW - 880, "admin", True, 44257),
         (NOW - 860, "root", False, 44394),
         (NOW - 840, "ubuntu", True, 44531)]


def sh(user="root", peer="203.0.113.43", fails=(), vfs=None):
    try:
        s = fs.Shell(vfs or fs.VFS(), peer=peer, user=user, peer_fails=fails)
    except TypeError:
        # A build that cannot be told what it rejected. Kept runnable so
        # this suite measures that build's answers rather than crashing on
        # its constructor.
        s = fs.Shell(vfs or fs.VFS(), peer=peer, user=user)
        s.peer_fails = list(fails)
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


def body(out, marker):
    return [l for l in out.splitlines()
            if l.strip() and not l.startswith(marker)]


# --- the failures this caller made -----------------------------------------

def t_lastb_shows_this_callers_own_attempts():
    s = sh(fails=FAILS)
    o, rc = run(s, "lastb")
    eq("lastb rc", rc, 0)
    rows = body(o, "btmp begins")
    eq("one line per rejected attempt", len(rows), len(FAILS))
    check("newest first", rows[0].split()[0] == "ubuntu", rows[0])
    check("the attempts name this caller's address",
          all("203.0.113.43" in r for r in rows), rows[0])
    check("and the pseudo-tty sshd uses for them",
          all("ssh:notty" in r for r in rows), rows[0])
    # util-linux prints a btmp record as a zero-length session, not as a
    # phantom: measured with `lastb -f` on records from this packer.
    check("each attempt is zero-length", rows[0].endswith("(00:00)"),
          rows[0])


def t_auth_log_has_the_same_failures():
    s = sh(fails=FAILS)
    o, _ = run(s, "grep 'Failed password' /var/log/auth.log")
    mine = [l for l in o.splitlines() if "203.0.113.43" in l]
    eq("one Failed password line per attempt", len(mine), len(FAILS))
    check("an unknown username is logged as invalid",
          any("invalid user admin" in l for l in mine), mine[:1])
    check("a real one is not",
          not any("invalid user root" in l for l in mine), mine[:1])
    o2, _ = run(s, "grep -c 'Invalid user' /var/log/auth.log")
    check("and gets its own Invalid user line", int(o2.strip()) >= 2, o2)


def t_lastb_and_auth_log_count_the_same():
    s = sh(fails=FAILS)
    a, _ = run(s, "lastb | grep -c 203.0.113.43")
    b, _ = run(s, "grep -c 'Failed password for .*203.0.113.43' "
                  "/var/log/auth.log")
    eq("lastb and auth.log agree on how many times this address failed",
       a.strip(), b.strip())


def t_btmp_size_matches_what_lastb_prints():
    s = sh(fails=FAILS)
    o, _ = run(s, "lastb")
    rows = body(o, "btmp begins")
    size, _ = run(s, "wc -c < /var/log/btmp")
    eq("btmp is 384 bytes per record", int(size.strip()), 384 * len(rows))


def t_utmpdump_reads_the_same_btmp():
    s = sh(fails=FAILS)
    o, rc = run(s, "utmpdump /var/log/btmp")
    eq("utmpdump rc", rc, 0)
    rows = [l for l in o.splitlines() if l.startswith("[")]
    eq("utmpdump dumps every btmp record", len(rows), len(FAILS))
    check("with the username in it", "[admin   ]" in o, o[:100])
    check("and the address in the host column", "[203.0.113.43" in o, o[:100])
    check("utmpdump announces the file it read",
          "Utmp dump of /var/log/btmp" in o, o[:60])


def t_the_login_that_worked_is_in_auth_log_too():
    s = sh(fails=FAILS)
    o, _ = run(s, "grep 203.0.113.43 /var/log/auth.log")
    check("the accepted login is recorded",
          any("Accepted password for root" in l for l in o.splitlines()),
          o[-120:])
    fails = [l for l in o.splitlines() if "Failed password" in l]
    acc = [l for l in o.splitlines() if "Accepted" in l]
    check("the failures come before the login that worked",
          o.index(fails[-1]) < o.index(acc[0]), acc[:1])


def t_the_journal_carries_the_failures():
    s = sh(fails=FAILS)
    o, _ = run(s, "journalctl -u ssh")
    eq("journalctl shows the same count as auth.log",
       len([l for l in o.splitlines()
            if "Failed password" in l and "203.0.113.43" in l]), len(FAILS))


def t_no_other_actors_failures_leak():
    """Another address's attempts are not this address's business."""
    s = sh(peer="203.0.113.77", fails=[(NOW - 700, "oracle", True, 51002)])
    o, _ = run(s, "lastb")
    rows = body(o, "btmp begins")
    eq("only the caller's own attempts are in btmp", len(rows), 1)
    check("and they are the caller's", "203.0.113.77" in rows[0], rows[0])
    check("no other address appears", "203.0.113.43" not in o, o[:120])


def t_reconnecting_does_not_double_the_record():
    """The same source keeps its filesystem between visits."""
    v = fs.VFS()
    sh(fails=FAILS, vfs=v)
    s2 = sh(fails=FAILS, vfs=v)
    o, _ = run(s2, "lastb")
    eq("a second session does not re-record the same attempts",
       len(body(o, "btmp begins")), len(FAILS))


def t_a_second_session_closes_the_first():
    v = fs.VFS()
    sh(fails=FAILS, vfs=v)
    s2 = sh(fails=FAILS, vfs=v)
    o, _ = run(s2, "last")
    live = [l for l in o.splitlines() if "still logged in" in l]
    eq("only one session is open at a time", len(live), 1)
    o2, _ = run(s2, "who")
    eq("and who sees one too", len(o2.splitlines()), 1)


# --- the files are the source ----------------------------------------------

def t_wtmp_holds_the_sessions_last_prints():
    s = sh()
    o, _ = run(s, "last")
    rows = body(o, "wtmp begins")
    size, _ = run(s, "wc -c < /var/log/wtmp")
    recs = int(size.strip()) // 384
    # Every closed session costs a login and a logout record, the open one
    # costs a login, and boot costs a BOOT_TIME and a RUN_LVL.
    closed = len([r for r in rows
                  if "still logged in" not in r and "still running" not in r])
    live = len([r for r in rows if "still logged in" in r])
    eq("wtmp holds exactly the records last read out of it",
       recs, 2 * closed + live + 2)


def t_the_usernames_are_in_the_file():
    s = sh()
    o, _ = run(s, "grep -c deploy /var/log/wtmp")
    check("grep finds a session's username in wtmp", int(o.strip()) >= 1, o)
    o2, _ = run(s, "grep -a -c 10.8.0.6 /var/log/wtmp")
    check("and the address it came from", int(o2.strip()) >= 1, o2)
    o3, rc = run(s, "grep 10.8.0.6 /var/log/wtmp")
    eq("grep on the record file exits 0", rc, 0)
    check("and says it is binary rather than printing it",
          o3.strip() == "grep: /var/log/wtmp: binary file matches", o3[:80])


def t_clearing_wtmp_clears_last():
    s = sh()
    before, _ = run(s, "last")
    check("there is a history to lose", len(body(before, "wtmp begins")) > 3,
          before[:80])
    o, rc = run(s, "> /var/log/wtmp; last")
    eq("last still exits 0 on an empty wtmp", rc, 0)
    eq("last prints nothing after the file is truncated",
       body(o, "wtmp begins"), [])
    check("and says the log begins now",
          "wtmp begins" in o, o[:60])


def t_clearing_btmp_clears_lastb():
    s = sh(fails=FAILS)
    o, _ = run(s, "> /var/log/btmp; lastb")
    eq("lastb prints nothing after the file is truncated",
       body(o, "btmp begins"), [])
    size, _ = run(s, "wc -c < /var/log/btmp")
    eq("and the file agrees", size.strip(), "0")


def t_clearing_run_utmp_clears_all_four_readers():
    s = sh()
    o, _ = run(s, "> /run/utmp; who; echo ---; users; echo ---; uptime")
    who, users, up = o.split("---")
    eq("who reports nobody", who.strip(), "")
    eq("users reports nobody", users.strip(), "")
    check("uptime counts nobody", "0 user" in up, up.strip())
    o2, _ = run(s, "w")
    eq("w lists nobody",
       [l for l in o2.splitlines() if l.startswith("root")], [])


def t_who_and_users_agree_before_anyone_touches_anything():
    s = sh()
    who, _ = run(s, "who")
    users, _ = run(s, "users")
    eq("users lists exactly who who lists",
       sorted(users.split()), sorted(l.split()[0] for l in who.splitlines()))
    up, _ = run(s, "uptime")
    check("and uptime counts them", "1 user" in up, up.strip())


def t_the_live_session_is_in_the_file_not_asserted():
    s = sh(peer="203.0.113.77")
    o, _ = run(s, "utmpdump /run/utmp")
    check("the live session has a record in /run/utmp",
          "203.0.113.77" in o, o[-90:])
    o2, _ = run(s, "utmpdump /var/log/wtmp | tail -1")
    check("and wtmp got one too", "203.0.113.77" in o2, o2)


# --- last's own formatting, against the real tool ---------------------------

def t_last_prints_the_logout_as_a_clock_time():
    s = sh()
    o, _ = run(s, "last")
    closed = [l for l in body(o, "wtmp begins")
              if " - " in l and "still" not in l]
    check("there is a closed session to look at", closed, o[:80])
    for line in closed:
        rhs = line.split(" - ", 1)[1]
        check("the logout is a bare HH:MM, as util-linux prints it",
              re.match(r"^\d\d:\d\d {1,2}\(\d+\+?\d*:?\d*\)?", rhs)
              is not None, rhs)


def t_last_truncates_the_host_column():
    s = sh()
    o, _ = run(s, "last")
    reboot = [l for l in o.splitlines() if l.startswith("reboot")][0]
    eq("the kernel version is cut to 16 characters",
       reboot.split()[3], fs.KERNEL[:16])
    w, _ = run(s, "last -w")
    rw = [l for l in w.splitlines() if l.startswith("reboot")][0]
    eq("-w prints it whole", rw.split()[3], fs.KERNEL)


def t_last_filters_by_name():
    s = sh()
    o, _ = run(s, "last deploy")
    rows = body(o, "wtmp begins")
    check("every line is that user's",
          rows and all(r.startswith("deploy") for r in rows), rows[:1])
    o2, _ = run(s, "last root")
    check("and root's sessions are root's",
          all(r.startswith("root") for r in body(o2, "wtmp begins")),
          o2[:80])
    o3, _ = run(s, "last nosuchuser")
    eq("an unknown name matches nothing", body(o3, "wtmp begins"), [])


def t_runlevel_records_need_x():
    s = sh()
    plain, _ = run(s, "last")
    check("runlevel is hidden by default", "runlevel" not in plain,
          plain[:80])
    x, _ = run(s, "last -x")
    check("-x shows it", "runlevel (to lvl 5)" in x, x[:200])
    check("-x still shows the boot", "reboot   system boot" in x, x[:200])


def t_last_reads_the_file_it_is_given():
    s = sh()
    o, _ = run(s, "last -f /var/log/btmp")
    eq("an empty btmp read as wtmp has no sessions",
       body(o, "btmp begins"), [])
    check("and the footer names the file it read", "btmp begins" in o, o[:60])
    o2, rc = run(s, "last -f /var/log/nosuchfile")
    eq("a missing file is an error", rc, 1)
    check("with the util-linux wording",
          "cannot open" in o2, o2[:80])


def t_lastb_is_root_only():
    s = sh(user="deploy", fails=FAILS)
    o, rc = run(s, "lastb")
    eq("lastb rc for a non-root user", rc, 1)
    check("btmp is not readable", "Permission denied" in o, o[:80])


# --- wc, which is how the sizes get checked --------------------------------

def t_wc_counts_each_operand():
    s = sh()
    o, rc = run(s, "wc -c /var/log/wtmp /run/utmp")
    eq("wc rc", rc, 0)
    lines = o.splitlines()
    eq("one line per file and a total", len(lines), 3)
    a, b = int(lines[0].split()[0]), int(lines[1].split()[0])
    check("the first line is the first file",
          lines[0].endswith("/var/log/wtmp"), lines[0])
    check("the second is the second", lines[1].endswith("/run/utmp"),
          lines[1])
    eq("and the total is their sum", int(lines[2].split()[0]), a + b)
    check("labelled total", lines[2].endswith("total"), lines[2])


def t_wc_agrees_with_itself_one_file_at_a_time():
    s = sh()
    multi, _ = run(s, "wc -c /var/log/wtmp /run/utmp /etc/passwd")
    singles = [int(run(s, "wc -c < %s" % f)[0].strip())
               for f in ("/var/log/wtmp", "/run/utmp", "/etc/passwd")]
    got = [int(l.split()[0]) for l in multi.splitlines()[:3]]
    eq("counting three files at once matches counting them one by one",
       got, singles)


def t_wc_pads_the_way_coreutils_does():
    s = sh()
    one, _ = run(s, "wc -l /etc/passwd")
    check("a single count is not padded", not one.startswith(" "), repr(one))
    three, _ = run(s, "wc /etc/passwd")
    check("three counts are padded to the size's width",
          re.match(r"^ *\d+ +\d+ +\d+ /etc/passwd$", three.strip("\n"))
          is not None, repr(three))


def t_wc_survives_a_missing_operand():
    s = sh()
    o, rc = run(s, "wc -c /etc/passwd /var/log/nosuchthing")
    eq("rc is 1", rc, 1)
    check("the error names the missing file",
          "nosuchthing: No such file or directory" in o, o[:90])
    check("the file that exists is still counted",
          any(l.endswith("/etc/passwd") for l in o.splitlines()), o[:90])
    check("and a total is still printed",
          any(l.endswith("total") for l in o.splitlines()), o[:90])


def t_wc_on_a_directory():
    s = sh()
    o, rc = run(s, "wc -c /etc")
    eq("rc is 1", rc, 1)
    check("wc says it is a directory", "Is a directory" in o, o[:80])
    check("and still prints a zero line",
          any(l.strip().startswith("0") for l in o.splitlines()), o[:80])


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
