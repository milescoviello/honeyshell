#!/usr/bin/env python3
"""What is scheduled on this box, when did it last run, and who agrees?

Four things answer that for a systemd timer -- `systemctl list-timers`,
`systemctl status` on the timer, `systemctl status` on the service it
starts, and `systemctl show -p` -- and the journal has the lines from when
it actually ran. They disagreed with each other and with the box's uptime.

    systemctl list-timers      LAST  -    PASSED  -    (all eight timers)
    journalctl -u apt-daily.service
        Aug 23 01:38:53 systemd[1]: Starting apt-daily.service ...
        Aug 23 01:38:53 systemd[1]: apt-daily.service: Deactivated ...
    uptime -p                  up 46 days

A timer that has never fired on a box up forty-six days, with this
morning's run of it in the journal directly underneath.

    systemctl status apt-daily.service
        Unit apt-daily.service could not be found.

...while list-timers' own ACTIVATES column names it, and the journal has
its Starting and Deactivated lines. Three readers, and the one anyone uses
to look at a scheduled job denied it existed. Adding it exposed the next
layer: it defaulted to running like the daemons, so status reported it
active with Main PID 0 -- a running process with no pid -- where systemd
shows a oneshot dead since its last trigger.

    systemctl status apt-daily.timer
        Active: active (elapsed) since ... 46 days ago

"elapsed" is what a timer says when it has fired and will not fire again;
one waiting for its next run says "waiting", and status names both the
next trigger and the unit it will start. Ours named neither.

    systemctl show apt-daily.timer -p LastTriggerUSec
        (nothing at all -- not an empty value, no line)

Reference output measured on the guest.
"""

import os
import re
import sys
import time

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


def R(cmd):
    S._err = []
    out = S.run(cmd)
    return out or "", "".join(S._err), S.last_rc


def timers():
    """[(next, left, last, passed, unit, activates)] from list-timers."""
    rows = []
    for line in R("systemctl list-timers --no-pager")[0].splitlines()[1:]:
        m = re.match(r"^(\w{3} [\d-]+ [\d:]+ UTC)\s+(\S+(?: \S+)?)\s+"
                     r"(\w{3} [\d-]+ [\d:]+ UTC|-)\s+"
                     r"(\S+(?: \S+)? ago|-)\s+(\S+\.timer)\s+(\S+)$", line)
        if m:
            rows.append(m.groups())
    return rows


def ts(text):
    return time.mktime(time.strptime(text, "%a %Y-%m-%d %H:%M:%S UTC"))


# ---------------------------------------------------------------------------
# list-timers knows when they last ran
# ---------------------------------------------------------------------------
def t_every_timer_has_fired_on_a_box_this_old():
    rows = timers()
    check("list-timers lists timers", len(rows) >= 6, str(len(rows)))
    up = time.time() - fs.BOOT_TS
    for nxt, _left, last, passed, unit, _svc in rows:
        check("%s has a LAST" % unit, last != "-", "still a dash")
        check("%s has a PASSED" % unit, passed != "-", "still a dash")
        if last == "-":
            continue
        check("%s last fired in the past" % unit, ts(last) < time.time(),
              last)
        check("%s last fired after the boot" % unit, ts(last) >= fs.BOOT_TS,
              "%s vs boot" % last)
        check("%s is next due after it last ran" % unit, ts(nxt) > ts(last),
              "%s !> %s" % (nxt, last))
        check("%s: the gap is not longer than the uptime" % unit,
              ts(nxt) - ts(last) <= up + 1,
              "%.0f s vs %.0f s up" % (ts(nxt) - ts(last), up))


def t_the_columns_agree_with_each_other():
    now = time.time()
    for nxt, left, last, passed, unit, _svc in timers():
        # LEFT is NEXT minus now, PASSED is now minus LAST, both in
        # systemd's short form. Parse them back loosely and compare.
        want = ts(nxt) - now
        check("%s: LEFT matches NEXT" % unit,
              abs(_span(left) - want) < 120,
              "%s vs %.0f s" % (left, want))
        if last != "-":
            check("%s: PASSED matches LAST" % unit,
                  abs(_span(passed) - (now - ts(last))) < 120,
                  "%s vs %.0f s" % (passed, now - ts(last)))


def _span(text):
    """systemd's short duration back to seconds."""
    total = 0
    for num, unit in re.findall(r"(\d+)\s*(days?|h|min|s)", text):
        total += int(num) * {"day": 86400, "days": 86400, "h": 3600,
                             "min": 60, "s": 1}[unit]
    return total


# ---------------------------------------------------------------------------
# ...and so do the other three readers
# ---------------------------------------------------------------------------
def t_show_gives_the_same_two_instants():
    for nxt, _l, last, _p, unit, svc in timers():
        out = R("systemctl show %s -p LastTriggerUSec "
                "-p NextElapseUSecRealtime -p Unit -p Result" % unit)[0]
        got = dict(l.split("=", 1) for l in out.splitlines() if "=" in l)
        check("%s: show has all four properties" % unit,
              set(got) == {"LastTriggerUSec", "NextElapseUSecRealtime",
                           "Unit", "Result"}, str(sorted(got)))
        check("%s: NextElapseUSecRealtime is list-timers' NEXT" % unit,
              got.get("NextElapseUSecRealtime") == nxt,
              "%s vs %s" % (got.get("NextElapseUSecRealtime"), nxt))
        if last != "-":
            check("%s: LastTriggerUSec is list-timers' LAST" % unit,
                  got.get("LastTriggerUSec") == last,
                  "%s vs %s" % (got.get("LastTriggerUSec"), last))
        check("%s: Unit is the ACTIVATES column" % unit,
              got.get("Unit") == svc, "%s vs %s" % (got.get("Unit"), svc))


def t_status_on_the_timer():
    for nxt, _l, _last, _p, unit, svc in timers():
        out, _e, rc = R("systemctl status %s --no-pager" % unit)
        check("%s: status exits 0" % unit, rc == 0, "rc=%s" % rc)
        check("%s: a waiting timer is not elapsed" % unit,
              "active (waiting)" in out, out[:120])
        m = re.search(r"Trigger: (\w{3} [\d-]+ [\d:]+ UTC)", out)
        check("%s: status names the next trigger" % unit, m is not None,
              out[:120])
        if m:
            check("%s: and it is list-timers' NEXT" % unit,
                  m.group(1) == nxt, "%s vs %s" % (m.group(1), nxt))
        check("%s: status names what it triggers" % unit,
              "Triggers: ● " + svc in out, out[:150])


def t_status_on_the_service_it_starts():
    for _n, _l, last, _p, unit, svc in timers():
        out, err, rc = R("systemctl status %s --no-pager" % svc)
        check("%s exists as a unit" % svc, "could not be found" not in err,
              err[:60])
        check("%s is a oneshot, not a running daemon" % svc,
              "inactive (dead)" in out, out[:120])
        check("%s has no Main PID" % svc, "Main PID" not in out,
              [l for l in out.splitlines() if "Main PID" in l][:1])
        check("%s is static, not enabled" % svc, "; static)" in out,
              [l for l in out.splitlines() if "Loaded:" in l][:1])
        check("%s says which timer triggers it" % svc,
              "TriggeredBy: ● " + unit in out, out[:200])
        if last != "-":
            m = re.search(r"inactive \(dead\) since "
                          r"(\w{3} [\d-]+ [\d:]+ UTC)", out)
            check("%s died when the timer last fired" % svc,
                  m and m.group(1) == last,
                  "%s vs %s" % (m and m.group(1), last))
        # ...and rc 3 for an inactive unit, as systemctl does.
        check("%s: status exits 3 while inactive" % svc, rc == 3,
              "rc=%s" % rc)


def t_the_journal_backs_them_up():
    """The one reader that was already right, and now agrees."""
    for _n, _l, _la, _p, _unit, svc in timers()[:3]:
        out = R("journalctl -u %s -n 5 --no-pager" % svc)[0]
        check("%s has journal lines" % svc,
              "-- No entries --" not in out and out.strip(), out[:60])
        check("%s: the journal names the unit" % svc, svc in out, out[:80])
    # A timer that fires hourly must appear more often than a weekly one.
    hourly = R("journalctl -u apt-daily.service --no-pager")[0].splitlines()
    weekly = R("journalctl -u fstrim.service --no-pager")[0].splitlines()
    check("the frequent timer has at least as many entries",
          len(hourly) >= len(weekly), "%d vs %d" % (len(hourly), len(weekly)))


def t_timers_and_units_are_one_list():
    listed = {r[4] for r in timers()}
    files = set(R("ls /usr/lib/systemd/system/")[0].split())
    missing = [t for t in listed if t not in files]
    check("every timer listed has a unit file", not missing, str(missing[:3]))
    for unit in sorted(listed)[:4]:
        check("%s: systemctl cat finds it" % unit,
              R("systemctl cat %s" % unit)[2] == 0,
              R("systemctl cat %s" % unit)[1][:50])
        check("%s: is-active says active" % unit,
              R("systemctl is-active %s" % unit)[0].strip() == "active",
              R("systemctl is-active %s" % unit)[0].strip())


TESTS = [t_every_timer_has_fired_on_a_box_this_old,
         t_the_columns_agree_with_each_other,
         t_show_gives_the_same_two_instants,
         t_status_on_the_timer,
         t_status_on_the_service_it_starts,
         t_the_journal_backs_them_up,
         t_timers_and_units_are_one_list]


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
