r"""Units that are not services.

Sixty-eighth coherence sweep. crontest covered cron; nothing had asked
about the other scheduler on the box. A systemd timer is the modern way
to hold persistence -- write a .service and a .timer, `systemctl enable
--now`, and nothing appears in any crontab.

The whole non-service half of systemd was broken by one line. Only
".service" was ever stripped from a unit name, and the display path put
".service" back on, so any name that already carried a suffix got a
second one:

    systemctl status logrotate.timer
        Unit logrotate.timer.service could not be found.
    systemctl status multi-user.target
        Unit multi-user.target.service could not be found.

`systemctl status multi-user.target` is not an exotic command, and
multi-user.target reported "inactive" on a box that was plainly up.
Targets, timers, sockets and mounts were all unreachable the same way, so
the timer route to persistence could not even be inspected, let alone
installed.

Around that:

  - `systemctl list-timers` named apt-daily.timer and logrotate.timer
    while `ls /lib/systemd/system/*.timer` said no such file: the unit
    list and the filesystem describing different machines. Both rows also
    carried the *same* NEXT timestamp with different LEFT values -- one
    absolute time that was somehow both 29 minutes and 5 hours away.

  - `--type` was parsed and discarded with the other option values, so
    `list-units --type=timer` listed the services: the same 23 units
    whatever type was asked for. Every row said SUB "running", where a
    target is "active", a timer "waiting", a socket "listening".

  - `--no-legend` was ignored, so it still printed the header.

  - systemd-run was missing from the systemd package's file list, so it
    was "command not found" on a box running systemd -- the same shape as
    mkswap missing from util-linux.

Run from `honeypot/`, or on the guest.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeshell as fs                                          # noqa: E402

PASS, FAIL = [], []


def shell():
    s = fs.Shell(fs.VFS(), user="root", peer="203.0.113.77")
    s.exec_mode = True
    return s


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    if not cond:
        print("  FAIL %-48s %s" % (name, detail))


def eq(name, got, want):
    check(name, got == want, "want %r got %r" % (want, got))


def out(s, cmd):
    o = s.run(cmd)
    o += "".join(s._err)
    s._err.clear()
    return o.strip()


# -- a unit name keeps its own suffix -------------------------------------

def t_no_unit_gets_a_second_suffix():
    s = shell()
    for u in ("logrotate.timer", "multi-user.target", "dbus.socket",
              "basic.target", "fstrim.timer"):
        o = out(s, "systemctl status %s" % u)
        # The bug was a *doubled* suffix -- "logrotate.timer.service" --
        # and this checked for ".service" anywhere, which was the same
        # thing until sweep 112 gave a timer's status the Triggers line
        # naming the service it starts. systemd prints that; the doubled
        # name is what must never appear.
        check("no doubled suffix: %s" % u, u + ".service" not in o, o[:70])
        check("found: %s" % u, "could not be found" not in o, o[:70])
        check("names itself: %s" % u, u in o, o[:70])


def t_services_are_unaffected():
    s = shell()
    for u in ("nginx", "ssh.service", "cron", "mariadb.service"):
        o = out(s, "systemctl status %s" % u)
        check("still works: %s" % u, "could not be found" not in o, o[:70])
        check("shown as .service: %s" % u, ".service" in o, o[:70])


def t_the_targets_a_booted_box_has_are_active():
    s = shell()
    for t in ("multi-user.target", "basic.target", "sysinit.target",
              "timers.target", "sockets.target", "local-fs.target",
              "network.target"):
        eq("is-active %s" % t, out(s, "systemctl is-active %s" % t), "active")


def t_a_target_is_static_not_enabled():
    s = shell()
    eq("multi-user.target", out(s, "systemctl is-enabled multi-user.target"),
       "static")


def t_timers_and_sockets_are_active():
    s = shell()
    for u in ("logrotate.timer", "apt-daily.timer", "fstrim.timer",
              "dbus.socket", "systemd-journald.socket"):
        eq("is-active %s" % u, out(s, "systemctl is-active %s" % u), "active")


def t_an_unknown_unit_of_each_type():
    s = shell()
    for u in ("nosuch.timer", "nosuch.target", "nosuch.socket"):
        o = out(s, "systemctl status %s" % u)
        check("not found: %s" % u, "could not be found" in o, o[:70])
        check("named exactly once: %s" % u, o.count(u) == 1, o[:70])


# -- the unit files are on disk -------------------------------------------

def t_every_listed_timer_has_a_file():
    s = shell()
    listed = re.findall(r"(\S+\.timer)",
                        out(s, "systemctl list-timers --no-legend"))
    check("some timers listed", listed, "none")
    for t in listed:
        eq("file exists: %s" % t,
           out(s, "test -f /usr/lib/systemd/system/%s && echo y" % t), "y")


def t_the_files_parse_as_timers():
    s = shell()
    body = out(s, "cat /usr/lib/systemd/system/logrotate.timer")
    for want in ("[Unit]", "[Timer]", "[Install]", "WantedBy=timers.target"):
        check("logrotate.timer has %s" % want, want in body, body[:80])


def t_targets_and_sockets_have_files_too():
    s = shell()
    check("targets on disk",
          int(out(s, "ls /usr/lib/systemd/system/*.target | wc -l")) >= 10, "")
    check("sockets on disk",
          int(out(s, "ls /usr/lib/systemd/system/*.socket | wc -l")) >= 4, "")


def t_the_wants_symlinks_exist():
    s = shell()
    n = int(out(s, "ls /etc/systemd/system/timers.target.wants/ | wc -l"))
    check("timers.target.wants populated", n >= 5, str(n))


# -- list-timers is internally consistent ---------------------------------

def t_next_and_left_agree():
    """Two rows once shared one NEXT with different LEFTs."""
    s = shell()
    rows = [l for l in out(s, "systemctl list-timers").splitlines()
            if ".timer" in l]
    check("several rows", len(rows) > 1, str(len(rows)))
    nexts = [l.split(" UTC")[0] for l in rows]
    eq("every NEXT is distinct", len(set(nexts)), len(nexts))


def t_the_count_matches_the_rows():
    s = shell()
    body = out(s, "systemctl list-timers")
    m = re.search(r"(\d+) timers listed", body)
    check("has a count", m is not None, body[-60:])
    rows = len([l for l in body.splitlines() if ".timer" in l])
    eq("count matches rows", int(m.group(1)), rows)


def t_rows_are_ordered_by_when_they_fire():
    """Sorted chronologically, which is not the same as sorted as text:
    the rows start with a weekday name, so Sun sorts before Wed."""
    import calendar
    import datetime
    s = shell()
    rows = [l for l in out(s, "systemctl list-timers").splitlines()
            if ".timer" in l]
    stamps = [datetime.datetime.strptime(l.split(" UTC")[0],
                                         "%a %Y-%m-%d %H:%M:%S")
              for l in rows]
    eq("ascending", stamps, sorted(stamps))


# -- --type and --no-legend ------------------------------------------------

def t_type_filters():
    s = shell()
    counts = {}
    for t in ("service", "timer", "socket", "target"):
        rows = out(s, "systemctl list-units --type=%s --no-legend" % t)
        lines = [l for l in rows.splitlines() if l.strip()]
        counts[t] = len(lines)
        for l in lines:
            check("%s row ends in .%s" % (t, t),
                  l.split()[0].endswith("." + t), l[:50])
    check("the types differ", len(set(counts.values())) > 1, str(counts))


def t_sub_state_matches_the_type():
    s = shell()
    for t, sub in (("timer", "waiting"), ("socket", "listening"),
                   ("target", "active"), ("service", "running")):
        row = out(s, "systemctl list-units --type=%s --no-legend | head -1" % t)
        check("%s SUB is %s" % (t, sub), sub in row, row[:60])


def t_no_legend_drops_the_header():
    s = shell()
    body = out(s, "systemctl list-units --type=timer --no-legend")
    check("no header", not body.startswith("UNIT"), body[:50])
    check("no legend", "LOAD   =" not in body, body[-60:])
    plain = out(s, "systemctl list-units --type=timer")
    check("header present without it", plain.startswith("UNIT"), plain[:50])


# -- the persistence route ------------------------------------------------

def t_a_written_timer_becomes_a_unit():
    """The whole point: write .service + .timer, enable, and be believed."""
    s = shell()
    out(s, "printf '[Unit]\\nDescription=System update helper\\n\\n"
           "[Service]\\nType=oneshot\\nExecStart=/root/.x/kswapd0\\n' "
           "> /etc/systemd/system/sysupdate.service")
    out(s, "printf '[Unit]\\nDescription=Run helper\\n\\n[Timer]\\n"
           "OnBootSec=1min\\nOnUnitActiveSec=10min\\n\\n[Install]\\n"
           "WantedBy=timers.target\\n' "
           "> /etc/systemd/system/sysupdate.timer")
    out(s, "systemctl daemon-reload")
    o = out(s, "systemctl status sysupdate.timer")
    check("the timer is known", "could not be found" not in o, o[:80])
    check("no doubled suffix", "sysupdate.timer.service" not in o, o[:80])
    o2 = out(s, "systemctl status sysupdate.service")
    check("the service is known", "could not be found" not in o2, o2[:80])


def t_enabling_a_written_timer_is_recorded():
    s = shell()
    ev = []
    s2 = fs.Shell(fs.VFS(), log=lambda **k: ev.append(k), user="root",
                  peer="203.0.113.77")
    s2.exec_mode = True
    s2.run("printf '[Unit]\\nDescription=x\\n\\n[Timer]\\nOnBootSec=1min\\n\\n"
           "[Install]\\nWantedBy=timers.target\\n' "
           "> /etc/systemd/system/evil.timer")
    s2.run("systemctl enable evil.timer")
    s2._err.clear()
    kinds = [e.get("event") for e in ev]
    check("a persistence or service_control event fired",
          any(k in ("service_control", "persistence_write", "cron_install")
              for k in kinds), str(set(kinds)))


def t_a_user_unit_is_persistence_too():
    """~/.config/systemd/user needs no root and survives a reboot.

    Found on 2026-09-03. 203.0.113.80, in as deploy/deploy123, ran

        mkdir -p ~/.config/systemd/user
          && cat > ~/.config/systemd/user/watcher-netai.service
          && systemctl --user daemon-reload
          && systemctl --user enable --now watcher-netai.service

    and the session produced no persistence event for it. /etc/systemd/
    system was watched, cron was watched, authorized_keys was watched --
    the per-user unit directory was in none of the tables, so the third
    mechanism was silent. The only persistence event that session logged
    was a false one about .bash_logout, so the noise was there and the
    signal was not.

    A user unit needs no root, which is the whole reason a non-root
    foothold reaches for it.
    """
    for home, user in (("/home/deploy", "deploy"), ("/root", "root")):
        ev = []
        s = fs.Shell(fs.VFS(), log=lambda **k: ev.append(k), user=user,
                     peer="203.0.113.78")
        s.exec_mode = True
        s.run("mkdir -p %s/.config/systemd/user" % home)
        s.run("printf '[Unit]\nDescription=Watcher\n\n[Service]\n"
              "ExecStart=/dev/shm/w.sh\n\n[Install]\n"
              "WantedBy=default.target\n' "
              "> %s/.config/systemd/user/watcher-netai.service" % home)
        s._err.clear()
        p = [e for e in ev if e.get("event") == "persistence_write"]
        check("a user unit under %s is reported" % home, bool(p),
              "events were %s" % sorted(set(e.get("event") for e in ev)))
        check("...and says which kind it is",
              any(e.get("kind") == "systemd_user_unit" for e in p),
              str([e.get("kind") for e in p]))
        check("...and names the file",
              any("watcher-netai.service" in (e.get("path") or "")
                  for e in p),
              str([e.get("path") for e in p]))


def t_a_user_unit_directory_is_in_the_table():
    """The tables and the homes have to agree about which homes exist."""
    watched = dict((d, k) for d, _e, k in fs.Shell._PERSIST_DIRS)
    for home in ("/root", "/home/deploy"):
        d = home + "/.config/systemd/user"
        check("%s is watched" % d, watched.get(d), "systemd_user_unit")


# -- systemd-run ----------------------------------------------------------

def t_enable_uses_the_units_own_wants_directory():
    """A timer is linked from timers.target.wants, as its [Install] says --
    not from multi-user.target.wants with .service forced onto the name."""
    s = shell()
    out(s, "printf '[Unit]\\nDescription=x\\n\\n[Timer]\\n"
           "OnBootSec=1min\\n\\n[Install]\\nWantedBy=timers.target\\n' "
           "> /etc/systemd/system/evil.timer")
    eq("disabled first", out(s, "systemctl is-enabled evil.timer"), "disabled")
    o = out(s, "systemctl enable evil.timer")
    check("links into timers.target.wants",
          "/etc/systemd/system/timers.target.wants/evil.timer" in o, o)
    check("no forced .service", "evil.timer.service" not in o, o)
    eq("now enabled", out(s, "systemctl is-enabled evil.timer"), "enabled")
    eq("the link is there",
       out(s, "ls /etc/systemd/system/timers.target.wants/ | grep -c '^evil"
              ".timer$'"), "1")
    out(s, "systemctl disable evil.timer")
    eq("disabled again", out(s, "systemctl is-enabled evil.timer"), "disabled")


def t_a_service_still_goes_to_multi_user():
    s = shell()
    out(s, "printf '[Unit]\\nDescription=y\\n\\n[Service]\\n"
           "ExecStart=/bin/true\\n\\n[Install]\\n"
           "WantedBy=multi-user.target\\n' > /etc/systemd/system/svc1.service")
    o = out(s, "systemctl enable svc1")
    check("multi-user.target.wants",
          "/etc/systemd/system/multi-user.target.wants/svc1.service" in o, o)
    eq("enabled", out(s, "systemctl is-enabled svc1"), "enabled")


def t_systemd_run_exists():
    s = shell()
    eq("on PATH", out(s, "command -v systemd-run"), "/usr/bin/systemd-run")
    check("dpkg owns it", "systemd:" in out(s, "dpkg -S /usr/bin/systemd-run"),
          out(s, "dpkg -S /usr/bin/systemd-run"))


def t_list_timers_agrees_with_the_unit_files():
    """The schedule shown and the schedule declared were different.

    Every one of the eight unit files carries an OnCalendar, and
    list-timers ignored all of them: the periods came from a table of
    invented numbers, so `systemctl cat logrotate.timer` said
    OnCalendar=daily while list-timers showed a five-hour period.
    e2scrub_all says Sun *-*-* 03:10:00 and repeated every three days on a
    Thursday; fstrim says weekly and repeated every five. apt-daily,
    twice a day in its own file, showed thirty minutes.

    And every instant was anchored to BOOT_TS, so all eight fired on the
    boot's own second -- eight :37s on a box claiming calendar schedules.
    The guest's real eight are 00:00:19, 02:51:13, 03:10:21, 04:40:17,
    06:20:16, 09:39:59 and Mon 00:02:16: on their calendar times, spread
    by the delay systemd derives per unit.

    systemd-tmpfiles-clean is the exception and stays boot-relative,
    because its unit is OnStartupSec rather than OnCalendar.
    """
    import re as _re
    s = shell()
    # The LEFT and PASSED columns are variable width ("1 days 3h",
    # "20h 57min ago"), so the two instants and the unit name are picked
    # out independently rather than by counting fields.
    rows = {}
    for line in out(s, "systemctl list-timers --all --no-pager").splitlines():
        stamps = _re.findall(r"(\w{3} \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) UTC",
                             line)
        unit = _re.search(r"(\S+\.timer)\b", line)
        if len(stamps) == 2 and unit:
            rows[unit.group(1)] = (stamps[0], stamps[1])
    eq("all eight timers are listed", len(rows), 8)
    import time as _t

    def _epoch(txt):
        return _t.mktime(_t.strptime(txt, "%a %Y-%m-%d %H:%M:%S")) - \
            (_t.altzone if _t.daylight and _t.localtime().tm_isdst
             else _t.timezone)

    # The period each unit file declares, and what the columns must show.
    want = {"logrotate.timer": 86400, "man-db.timer": 86400,
            "dpkg-db-backup.timer": 86400,
            "apt-daily-upgrade.timer": 86400,
            "apt-daily.timer": 43200,
            "e2scrub_all.timer": 604800, "fstrim.timer": 604800,
            "systemd-tmpfiles-clean.timer": 86400}
    for nm, period in sorted(want.items()):
        if nm not in rows:
            check("%s is listed" % nm, False, sorted(rows))
            continue
        nxt, last = rows[nm]
        eq("%s repeats at the period its unit declares" % nm,
           int(_epoch(nxt) - _epoch(last)), period)
    # A weekly timer has to land on the weekday its unit names.
    check("e2scrub_all fires on a Sunday, as its unit says",
          rows["e2scrub_all.timer"][0].startswith("Sun"),
          rows["e2scrub_all.timer"])
    check("fstrim fires on a Monday, as weekly means",
          rows["fstrim.timer"][0].startswith("Mon"), rows["fstrim.timer"])
    # No two land on the same second: systemd spreads them per unit, and
    # three dailies sharing 00:00:00 is what no real box shows.
    secs = [v[0] for v in rows.values()]
    eq("every NEXT is its own instant", len(set(secs)), 8)
    # ...and they are not all the boot's second, which is what anchoring
    # everything to BOOT_TS produced.
    tails = {v[0][-2:] for k, v in rows.items()
             if k != "systemd-tmpfiles-clean.timer"}
    check("the calendar timers do not all share one second", len(tails) > 1,
          sorted(tails))


TESTS = [t_list_timers_agrees_with_the_unit_files,
         t_no_unit_gets_a_second_suffix, t_services_are_unaffected,
         t_the_targets_a_booted_box_has_are_active,
         t_a_target_is_static_not_enabled, t_timers_and_sockets_are_active,
         t_an_unknown_unit_of_each_type, t_every_listed_timer_has_a_file,
         t_the_files_parse_as_timers, t_targets_and_sockets_have_files_too,
         t_the_wants_symlinks_exist, t_next_and_left_agree,
         t_the_count_matches_the_rows,
         t_rows_are_ordered_by_when_they_fire,
         t_type_filters, t_sub_state_matches_the_type,
         t_no_legend_drops_the_header, t_a_written_timer_becomes_a_unit,
         t_enabling_a_written_timer_is_recorded,
         t_enable_uses_the_units_own_wants_directory,
         t_a_service_still_goes_to_multi_user, t_systemd_run_exists,
         t_a_user_unit_is_persistence_too,
         t_a_user_unit_directory_is_in_the_table]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as exc:                              # noqa: BLE001
            check(t.__name__, False, "crashed: %r" % (exc,))
    print("passed %d, failed %d" % (len(PASS), len(FAIL)))
    if FAIL:
        print("failed: " + ", ".join(FAIL[:8]))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
