#!/usr/bin/env python3
"""systemd-run and the sysv helpers -- scheduling that leaves a trace.

The axis: the ways to make something run later that are not cron. After
sweep 85 taught the box to read ~/.bashrc and sweep 95 taught it to read
$PATH, this is the same shape a third time -- the box accepts a
persistence action and then does nothing with it:

    systemd-run /bin/true            no output, no unit, rc 0, on a box
                                     where systemd-run is installed and
                                     `systemctl list-units` is the next
                                     thing anyone types
    systemd-run --unit=x --on-calendar=...
                                     a timer without touching cron or
                                     /etc, which is why a modern loader
                                     reaches for it -- and it produced
                                     nothing at all
    service --status-all             printed systemctl's unit table, a
                                     different command's output listing
                                     things /etc/init.d has never heard of
    update-rc.d evil defaults        rc 0 and silence for a script that
                                     does not exist

Reference output measured on the guest (Debian 13, systemd 257).
"""
import re
import sys

import fakeshell as F

FAILS, CHECKS = [], []


def check(label, got, want):
    CHECKS.append(label)
    if got != want:
        FAILS.append((label, got, want))


def sh():
    v = F.VFS()
    s = F.Shell(v, peer="203.0.113.210")
    s.exec_mode = True
    return v, s


def err(s, cmd):
    s._err = []
    s.run(cmd)
    return "".join(s._err).strip(), s.last_rc


def main():
    v, s = sh()

    # -- a transient unit ------------------------------------------------------
    msg, rc = err(s, "systemd-run /bin/true")
    check("systemd-run says what unit it made",
          bool(re.match(r"^Running as unit: run-p\d+-i\d+\.service; "
                        r"invocation ID: [0-9a-f]{32}$", msg)), True)
    check("...and exits 0", rc, 0)
    check("the invocation ID is 32 hex digits",
          len(msg.split("invocation ID: ")[1]), 32)

    msg, rc = err(s, "systemd-run --unit=evil /bin/sleep 5")
    check("a named unit is named",
          msg.startswith("Running as unit: evil.service; invocation ID: "),
          True)
    check("systemctl agrees it is active",
          s.run("systemctl is-active evil").strip(), "active")
    check("list-units shows it",
          any("evil.service" in l for l in
              s.run("systemctl list-units --no-pager").splitlines()), True)
    check("...with the description systemd-run gives it",
          "[systemd-run] /bin/sleep 5" in s.run("systemctl list-units "
                                                "--no-pager"), True)
    check("status finds it too",
          s.run("systemctl status evil --no-pager").splitlines()[0],
          "● evil.service - [systemd-run] /bin/sleep 5")
    check("...loaded from where systemd puts transient units",
          "/run/systemd/transient/evil.service" in
          s.run("systemctl status evil --no-pager"), True)

    # The unit file is a real file, in the real place, with systemd's own
    # header -- so `cat` and `systemctl cat` agree with each other.
    body = s.run("cat /run/systemd/transient/evil.service")
    check("the file has systemd's transient header",
          body.splitlines()[0],
          "# This is a transient unit file, created programmatically via "
          "the systemd API. Do not edit.")
    check("...the description", "Description=[systemd-run] /bin/sleep 5"
          in body, True)
    check("...and the quoted ExecStart",
          'ExecStart="/bin/sleep" "5"' in body, True)
    check("systemctl cat shows the same file",
          "Description=[systemd-run] /bin/sleep 5"
          in s.run("systemctl cat evil --no-pager"), True)
    check("it is reported as a persistence event",
          any(e.get("kind") == "systemd_run"
              for e in _events(s, "systemd-run --unit=e2 /bin/true")), True)

    # -- --scope ---------------------------------------------------------------
    v2, s2 = sh()
    msg, _rc = err(s2, "systemd-run --scope /bin/true")
    check("a scope is a scope, not a service",
          bool(re.match(r"^Running as unit: run-p\d+-i\d+\.scope; ", msg)),
          True)

    # -- a timer ---------------------------------------------------------------
    v3, s3 = sh()
    msg, rc = err(s3, "systemd-run --unit=evt --on-calendar='*:0/5' /bin/true")
    check("a timer prints two lines", msg.splitlines(),
          ["Running timer as unit: evt.timer",
           "Will run service as unit: evt.service"])
    check("the timer is active",
          s3.run("systemctl is-active evt.timer").strip(), "active")
    rows = [l for l in s3.run("systemctl list-timers --no-pager").splitlines()
            if "evt.timer" in l]
    check("list-timers knows about it", len(rows), 1)
    if rows:
        # A timer that has not fired yet is due one period after it was
        # created, not one period after you looked at it -- so a few
        # seconds of test time show up here. Sweep 112 anchored the
        # schedule to the unit file instead of recomputing "now + period"
        # on every read, which is what a real timer does: its next elapse
        # does not move because something ran list-timers.
        check("...and says when, from the calendar it was given",
              rows[0].split()[4] in ("5min", "4min"), True)
        check("...and which service it activates",
              rows[0].split()[-1], "evt.service")
    check("both unit files exist",
          (s3.run("test -f /run/systemd/transient/evt.timer && echo y").strip(),
           s3.run("test -f /run/systemd/transient/evt.service "
                  "&& echo y").strip()), ("y", "y"))
    check("the timer file carries the calendar",
          "OnCalendar=*:0/5" in
          s3.run("cat /run/systemd/transient/evt.timer"), True)
    check("a daily timer is a day away",
          [("1 days" in l or "23h" in l) for l in
           _lines(s3, "systemd-run --unit=dly --on-calendar=daily /bin/true",
                  "systemctl list-timers --no-pager", "dly.timer")],
          [True])
    check("the timer is reported as persistence",
          any(e.get("kind") == "systemd_run_timer"
              for e in _events(s3, "systemd-run --unit=e3 "
                                   "--on-calendar=hourly /bin/true")), True)

    # -- the failure path ------------------------------------------------------
    v4, s4 = sh()
    msg, rc = err(s4, "systemd-run /nonexistent")
    check("a missing executable is refused before anything is made",
          (msg, rc),
          ("Failed to find executable /nonexistent: No such file or "
           "directory", 1))
    check("...and no unit was created",
          s4.run("ls /run/systemd/transient").strip(), "")
    msg, rc = err(s4, "systemd-run")
    check("no command at all is a usage error",
          (msg, rc), ("systemd-run: Command line to execute required.", 1))

    # -- service --------------------------------------------------------------
    v5, s5 = sh()
    out = s5.run("service --status-all")
    check("--status-all is one line per init script",
          [l.split()[-1] for l in out.splitlines()],
          sorted(s5.run("ls /etc/init.d").split()))
    check("...in the [ + ] format", out.splitlines()[0].startswith(" [ "),
          True)
    check("...marking the ones that are up",
          " [ + ]  ssh" in out, True)
    check("...and the ones that are not",
          " [ - ]  procps" in out, True)
    before = s5.run("service --status-all")
    s5.run("systemctl stop cron")
    after = s5.run("service --status-all")
    check("a stopped service flips its box",
          (" [ + ]  cron" in before, " [ - ]  cron" in after), (True, True))
    check("service X status is still systemctl status",
          s5.run("service ssh status").splitlines()[0],
          "● ssh.service - OpenBSD Secure Shell server")

    # -- update-rc.d ------------------------------------------------------------
    v6, s6 = sh()
    check("a script that does not exist is refused",
          err(s6, "update-rc.d evil defaults"),
          ("update-rc.d: error: unable to read /etc/init.d/evil", 1))
    check("one that does is accepted",
          err(s6, "update-rc.d ssh defaults"), ("", 0))
    check("removing a script that is not there is refused",
          err(s6, "update-rc.d evil remove"),
          ("update-rc.d: error: cannot find a LSB script for evil", 1))
    check("...unless forced", err(s6, "update-rc.d -f evil remove"), ("", 0))
    check("registering a real script is persistence",
          any(e.get("kind") == "update_rc_d"
              for e in _events(s6, "update-rc.d cron defaults")), True)

    # -- and the box still agrees with itself -----------------------------------
    v7, s7 = sh()
    s7.run("systemd-run --unit=zz /bin/sleep 9")
    check("the unit systemd-run made is in the unit-file list",
          any("zz.service" in l for l in
              s7.run("systemctl list-unit-files --no-pager").splitlines()),
          True)
    check("stopping it works",
          (s7.run("systemctl stop zz"),
           s7.run("systemctl is-active zz").strip()), ("", "inactive"))
    check("a unit nobody made is still unknown",
          s7.run("systemctl is-active nosuchunit").strip(), "inactive")

    # -- and a filter filters ---------------------------------------------------
    # `systemctl list-units X` ignored its operand and printed all of them,
    # the same shape as `ip link show eth0` listing lo as well in sweep 92.
    # Both the rows and the trailing "N loaded units listed." line contain
    # " loaded ", so match on the unit column being a unit name.
    def _units_of(text):
        out = []
        for line in text.splitlines():
            f = line.split()
            if (len(f) > 2 and f[1] == "loaded"
                    and f[0].endswith((".service", ".timer", ".socket",
                                       ".mount", ".target", ".scope",
                                       ".slice", ".path"))):
                out.append(f[0])
        return out

    v8, s8 = sh()
    s8.run("systemd-run --unit=onlyme /bin/sleep 5")

    rows = _units_of(s8.run("systemctl list-units onlyme.service "
                            "--no-pager"))
    check("list-units with an operand lists one unit", len(rows), 1)
    check("...and it is the one asked for", rows[0], "onlyme.service")
    globbed = _units_of(s8.run("systemctl list-units 'systemd-*' "
                               "--no-pager"))
    check("a glob matches several", len(globbed) > 3, True)
    check("...and only matching ones",
          all(g.startswith("systemd-") for g in globbed), True)
    check("no operand still lists everything",
          len(_units_of(s8.run("systemctl list-units --no-pager")))
          > len(globbed), True)

    for label, got, want in FAILS:
        print("FAIL %s\n  got  %r\n  want %r" % (label, got, want))
    return len(FAILS)


def _events(s, cmd):
    got = []
    old = s.log
    s.log = lambda **kw: got.append(kw)
    try:
        s.run(cmd)
    finally:
        s.log = old
    return [e for e in got if e.get("event") == "persistence"]


def _lines(s, setup, listcmd, needle):
    s.run(setup)
    return [l for l in s.run(listcmd).splitlines() if needle in l]


if __name__ == "__main__":
    rc = main()
    print("runtest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
