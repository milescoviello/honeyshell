#!/usr/bin/env python3
"""Installing persistence as a systemd unit: does the box agree with itself?

_reap_session_processes says a backgrounded loader dies with the session
and that "a process installed as a *system* unit survives, which is the
difference an operator is testing". So this asks whether the unit route
actually works, by the four commands an operator uses to check it.

Asked over real SSH against the live honeypot, from a clean unit:

    is-enabled: disabled
    is-active : inactive
    MainPID   : 21708          <- names a process
    Loaded    : loaded (/usr/lib/systemd/system/zz.service; disabled; ...)
    ps count  : 0              <- nothing running
    $ systemctl enable --now zz.service
    Created symlink '/etc/systemd/system/multi-user.target.wants/zz.service'
        -> '/etc/systemd/system/zz.service'
    is-active : inactive       <- --now did not start it
    ps count  : 0

Three disagreements, all on the persistence path:

  * `show -p MainPID` named a pid for a unit that had never run, while
    is-active said inactive and ps showed nothing -- three answers to
    "is it running?";
  * `status` and `show -p FragmentPath` said the unit file was in
    /usr/lib/systemd/system while `enable` had just printed the symlink
    pointing at /etc/systemd/system, where the attacker actually wrote it;
  * `enable --now` created the symlink and left the unit dead. `--now` was
    not parsed anywhere in the emulator.

Measured on the guest, Debian 13.6, with a real unit dropped in /etc and
removed afterwards: an inactive unit reports MainPID 0, `enable --now`
brings it to active with a live pid that `ps -p` finds, and Loaded names
/etc/systemd/system/ztest.service.

Usage:  python3 unitnowtest.py
"""

import sys

import fakeshell

CHECKS, FAILS = [], []


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    fs = fakeshell.VFS()
    return fakeshell.Shell(vfs=fs, peer="198.51.100.15", peer_port=40444)


def r(sh, cmd):
    """Guarded: a suite that raises against the broken tree reports a
    traceback instead of the failures it was written to find."""
    try:
        return sh.run(cmd).rstrip("\n")
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


UNIT = "/etc/systemd/system/zz.service"
sh = shell()
r(sh, 'printf "[Unit]\\nDescription=sys\\n[Service]\\n'
      'ExecStart=/var/tmp/kdev\\n[Install]\\n'
      'WantedBy=multi-user.target\\n" > ' + UNIT)
r(sh, "head -c 2000 /dev/urandom > /var/tmp/kdev")
r(sh, "chmod +x /var/tmp/kdev")
r(sh, "systemctl daemon-reload")


def running(sh):
    return r(sh, 'ps aux | grep -c "[k]dev"')


# ------------------------------------------- a unit that has never started
check("a never-started unit is inactive",
      r(sh, "systemctl is-active zz.service"), "inactive")
check("...and has no main pid",
      r(sh, "systemctl show zz.service -p MainPID --value"), "0",
      "systemd reports MainPID=0 for anything not running; naming a pid "
      "here contradicts both is-active and ps")
check("...and no ExecMainPID either",
      r(sh, "systemctl show zz.service -p ExecMainPID --value"), "0")
check("...and ps shows nothing", running(sh), "0")

# ------------------------------------------ the unit file is where it is
frag = r(sh, "systemctl show zz.service -p FragmentPath --value")
check("FragmentPath names where the attacker wrote the file", frag, UNIT,
      "enable prints a symlink to this path in the same breath")
loaded = r(sh, "systemctl status zz.service 2>&1 | sed -n 2p")
check("status agrees with FragmentPath", UNIT in loaded, True,
      "got %r" % loaded.strip()[:110])

# --------------------------------------------------- enable --now starts it
out = r(sh, "systemctl enable --now zz.service 2>&1")
check("enable --now still creates the symlink",
      "multi-user.target.wants/zz.service" in out, True,
      "got %r" % out[:130])
check("enable --now starts the unit",
      r(sh, "systemctl is-active zz.service"), "active",
      "--now is enable *and* start; this is the one command a loader uses "
      "to install persistence and turn it on")
pid = r(sh, "systemctl show zz.service -p MainPID --value")
check("...and it now has a main pid", pid.isdigit() and pid != "0", True,
      "got %r" % pid)
check("...that ps can see", running(sh), "1")
check("...and status quotes the same pid",
      ("Main PID: %s" % pid) in r(sh, "systemctl status zz.service 2>&1"),
      True)
check("...and the symlink is on disk",
      r(sh, "test -L /etc/systemd/system/multi-user.target.wants/"
            "zz.service && echo yes || echo no"), "yes")
check("...and is-enabled agrees",
      r(sh, "systemctl is-enabled zz.service"), "enabled")

# ------------------------------------------------- disable --now stops it
r(sh, "systemctl disable --now zz.service")
check("disable --now stops the unit",
      r(sh, "systemctl is-active zz.service"), "inactive")
check("...and the main pid goes back to 0",
      r(sh, "systemctl show zz.service -p MainPID --value"), "0")
check("...and ps loses the process", running(sh), "0")

# ------------------------------------- plain enable still does not start
sh2 = shell()
r(sh2, 'printf "[Unit]\\nDescription=sys\\n[Service]\\n'
       'ExecStart=/var/tmp/kdev\\n[Install]\\n'
       'WantedBy=multi-user.target\\n" > ' + UNIT)
r(sh2, "systemctl daemon-reload")
r(sh2, "systemctl enable zz.service")
check("enable without --now enables but does not start",
      r(sh2, "systemctl is-active zz.service"), "inactive",
      "only --now starts it; enable on its own is a boot-time promise")
check("...though it is enabled",
      r(sh2, "systemctl is-enabled zz.service"), "enabled")

# ----------------------------------------- a stock unit is still coherent
sh3 = shell()
act = r(sh3, "systemctl is-active cron")
mp = r(sh3, "systemctl show cron -p MainPID --value")
check("a stock running unit still reports its pid",
      act == "active" and mp.isdigit() and mp != "0", True,
      "got is-active=%r MainPID=%r" % (act, mp))
r(sh3, "systemctl stop cron")
check("...and a stopped one reports 0",
      r(sh3, "systemctl show cron -p MainPID --value"), "0")
check("...and says so", r(sh3, "systemctl is-active cron"), "inactive")

for f in FAILS:
    print(" ", f)
print("   unitnow: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
