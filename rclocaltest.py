"""/etc/rc.local: the oldest persistence route, and the unit behind it.

Found by searching the suite inventory for persistence mechanisms with no
coverage at all. rc.local had none, and the box had no trace of the unit
that implements it:

    systemctl status rc-local.service     Unit rc-local.service could not be found.
    systemctl is-enabled rc-local.service not-found
    systemctl show -p FragmentPath        (empty)
    systemctl list-unit-files rc-local.service   0 unit files listed.
    ls /lib/systemd/system/rc-local.service      No such file

On the guest -- Debian 13.6, which is what this box claims to be -- the
unit ships whether or not /etc/rc.local exists:

    rc-local.service static -
    is-enabled            static      rc 0
    FragmentPath          /usr/lib/systemd/system/rc-local.service
    status                (circle) rc-local.service - /etc/rc.local Compatibility
                          Loaded: loaded (...; static)
                          Active: inactive (dead)

So someone dropping an /etc/rc.local and checking whether the mechanism
exists was told it does not, on a box where it always does. /etc/rc.local
itself is correctly absent on both -- Debian has not shipped one for
years; the *unit* is what is always there.

The fix is the whole unit file, seeded verbatim, and nothing else: the
box already discovers units from the filesystem and already derives
enablement from the body, so a unit with no [Install] reports "static"
without anything asserting it. That is also why it is static and not
enabled -- systemd-rc-local-generator pulls it in when /etc/rc.local is
executable, rather than a .wants symlink doing it.

Seeding it exposed two things that were constants:

  * `list-unit-files` printed STATE "enabled" and PRESET "enabled" for
    every row, so a static unit claimed to start at boot. The guest lists
    "rc-local.service static -", "systemd-journald.service static -" and
    "multi-user.target static -". PRESET is "-" for anything that cannot
    be enabled.
  * a static unit's `status` Loaded line carries no preset at all:
    "loaded (...; static)", not "...; static; preset: enabled".

Both were noted as unfixed in sweep 196, which had no case that showed
them. This is the case.

Usage:  python3 rclocaltest.py
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


sh = shell()


def r(cmd):
    try:
        return sh.run(cmd).rstrip("\n")
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


UNIT = "rc-local.service"
PATH = "/usr/lib/systemd/system/rc-local.service"

# ------------------------------------------------------- the unit is there
check("the unit file exists where systemd keeps it",
      r("test -f %s && echo yes || echo no" % PATH), "yes",
      "Debian ships this on every install; we had no trace of it")
body = r("cat %s" % PATH)
check("it is the /etc/rc.local compatibility unit",
      "Description=/etc/rc.local Compatibility" in body, True)
check("...guarded by the condition that makes it safe to ship",
      "ConditionFileIsExecutable=/etc/rc.local" in body, True,
      "this is why ExecStart may name a file that does not exist")
check("...running /etc/rc.local start",
      "ExecStart=/etc/rc.local start" in body, True)
check("...as a forking service", "Type=forking" in body, True)
check("...that stays up once it has run",
      "RemainAfterExit=yes" in body, True)
check("it has no [Install] section", "[Install]" in body, False,
      "the generator pulls it into multi-user.target, not a .wants "
      "symlink -- which is what makes it static rather than enabled")

# --------------------------------------------------- and every reader knows
check("is-enabled says static", r("systemctl is-enabled %s" % UNIT), "static")
check("is-active says inactive", r("systemctl is-active %s" % UNIT),
      "inactive")
check("FragmentPath names the file",
      r("systemctl show %s -p FragmentPath --value" % UNIT), PATH)
row = r("systemctl list-unit-files %s | sed -n 2p" % UNIT)
check("list-unit-files finds exactly it",
      r("systemctl list-unit-files %s | tail -1" % UNIT), "1 unit files listed.")
check("...and reports it static, not enabled",
      " ".join(row.split()), "rc-local.service static -",
      "the guest prints exactly this")
st = r("systemctl status %s 2>&1" % UNIT)
check("status knows the unit", "could not be found" in st, False)
check("...and describes it", "/etc/rc.local Compatibility" in st, True)
check("...loaded from the right path, static, with no preset",
      "loaded (%s; static)" % PATH in st, True,
      "a static unit's Loaded line carries no preset on a real box; got "
      "%r" % st.splitlines()[1].strip() if len(st.splitlines()) > 1 else st)
check("...and inactive (dead)", "inactive (dead)" in st, True)

# ------------------------------- /etc/rc.local itself is absent, as on Debian
check("/etc/rc.local does not exist",
      r("test -e /etc/rc.local && echo yes || echo no"), "no",
      "Debian stopped shipping one; the unit is what is always present")

# --------------------------------- the state columns are derived, not fixed
for unit, want in (("ssh.service", "enabled enabled"),
                   ("systemd-journald.service", "static -"),
                   ("multi-user.target", "static -"),
                   ("fstrim.timer", "enabled enabled")):
    got = " ".join(r("systemctl list-unit-files %s | sed -n 2p"
                     % unit).split())
    check("list-unit-files state for %s" % unit, got,
          "%s %s" % (unit, want), "measured against the guest")

# ------------------------------------- an unknown unit is still unknown
check("an invented unit is still not-found",
      r("systemctl is-enabled nosuchunit.service"), "not-found",
      "seeding a real unit must not make everything exist")
check("...and status still says so",
      "could not be found" in r("systemctl status nosuchunit.service 2>&1"),
      True)

for f in FAILS:
    print(" ", f)
print("   rclocal: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
