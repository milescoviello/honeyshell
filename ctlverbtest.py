"""The systemd ctl trio, and which query verbs each one actually takes.

Axis chosen to get out of the disk/device family three sweeps had been
living in. hostnamectl, timedatectl and localectl each restate something
an older command already answers, which makes them natural places for one
box to give two answers.

Three findings, and the interesting part is that they point in different
directions.

**timedatectl show did not exist.** The scripted way to read one property
answered with the whole human table:

    guest   timedatectl show -p Timezone --value   ->  Etc/UTC
            timedatectl show                       ->  Timezone=Etc/UTC
                                                       LocalRTC=no ...
    ours    both                                   ->  the status block

Same shape as list-unit-files ignoring its operand in sweep 196.

**localectl was missing outright.** systemd ships it and the guest has it
at /usr/bin/localectl, so a box with hostnamectl and timedatectl and no
localectl had shipped two thirds of a package -- and `dpkg -L systemd`
here did not list it either.

**hostnamectl was too permissive.** It is the one of the trio with no
`show` verb and no -p, which reads like an oversight and is not. Ours
accepted anything and printed the status block, so a script that runs
`hostnamectl show` gets an error on Debian and output here -- a tell in
the direction people forget to check.

    guest   hostnamectl show        Unknown command verb 'show', did you
                                    mean 'help'?                    rc 1
            hostnamectl frobnicate  Unknown command verb 'frobnicate'.
            hostnamectl -p X        hostnamectl: invalid option -- 'p'

Two things measured that turned out **not** to be bugs, recorded so nobody
re-opens them: /etc/timezone and /etc/default/keyboard are absent on the
guest as well -- Debian stopped shipping both -- and `loginctl
show-session` works fine; an earlier probe of it failed only because it
passed a session id from a connection that had already closed.

Usage:  python3 ctlverbtest.py
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


def rc(cmd):
    return r("%s >/dev/null 2>&1; echo $?" % cmd)


def line0(text):
    """First line or "" -- splitlines()[0] raises on an empty answer."""
    parts = text.splitlines()
    return parts[0] if parts else ""


# ------------------------------------------------- timedatectl show exists
show = r("timedatectl show")
check("timedatectl show prints key=value",
      all("=" in l for l in show.splitlines()) and bool(show.splitlines()),
      True, "it printed the status block instead; got %r" % show[:80])
check("...including the timezone",
      any(l.startswith("Timezone=") for l in show.splitlines()), True)
for key in ("LocalRTC", "CanNTP", "NTP", "NTPSynchronized", "TimeUSec",
            "RTCTimeUSec"):
    check("show has %s" % key,
          any(l.startswith(key + "=") for l in show.splitlines()), True)

check("show -p NAME --value gives the bare value",
      r("timedatectl show -p Timezone --value"),
      r("timedatectl show").split("Timezone=", 1)[1].splitlines()[0]
      if "Timezone=" in show else "<none>",
      "this is how a script reads one property")
check("...and it is the zone /etc/localtime names",
      r("timedatectl show -p Timezone --value"),
      r("readlink /etc/localtime").replace("/usr/share/zoneinfo/", ""),
      "timedatectl reads the zone from that symlink, so they cannot differ")
check("show -p NTP --value", r("timedatectl show -p NTP --value"), "yes")
check("show -p on one property prints only that one",
      len(r("timedatectl show -p Timezone").splitlines()), 1)

# ------------------------------------------------ and it still refuses junk
check("timedatectl rejects an unknown verb",
      r("timedatectl frobnicate 2>&1"), "Unknown command verb 'frobnicate'.")
check("...with a non-zero status", rc("timedatectl frobnicate"), "1")
check("plain timedatectl still prints the table",
      "Local time" in line0(r("timedatectl")), True)

# ------------------------------------------------------- localectl exists
check("localectl is on PATH", r("command -v localectl"), "/usr/bin/localectl",
      "systemd ships it; the box had two thirds of the trio")
check("dpkg credits the package with it",
      r("dpkg -L systemd 2>/dev/null | grep -c localectl"), "1")
loc = r("localectl")
check("localectl prints the three rows", len(loc.splitlines()), 3,
      "got %r" % loc[:90])
check("...System Locale first",
      line0(loc).strip().startswith("System Locale:"), True)
check("...VC Keymap unset", "VC Keymap: (unset)" in loc, True,
      "there is no /etc/default/keyboard here, as on the guest")
check("...X11 Layout unset", "X11 Layout: (unset)" in loc, True)
check("the rows are right-aligned to 16",
      [len(l.split(":")[0]) for l in loc.splitlines()], [16, 16, 16])

# --------------------------------- and it agrees with the other readers
lang_ctl = loc.split("LANG=", 1)[1].splitlines()[0] if "LANG=" in loc else ""
check("localectl agrees with /etc/locale.conf",
      lang_ctl, r("cat /etc/locale.conf").split("=", 1)[1],
      "it reads that file rather than restating the value")
check("...and with locale(1)",
      lang_ctl, r("locale | grep ^LANG=").split("=", 1)[1])
check("list-locales lists it", r("localectl list-locales"), lang_ctl)
check("localectl rejects an unknown verb",
      r("localectl frobnicate 2>&1"), "Unknown command verb 'frobnicate'.")

# ------------------------------------------- hostnamectl has no show verb
check("hostnamectl rejects show",
      r("hostnamectl show 2>&1"),
      "Unknown command verb 'show', did you mean 'help'?",
      "systemctl and timedatectl take show; hostnamectl does not, and "
      "printing status for it is a tell in the permissive direction")
check("...with a non-zero status", rc("hostnamectl show"), "1")
check("hostnamectl rejects an unknown verb",
      r("hostnamectl frobnicate 2>&1"),
      "Unknown command verb 'frobnicate'.")
check("hostnamectl rejects -p",
      r("hostnamectl -p StaticHostname 2>&1"),
      "hostnamectl: invalid option -- 'p'")

# ------------------------------------- while everything real still works
check("hostnamectl status still prints",
      "Static hostname" in line0(r("hostnamectl")), True)
check("hostnamectl hostname still answers", r("hostnamectl hostname"),
      r("hostname"))
check("hostnamectl --static still answers", r("hostnamectl --static"),
      r("cat /etc/hostname"))
check("set-hostname still works",
      (r("hostnamectl set-hostname box7"), r("hostnamectl hostname"))[1],
      "box7")
check("...and the kernel followed",
      r("cat /proc/sys/kernel/hostname"), "box7",
      "one hostname, every reader")
r("hostnamectl set-hostname web01")

for f in FAILS:
    print(" ", f)
print("   ctlverb: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
