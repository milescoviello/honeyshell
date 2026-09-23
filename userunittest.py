#!/usr/bin/env python3
"""`systemctl --user` read the system search path and denied what it found.

On 2026-09-15 at 22:16 UTC, 203.0.113.67 logged in as deploy and ran the
whole modern persistence sequence in one command:

    sh -lc 'mkdir -p ~/.config/systemd/user &&
            cat > ~/.config/systemd/user/watcher-netai.service &&
            systemctl --user daemon-reload &&
            systemctl --user enable --now watcher-netai.service'

The honeypot wrote the file, logged it as persistence --

    persistence_write path=/home/deploy/.config/systemd/user/
                           watcher-netai.service kind=systemd_user_unit

-- and then told the attacker:

    Failed to enable unit: Unit watcher-netai.service does not exist
    rc=1

Two readers of one question. `_PERSIST_DIRS` was taught about
`~/.config/systemd/user` on 2026-09-03, for this same actor and this same
unit name; `systemctl` never was. So the alarm fired and the box denied it
at the same instant, and the attacker is the one who got the honest answer.

`--user` selects a different unit search path. It was being dropped with
every other flag by `if x.startswith("-"): continue`, so a user unit was
looked for among the system units, not found, and reported missing while
`cat` printed it back.

Ground truth, systemd 257 (257.13-1~deb13u1) in a debian:trixie container,
with the file present:

    $ systemctl --user enable --now watcher-netai.service
    Created symlink '/home/deploy/.config/systemd/user/
      default.target.wants/watcher-netai.service' ->
      '/home/deploy/.config/systemd/user/watcher-netai.service'.

and with the unit genuinely absent:

    $ systemctl --user enable nosuch.service
    Failed to enable unit: Unit nosuch.service does not exist
    rc=1

So the message we gave is real -- it is simply reserved for the case where
the unit is not there, which was not this case.

A user unit needs no root and survives a reboot the same way a system one
does, which is why the persistence detector treats it as the same alarm.
An emulator that refuses to install it loses the rest of the session.

Usage:  python3 userunittest.py
"""

import sys

import fakeshell as fs

CHECKS, FAILS = [], []

UNIT = ("[Unit]\n"
        "Description=netai watcher\n"
        "[Service]\n"
        "ExecStart=/dev/shm/w.sh\n"
        "Restart=always\n"
        "[Install]\n"
        "WantedBy=default.target\n")


def check(name, got, want, note=""):
    ok = got == want
    CHECKS.append(ok)
    if not ok:
        FAILS.append("FAIL %s\n  got  %r\n  want %r%s"
                     % (name, got, want, "\n  -- " + note if note else ""))


def shell():
    sh = fs.Shell(fs.VFS(), peer="203.0.113.88")
    sh.exec_mode = True
    return sh


def run(sh, cmd):
    """(stdout, stderr, rc), with the error buffer drained."""
    try:
        out = sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "", "<%s>" % exc, None
    err = "".join(sh._err)
    sh._err = []
    return out, err, sh.last_rc


def plant(sh, body=UNIT, name="watcher-netai.service"):
    run(sh, "mkdir -p ~/.config/systemd/user")
    lines = " ".join("'%s'" % ln for ln in body.rstrip("\n").split("\n"))
    run(sh, "printf '%%s\\n' %s > ~/.config/systemd/user/%s" % (lines, name))


# ===================================== the sequence that was denied
sh = shell()
plant(sh)

out, err, rc = run(sh, "cat ~/.config/systemd/user/watcher-netai.service")
check("the unit file is really there first", "ExecStart=/dev/shm/w.sh" in out,
      True, "everything below is about a file that exists")

out, err, rc = run(sh, "systemctl --user daemon-reload")
check("daemon-reload succeeds", rc, 0)

out, err, rc = run(sh, "systemctl --user enable --now watcher-netai.service")
check("enable --now succeeds on a unit that exists", rc, 0,
      "production got rc 1 and \"Unit ... does not exist\"")
check("...and does not deny the unit",
      "does not exist" in err, False,
      "systemd reserves that message for a unit that is genuinely absent")
check("...and reports the symlink it created",
      "Created symlink" in err, True)
check("...inside the user's own tree, not /etc/systemd/system",
      "/root/.config/systemd/user/default.target.wants/"
      "watcher-netai.service" in err, True,
      "a user manager does not write to /etc/systemd/system at all")
check("...naming the unit file as the target",
      "/root/.config/systemd/user/watcher-netai.service" in err, True)

out, err, rc = run(sh, "ls ~/.config/systemd/user/default.target.wants/")
check("the wants symlink exists in the filesystem too",
      "watcher-netai.service" in out, True,
      "the message and the filesystem have to agree")

out, err, rc = run(sh, "systemctl --user is-active watcher-netai.service")
check("--now leaves the unit active", out.strip(), "active",
      "enable --now is enable *and* start")

# ======================================= the denial is still available
out, err, rc = run(sh, "systemctl --user enable nosuch.service")
check("a unit that really is absent is still refused", rc, 1)
check("...with the message systemd uses",
      "Failed to enable unit: Unit nosuch.service does not exist" in err,
      True, "measured against systemd 257 in debian:trixie")

# ================================ a user manager knows no system units
out, err, rc = run(sh, "systemctl --user status ssh")
check("--user does not answer for a system unit", rc, 4,
      "asking the user manager about sshd must not reach the real one")

out, err, rc = run(sh, "systemctl --user list-unit-files")
check("--user lists the user's own units", "watcher-netai.service" in out,
      True)
# Enablement is derived from the .wants symlink, and the reader looked for
# it only under /etc/systemd/system -- so a unit enable had just linked in
# the user's tree read back "disabled" one line after systemctl said it had
# created the symlink. Exactly the shape the comment above that reader
# describes being fixed for timers, one search path further out.
# systemd 257 in debian:trixie goes disabled -> enabled across an enable.
row = next((ln.split() for ln in out.splitlines()
            if ln.startswith("watcher-netai.service")), [])
check("...and says the enabled one is enabled", row[1:2], ["enabled"],
      "enable, is-active and list-unit-files have to agree about one unit")
for sysunit in ("apt-daily", "-.mount", "systemd-journald"):
    check("...and not the system unit %s" % sysunit, sysunit in out, False,
          "these come from _TIMER_PERIOD and _OTHER_UNITS, which were "
          "added back whatever the search path was")

# ================================== and the system side is unchanged
out, err, rc = run(sh, "systemctl is-active ssh")
check("the system manager still answers for ssh", out.strip(), "active")
out, err, rc = run(sh, "systemctl list-unit-files")
check("...and still lists the system units", "apt-daily" in out, True,
      "the fix must not cost the system half")

# ========================= the two readers agree about the same write
sh2 = shell()
seen = []
sh2.log = lambda **kw: seen.append(kw)
plant(sh2)
kinds = [e.get("kind") for e in seen if e.get("event") == "persistence_write"]
check("the write is still logged as persistence",
      "systemd_user_unit" in kinds, True,
      "the detector knew about this directory before systemctl did")
out, err, rc = run(sh2, "systemctl --user enable --now watcher-netai.service")
check("...and systemctl now agrees the unit exists", rc, 0,
      "the alarm and the box used to disagree at the same instant")

# A unit that was never enabled must still read disabled, or the check
# above passes for the wrong reason.
sh3 = shell()
plant(sh3, name="unenabled.service")
out, err, rc = run(sh3, "systemctl --user list-unit-files")
row = next((ln.split() for ln in out.splitlines()
            if ln.startswith("unenabled.service")), [])
check("a unit nobody enabled still reads disabled", row[1:2], ["disabled"],
      "or the enabled check above passes for the wrong reason")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
