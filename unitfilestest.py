"""`systemctl list-unit-files NAME` -- the check made right after installing one.

Found while looking for a persistence mechanism nobody had swept. `at` was
the candidate and turned out to be a non-finding: neither the guest nor the
emulator has at, atq, atrm or batch, and both say so. But the probe used

    systemctl list-unit-files atd.service

to see whether the box had an atd unit, and the answer was all 56 units on
the box, ending "56 unit files listed." The operand was thrown away.

Real systemd, measured on the guest (Debian 13.6):

    list-unit-files atd.service        0 unit files listed.
    list-unit-files nosuchunit.service 0 unit files listed.
    list-unit-files ssh.service        1 unit files listed.  + the row
    list-unit-files ssh                0 unit files listed.  (no completion)
    list-unit-files 'ssh.*'            2
    list-unit-files 'ssh*'             8
    list-unit-files '*.timer'          8
    list-unit-files ssh.service cron.service   1  (patterns are unioned)

So: plain globbing against the full unit name, several patterns unioned,
and a bare name matches nothing because it is not a glob and no `.service`
is implied.

Two more things fell out of the same listing. Every name was printed with
".service" appended, so the root mount appeared as "-.mount.service" and a
timer as "apt-daily-upgrade.timer.service" -- suffixes that no unit has.
`status` had this same bug and fixed it with _unit_full; this call site
never got the fix. And systemd sizes the name column to the widest row it
is printing, which only shows once filtering works: a filter matching one
unit gives "UNIT FILE   STATE   PRESET", not a fixed 25-wide header.

Usage:  python3 unitfilestest.py
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


def listing(pattern=""):
    """(rows, count, header) for a list-unit-files call.

    Guarded: against a tree where the count line is missing or the output
    is empty this returns sentinels rather than raising, so the suite
    reports its failures instead of a traceback.
    """
    try:
        out = sh.run("systemctl list-unit-files %s" % pattern)
    except Exception as exc:                                   # noqa: BLE001
        return [], -1, "<raised %s>" % type(exc).__name__
    lines = out.splitlines()
    if not lines:
        return [], -1, ""
    header = lines[0]
    count = -1
    for l in lines:
        if l.endswith("unit files listed."):
            try:
                count = int(l.split()[0])
            except (ValueError, IndexError):
                count = -1
    rows = [l.split()[0] for l in lines[1:]
            if l.strip() and not l.endswith("unit files listed.")]
    return rows, count, header


# --------------------------------------------------------- the filter works
rows, n, _ = listing("atd.service")
check("an absent unit lists nothing", n, 0,
      "this returned every unit on the box, which is what hid the fact "
      "that the operand was being discarded")
check("...and prints no rows", rows, [])

rows, n, _ = listing("nosuchunit.service")
check("an invented name lists nothing", n, 0)

rows, n, _ = listing("ssh.service")
check("a real unit lists exactly itself", n, 1)
check("...and it is the right one", rows, ["ssh.service"])

rows, n, _ = listing("ssh")
check("a bare name matches nothing", n, 0,
      "systemd does not complete .service for this operand; measured on "
      "the guest, `list-unit-files ssh` gives 0")

# ------------------------------------------------------------- globbing
rows, n, _ = listing("*.timer")
check("a glob matches by suffix", n > 0 and all(r.endswith(".timer")
                                                for r in rows), True,
      "got %r" % rows[:4])
rows, n, _ = listing("*.mount")
check("...and for mounts too", n > 0 and all(r.endswith(".mount")
                                             for r in rows), True,
      "got %r" % rows[:4])
rows_a, na, _ = listing("ssh.service")
rows_b, nb, _ = listing("cron.service")
rows_u, nu, _ = listing("ssh.service cron.service")
check("several patterns are unioned", nu, na + nb,
      "systemd takes the union; got %r for the pair" % rows_u)

# --------------------------------------------- the suffix is the unit's own
allrows, total, header = listing()
check("everything is still listed with no pattern", total > 10, True)
bad = [r for r in allrows if r.endswith(".mount.service")
       or r.endswith(".timer.service") or r.endswith(".socket.service")
       or r.endswith(".target.service")]
check("no unit is given a second suffix", bad, [],
      "the root mount listed as '-.mount.service' and a timer as "
      "'apt-daily-upgrade.timer.service'; _unit_full is the helper status "
      "already uses for this")
check("the root mount is named as systemd names it",
      "-.mount" in allrows, True)
check("...and is not also there wrongly",
      "-.mount.service" in allrows, False)

# ------------------------------------------------- the column is sized
_, _, h1 = listing("ssh.service")
check("a one-row listing gets a narrow header",
      h1.startswith("UNIT FILE ") and len(h1.split("STATE")[0]) < 20, True,
      "systemd sizes the name column to what it prints; got %r" % h1)
_, _, hall = listing()
check("...and the full listing gets a wide one",
      len(hall.split("STATE")[0]) > len(h1.split("STATE")[0]), True,
      "got %r vs %r" % (hall[:40], h1[:40]))
longest = max([len(r) for r in allrows] or [0])
check("the widest name still fits its column",
      len(hall.split("STATE")[0].rstrip()) <= len("UNIT FILE")
      or longest <= len(hall.split("STATE")[0]), True)

# -------------------------------------------------- the count is the rows
for pat in ("", "ssh.service", "*.timer", "atd.service"):
    r2, n2, _ = listing(pat)
    check("count matches rows for %r" % (pat or "<none>"), n2, len(r2),
          "the summary line and the listing have to be the same listing")

for f in FAILS:
    print(" ", f)
print("   unitfiles: %d checks, %d differ" % (len(CHECKS), len(FAILS)))
sys.exit(1 if FAILS else 0)
