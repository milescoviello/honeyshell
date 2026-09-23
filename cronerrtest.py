#!/usr/bin/env python3
"""When crontab refuses a file, does it refuse it the way cron does?

Found by following the traffic the systemd fix opened up. `203.0.113.77`
and `203.0.113.69` now get past `systemctl --user enable`, and the step
before it is a cron install that has been failing all along:

    CRON="$(crontab -l 2>/dev/null || true)"
    echo "$CRON" | grep -F '...' >/dev/null 2>&1 || \\
      printf '%s\\n%s\\n' "@reboot  /dev/shm/w.sh "astats" "netai" ..." \\
        "0 * * * * cd "/dev/shm" && ./w.sh "astats" ..." \\
        | (cat -; echo "$CRON") | crontab -

    -> rc=1   "-":1: bad command
              errors in crontab file, can't install.

The refusal is *correct*. Their own quoting is broken -- the inner quotes
close and reopen, so the shell word-splits and `printf '%s\\n%s\\n'` cycles
its format over the pieces, producing

    @reboot  /dev/shm/w.sh astats netai kstats ssh
    2
    ranges
    0 * * * * cd /dev/shm && ./w.sh astats netai kstats ssh
    2
    ranges

Real cron rejects that too, and vixie cron in debian:trixie was checked to
be sure: it installs nothing and returns 1. Our printf, our `(cat -; echo)`
pipeline and our word-splitting all produce those six lines byte for byte.

What was wrong was the *reason*:

    real cron   "-":2: bad hour
    emulator    "-":1: bad command

Line 2 is the bare `2`. Real cron reads it as a minute, reaches the end of
the line looking for an hour, and says so. We said "bad command" and named
the wrong line.

Three defects behind that, all measured against vixie cron in
debian:trixie:

  * **the line number.** Not a simple off-by-one, which is why a blanket
    +1 would have been wrong for half the cases. Cron prints the 1-based
    line when the parse reached the end of the line, and one less when it
    failed with input still to come on that line. `ranges` alone is
    "-":1: because the bad token is the last one; `60 * * * * /bin/true`
    is "-":0: because five more tokens follow. Ours was 0-based, which
    matched the second group by accident and was wrong for the first.
  * **running out mid-schedule.** `2` is "bad hour", `2 3` is
    "bad day-of-month", `2 3 4` is "bad month", `2 3 4 5` is
    "bad day-of-week". Every one of them was "bad command".
  * **a schedule with no command is accepted.** `* * * * *` installs on a
    real box and runs an empty command; we rejected it. So did
    `2 3 4 5 6`.

And `@nosuch /bin/true` is "bad time specifier", not "bad minute" -- an
`@` line has no minute field to be bad.

Usage:  python3 cronerrtest.py
"""

import sys

import fakeshell as fs

CHECKS, FAILS = [], []

# Every row measured against vixie cron in a debian:trixie container.
# (input lines, first line of stderr or ACCEPT)
ACCEPT = "(accepted)"
CASES = [
    # the parse reached end of line -> 1-based
    (["ranges"],                                   '"-":1: bad minute'),
    (["2"],                                        '"-":1: bad hour'),
    (["2 3"],                                      '"-":1: bad day-of-month'),
    (["2 3 4"],                                    '"-":1: bad month'),
    (["2 3 4 5"],                                  '"-":1: bad day-of-week'),
    (["* *"],                                      '"-":1: bad day-of-month'),
    # input still to come on the line -> one less
    (["60 * * * * /bin/true"],                     '"-":0: bad minute'),
    (["*/0 * * * * /bin/true"],                    '"-":0: bad minute'),
    (["* 25 * * * /bin/true"],                     '"-":0: bad hour'),
    (["* abc * * * /bin/true"],                    '"-":0: bad hour'),
    (["* * 32 * * /bin/true"],                     '"-":0: bad day-of-month'),
    (["* * abc * * /bin/true"],                    '"-":0: bad day-of-month'),
    (["* * * * 8 /bin/true"],                      '"-":0: bad day-of-week'),
    (["@nosuch /bin/true"],                        '"-":0: bad time specifier'),
    # the same rule on a later line
    (["* * * * * /a", "ranges"],                   '"-":2: bad minute'),
    (["* * * * * /a", "60 * * * * /b"],            '"-":1: bad minute'),
    (["* * * * * /a", "* * * * * /b",
      "60 * * * * /c"],                            '"-":2: bad minute'),
    # accepted
    (["* * * * *"],                                ACCEPT),
    (["2 3 4 5 6"],                                ACCEPT),
    (["@reboot"],                                  ACCEPT),
    (["@daily"],                                   ACCEPT),
    (["@reboot /dev/shm/w.sh astats netai"],       ACCEPT),
    (["* * * jan * /bin/true"],                    ACCEPT),
    (["* * * * mon /bin/true"],                    ACCEPT),
    (["2 3 4 5 6 /bin/true"],                      ACCEPT),
    (["# just a comment", "* * * * * /a"],         ACCEPT),
    (["MAILTO=root", "* * * * * /a"],              ACCEPT),
]

# The command as logged, byte for byte, from 203.0.113.77 at 14:59:55.
PROD = ('\nCRON="$(crontab -l 2>/dev/null || true)"\necho "$CRON" | grep -F '
        '\'/dev/shm/w.sh "astats" "netai" "kstats" "ssh 2 ranges"\' '
        '>/dev/null 2>&1 || \\\n'
        '  printf \'%s\\n%s\\n\' '
        '"@reboot  /dev/shm/w.sh "astats" "netai" "kstats" "ssh 2 ranges"" '
        '"0 * * * * cd "/dev/shm" && ./w.sh "astats" "netai" "kstats" '
        '"ssh 2 ranges"" | (cat -; echo "$CRON") | crontab -\n')

# What bash and coreutils really make of that printf, measured in the
# container. If our word-splitting or format cycling ever drifts, the
# crontab result below would change for a reason that has nothing to do
# with cron, so the intermediate is pinned too.
PROD_LINES = [
    "@reboot  /dev/shm/w.sh astats netai kstats ssh",
    "2",
    "ranges",
    "0 * * * * cd /dev/shm && ./w.sh astats netai kstats ssh",
    "2",
    "ranges",
]


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


def install(sh, lines):
    """Pipe these lines into `crontab -`; return its first stderr line."""
    try:
        sh.run("crontab -r 2>/dev/null")
        sh._err = []
        quoted = " ".join("'%s'" % ln for ln in lines)
        sh.run("printf '%%s\\n' %s | crontab -" % quoted)
        err = "".join(sh._err).strip()
        sh._err = []
        return err.split("\n")[0] if err else ACCEPT
    except Exception as exc:                                   # noqa: BLE001
        return "<%s>" % exc


sh = shell()
for lines, want in CASES:
    check("crontab - %s" % (lines if len(lines) > 1 else lines[0]),
          install(sh, lines), want,
          "measured against vixie cron in debian:trixie")

# An accepted crontab has to actually be there afterwards -- "accepted"
# must not mean "silently dropped".
sh2 = shell()
install(sh2, ["* * * * *"])
sh2._err = []
check("a schedule with no command installs and reads back",
      sh2.run("crontab -l").strip(), "* * * * *",
      "cron accepts it and runs an empty command")

sh3 = shell()
install(sh3, ["@reboot /dev/shm/w.sh astats netai"])
sh3._err = []
check("an @reboot line installs and reads back",
      sh3.run("crontab -l").strip(), "@reboot /dev/shm/w.sh astats netai",
      "@reboot is the commonest persistence idiom there is")

# A rejected crontab must leave the previous one alone, which is the whole
# point of refusing: cron installs nothing rather than a partial file.
sh4 = shell()
install(sh4, ["*/5 * * * * /good"])
# Deliberately not through install(), which clears first: the point is
# what a *failed* install does to a crontab that is already there. Real
# cron leaves it untouched, and the first draft of this check called the
# clearing helper and so proved nothing but its own setup.
sh4._err = []
sh4.run("printf '%s\\n' 'ranges' | crontab -")
sh4._err = []
check("a refused install does not disturb the existing crontab",
      sh4.run("crontab -l").strip(), "*/5 * * * * /good",
      "cron installs nothing rather than a partial file")

# ============================== the command as the attacker really sent it
sh5 = shell()
sh5._err = []
out = sh5.run("printf '%s\\n%s\\n' "
              '"@reboot  /dev/shm/w.sh "astats" "netai" "kstats" '
              '"ssh 2 ranges"" '
              '"0 * * * * cd "/dev/shm" && ./w.sh "astats" "netai" '
              '"kstats" "ssh 2 ranges""')
sh5._err = []
check("their printf splits the way bash splits it",
      out.split("\n")[:6], PROD_LINES,
      "if this drifts the crontab result below changes for the wrong "
      "reason")

sh6 = shell()
sh6.run(PROD)
err6 = "".join(sh6._err).strip().split("\n")[0]
sh6._err = []
check("the logged command is refused exactly as cron refuses it",
      err6, '"-":2: bad hour',
      "production said \"-\":1: bad command; real cron says \"-\":2: bad hour")
check("...and installs nothing", sh6.run("crontab -l").strip(), "",
      "a refusal that still installed would be the worse bug")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
