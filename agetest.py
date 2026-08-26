#!/usr/bin/env python3
"""Password aging: when does this account expire, and can it be changed?

/etc/shadow carries six aging columns. `chage -l` prints them, `passwd -S`
prints them, and `chage`, `passwd` and `usermod` all write them. Three
readers of one row, and they were three separate opinions:

    chage -l <user>     read the last-change column and invented the other
                        six: "never", "never", "never", 0, 99999, 7
    passwd -S <user>    printed "0 99999 7 -1" as a literal, and the date
                        in US format
    passwd -S -a        printed one line where the real one prints thirty
    chage -M 30 root    chage: PAM: Authentication token manipulation error
    usermod -e <date>   rc 0, and the file unchanged
    passwd -e <user>    reported success and wrote nothing

So setting a maximum with chage was refused outright, and setting an expiry
date with usermod was *accepted* and discarded -- which is worse, because
the box agreed to it. `chage -I -1 -m 0 -M 99999 -E -1 <user>` is the line
an operator runs after adding an account so it cannot expire out from under
them, and then they check it with `chage -l`. Both halves have to hold.

Measured on the guest (shadow 4.17, Debian 13), for a row of
`20600:3:30:5:10:20900:`

    Last password change   : May 27, 2026     the lastchg column
    Password expires       : Jun 26, 2026     lastchg + max
    Password inactive      : Jul 06, 2026     lastchg + max + inactive
    Account expires        : Mar 23, 2027     the expire column
    passwd -S              agetest2 L 2026-05-27 3 30 5 10

with these edges, each of which was measured rather than reasoned about:

    max >= 10000        "never" -- 9999 gives Oct 11 2053 and 10000 does
                        not, so the box's own 99999 must not print a date
                        in 2297
    the inactive line   inherits that ceiling, and is "never" on its own
                        for an inactive of 0 or less
    lastchg == 0        all three of the first lines read "password must
                        be changed", and passwd -S prints 1970-01-01
    chage -M -1         clears the column rather than storing -1
    passwd -u on an     two lines of refusal and rc 3, not a silent
    account with no     success
    password
    passwd -d/-l/-e     "passwd: password changed." -- there is no
                        "password expiry information changed" in this
                        shadow

The suite does not pin the box's own aging values. It writes a row, reads
it back through all three commands, and requires them to agree.

Usage:  python3 agetest.py
"""

import re
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
    return fakeshell.Shell(vfs=fs, peer="198.51.100.13", peer_port=40333)


def out(sh, cmd):
    try:
        return sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<raised %s: %s>" % (type(exc).__name__, exc)


def shadow(sh, user):
    """The aging columns of one row, as text, or a sentinel."""
    for line in out(sh, "cat /etc/shadow").splitlines():
        f = line.split(":")
        if f and f[0] == user:
            return ":".join(f[2:])
    return "<no such row>"


def chage_field(sh, user, n):
    lines = out(sh, "chage -l %s" % user).splitlines()
    if len(lines) <= n:
        return "<only %d lines>" % len(lines)
    return lines[n].split(":", 1)[-1].strip()


S = shell()
U = "deploy"

# ------------------------------------------------- the setting flags work
check("chage -E writes the expire column",
      (out(S, "chage -E 2027-01-31 %s; echo rc=$?" % U).strip(),
       shadow(S, U).split(":")[5]),
      ("rc=0", "20849"),
      "it answered 'PAM: Authentication token manipulation error' and "
      "exited 1 for every setting flag")
check("...and chage -l reads it back",
      chage_field(S, U, 3), "Jan 31, 2027")

out(S, "chage -d 20600 -m 3 -M 30 -W 5 -I 10 -E 20900 %s" % U)
check("a whole row goes in at once", shadow(S, U), "20600:3:30:5:10:20900:")
check("Last password change", chage_field(S, U, 0), "May 27, 2026")
check("Password expires is lastchg + max", chage_field(S, U, 1),
      "Jun 26, 2026")
check("Password inactive is lastchg + max + inactive",
      chage_field(S, U, 2), "Jul 06, 2026")
check("Account expires is the expire column", chage_field(S, U, 3),
      "Mar 23, 2027")
check("the three counts come from the file",
      [chage_field(S, U, n) for n in (4, 5, 6)], ["3", "30", "5"],
      "these were the literals 0, 99999 and 7")

# passwd -S is the same row, in one line.
check("passwd -S agrees with the file", out(S, "passwd -S %s" % U).strip(),
      "%s P 2026-05-27 3 30 5 10" % U,
      "its four aging columns were literals, and its date was US-format")

# ------------------------------------------------------------- the edges
out(S, "chage -M 9999 %s" % U)
check("a max of 9999 is a date", chage_field(S, U, 1), "Oct 11, 2053")
out(S, "chage -M 10000 %s" % U)
check("a max of 10000 is never", chage_field(S, U, 1), "never",
      "shadow's ceiling, measured: 9999 prints a date and 10000 does not")
out(S, "chage -M 99999 %s" % U)
check("...and so is 99999", chage_field(S, U, 1), "never",
      "the box's own accounts carry 99999, and it printed Dec 31, 2297")
check("the inactive line inherits the ceiling", chage_field(S, U, 2),
      "never")
out(S, "chage -M 30 -I 0 %s" % U)
check("an inactive of 0 is not never", chage_field(S, U, 2), "Jun 26, 2026")
out(S, "chage -M -1 %s" % U)
check("-1 clears a column rather than storing it",
      shadow(S, U).split(":")[2], "",
      "a max of -1 in the file is not a thing")
check("...and the line goes back to never", chage_field(S, U, 1), "never")

out(S, "chage -d 0 %s" % U)
check("a lastchg of 0 says so in words",
      [chage_field(S, U, n) for n in (0, 1, 2)],
      ["password must be changed"] * 3,
      "not Jan 01, 1970 three times")
check("...and passwd -S prints the epoch date",
      out(S, "passwd -S %s" % U).split()[2], "1970-01-01",
      "the two commands spell the same zero differently, and both are "
      "measured")

# ------------------------------------------------------ usermod agrees
V = shell()
out(V, "usermod -e 2027-01-31 %s" % U)
check("usermod -e writes the file", shadow(V, U).split(":")[5], "20849",
      "it exited 0 and changed nothing, so chage -l still said never")
out(V, "usermod -f 14 %s" % U)
check("usermod -f writes the inactive column",
      shadow(V, U).split(":")[4], "14")
check("chage -l sees what usermod did", chage_field(V, U, 3),
      "Jan 31, 2027")
check("passwd -S sees it too", out(V, "passwd -S %s" % U).split()[-1], "14")
out(V, "usermod -e -1 -f -1 %s" % U)
check("usermod -1 clears both", shadow(V, U), "19811:0:99999:7:::")
check("usermod rejects a bad date",
      out(V, "usermod -e nonsense %s >/dev/null 2>&1; echo $?" % U).strip(),
      "3")
out(V, "usermod --expiredate 2028-06-01 %s" % U)
check("the long form works too", chage_field(V, U, 3), "Jun 01, 2028")

# -------------------------------------------------------- passwd's flags
W = shell()
out(W, "passwd -n 3 -x 60 -w 9 -i 20 %s" % U)
check("passwd's aging flags write the file", shadow(W, U),
      "19811:3:60:9:20::",
      "they were parsed and dropped: passwd -x 60 reported success and "
      "left the row alone")
check("chage -l agrees with them",
      [chage_field(W, U, n) for n in (4, 5, 6)], ["3", "60", "9"])
check("passwd's message", out(W, "passwd -x 60 %s" % U).strip(),
      "passwd: password changed.",
      "'password expiry information changed' is not a string this shadow "
      "has")
out(W, "passwd -e %s" % U)
check("passwd -e sets lastchg to 0", shadow(W, U).split(":")[0], "0",
      "it reported success and wrote nothing")
check("...so chage -l says the password must be changed",
      chage_field(W, U, 0), "password must be changed")

# ------------------------------------------------------ -a and the errors
X = shell()
rows = [l for l in out(X, "passwd -S -a").splitlines() if l.strip()]
shadow_rows = [l for l in out(X, "cat /etc/shadow").splitlines() if ":" in l]
check("passwd -S -a covers every account", len(rows), len(shadow_rows),
      "it printed one line -- the caller's -- on a box with %d rows"
      % len(shadow_rows))
check("...one per row, in file order",
      [r.split()[0] for r in rows], [l.split(":")[0] for l in shadow_rows])
check("every -a line has seven fields",
      sorted({len(r.split()) for r in rows}) or [-1], [7])
check("the dates are ISO",
      [r for r in rows if not re.match(r"^\S+ \S+ \d{4}-\d{2}-\d{2} ", r)][:2],
      [])

check("chage -l on a missing user",
      out(X, "chage -l nosuchuser 2>&1; echo rc=$?").strip().splitlines(),
      ["chage: user 'nosuchuser' does not exist in /etc/passwd", "rc=1"])
check("chage -E on a missing user",
      out(X, "chage -E 2027-01-01 nosuchuser 2>&1; echo rc=$?"
          ).strip().splitlines(),
      ["chage: user 'nosuchuser' does not exist in /etc/passwd", "rc=1"],
      "the same error whether you are reading or writing")
check("passwd -S on a missing user",
      out(X, "passwd -S nosuchuser 2>&1; echo rc=$?").strip().splitlines(),
      ["passwd: user 'nosuchuser' does not exist", "rc=1"])
check("the date is not taken for the username",
      out(X, "chage -E 2027-01-31 %s 2>&1; echo rc=$?" % U).strip(), "rc=0",
      "each flag consumes its own value before the operand is chosen")

# An account with nothing but a lock marker cannot be unlocked.
Y = shell()
out(Y, "useradd -m nopw")
check("passwd -u refuses a passwordless account",
      out(Y, "passwd -u nopw 2>&1; echo rc=$?").strip().splitlines(),
      ["passwd: unlocking the password would result in a passwordless "
       "account.",
       "You should set a password with usermod -p to unlock the password "
       "of this account.", "rc=3"])

# And the whole point: the persistence line has to work and be visible.
Z = shell()
out(Z, "useradd -m -s /bin/bash backdoor")
out(Z, "chage -I -1 -m 0 -M 99999 -E -1 backdoor")
check("the never-expire line takes",
      shadow(Z, "backdoor").split(":")[1:], ["0", "99999", "7", "", "", ""],
      "this is what gets run after adding an account")
check("...and reads back as never",
      [chage_field(Z, "backdoor", n) for n in (1, 2, 3)],
      ["never", "never", "never"])

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
