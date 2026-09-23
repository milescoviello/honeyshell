#!/usr/bin/env python3
"""dpkg said wtmpdb was installed; the command it is named for was absent.

An axis nobody had asked: the login-record tools. `who`, `w`, `last`,
`$SSH_CONNECTION`, `tty` and `who -b`/`uptime` all agree with each other
on this box, which is why nothing had looked further. The package that
provides them did not.

    $ dpkg -l wtmpdb
    ii  wtmpdb  0.13.0-2  amd64  Debian wtmpdb package
    $ dpkg -S /usr/bin/last
    wtmpdb: /usr/bin/last
    $ wtmpdb last
    bash: wtmpdb: command not found

On trixie the legacy wtmp reader is gone and `last` *is* wtmpdb, so an
operator who looks at login records and then reaches for the tool that
manages them found a box that could not be the one dpkg described.

`sessiontest` already asserted "every file wtmpdb lists exists", and it
passed -- because the list did not mention /usr/bin/wtmpdb either. The
box was consistent with itself and not with Debian, which is the only
kind of inconsistency a self-check cannot find.

Ground truth, wtmpdb 0.73.0-3+deb13u1 installed in debian:trixie:

    $ dpkg -L wtmpdb | grep /bin/
    /usr/bin/wtmpdb
    /usr/bin/last
    $ dpkg-query -W -f='${Version}' wtmpdb
    0.73.0-3+deb13u1
    $ apt-cache show wtmpdb | grep ^Description
    Description: utility to display login/logout/reboot information
    $ wtmpdb --version
    wtmpdb 0.73.0
    $ wtmpdb bogus
    Unexpected argument: bogus
    Usage: wtmpdb [command] [options]
    Commands: last, boot, boottime, rotate, shutdown, import

Three things were wrong and all three are the same kind of wrong -- the
package was added to the list without being looked at:

  * the namesake binary was missing entirely
  * the version was 0.13.0-2, a digit out from 0.73.0-3+deb13u1
  * the description was the generic "Debian wtmpdb package" placeholder,
    where every neighbouring package carries its real one

A fourth, `lastb`, is left alone deliberately and recorded as decision 72:
trixie ships it nowhere, but removing a command two suites exercise is a
persona decision rather than a correction.

Usage:  python3 wtmpdbtest.py
"""

import sys

import fakeshell as fs

CHECKS, FAILS = [], []


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
    try:
        out = sh.run(cmd)
    except Exception as exc:                                   # noqa: BLE001
        return "<%s>" % exc, "", None
    err = "".join(sh._err)
    sh._err = []
    return out, err, sh.last_rc


sh = shell()

# ===================================== the package describes itself honestly
out, _e, _rc = run(sh, "dpkg -l wtmpdb")
row = [ln for ln in out.splitlines() if ln.startswith("ii")]
check("wtmpdb is installed", bool(row), True)
if row:
    f = row[0].split()
    check("...at the version trixie ships", f[2], "0.73.0-3+deb13u1",
          "was 0.13.0-2")
    check("...with its real description, not the placeholder",
          " ".join(f[4:]), "utility to display login/logout/reboot "
          "information",
          "was \"Debian wtmpdb package\", which no neighbour carries")

# ============================================ the file list matches Debian
out, _e, _rc = run(sh, "dpkg -L wtmpdb")
listed = [ln for ln in out.splitlines() if ln.startswith("/usr/bin/")]
check("dpkg -L names the binary the package is named for",
      "/usr/bin/wtmpdb" in listed, True,
      "this was the omission that let the self-check pass")
check("...and last, which dpkg -S already credited to it",
      "/usr/bin/last" in listed, True)

# The invariant sessiontest already had, restated here because it is the
# one that could not see this bug: it walks list -> filesystem, and the
# binary was missing from both, so the two agreed about nothing.
for f in listed:
    _o, _e, rc = run(sh, "test -e %s" % f)
    check("%s exists" % f, rc, 0, "dpkg -L must not name a missing file")

# ...and the direction it could not check: filesystem -> list.
_o, _e, rc = run(sh, "test -e /usr/bin/wtmpdb")
check("the binary is really on disk", rc, 0)
out, _e, rc = run(sh, "command -v wtmpdb")
check("...and on PATH", out.strip(), "/usr/bin/wtmpdb")
out, _e, _rc = run(sh, "dpkg -S /usr/bin/wtmpdb")
check("...and dpkg attributes it back to wtmpdb", out.strip(),
      "wtmpdb: /usr/bin/wtmpdb",
      "the two readers have to close the loop")

# ==================================================== the command behaves
out, _e, rc = run(sh, "wtmpdb --version")
check("--version prints the upstream version", out.strip(), "wtmpdb 0.73.0",
      "not the Debian revision dpkg reports -- measured, they differ")
check("...and exits 0", rc, 0)

out, _e, rc = run(sh, "wtmpdb --help")
check("--help names the commands it really has",
      out.strip().splitlines()[:2],
      ["Usage: wtmpdb [command] [options]",
       "Commands: last, boot, boottime, rotate, shutdown, import"])
check("...and exits 0", rc, 0)

out, err, rc = run(sh, "wtmpdb bogus")
check("an unknown verb is named on stderr",
      "Unexpected argument: bogus" in err, True)
check("...with the usage on stdout",
      out.startswith("Usage: wtmpdb [command]"), True)
check("...and still exits 0", rc, 0,
      "measured: wtmpdb exits 0 even on a bad verb")

out, _e, rc = run(sh, "wtmpdb")
check("a bare wtmpdb prints the usage",
      out.startswith("Usage: wtmpdb [command]"), True)

# ============================= wtmpdb last and last are the same records
a, _e, _rc = run(sh, "last")
b, _e, _rc = run(sh, "wtmpdb last")
check("wtmpdb last and last agree, line for line", b, a,
      "they are the same tool reading the same records; if these ever "
      "diverge the box has two answers to one question again")

a, _e, _rc = run(sh, "last -2")
b, _e, _rc = run(sh, "wtmpdb last -2")
check("...including when a limit is passed through", b, a)

# The session this suite is running in has to appear in both.
check("the caller's own session is in wtmpdb last",
      "203.0.113.88" in b or "203.0.113.88" in a, True)

# ======================== and the neighbours still answer for themselves
out, _e, _rc = run(sh, "dpkg -S /usr/bin/w")
check("w still belongs to procps", out.strip(), "procps: /usr/bin/w",
      "the fix must not move files between packages")
out, _e, _rc = run(sh, "dpkg -L util-linux-extra")
check("util-linux-extra still ships utmpdump",
      "/usr/bin/utmpdump" in out, True)
check("...and still does not ship last",
      "/usr/bin/last" in out, False,
      "the half of the earlier note that was checked, and is right")

print("%d checks, %d failed" % (len(CHECKS), len(FAILS)))
for f in FAILS:
    print(f)
sys.exit(1 if FAILS else 0)
