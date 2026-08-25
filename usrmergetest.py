#!/usr/bin/env python3
"""dpkg does not follow the merged-/usr symlinks, and that is the answer.

`/bin`, `/sbin`, `/lib` and `/lib64` are symlinks into `/usr` on Debian 13.
dpkg's file list records only the `/usr` side, and it does **not** resolve
the other spelling:

    dpkg -S /bin/ls        rc 1   dpkg-query: no path found matching pattern /bin/ls
    dpkg -S /bin/ps        rc 1   ... /bin/ps
    dpkg -S /bin/netstat   rc 1   ... /bin/netstat
    dpkg -S /sbin/ip       rc 1   ... /sbin/ip
    dpkg -S /usr/bin/ls    rc 0   coreutils: /usr/bin/ls

Measured on trixie. This emulator resolved the symlink and answered
confidently for every spelling -- the box being *more* helpful than the tool
it imitates, which is its own kind of tell.

It matters on this box specifically. `dpkg -S /bin/ps` is what you run to
find out which package owns a binary an anti-forensics script has replaced,
and 203.0.113.33 replaced exactly that file on 2026-08-25. The real answer
to that question is the unhelpful one, and an admin who gets a package name
where the real dpkg would refuse learns something true about the box.

Usage:  python3 usrmergetest.py
"""

import sys

import fakeshell as F

CHECKS, FAILS = [], []

#: Spellings dpkg's list does not contain, because they are the pre-merge
#: symlink paths.
UNLISTED = ["/bin/ls", "/bin/ps", "/bin/netstat", "/bin/kill", "/sbin/ip",
            "/bin/grep", "/sbin/sysctl"]

#: The canonical spellings, which do resolve. (path, package)
LISTED = [("/usr/bin/ls", "coreutils"), ("/usr/bin/ps", "procps"),
          ("/usr/sbin/ip", "iproute2"), ("/usr/bin/curl", "curl"),
          ("/usr/bin/wget", "wget")]


def check(name, got, want):
    CHECKS.append(name)
    if got != want:
        FAILS.append((name, got, want))


def sh():
    return F.Shell()


def t_the_unlisted_spellings_are_refused():
    s = sh()
    for path in UNLISTED:
        out = s.run("dpkg -S %s 2>&1" % path).strip()
        rc = s.run("dpkg -S %s >/dev/null 2>&1; echo $?" % path).strip()
        check("dpkg -S %s rc" % path, rc, "1")
        check("dpkg -S %s message" % path, out,
              "dpkg-query: no path found matching pattern %s" % path)
        # And nothing on stdout: the message is a diagnostic.
        check("dpkg -S %s prints nothing on stdout" % path,
              s.run("dpkg -S %s 2>/dev/null" % path).strip(), "")


def t_the_canonical_spellings_resolve():
    s = sh()
    for path, pkg in LISTED:
        check("dpkg -S %s" % path,
              s.run("dpkg -S %s 2>/dev/null" % path).strip(),
              "%s: %s" % (pkg, path))
        check("dpkg -S %s rc" % path,
              s.run("dpkg -S %s >/dev/null 2>&1; echo $?" % path).strip(), "0")


def t_the_binary_is_still_there_under_both_names():
    """The refusal is dpkg's bookkeeping, not the file being absent.

    This is the pair that makes the behaviour make sense: /bin/ps runs, and
    `dpkg -S` on that exact path still says it knows nothing about it.
    """
    s = sh()
    for path in ("/bin/ps", "/bin/ls", "/sbin/ip"):
        check("%s exists" % path,
              s.run("test -x %s; echo $?" % path).strip(), "0")
    check("/bin and /usr/bin are the same file",
          s.run("stat -c %i /bin/ls").strip(),
          s.run("stat -c %i /usr/bin/ls").strip())
    # dpkg -L lists the /usr spelling, which is the reason -S refuses the
    # other one.
    listed = s.run("dpkg -L coreutils")
    check("dpkg -L lists the /usr spelling", "/usr/bin/ls" in listed, True)
    check("...and not the /bin one",
          any(l == "/bin/ls" for l in listed.splitlines()), False)


def t_a_bare_name_still_searches():
    """No slash means a search, and that path is unchanged."""
    s = sh()
    check("dpkg -S ls finds coreutils",
          "coreutils" in s.run("dpkg -S ls 2>/dev/null"), True)
    check("...with rc 0",
          s.run("dpkg -S ls >/dev/null 2>&1; echo $?").strip(), "0")


def t_a_path_that_does_not_exist_is_still_refused():
    s = sh()
    check("dpkg -S /no/such/file rc",
          s.run("dpkg -S /no/such/file >/dev/null 2>&1; echo $?").strip(), "1")
    check("dpkg -S /no/such/file message",
          s.run("dpkg -S /no/such/file 2>&1").strip(),
          "dpkg-query: no path found matching pattern /no/such/file")


def main():
    for fn in (t_the_unlisted_spellings_are_refused,
               t_the_canonical_spellings_resolve,
               t_the_binary_is_still_there_under_both_names,
               t_a_bare_name_still_searches,
               t_a_path_that_does_not_exist_is_still_refused):
        fn()
    for name, got, want in FAILS:
        print("  FAIL %-50s got %r want %r" % (name, got, want))
    return len(FAILS)


if __name__ == "__main__":
    rc = main()
    print("usrmergetest: %d checks, %s"
          % (len(CHECKS), "%d differ" % rc if rc else "all pass"))
    sys.exit(1 if rc else 0)
